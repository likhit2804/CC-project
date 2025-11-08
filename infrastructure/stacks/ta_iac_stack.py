from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    aws_s3 as s3,
    aws_dynamodb as ddb,
    aws_sqs as sqs,
    aws_lambda as _lambda,
    aws_apigateway as apigw,
    aws_iam as iam,
    aws_logs as logs,
    aws_lambda_event_sources as event_sources,
    CfnOutput
)
from constructs import Construct
import os

class TAIaCStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        # ========== STORAGE LAYER ==========
        bucket = s3.Bucket(
            self, "IaCPlansBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN
        )

        table = ddb.Table(
            self, "ScansTable",
            partition_key=ddb.Attribute(name="scan_id", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            encryption=ddb.TableEncryption.AWS_MANAGED,
            removal_policy=RemovalPolicy.RETAIN
        )

        cache_table = ddb.Table(
            self, "FeedCache",
            partition_key=ddb.Attribute(name="key", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            encryption=ddb.TableEncryption.AWS_MANAGED,
            removal_policy=RemovalPolicy.RETAIN
        )

        # ========== QUEUE SYSTEM ==========
        dlq = sqs.Queue(self, "DeadLetterQueue", retention_period=Duration.days(14))
        queue = sqs.Queue(
            self, "ScanQueue",
            visibility_timeout=Duration.minutes(15),
            dead_letter_queue=sqs.DeadLetterQueue(max_receive_count=5, queue=dlq)
        )

        # ========== IAM POLICY ==========
        lambda_policy = iam.PolicyStatement(
            actions=[
                "s3:PutObject", "s3:GetObject", "s3:PutObjectAcl",
                "dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:UpdateItem",
                "sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage"
            ],
            resources=["*"]
        )

        # Path to Lambda code and layers
        lambda_code_path = os.path.join(os.path.dirname(__file__), "..", "..", "lambdas")

        # ========== DEPENDENCY LAYER ==========
        ta_iac_layer = _lambda.LayerVersion(
            self, "TAIaCLayer",
            code=_lambda.Code.from_asset("layers/ta_iac_libs"),  # must exist
            compatible_runtimes=[_lambda.Runtime.PYTHON_3_10],
            description="TA-IaC shared dependencies (dotenv, requests, shodan, boto3)"
        )

        # ========== LAMBDAS ==========
        submitter = _lambda.Function(
            self, "SubmitterFunction",
            runtime=_lambda.Runtime.PYTHON_3_10,
            handler="submitter_lambda.handler",
            code=_lambda.Code.from_asset(lambda_code_path),
            timeout=Duration.seconds(30),
            layers=[ta_iac_layer],
            environment={
                "QUEUE_URL": queue.queue_url,
                "TABLE_NAME": table.table_name,
                "S3_BUCKET": bucket.bucket_name
            }
        )

        worker = _lambda.Function(
            self, "WorkerFunction",
            runtime=_lambda.Runtime.PYTHON_3_10,
            handler="worker_lambda.handler",
            code=_lambda.Code.from_asset(lambda_code_path),
            timeout=Duration.minutes(5),
            layers=[ta_iac_layer],
            environment={
                "TABLE_NAME": table.table_name,
                "S3_BUCKET": bucket.bucket_name,
                "CACHE_TABLE_NAME": cache_table.table_name,
                "OTX_API_KEY": os.getenv("OTX_API_KEY", ""),
                "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY", ""),
                "ABUSEIPDB_API_KEY": os.getenv("ABUSEIPDB_API_KEY", ""),
                "GREYNOISE_API_KEY": os.getenv("GREYNOISE_API_KEY", "")
            }
        )

        # ========== PERMISSIONS ==========
        bucket.grant_put(submitter)
        bucket.grant_read(worker)
        queue.grant_send_messages(submitter)
        queue.grant_consume_messages(worker)
        table.grant_read_write_data(submitter)
        table.grant_read_write_data(worker)
        cache_table.grant_read_write_data(worker)

        # ✅ Connect SQS → Worker Lambda
        worker.add_event_source(event_sources.SqsEventSource(queue))

        # ========== API GATEWAY ==========
        api = apigw.RestApi(
            self, "TAIaCApi",
            rest_api_name="TA-IaC API",
            deploy_options=apigw.StageOptions(stage_name="prod")
        )

        scans = api.root.add_resource("scans")
        scans.add_method("POST", apigw.LambdaIntegration(submitter))

        scan_id = scans.add_resource("{scan_id}")
        scan_id.add_method("GET", apigw.LambdaIntegration(submitter))

        # ========== LOGGING ==========
        logs.LogGroup(
            self, "SubmitterLogGroup",
            log_group_name=f"/aws/lambda/{submitter.function_name}",
            retention=logs.RetentionDays.ONE_MONTH
        )

        logs.LogGroup(
            self, "WorkerLogGroup",
            log_group_name=f"/aws/lambda/{worker.function_name}",
            retention=logs.RetentionDays.ONE_MONTH
        )

        # ========== OUTPUTS ==========
        CfnOutput(self, "ApiUrl", value=api.url)
