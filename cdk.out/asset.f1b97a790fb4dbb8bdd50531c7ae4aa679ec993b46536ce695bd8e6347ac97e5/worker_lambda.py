import os, json, logging, time, traceback
import boto3
from botocore.exceptions import ClientError

# ==== Initialize AWS clients ====
s3 = boto3.client('s3')
ddb = boto3.client('dynamodb')

# ==== Environment variables ====
TABLE_NAME = os.environ['TABLE_NAME']
S3_BUCKET = os.environ['S3_BUCKET']
CACHE_TABLE = os.environ.get('CACHE_TABLE_NAME', None)

# ==== Logging ====
logger = logging.getLogger('worker')
logger.setLevel(logging.INFO)

# ==== Safe imports of local libs ====
try:
    from lib.parser import parse_iac_plan
    from lib.correlation_engine import correlate_threats
    from lib.risk_scoring import calculate_risk
    from lib.explanation_builder import build_explanation
    from lib.adapters.aggregator import ThreatAggregator
except Exception as imp_err:
    logger.error(f"❌ Failed to import one or more TA-IaC libs: {imp_err}")
    raise

# ==== Aggregator ====
try:
    agg = ThreatAggregator(cache_table=CACHE_TABLE)
except Exception as e:
    logger.error(f"❌ Failed to initialize ThreatAggregator: {e}")
    raise

# ==== DynamoDB update helper ====
def update_status(scan_id, status, results=None, error=None):
    try:
        expr = 'SET #s = :s'
        ean = {'#s': 'status'}
        eav = {':s': {'S': status}}

        if results is not None:
            expr += ', results_json = :r'
            eav[':r'] = {'S': json.dumps(results)}
        if error is not None:
            expr += ', error_message = :e'
            eav[':e'] = {'S': str(error)}

        ddb.update_item(
            TableName=TABLE_NAME,
            Key={'scan_id': {'S': scan_id}},
            UpdateExpression=expr,
            ExpressionAttributeNames=ean,
            ExpressionAttributeValues=eav
        )
        logger.info(f"✅ Updated scan {scan_id} → {status}")
    except Exception as e:
        logger.error(f"❌ DynamoDB update failed for {scan_id}: {e}")
        raise

# ==== Main worker logic ====
def process_scan(scan_id, s3_key):
    logger.info(f"📥 Fetching IaC plan from s3://{S3_BUCKET}/{s3_key}")
    try:
        obj = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
        plan = json.loads(obj['Body'].read())
    except Exception as e:
        logger.error(f"❌ Failed to read S3 object {s3_key}: {e}")
        raise

    logger.info(f"🔍 Parsing and analyzing {scan_id}")
    try:
        parsed = parse_iac_plan(plan)
    except Exception as e:
        logger.error(f"❌ Failed to parse IaC plan: {e}")
        raise

    results = []
    for res in parsed:
        try:
            findings = agg.check_resource(res)
            correlated = correlate_threats(res, findings)
            score = calculate_risk(correlated)
            explain = build_explanation(res, correlated, score)
            results.append(explain)
        except Exception as e:
            rid = res.get('resource_id', 'unknown')
            logger.exception(f"⚠️ Error processing resource {rid}: {e}")

    update_status(scan_id, 'COMPLETED', results=results)
    logger.info(f"✅ Completed scan {scan_id} with {len(results)} findings")
    return results

# ==== Lambda handler ====
def handler(event, context):
    logger.info(f"📨 Incoming event: {json.dumps(event)[:500]}")

    for rec in event.get('Records', []):
        try:
            body = json.loads(rec['body'])
            scan_id = body.get('scan_id')
            s3_key = body.get('s3_key')
            logger.info(f"🚀 Starting scan {scan_id}")

            update_status(scan_id, 'WORKING')
            process_scan(scan_id, s3_key)
        except Exception as e:
            tb = traceback.format_exc()
            logger.error(f"❌ Failed to process scan: {e}\n{tb}")
            if 'scan_id' in locals():
                update_status(scan_id, 'FAILED', error=tb)

    logger.info("✅ Worker invocation complete")
