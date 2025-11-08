import os, json, logging, time, traceback
import boto3
from botocore.exceptions import ClientError
from lib.parser import parse_iac_plan
from lib.correlation_engine import correlate_threats
from lib.risk_scoring import calculate_risk
from lib.explanation_builder import build_explanation
from lib.adapters.aggregator import ThreatAggregator

s3 = boto3.client('s3')
ddb = boto3.client('dynamodb')

TABLE_NAME = os.environ['TABLE_NAME']
S3_BUCKET = os.environ['S3_BUCKET']
CACHE_TABLE = os.environ.get('CACHE_TABLE_NAME')

logger = logging.getLogger('worker')
logger.setLevel(logging.INFO)

agg = ThreatAggregator(cache_table=CACHE_TABLE)

def update_status(scan_id, status, results=None, error=None):
    expr = 'SET #s = :s'
    ean = {'#s':'status'}
    eav = {':s': {'S': status}}
    if results is not None:
        expr += ', results_json = :r'
        eav[':r'] = {'S': json.dumps(results)}
    if error is not None:
        expr += ', error_message = :e'
        eav[':e'] = {'S': str(error)}
    ddb.update_item(TableName=TABLE_NAME, Key={'scan_id': {'S': scan_id}},
                    UpdateExpression=expr, ExpressionAttributeNames=ean, ExpressionAttributeValues=eav)

def process_scan(scan_id, s3_key):
    obj = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
    plan = json.loads(obj['Body'].read())
    parsed = parse_iac_plan(plan)
    results = []
    skipped = []
    for res in parsed:
        try:
            findings = agg.check_resource(res)
            correlated = correlate_threats(res, findings)
            score = calculate_risk(correlated)
            explain = build_explanation(res, correlated, score)
            results.append(explain)
        except Exception as e:
            logger.exception('Error processing resource %s', res.get('resource_id'))
    update_status(scan_id, 'COMPLETED', results=results)
    return results

def handler(event, context):
    # SQS event
    for rec in event.get('Records', []):
        body = json.loads(rec['body'])
        scan_id = body['scan_id']; s3_key = body['s3_key']
        try:
            update_status(scan_id, 'WORKING')
            process_scan(scan_id, s3_key)
        except Exception as e:
            logger.error('Failed scan %s: %s', scan_id, str(e))
            tb = traceback.format_exc()
            update_status(scan_id, 'FAILED', error=tb)
