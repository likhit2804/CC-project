import os, json, uuid, time, logging
import boto3
from botocore.exceptions import ClientError
from decimal import Decimal

s3 = boto3.client('s3')
sqs = boto3.client('sqs')
ddb = boto3.client('dynamodb')

QUEUE_URL = os.environ['QUEUE_URL']
TABLE_NAME = os.environ['TABLE_NAME']
S3_BUCKET = os.environ['S3_BUCKET']

logger = logging.getLogger('submitter')
logger.setLevel(logging.INFO)

def _write_ddb(scan_id, timestamp):
    ddb.put_item(
        TableName=TABLE_NAME,
        Item={
            'scan_id': {'S': scan_id},
            'status': {'S': 'PENDING'},
            'timestamp': {'N': str(timestamp)},
            'results_json': {'S': '[]'},
            'skipped_feeds': {'S': '[]'}
        }
    )

def _get_scan(scan_id):
    try:
        resp = ddb.get_item(
            TableName=TABLE_NAME,
            Key={'scan_id': {'S': scan_id}}
        )
        if 'Item' not in resp:
            return None
        item = resp['Item']

        # Convert DynamoDB types to JSON-safe
        def conv(v):
            if 'S' in v: return v['S']
            if 'N' in v: return float(v['N'])
            if 'BOOL' in v: return v['BOOL']
            return None
        return {k: conv(v) for k, v in item.items()}

    except ClientError as e:
        logger.exception('DynamoDB read error')
        return None


def handler(event, context):
    """
    Handles both POST /scans and GET /scans/{scan_id}
    """
    logger.info(f"Incoming event: {json.dumps(event)[:300]}")

    method = event.get('httpMethod', 'POST').upper()

    # === GET /scans/{scan_id} ===
    if method == 'GET':
        path_params = event.get('pathParameters') or {}
        scan_id = path_params.get('scan_id')
        if not scan_id:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing scan_id'})
            }

        item = _get_scan(scan_id)
        if not item:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Scan not found'})
            }

        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps(item)
        }

    # === POST /scans ===
    try:
        body = event.get('body')
        if body is None:
            body = event  # if invoked directly
        if isinstance(body, str):
            body = json.loads(body)
    except Exception:
        logger.exception('Bad request JSON')
        return {'statusCode': 400, 'body': json.dumps({'error': 'Invalid JSON'})}

    scan_id = 'api-' + str(uuid.uuid4())
    s3_key = f'iac-scans/{scan_id}.json'
    timestamp = int(time.time())

    try:
        # Upload plan to S3
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=json.dumps(body).encode('utf-8'),
            ServerSideEncryption='AES256'
        )

        # Write initial record
        _write_ddb(scan_id, timestamp)

        # Send to SQS
        sqs.send_message(
            QueueUrl=QUEUE_URL,
            MessageBody=json.dumps({'scan_id': scan_id, 's3_key': s3_key})
        )

        logger.info('Submitted scan %s', scan_id)
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'scan_id': scan_id})
        }

    except ClientError:
        logger.exception('AWS error')
        return {'statusCode': 500, 'body': json.dumps({'error': 'internal'})}
