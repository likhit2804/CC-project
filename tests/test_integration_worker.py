from lambdas.lib.parser import parse_iac_plan
def test_parse_sample():
    data = {'resource_changes':[{'address':'aws_s3_bucket.mybucket','type':'aws_s3_bucket','name':'mybucket','change':{'after':{'acl':'public-read'}}}]}
    parsed = parse_iac_plan(data)
    assert parsed[0]['type']=='aws_s3_bucket'
