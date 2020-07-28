import json
import boto3
import time
import os
 
"""
- Ingest IAM access advisor data to an S3 bucket
- Lambda function should trigger from AWS event bridge in all the AWS regions
- This would copy the access analyzer findings to an S3 bucket.
 
IAM :
- Post IAM events when the region is us-east-1.
- As IAM is global there is no need to copy them from all the regions
 
 
Environment Variables:
    destination_bucket = the name of the bucket to which files should be written.
"""
destination_bucket = "nag_access_analyzer_bucket"
 
my_session = boto3.session.Session()
my_region = my_session.region_name
 
 
def store_results(bucket, key, data):
    awss3_client = boto3.client('s3', region_name="us-east-1")
    awss3_client.put_object(Bucket=bucket, Key=key, Body=data)
 
def lambda_handler(event, context):
 
    s3 = boto3.client('s3', region_name="us-east-1")
 
    for record in event['Records']:
        payload=record["body"]
        access_analyser_data = record["body"]
        data = json.loads(access_analyser_data)
        my_aws_account = data.get("account", None)
        my_id = data.get("id", None)
        k_id = "direct_access_advisor/{}/{}/{}.json".format(my_region, my_aws_account,my_id)
        if key_exists := data.get("detail", {}).get("resourceType"):
            if data["detail"]["resourceType"] in ["AWS::IAM::Role", "AWS::IAM::User"]:
               if my_region in "us-east-1":
                  store_results(bucket=destination_bucket, key=k_id,data=access_analyser_data)
            else:
                store_results(bucket=destination_bucket, key=k_id,data=access_analyser_data)
