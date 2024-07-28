import boto3
import csv
from botocore.exceptions import ClientError

regions = ['ap-south-1', 'eu-north-1', 'eu-west-3', 'eu-west-2', 'eu-west-1', 'ap-northeast-3', 'ap-northeast-2', 'ap-northeast-1', 'ca-central-1', 'sa-east-1', 'ap-southeast-1', 'ap-southeast-2', 'eu-central-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']  # List of regions
account_number = boto3.client('sts').get_caller_identity()['Account']

# Function to create clients for a given region
def create_clients(region):
    return {
        'ec2': boto3.client('ec2', region_name=region, verify=False),
        'rds': boto3.client('rds', region_name=region, verify=False),
        'lambda': boto3.client('lambda', region_name=region, verify=False),
        'elb': boto3.client('elb', region_name=region, verify=False),
        'elbv2': boto3.client('elbv2', region_name=region, verify=False),
        'ecs': boto3.client('ecs', region_name=region, verify=False),
        'dynamodb': boto3.client('dynamodb', region_name=region, verify=False),
        'sns': boto3.client('sns', region_name=region, verify=False),
        'sqs': boto3.client('sqs', region_name=region, verify=False),
        'redshift': boto3.client('redshift', region_name=region, verify=False),
        'dms': boto3.client('dms', region_name=region, verify=False),
        'secretsmanager': boto3.client('secretsmanager', region_name=region, verify=False),
        'elasticache': boto3.client('elasticache', region_name=region, verify=False),
        'es': boto3.client('es', region_name=region, verify=False),
        'elasticbeanstalk': boto3.client('elasticbeanstalk', region_name=region, verify=False),
        's3': boto3.client('s3', region_name=region, verify=False),
        'ecr': boto3.client('ecr', region_name=region, verify=False),
        'route53': boto3.client('route53', region_name=region, verify=False),
        'cognito-idp': boto3.client('cognito-idp', region_name=region, verify=False),
        'cognito-identity': boto3.client('cognito-identity', region_name=region, verify=False),
    }

def paginate_boto3_results(client, method, key, **kwargs):
    results = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        results.extend(page.get(key, []))
    return results

def get_tags(client, resource_type, arn):
    try:
        if resource_type == 's3':
            response = client.get_bucket_tagging(Bucket=arn)
            return {tag['Key']: tag['Value'] for tag in response.get('TagSet', [])}
        elif resource_type == 'ec2':
            response = client.describe_tags(Filters=[{'Name': 'resource-id', 'Values': [arn]}])
            return {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
        elif resource_type == 'rds':
            response = client.list_tags_for_resource(ResourceName=arn)
            return {tag['Key']: tag['Value'] for tag in response.get('TagList', [])}
        elif resource_type == 'lambda':
            response = client.list_tags(Resource=arn)
            return response.get('Tags', {})
        elif resource_type == 'elb':
            response = client.describe_tags(LoadBalancerNames=[arn])
            tags = {}
            if response['TagDescriptions']:
                for tag in response['TagDescriptions'][0]['Tags']:
                    tags[tag['Key']] = tag['Value']
            return tags
        elif resource_type == 'elbv2':
            response = client.describe_tags(ResourceArns=[arn])
            tags = {}
            if response['TagDescriptions']:
                for tag in response['TagDescriptions'][0]['Tags']:
                    tags[tag['Key']] = tag['Value']
            return tags
        elif resource_type == 'dynamodb':
            response = client.list_tags_of_resource(ResourceArn=arn)
            return {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
        elif resource_type == 'sns':
            response = client.list_tags_for_resource(ResourceArn=arn)
            return {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
        elif resource_type == 'sqs':
            response = client.list_queue_tags(QueueUrl=arn)
            return response.get('Tags', {})
        elif resource_type == 'redshift':
            response = client.describe_tags(ResourceName=arn)
            return {tag['Key']: tag['Value'] for tag in response.get('TaggedResources', [])}
        elif resource_type == 'dms':
            response = client.list_tags_for_resource(ResourceArn=arn)
            return {tag['Key']: tag['Value'] for tag in response.get('TagList', [])}
        elif resource_type == 'secretsmanager':
            response = client.describe_secret(SecretId=arn)
            return {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
        elif resource_type == 'elasticache':
            response = client.list_tags_for_resource(ResourceName=arn)
            return {tag['Key']: tag['Value'] for tag in response.get('TagList', [])}
        elif resource_type == 'es':
            response = client.list_tags(ARN=arn)
            return {tag['Key']: tag['Value'] for tag in response.get('TagList', [])}
        elif resource_type == 'elasticbeanstalk':
            response = client.list_tags_for_resource(ResourceArn=arn)
            return {tag['Key']: tag['Value'] for tag in response.get('ResourceTags', [])}
        elif resource_type == 'ecr':
            response = client.list_tags_for_resource(resourceArn=arn)
            return {tag['Key']: tag['Value'] for tag in response.get('tags', [])}
        elif resource_type == 'route53':
            response = client.list_tags_for_resource(ResourceType='hostedzone', ResourceId=arn)
            return {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
        elif resource_type == 'cognito-idp':
            response = client.list_user_pools(MaxResults=60)
            return {tag['Key']: tag['Value'] for tag in response.get('UserPools', [])}
        elif resource_type == 'cognito-identity':
            response = client.list_identity_pools(MaxResults=60)
            return {tag['Key']: tag['Value'] for tag in response.get('IdentityPools', [])}
    except ClientError as e:
        print(f"Error fetching tags for {resource_type} {arn}: {e}")
        return {}

# Specify the 'fiserv' tag keys
fiserv_tag_keys = ['fiserv::apm', 'fiserv::app', 'fiserv::description', 'fiserv::owner', 'fiserv::group', 'fiserv::stage', 'fiserv::environment']

resources = []
processed_s3_buckets = set()

for region in regions:
    print(f"Processing region: {region}")
    clients = create_clients(region)

    # Fetch Cognito User Pools
    try:
        user_pools = paginate_boto3_results(clients['cognito-idp'], 'list_user_pools', 'UserPools')
        for pool in user_pools:
            pool_arn = f"arn:aws:cognito-idp:{region}:{account_number}:userpool/{pool['Id']}"
            tags = get_tags(clients['cognito-idp'], 'cognito-idp', pool_arn)
            resources.append({
                'ResourceType': 'Cognito User Pool',
                'ResourceArn': pool_arn,
                'ResourceName': pool['Name'],
                'Region': region,
                'Tags': tags
            })
    except ClientError as e:
        print(f"Error fetching Cognito User Pools: {e}")

    # Fetch Cognito Identity Pools
    try:
        identity_pools = paginate_boto3_results(clients['cognito-identity'], 'list_identity_pools', 'IdentityPools')
        for pool in identity_pools:
            pool_arn = f"arn:aws:cognito-identity:{region}:{account_number}:identitypool/{pool['IdentityPoolId']}"
            tags = get_tags(clients['cognito-identity'], 'cognito-identity', pool_arn)
            resources.append({
                'ResourceType': 'Cognito Identity Pool',
                'ResourceArn': pool_arn,
                'ResourceName': pool['IdentityPoolName'],
                'Region': region,
                'Tags': tags
            })
    except ClientError as e:
        print(f"Error fetching Cognito Identity Pools: {e}")

    # Other resource fetching code follows...

csv_headers = ['Resource Type', 'Resource ARN', 'Resource Name', 'Region'] + fiserv_tag_keys

with open('aws_resources.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(csv_headers)
    for resource in resources:
        row = [
            resource['ResourceType'],
            resource['ResourceArn'],
            resource['ResourceName'],
            resource['Region']
        ]
        tags = resource['Tags']
        row.extend(tags.get(tag_key, '') for tag_key in fiserv_tag_keys)
        writer.writerow(row)
