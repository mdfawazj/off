Error fetching tags for elasticache sbox-merchant: An error occurred (InvalidARN) when calling the ListTagsForResource operation: Input ARN string does not have 7 components.
Traceback (most recent call last):
  File "C:\Users\f37yhcs\Desktop\pulled\giftdev\vernew_copy1.py", line 314, in <module>
    es_domains = paginate_boto3_results(clients['es'], 'list_domain_names', 'DomainNames')
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\f37yhcs\Desktop\pulled\giftdev\vernew_copy1.py", line 39, in paginate_boto3_results
    paginator = client.get_paginator(method)
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\f37yhcs\AppData\Roaming\Python\Python311\site-packages\botocore\client.py", line 1164, in get_paginator
    raise OperationNotPageableError(operation_name=operation_name)
botocore.exceptions.OperationNotPageableError: Operation cannot be paginated: list_domain_names




import boto3
import csv
from botocore.exceptions import ClientError

# List of regions to scan
regions = ['us-east-1']  # Adjust the regions as needed

# Get the account number
account_number = boto3.client('sts').get_caller_identity()['Account']

# Function to create clients for a given region
def create_clients(region):
    return {
        'cognito': boto3.client('cognito-identity', region_name=region, verify=False),
        'cognito_client': boto3.client('cognito-idp', region_name=region, verify=False),
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
        's3': boto3.client('s3', region_name='us-east-1', verify=False),
        'ecr': boto3.client('ecr', region_name=region, verify=False),
        'route53': boto3.client('route53', region_name='us-east-1', verify=False),
    }

# Function to paginate through boto3 results
def paginate_boto3_results(client, method, key, params=None):
    results = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**params if params else {}):
        results.extend(page.get(key, []))
    return results

# Function to get tags for various resources
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
        elif resource_type == 'cognito':
            if 'user-pool' in arn:
                response = client.list_tags_for_resource(UserPoolId=arn.split('/')[-1])
                return {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
            elif 'identity' in arn:
                response = client.list_tags_for_resource(ResourceArn=arn)
                return {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
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
    except ClientError as e:
        print(f"Error fetching tags for {resource_type} {arn}: {e}")
        return {}

# Specify the 'fiserv' tag keys
fiserv_tag_keys = ['fiserv::apm', 'fiserv::app', 'fiserv::description', 'fiserv::owner', 'fiserv::group', 'fiserv::stage', 'fiserv::environment']

resources = []
processed_s3_buckets = set()
processed_route53_zones = set()

for region in regions:
    print(f"Processing region: {region}")
    clients = create_clients(region)

    # Fetch Cognito User Pools
    cognito_user_pools = paginate_boto3_results(clients['cognito_client'], 'list_user_pools', 'UserPools', {'MaxResults': 20})
    for pool in cognito_user_pools:
        pool_arn = pool['Id']
        tags = get_tags(clients['cognito_client'], 'cognito-idp', pool_arn)
        resources.append({
            'ResourceType': 'Cognito User Pool',
            'ResourceArn': pool_arn,
            'ResourceName': pool['Name'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Cognito Identity Pools
    cognito_identity_pools = paginate_boto3_results(clients['cognito'], 'list_identity_pools', 'IdentityPools', {'MaxResults': 10})
    for pool in cognito_identity_pools:
        pool_arn = pool['IdentityPoolId']
        tags = get_tags(clients['cognito'], 'cognito-identity', pool_arn)
        resources.append({
            'ResourceType': 'Cognito Identity Pool',
            'ResourceArn': pool_arn,
            'ResourceName': pool['IdentityPoolName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch EC2 instances
    ec2_instances = paginate_boto3_results(clients['ec2'], 'describe_instances', 'Reservations')
    for reservation in ec2_instances:
        for instance in reservation['Instances']:
            tags = get_tags(clients['ec2'], 'ec2', instance['InstanceId'])
            resources.append({
                'ResourceType': 'EC2 Instance',
                'ResourceArn': f"arn:aws:ec2:{region}:{account_number}:instance/{instance['InstanceId']}",
                'ResourceName': tags.get('Name', 'N/A'),
                'Region': region,
                'Tags': tags
            })

    # Fetch RDS DB instances
    rds_instances = paginate_boto3_results(clients['rds'], 'describe_db_instances', 'DBInstances')
    for instance in rds_instances:
        tags = get_tags(clients['rds'], 'rds', instance['DBInstanceArn'])
        resources.append({
            'ResourceType': 'RDS Instance',
            'ResourceArn': instance['DBInstanceArn'],
            'ResourceName': instance['DBInstanceIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Lambda functions
    lambda_functions = paginate_boto3_results(clients['lambda'], 'list_functions', 'Functions')
    for function in lambda_functions:
        tags = get_tags(clients['lambda'], 'lambda', function['FunctionArn'])
        resources.append({
            'ResourceType': 'Lambda Function',
            'ResourceArn': function['FunctionArn'],
            'ResourceName': function['FunctionName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Classic Load Balancers
    elbs = paginate_boto3_results(clients['elb'], 'describe_load_balancers', 'LoadBalancerDescriptions')
    for elb in elbs:
        tags = get_tags(clients['elb'], 'elb', elb['LoadBalancerName'])
        resources.append({
            'ResourceType': 'Classic Load Balancer',
            'ResourceArn': f"arn:aws:elb:{region}:{account_number}:loadbalancer/{elb['LoadBalancerName']}",
            'ResourceName': elb['LoadBalancerName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Application and Network Load Balancers
    elbv2s = paginate_boto3_results(clients['elbv2'], 'describe_load_balancers', 'LoadBalancers')
    for elbv2 in elbv2s:
        tags = get_tags(clients['elbv2'], 'elbv2', elbv2['LoadBalancerArn'])
        resources.append({
            'ResourceType': 'Application/Network Load Balancer',
            'ResourceArn': elbv2['LoadBalancerArn'],
            'ResourceName': elbv2['LoadBalancerName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch ECS clusters
    ecs_clusters = paginate_boto3_results(clients['ecs'], 'list_clusters', 'clusterArns')
    for cluster_arn in ecs_clusters:
        cluster_name = cluster_arn.split('/')[-1]
        tags = get_tags(clients['ecs'], 'ecs', cluster_arn)
        resources.append({
            'ResourceType': 'ECS Cluster',
            'ResourceArn': cluster_arn,
            'ResourceName': cluster_name,
            'Region': region,
            'Tags': tags
        })

    # Fetch DynamoDB tables
    dynamodb_tables = paginate_boto3_results(clients['dynamodb'], 'list_tables', 'TableNames')
    for table_name in dynamodb_tables:
        table_arn = f"arn:aws:dynamodb:{region}:{account_number}:table/{table_name}"
        tags = get_tags(clients['dynamodb'], 'dynamodb', table_arn)
        resources.append({
            'ResourceType': 'DynamoDB Table',
            'ResourceArn': table_arn,
            'ResourceName': table_name,
            'Region': region,
            'Tags': tags
        })

    # Fetch SNS topics
    sns_topics = paginate_boto3_results(clients['sns'], 'list_topics', 'Topics')
    for topic in sns_topics:
        tags = get_tags(clients['sns'], 'sns', topic['TopicArn'])
        resources.append({
            'ResourceType': 'SNS Topic',
            'ResourceArn': topic['TopicArn'],
            'ResourceName': topic['TopicArn'].split(':')[-1],
            'Region': region,
            'Tags': tags
        })

    # Fetch SQS queues
    sqs_queues = paginate_boto3_results(clients['sqs'], 'list_queues', 'QueueUrls')
    for queue_url in sqs_queues:
        tags = get_tags(clients['sqs'], 'sqs', queue_url)
        resources.append({
            'ResourceType': 'SQS Queue',
            'ResourceArn': queue_url,
            'ResourceName': queue_url.split('/')[-1],
            'Region': region,
            'Tags': tags
        })

    # Fetch Redshift clusters
    redshift_clusters = paginate_boto3_results(clients['redshift'], 'describe_clusters', 'Clusters')
    for cluster in redshift_clusters:
        tags = get_tags(clients['redshift'], 'redshift', cluster['ClusterIdentifier'])
        resources.append({
            'ResourceType': 'Redshift Cluster',
            'ResourceArn': cluster['ClusterIdentifier'],
            'ResourceName': cluster['ClusterIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch DMS replication instances
    dms_instances = paginate_boto3_results(clients['dms'], 'describe_replication_instances', 'ReplicationInstances')
    for instance in dms_instances:
        tags = get_tags(clients['dms'], 'dms', instance['ReplicationInstanceArn'])
        resources.append({
            'ResourceType': 'DMS Replication Instance',
            'ResourceArn': instance['ReplicationInstanceArn'],
            'ResourceName': instance['ReplicationInstanceIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch SecretsManager secrets
    secrets = paginate_boto3_results(clients['secretsmanager'], 'list_secrets', 'SecretList')
    for secret in secrets:
        tags = get_tags(clients['secretsmanager'], 'secretsmanager', secret['ARN'])
        resources.append({
            'ResourceType': 'Secrets Manager Secret',
            'ResourceArn': secret['ARN'],
            'ResourceName': secret['Name'],
            'Region': region,
            'Tags': tags
        })

    # Fetch ElastiCache clusters
    elasticache_clusters = paginate_boto3_results(clients['elasticache'], 'describe_cache_clusters', 'CacheClusters')
    for cluster in elasticache_clusters:
        tags = get_tags(clients['elasticache'], 'elasticache', cluster['CacheClusterId'])
        resources.append({
            'ResourceType': 'ElastiCache Cluster',
            'ResourceArn': cluster['CacheClusterId'],
            'ResourceName': cluster['CacheClusterId'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Elasticsearch domains
    es_domains = paginate_boto3_results(clients['es'], 'list_domain_names', 'DomainNames')
    for domain in es_domains:
        domain_arn = f"arn:aws:es:{region}:{account_number}:domain/{domain['DomainName']}"
        tags = get_tags(clients['es'], 'es', domain_arn)
        resources.append({
            'ResourceType': 'Elasticsearch Domain',
            'ResourceArn': domain_arn,
            'ResourceName': domain['DomainName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Elastic Beanstalk applications
    elasticbeanstalk_apps = paginate_boto3_results(clients['elasticbeanstalk'], 'describe_applications', 'Applications')
    for app in elasticbeanstalk_apps:
        app_arn = app['ApplicationArn']
        tags = get_tags(clients['elasticbeanstalk'], 'elasticbeanstalk', app_arn)
        resources.append({
            'ResourceType': 'Elastic Beanstalk Application',
            'ResourceArn': app_arn,
            'ResourceName': app['ApplicationName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch S3 buckets (global)
    if region == 'us-east-1' and 'us-east-1' not in processed_s3_buckets:
        s3_buckets = paginate_boto3_results(clients['s3'], 'list_buckets', 'Buckets')
        for bucket in s3_buckets:
            bucket_name = bucket['Name']
            bucket_arn = f"arn:aws:s3:::{bucket_name}"
            tags = get_tags(clients['s3'], 's3', bucket_name)
            resources.append({
                'ResourceType': 'S3 Bucket',
                'ResourceArn': bucket_arn,
                'ResourceName': bucket_name,
                'Region': 'us-east-1',
                'Tags': tags
            })
        processed_s3_buckets.add('us-east-1')

    # Fetch Route53 hosted zones (global)
    if region == 'us-east-1' and 'us-east-1' not in processed_route53_zones:
        route53_zones = paginate_boto3_results(clients['route53'], 'list_hosted_zones', 'HostedZones')
        for zone in route53_zones:
            zone_id = zone['Id'].split('/')[-1]
            zone_arn = zone_id  # No need for full ARN for Route53
            tags = get_tags(clients['route53'], 'route53', zone_id)
            resources.append({
                'ResourceType': 'Route53 Hosted Zone',
                'ResourceArn': zone_arn,
                'ResourceName': zone['Name'],
                'Region': 'us-east-1',
                'Tags': tags
            })
        processed_route53_zones.add('us-east-1')

# Write results to a CSV file
csv_columns = ['ResourceType', 'ResourceArn', 'ResourceName', 'Region', 'Tags']
csv_file = "aws_resources.csv"
try:
    with open(csv_file, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        for data in resources:
            writer.writerow(data)
except IOError as e:
    print(f"I/O error: {e}")
