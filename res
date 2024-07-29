import boto3
import csv
from botocore.exceptions import ClientError

regions = ['us-east-1']  # List of regions
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

def paginate_boto3_results(client, method, key):
    results = []
    paginator = client.get_paginator(method)
    page_iterator = paginator.paginate(PaginationConfig={'MaxItems': 1000})

    for page in paginator.paginate():
        results.extend(page.get(key, []))
    return results


def fetch_cognito_user_pools(client):
    results = []
    paginator = client.get_paginator('list_user_pools')
    for page in paginator.paginate(MaxResults=60):
        results.extend(page.get('UserPools', []))
    return results

def fetch_cognito_identity_pools(client):
    results = []
    paginator = client.get_paginator('list_identity_pools')
    for page in paginator.paginate(MaxResults=60):
        results.extend(page.get('IdentityPools', []))
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
            print(response)
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
        user_pools = fetch_cognito_user_pools(clients['cognito-idp'])
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
        identity_pools = fetch_cognito_identity_pools(clients['cognito-identity'])
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
            'ResourceType': 'RDS DB Instance',
            'ResourceArn': instance['DBInstanceArn'],
            'ResourceName': instance['DBInstanceIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch RDS DB clusters
    rds_clusters = paginate_boto3_results(clients['rds'], 'describe_db_clusters', 'DBClusters')
    for cluster in rds_clusters:
        tags = get_tags(clients['rds'], 'rds', cluster['DBClusterArn'])
        resources.append({
            'ResourceType': 'RDS DB Cluster',
            'ResourceArn': cluster['DBClusterArn'],
            'ResourceName': cluster['DBClusterIdentifier'],
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
            'ResourceArn': f"arn:aws:elasticloadbalancing:{region}:{account_number}:loadbalancer/{elb['LoadBalancerName']}",
            'ResourceName': elb['LoadBalancerName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Application Load Balancers
    albs = paginate_boto3_results(clients['elbv2'], 'describe_load_balancers', 'LoadBalancers')
    for alb in albs:
        tags = get_tags(clients['elbv2'], 'elbv2', alb['LoadBalancerArn'])
        resources.append({
            'ResourceType': 'Application Load Balancer',
            'ResourceArn': alb['LoadBalancerArn'],
            'ResourceName': alb['LoadBalancerName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch ECS clusters
    ecs_clusters = paginate_boto3_results(clients['ecs'], 'list_clusters', 'clusterArns')
    for cluster_arn in ecs_clusters:
        tag_response = clients['ecs'].list_tags_for_resource(resourceArn=cluster_arn)
        cluster_tags = tag_response.get('tags', [])
        fiserv_tags = {tag['key']: tag['value'] for tag in cluster_tags}
        resources.append({
            'ResourceType': 'ECS Cluster',
            'ResourceArn': cluster_arn,
            'ResourceName': cluster_arn.split('/')[-1],
            'Region': region,
            'Tags': fiserv_tags
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
        topic_arn = topic['TopicArn']
        tags = get_tags(clients['sns'], 'sns', topic_arn)
        resources.append({
            'ResourceType': 'SNS Topic',
            'ResourceArn': topic_arn,
            'ResourceName': topic_arn.split(':')[-1],
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
        cluster_arn = f"arn:aws:redshift:{region}:{account_number}:cluster/{cluster['ClusterIdentifier']}"
        tags = get_tags(clients['redshift'], 'redshift', cluster_arn)
        resources.append({
            'ResourceType': 'Redshift Cluster',
            'ResourceArn': cluster_arn,
            'ResourceName': cluster['ClusterIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch DMS replication tasks
    dms_tasks = paginate_boto3_results(clients['dms'], 'describe_replication_tasks', 'ReplicationTasks')
    for task in dms_tasks:
        task_arn = task['ReplicationTaskArn']
        tags = get_tags(clients['dms'], 'dms', task_arn)
        resources.append({
            'ResourceType': 'DMS Replication Task',
            'ResourceArn': task_arn,
            'ResourceName': task['ReplicationTaskIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch SecretsManager secrets
    secrets = paginate_boto3_results(clients['secretsmanager'], 'list_secrets', 'SecretList')
    for secret in secrets:
        secret_arn = secret['ARN']
        tags = get_tags(clients['secretsmanager'], 'secretsmanager', secret_arn)
        resources.append({
            'ResourceType': 'SecretsManager Secret',
            'ResourceArn': secret_arn,
            'ResourceName': secret['Name'],
            'Region': region,
            'Tags': tags
        })

    # Fetch ElastiCache clusters
    elasticache_clusters = paginate_boto3_results(clients['elasticache'], 'describe_cache_clusters', 'CacheClusters')
    for cluster in elasticache_clusters:
        cluster_arn = f"arn:aws:elasticache:{region}:{account_number}:cluster:{cluster['CacheClusterId']}"
        tags = get_tags(clients['elasticache'], 'elasticache', cluster_arn)
        resources.append({
            'ResourceType': 'ElastiCache Cluster',
            'ResourceArn': cluster_arn,
            'ResourceName': cluster['CacheClusterId'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Elasticsearch domains
    try:
        es_domains = clients['es'].list_domain_names().get('DomainNames', [])
        for domain in es_domains:
            domain_name = domain['DomainName']
            domain_arn = f"arn:aws:es:{region}:{account_number}:domain/{domain_name}"
            tags = get_tags(clients['es'], 'es', domain_arn)
            resources.append({
                'ResourceType': 'Elasticsearch Domain',
                'ResourceArn': domain_arn,
                'ResourceName': domain_name,
                'Region': region,
                'Tags': tags
            })
    except ClientError as e:
        print(f"Error fetching Elasticsearch domains: {e}")

    # Fetch Elastic Beanstalk applications
    try:
        ebs_apps = clients['elasticbeanstalk'].describe_applications().get('Applications', [])
        for app in ebs_apps:
            app_name = app['ApplicationName']
            tags = get_tags(clients['elasticbeanstalk'], 'elasticbeanstalk', f"arn:aws:elasticbeanstalk:{region}:{account_number}:application/{app_name}")
            resources.append({
                'ResourceType': 'Elastic Beanstalk Application',
                'ResourceArn': f"arn:aws:elasticbeanstalk:{region}:{account_number}:application/{app_name}",
                'ResourceName': app_name,
                'Region': region,
                'Tags': tags
            })
    except ClientError as e:
        print(f"Error fetching Elastic Beanstalk applications: {e}")

    # Fetch Elastic Beanstalk environments
    try:
        ebs_envs = clients['elasticbeanstalk'].describe_environments().get('Environments', [])
        for env in ebs_envs:
            env_name = env['EnvironmentName']
            tags = get_tags(clients['elasticbeanstalk'], 'elasticbeanstalk',
                            f"arn:aws:elasticbeanstalk:{region}:{account_number}:environment/{env_name}")
            resources.append({
                'ResourceType': 'Elastic Beanstalk Environment',
                'ResourceArn': f"arn:aws:elasticbeanstalk:{region}:{account_number}:environment/{env_name}",
                'ResourceName': env_name,
                'Region': region,
                'Tags': tags
            })
    except ClientError as e:
        print(f"Error fetching Elastic Beanstalk environments: {e}")

    # Fetch S3 buckets
    try:
        s3_buckets = clients['s3'].list_buckets().get('Buckets', [])
        for bucket in s3_buckets:
            bucket_name = bucket['Name']
            if bucket_name not in processed_s3_buckets:
                processed_s3_buckets.add(bucket_name)
                tags = get_tags(clients['s3'], 's3', bucket_name)
                resources.append({
                    'ResourceType': 'S3 Bucket',
                    'ResourceArn': f"arn:aws:s3:::{bucket_name}",
                    'ResourceName': bucket_name,
                    'Region': region,
                    'Tags': tags
                })
    except ClientError as e:
        print(f"Error fetching S3 buckets: {e}")

    # Fetch ECR repositories
    ecr_repositories = paginate_boto3_results(clients['ecr'], 'describe_repositories', 'repositories')
    for repo in ecr_repositories:
        repo_arn = repo['repositoryArn']
        tags = get_tags(clients['ecr'], 'ecr', repo_arn)
        resources.append({
            'ResourceType': 'ECR Repository',
            'ResourceArn': repo_arn,
            'ResourceName': repo['repositoryName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Route 53 hosted zones
    route53_zones = paginate_boto3_results(clients['route53'], 'list_hosted_zones', 'HostedZones')
    for zone in route53_zones:
        zone_id = zone['Id'].split('/')[-1]
        tags = get_tags(clients['route53'], 'route53', zone_id)
        resources.append({
            'ResourceType': 'Route 53 Hosted Zone',
            'ResourceArn': f"arn:aws:route53:::hostedzone/{zone_id}",
            'ResourceName': zone['Name'],
            'Region': region,
            'Tags': tags
        })

csv_headers = ['Resource Type', 'Resource ARN', 'Region', 'Resource Name', 'Account Number'] + fiserv_tag_keys

with open('all_resources_gift_dev.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(csv_headers)

    for resource in resources:
        resource_type = resource['ResourceType']
        resource_arn = resource['ResourceArn']
        resource_name = resource['ResourceName']
        tags = resource['Tags']
        region = resource['Region']  # Use the region from the resource data
        fiserv_tags = [tags.get(tag, '') for tag in fiserv_tag_keys]

        row_data = [resource_type, resource_arn, region, resource_name, account_number] + fiserv_tags
        writer.writerow(row_data)

















{'UserPools': [{'Id': 'us-east-1_0ggLbOhJZ', 'Name': 'gsg-market-sandbox', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger'
, 'PreTokenGenerationConfig': {'LambdaVersion': 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger'}}, 'LastModifiedDate': datetime.datetime(201
9, 8, 19, 13, 15, 34, 769000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2019, 8, 19, 13, 15, 34, 769000, tzinfo=tzlocal())}, {'Id': 'us-east-1_1HyXNwNG0', 'Name': 'GSG API A
ccounts', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger', 'PreTokenGenerationConfig': {'LambdaVersion': 'V1_0', 'LambdaAr
n': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger'}}, 'LastModifiedDate': datetime.datetime(2019, 2, 7, 18, 12, 44, 811000, tzinfo=tzlocal()), 'CreationDate': d
atetime.datetime(2018, 11, 3, 19, 14, 23, 645000, tzinfo=tzlocal())}, {'Id': 'us-east-1_1ixoz7BNp', 'Name': 'GSG Portal Users', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-eas
t-1:628913298676:function:gsg-custom-messages', 'PostConfirmation': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-post-confirmation-trigger'}, 'LastModifiedDate': datetime.dateti
me(2023, 5, 5, 16, 9, 56, 15000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2018, 10, 4, 14, 0, 49, 255000, tzinfo=tzlocal())}, {'Id': 'us-east-1_1tS0DxffH', 'Name': 'gsg-loa
n-sandbox', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger', 'PreTokenGenerationConfig': {'LambdaVersion': 'V1_0', 'Lambda
Arn': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger'}}, 'LastModifiedDate': datetime.datetime(2021, 4, 22, 15, 45, 35, 589000, tzinfo=tzlocal()), 'CreationDate'
: datetime.datetime(2021, 4, 22, 15, 45, 35, 589000, tzinfo=tzlocal())}, {'Id': 'us-east-1_33jgB1Uak', 'Name': 'internal-services-dev', 'LambdaConfig': {}, 'LastModifiedDate': datetime
.datetime(2020, 1, 29, 17, 27, 19, 91000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2020, 1, 29, 17, 27, 19, 91000, tzinfo=tzlocal())}, {'Id': 'us-east-1_7rym4VI9b', 'Name':
 'gsg-batch-service-py-sandbox', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:958612202038:function:gsg-sv-pre-token-trigger', 'PreTokenGenerationConfig': {'LambdaV
ersion': 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:958612202038:function:gsg-sv-pre-token-trigger'}}, 'LastModifiedDate': datetime.datetime(2024, 5, 23, 6, 23, 39, 234000, tzinfo=
tzlocal()), 'CreationDate': datetime.datetime(2024, 5, 23, 6, 23, 39, 234000, tzinfo=tzlocal())}, {'Id': 'us-east-1_9CMfPSfkO', 'Name': 'amplify_backend_manager_dr5rot048dsr3', 'Lambda
Config': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-5fd85b8c', 'DefineAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:functio
n:amplify-login-define-auth-challenge-5fd85b8c', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-create-auth-challenge-5fd85b8c', 'VerifyAuthChalle
ngeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-5fd85b8c'}, 'LastModifiedDate': datetime.datetime(2021, 4, 20, 11, 30, 3, 558000, tzin
fo=tzlocal()), 'CreationDate': datetime.datetime(2021, 4, 20, 11, 29, 44, 88000, tzinfo=tzlocal())}, {'Id': 'us-east-1_9PInrBWeY', 'Name': 'amplify_backend_manager_d2c0hjrkymv4pj', 'La
mbdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-f8c79e2c', 'DefineAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:fun
ction:amplify-login-define-auth-challenge-f8c79e2c', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-create-auth-challenge-f8c79e2c', 'VerifyAuthCh
allengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-f8c79e2c'}, 'LastModifiedDate': datetime.datetime(2021, 6, 4, 0, 29, 9, 140000, tz
info=tzlocal()), 'CreationDate': datetime.datetime(2021, 6, 4, 0, 28, 57, 49000, tzinfo=tzlocal())}, {'Id': 'us-east-1_B7rdW5Qzm', 'Name': 'amplify_backend_manager_d8mpxrgsts83k', 'Lam
bdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-91d0b3d2', 'DefineAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:func
tion:amplify-login-define-auth-challenge-91d0b3d2', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-create-auth-challenge-91d0b3d2', 'VerifyAuthCha
llengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-91d0b3d2'}, 'LastModifiedDate': datetime.datetime(2023, 5, 15, 8, 5, 24, 982000, tz
info=tzlocal()), 'CreationDate': datetime.datetime(2023, 5, 15, 8, 5, 24, 982000, tzinfo=tzlocal())}, {'Id': 'us-east-1_DPBmdZ3oN', 'Name': 'amplify_backend_manager_d3obhecknsd7h3', 'L
ambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-43c337cd', 'DefineAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:fu
nction:amplify-login-define-auth-challenge-43c337cd', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-create-auth-challenge-43c337cd', 'VerifyAuthC
hallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-43c337cd'}, 'LastModifiedDate': datetime.datetime(2023, 5, 8, 1, 12, 54, 980000, 
tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2023, 5, 8, 1, 12, 54, 980000, tzinfo=tzlocal())}, {'Id': 'us-east-1_E8ufxpcmd', 'Name': 'DefaultAuthName-user-pool', 'LambdaConfig
': {'PreSignUp': 'arn:aws:lambda:us-east-1:628913298676:function:proto-work-PreSignUpFunction-mXArlJ1zq1s4'}, 'LastModifiedDate': datetime.datetime(2024, 5, 26, 7, 22, 5, 847000, tzinf
o=tzlocal()), 'CreationDate': datetime.datetime(2024, 5, 4, 11, 4, 46, 713000, tzinfo=tzlocal())}, {'Id': 'us-east-1_FnrS9zggW', 'Name': 'wgiftcard-portal-users-DEV', 'LambdaConfig': {
'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:emp-latest-forgotpwd', 'DefineAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:mmpCustomAuth-stage', 'Cr
eateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:mmpCustomAuth-stage', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:mmpCustomAuth-s
tage'}, 'LastModifiedDate': datetime.datetime(2024, 3, 25, 11, 40, 37, 791000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2020, 5, 18, 14, 25, 23, 972000, tzinfo=tzlocal())},
 {'Id': 'us-east-1_GooSBvsfR', 'Name': 'gsg-ecomm-sandbox', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger', 'PreTokenGene
rationConfig': {'LambdaVersion': 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger'}}, 'LastModifiedDate': datetime.datetime(2019, 9, 25, 17, 3
9, 16, 881000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2019, 9, 25, 17, 35, 53, 284000, tzinfo=tzlocal())}, {'Id': 'us-east-1_I60R0EIXZ', 'Name': 'gsg-batch-service-py-san
dbox', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:958612202038:function:gsg-sv-pre-token-trigger', 'PreTokenGenerationConfig': {'LambdaVersion': 'V1_0', 'LambdaAr
n': 'arn:aws:lambda:us-east-1:958612202038:function:gsg-sv-pre-token-trigger'}}, 'LastModifiedDate': datetime.datetime(2024, 5, 23, 6, 49, 37, 149000, tzinfo=tzlocal()), 'CreationDate'
: datetime.datetime(2024, 5, 23, 6, 49, 37, 149000, tzinfo=tzlocal())}, {'Id': 'us-east-1_JSRUvUtgZ', 'Name': 'amplify_backend_manager_dtpa71gmagh92', 'LambdaConfig': {'CustomMessage':
 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-25d8b99d', 'DefineAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-define-aut
h-challenge-25d8b99d', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-create-auth-challenge-25d8b99d', 'VerifyAuthChallengeResponse': 'arn:aws:lam
bda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-25d8b99d'}, 'LastModifiedDate': datetime.datetime(2023, 4, 5, 2, 38, 18, 384000, tzinfo=tzlocal()), 'CreationDat
e': datetime.datetime(2023, 4, 5, 2, 38, 18, 384000, tzinfo=tzlocal())}, {'Id': 'us-east-1_JSrz4dwcq', 'Name': 'catalogmobileapp929c9c4a_userpool_929c9c4a-staging', 'LambdaConfig': {},
 'LastModifiedDate': datetime.datetime(2023, 5, 8, 2, 25, 47, 168000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2023, 5, 8, 2, 25, 47, 168000, tzinfo=tzlocal())}, {'Id': 'us
-east-1_K3Bn6Vijd', 'Name': 'amplify_backend_manager_d179owmbxrbikk', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-749
e72b0', 'DefineAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-define-auth-challenge-749e72b0', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298
676:function:amplify-login-create-auth-challenge-749e72b0', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-749e72b0'
}, 'LastModifiedDate': datetime.datetime(2021, 4, 15, 9, 45, 9, 963000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2021, 4, 15, 9, 44, 50, 131000, tzinfo=tzlocal())}, {'Id': 
'us-east-1_KBLQHb83R', 'Name': 'gsg-svdot-qa', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger-test', 'PreTokenGenerationCo
nfig': {'LambdaVersion': 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger-test'}}, 'LastModifiedDate': datetime.datetime(2023, 3, 31, 9, 58, 3
7, 98000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2023, 3, 31, 9, 47, 59, 345000, tzinfo=tzlocal())}, {'Id': 'us-east-1_LCFl8B93S', 'Name': 'CloudWatchDashboardSharing', '
LambdaConfig': {}, 'LastModifiedDate': datetime.datetime(2022, 11, 16, 15, 29, 27, 578000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2022, 11, 16, 15, 29, 27, 578000, tzinfo
=tzlocal())}, {'Id': 'us-east-1_LkD2T1l8O', 'Name': 'gsg-batch-service-py-sandbox', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:958612202038:function:gsg-sv-pre-to
ken-trigger', 'PreTokenGenerationConfig': {'LambdaVersion': 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:958612202038:function:gsg-sv-pre-token-trigger'}}, 'LastModifiedDate': dateti
me.datetime(2024, 5, 23, 6, 10, 16, 758000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2024, 5, 23, 6, 10, 16, 758000, tzinfo=tzlocal())}, {'Id': 'us-east-1_N6fVQPLFA', 'Name
': 'amplify_backend_manager_d7iesq9wh2jgo', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-aca94844', 'DefineAuthChallen
ge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-define-auth-challenge-aca94844', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login
-create-auth-challenge-aca94844', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-aca94844'}, 'LastModifiedDate': dat
etime.datetime(2021, 5, 28, 2, 19, 57, 525000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2021, 5, 28, 2, 19, 45, 407000, tzinfo=tzlocal())}, {'Id': 'us-east-1_OMBsQljba', 'N
ame': 'amplify_backend_manager_d3fbh36girfl49', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-0b0dce20', 'DefineAuthCha
llenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-define-auth-challenge-0b0dce20', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-l
ogin-create-auth-challenge-0b0dce20', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-0b0dce20'}, 'LastModifiedDate':
 datetime.datetime(2020, 12, 29, 13, 31, 24, 861000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2020, 12, 29, 13, 31, 4, 880000, tzinfo=tzlocal())}, {'Id': 'us-east-1_OrUtgo8
41', 'Name': 'amplify_backend_manager_d1694l1ojaegjg', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-49ea4b35', 'Define
AuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-define-auth-challenge-49ea4b35', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:am
plify-login-create-auth-challenge-49ea4b35', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-49ea4b35'}, 'LastModifie
dDate': datetime.datetime(2021, 1, 13, 12, 31, 53, 130000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2021, 1, 13, 12, 31, 33, 353000, tzinfo=tzlocal())}, {'Id': 'us-east-1_O
sDRLi3PP', 'Name': 'my-user-pool', 'LambdaConfig': {}, 'LastModifiedDate': datetime.datetime(2023, 9, 15, 5, 14, 28, 924000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2023, 
9, 15, 5, 14, 28, 924000, tzinfo=tzlocal())}, {'Id': 'us-east-1_PZaeB4rAS', 'Name': 'amplify_backend_manager_d3r5uqr0ia9xxd', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-
1:628913298676:function:amplify-login-custom-message-78190fb8', 'DefineAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-define-auth-challenge-78190fb8', 'C
reateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-create-auth-challenge-78190fb8', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:62891329867
6:function:amplify-login-verify-auth-challenge-78190fb8'}, 'LastModifiedDate': datetime.datetime(2021, 6, 3, 20, 19, 38, 247000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(20
21, 6, 3, 20, 19, 26, 145000, tzinfo=tzlocal())}, {'Id': 'us-east-1_PuALmYTNQ', 'Name': 'wgiftcard-dev-customauth', 'LambdaConfig': {}, 'LastModifiedDate': datetime.datetime(2022, 10, 
27, 4, 50, 14, 320000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2022, 10, 27, 4, 50, 14, 320000, tzinfo=tzlocal())}, {'Id': 'us-east-1_Q1eFy1UhG', 'Name': 'gsg-ha-dev', 'La
mbdaConfig': {}, 'LastModifiedDate': datetime.datetime(2023, 9, 15, 1, 40, 49, 186000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2023, 9, 15, 1, 40, 48, 918000, tzinfo=tzloc
al())}, {'Id': 'us-east-1_QDQc763SD', 'Name': 'amplify_backend_manager_d1qw241r68utjo', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-
custom-message-a66cc101', 'DefineAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-define-auth-challenge-a66cc101', 'CreateAuthChallenge': 'arn:aws:lambda:u
s-east-1:628913298676:function:amplify-login-create-auth-challenge-a66cc101', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-c
hallenge-a66cc101'}, 'LastModifiedDate': datetime.datetime(2023, 4, 1, 2, 40, 45, 896000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2023, 4, 1, 2, 40, 45, 896000, tzinfo=tzl
ocal())}, {'Id': 'us-east-1_UWYb8zhi7', 'Name': 'gsg-ha-test', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-sv-pre-token-trigger', 'PreTok
enGenerationConfig': {'LambdaVersion': 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-sv-pre-token-trigger'}}, 'LastModifiedDate': datetime.datetime(2024, 2, 
13, 5, 6, 42, 221000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2024, 2, 13, 5, 6, 42, 221000, tzinfo=tzlocal())}, {'Id': 'us-east-1_UclMT2bo4', 'Name': 'amplify_backend_man
ager_dnhatf2etltkl', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-1133e5db', 'DefineAuthChallenge': 'arn:aws:lambda:us
-east-1:628913298676:function:amplify-login-define-auth-challenge-1133e5db', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-create-auth-challenge-
1133e5db', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-1133e5db'}, 'LastModifiedDate': datetime.datetime(2022, 7,
 7, 4, 43, 51, 384000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2022, 7, 7, 4, 43, 14, 295000, tzinfo=tzlocal())}, {'Id': 'us-east-1_WfTzs92Iv', 'Name': 'gsg-batch-service-
py-dev', 'LambdaConfig': {}, 'LastModifiedDate': datetime.datetime(2023, 9, 29, 3, 42, 37, 866000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2023, 9, 29, 3, 42, 37, 866000, 
tzinfo=tzlocal())}, {'Id': 'us-east-1_XNl6wTlVO', 'Name': 'gsg-autoreload-sandbox', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token
-trigger', 'PreTokenGenerationConfig': {'LambdaVersion': 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger'}}, 'LastModifiedDate': datetime.dat
etime(2020, 3, 24, 22, 47, 34, 279000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2020, 3, 24, 22, 47, 34, 279000, tzinfo=tzlocal())}, {'Id': 'us-east-1_XwR2RwJf1', 'Name': '
gsg-ha-dev', 'LambdaConfig': {}, 'LastModifiedDate': datetime.datetime(2023, 9, 14, 6, 36, 1, 156000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2023, 9, 14, 6, 36, 1, 156000
, tzinfo=tzlocal())}, {'Id': 'us-east-1_XyxicmlEk', 'Name': 'gsg-ttr-sandbox', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trig
ger', 'PreTokenGenerationConfig': {'LambdaVersion': 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger'}}, 'LastModifiedDate': datetime.datetime
(2019, 12, 18, 15, 37, 37, 794000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2019, 12, 18, 15, 37, 37, 794000, tzinfo=tzlocal())}, {'Id': 'us-east-1_YokLl9EcV', 'Name': 'amp
lify_backend_manager_dni3pu0oeo0sg', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-d2b27fd3', 'DefineAuthChallenge': 'a
rn:aws:lambda:us-east-1:628913298676:function:amplify-login-define-auth-challenge-d2b27fd3', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-create
-auth-challenge-d2b27fd3', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-d2b27fd3'}, 'LastModifiedDate': datetime.d
atetime(2022, 7, 6, 8, 3, 14, 523000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2022, 7, 6, 8, 2, 37, 531000, tzinfo=tzlocal())}, {'Id': 'us-east-1_YukTq3PIW', 'Name': 'gsg-
internal-services-sandbox', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger', 'PreTokenGenerationConfig': {'LambdaVersion':
 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger'}}, 'LastModifiedDate': datetime.datetime(2019, 6, 3, 18, 18, 4, 822000, tzinfo=tzlocal()), 
'CreationDate': datetime.datetime(2019, 6, 3, 18, 18, 4, 822000, tzinfo=tzlocal())}, {'Id': 'us-east-1_Zhpzy42Ao', 'Name': 'gsg-payments-sandbox', 'LambdaConfig': {'PreTokenGeneration'
: 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger', 'PreTokenGenerationConfig': {'LambdaVersion': 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:628913298676:func
tion:gsg-pre-token-trigger'}}, 'LastModifiedDate': datetime.datetime(2020, 5, 5, 19, 13, 50, 571000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2020, 5, 5, 19, 13, 50, 571000
, tzinfo=tzlocal())}, {'Id': 'us-east-1_abvoURHxq', 'Name': 'ecomm', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger', 'Pre
TokenGenerationConfig': {'LambdaVersion': 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger'}}, 'LastModifiedDate': datetime.datetime(2019, 5, 
8, 16, 0, 21, 898000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2019, 5, 8, 16, 0, 21, 898000, tzinfo=tzlocal())}, {'Id': 'us-east-1_b2ufpp2D5', 'Name': 'amplify_backend_man
ager_d570mit9zgejs', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-bc0d4de4', 'DefineAuthChallenge': 'arn:aws:lambda:us
-east-1:628913298676:function:amplify-login-define-auth-challenge-bc0d4de4', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-create-auth-challenge-
bc0d4de4', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-bc0d4de4'}, 'LastModifiedDate': datetime.datetime(2021, 1,
 12, 14, 6, 5, 203000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2021, 1, 12, 14, 5, 45, 146000, tzinfo=tzlocal())}, {'Id': 'us-east-1_b3Kyv5CvT', 'Name': 'gsg-sv-user-pool-
dev', 'LambdaConfig': {}, 'LastModifiedDate': datetime.datetime(2023, 9, 13, 3, 1, 18, 50000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2023, 9, 13, 3, 1, 17, 851000, tzinfo
=tzlocal())}, {'Id': 'us-east-1_bpLsuLsee', 'Name': 'amplify_backend_manager_d2z9o1c6alm6x', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-l
ogin-custom-message-0b6b7465', 'DefineAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-define-auth-challenge-0b6b7465', 'CreateAuthChallenge': 'arn:aws:lam
bda:us-east-1:628913298676:function:amplify-login-create-auth-challenge-0b6b7465', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-a
uth-challenge-0b6b7465'}, 'LastModifiedDate': datetime.datetime(2023, 5, 8, 1, 6, 11, 596000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2023, 5, 8, 1, 6, 11, 596000, tzinfo=
tzlocal())}, {'Id': 'us-east-1_bqHTawIWq', 'Name': 'marketplace688c53cd_userpool_688c53cd-previews', 'LambdaConfig': {}, 'LastModifiedDate': datetime.datetime(2024, 4, 29, 9, 21, 27, 2
23000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2022, 7, 26, 11, 7, 52, 994000, tzinfo=tzlocal())}, {'Id': 'us-east-1_dFCE7zLj9', 'Name': 'gsg-ha-dev', 'LambdaConfig': {}, 
'LastModifiedDate': datetime.datetime(2023, 9, 14, 6, 42, 2, 459000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2023, 9, 14, 6, 42, 2, 259000, tzinfo=tzlocal())}, {'Id': 'us-
east-1_eiCRKgwWP', 'Name': 'amplify_backend_manager_d2hd547lsvnb9h', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-f515
c221', 'DefineAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-define-auth-challenge-f515c221', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:6289132986
76:function:amplify-login-create-auth-challenge-f515c221', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-f515c221'}
, 'LastModifiedDate': datetime.datetime(2023, 8, 14, 15, 20, 3, 95000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2023, 8, 14, 15, 20, 2, 918000, tzinfo=tzlocal())}, {'Id': '
us-east-1_gYUsSVJrM', 'Name': 'identity-service-dev', 'LambdaConfig': {}, 'LastModifiedDate': datetime.datetime(2019, 11, 13, 22, 5, 55, 248000, tzinfo=tzlocal()), 'CreationDate': date
time.datetime(2019, 11, 13, 22, 5, 55, 248000, tzinfo=tzlocal())}, {'Id': 'us-east-1_hSaVoIE0x', 'Name': 'amplify_backend_manager_dwog9fa0wigsm', 'LambdaConfig': {'CustomMessage': 'arn
:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-4d65367c', 'DefineAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-define-auth-cha
llenge-4d65367c', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-create-auth-challenge-4d65367c', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:u
s-east-1:628913298676:function:amplify-login-verify-auth-challenge-4d65367c'}, 'LastModifiedDate': datetime.datetime(2021, 4, 23, 7, 25, 21, 874000, tzinfo=tzlocal()), 'CreationDate': 
datetime.datetime(2021, 4, 23, 7, 25, 2, 666000, tzinfo=tzlocal())}, {'Id': 'us-east-1_iYjcUqpBN', 'Name': 'marketplace_proto_userpool', 'LambdaConfig': {}, 'LastModifiedDate': datetim
e.datetime(2021, 6, 3, 23, 15, 18, 223000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2021, 6, 3, 23, 15, 18, 223000, tzinfo=tzlocal())}, {'Id': 'us-east-1_l8nGFwd2d', 'Name'
: 'amplify_backend_manager_dw3tauzl3x22p', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-custom-message-00b5dfb9', 'DefineAuthChalleng
e': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-define-auth-challenge-00b5dfb9', 'CreateAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-
create-auth-challenge-00b5dfb9', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-challenge-00b5dfb9'}, 'LastModifiedDate': date
time.datetime(2021, 1, 12, 14, 36, 22, 518000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2021, 1, 12, 14, 36, 3, 57000, tzinfo=tzlocal())}, {'Id': 'us-east-1_ldHyqZzI6', 'Na
me': 'gsg-risk-sandbox', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger', 'PreTokenGenerationConfig': {'LambdaVersion': 'V
1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger'}}, 'LastModifiedDate': datetime.datetime(2019, 10, 9, 18, 32, 7, 215000, tzinfo=tzlocal()), 'C
reationDate': datetime.datetime(2019, 10, 9, 18, 32, 7, 215000, tzinfo=tzlocal())}, {'Id': 'us-east-1_npqBohgvL', 'Name': 'marketplace688c53cd_userpool_688c53cd-dev', 'LambdaConfig': {
}, 'LastModifiedDate': datetime.datetime(2024, 4, 30, 11, 40, 4, 715000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2021, 6, 4, 12, 48, 50, 405000, tzinfo=tzlocal())}, {'Id':
 'us-east-1_pwm2pxySV', 'Name': 'ops-portal-dev', 'LambdaConfig': {}, 'LastModifiedDate': datetime.datetime(2020, 1, 17, 15, 24, 34, 237000, tzinfo=tzlocal()), 'CreationDate': datetime
.datetime(2020, 1, 13, 22, 30, 49, 820000, tzinfo=tzlocal())}, {'Id': 'us-east-1_qF0tUevTo', 'Name': 'gsgecho', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:lambda:us-east-1:6289132
98676:function:gsg-pre-token-trigger', 'PreTokenGenerationConfig': {'LambdaVersion': 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:628913298676:function:gsg-pre-token-trigger'}}, 'Las
tModifiedDate': datetime.datetime(2019, 4, 26, 12, 35, 37, 255000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2019, 4, 16, 16, 35, 36, 108000, tzinfo=tzlocal())}, {'Id': 'us-
east-1_sQGHn2Rit', 'Name': 'saml-test', 'LambdaConfig': {'PreSignUp': 'arn:aws:lambda:us-east-1:628913298676:function:print-lambda', 'CustomMessage': 'arn:aws:lambda:us-east-1:62891329
8676:function:print-lambda', 'PostConfirmation': 'arn:aws:lambda:us-east-1:628913298676:function:print-lambda', 'PostAuthentication': 'arn:aws:lambda:us-east-1:628913298676:function:pr
int-lambda'}, 'LastModifiedDate': datetime.datetime(2024, 1, 2, 8, 15, 39, 913000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2019, 12, 30, 19, 56, 39, 555000, tzinfo=tzlocal
())}, {'Id': 'us-east-1_tihdVO089', 'Name': 'amplify_backend_manager_d3oi9rnjiewswk', 'LambdaConfig': {'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-cu
stom-message-0d1a55e5', 'DefineAuthChallenge': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-define-auth-challenge-0d1a55e5', 'CreateAuthChallenge': 'arn:aws:lambda:us-
east-1:628913298676:function:amplify-login-create-auth-challenge-0d1a55e5', 'VerifyAuthChallengeResponse': 'arn:aws:lambda:us-east-1:628913298676:function:amplify-login-verify-auth-cha
llenge-0d1a55e5'}, 'LastModifiedDate': datetime.datetime(2021, 5, 24, 1, 12, 51, 784000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2021, 5, 24, 1, 12, 39, 659000, tzinfo=tzl
ocal())}, {'Id': 'us-east-1_vgRv2E3kL', 'Name': 'SAML Test Pool', 'LambdaConfig': {}, 'LastModifiedDate': datetime.datetime(2019, 7, 25, 12, 51, 17, 910000, tzinfo=tzlocal()), 'Creatio
nDate': datetime.datetime(2019, 7, 25, 12, 51, 17, 910000, tzinfo=tzlocal())}, {'Id': 'us-east-1_xVc2kwIXm', 'Name': 'gsg-svdot-dev', 'LambdaConfig': {'PreTokenGeneration': 'arn:aws:la
mbda:us-east-1:628913298676:function:gsg-sv-pre-token-trigger-es6-sandbox', 'PreTokenGenerationConfig': {'LambdaVersion': 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:628913298676:fu
nction:gsg-sv-pre-token-trigger-es6-sandbox'}}, 'LastModifiedDate': datetime.datetime(2024, 1, 19, 1, 39, 35, 648000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2022, 9, 26, 
3, 38, 12, 720000, tzinfo=tzlocal())}, {'Id': 'us-east-1_xd5VklE2Q', 'Name': 'gyft-b2b-market', 'LambdaConfig': {'PreSignUp': 'arn:aws:lambda:us-east-1:628913298676:function:gyft-marke
t-user-signup', 'CustomMessage': 'arn:aws:lambda:us-east-1:628913298676:function:generic-cognito-triggers:dev-gbm', 'PreTokenGeneration': 'arn:aws:lambda:us-east-1:628913298676:functio
n:gift-market-portal-cognito-pre-token-trigger', 'PreTokenGenerationConfig': {'LambdaVersion': 'V1_0', 'LambdaArn': 'arn:aws:lambda:us-east-1:628913298676:function:gift-market-portal-c
ognito-pre-token-trigger'}}, 'LastModifiedDate': datetime.datetime(2024, 7, 3, 17, 32, 5, 364000, tzinfo=tzlocal()), 'CreationDate': datetime.datetime(2019, 8, 13, 22, 15, 52, 578000, 
tzinfo=tzlocal())}, {'Id': 'us-east-1_yMyleuE9Q', 'Name': 'wgiftcard-portal-users-TEST', 'LambdaConfig': {}, 'LastModifiedDate': datetime.datetime(2024, 2, 12, 7, 1, 30, 535000, tzinfo
=tzlocal()), 'CreationDate': datetime.datetime(2024, 2, 12, 6, 29, 50, 675000, tzinfo=tzlocal())}], 'ResponseMetadata': {'RequestId': 'fd424045-fe56-411d-9a8e-1c25f8949dde', 'HTTPStatu
sCode': 200, 'HTTPHeaders': {'date': 'Mon, 29 Jul 2024 00:43:13 GMT', 'content-type': 'application/x-amz-json-1.1', 'content-length': '22780', 'connection': 'keep-alive', 'x-amzn-requestid': 'fd424045-fe56-411d-9a8e-1c25f8949dde'}, 'RetryAttempts': 0}}
Traceback (most recent call last):
  File "C:\Users\f37yhcs\Desktop\pulled\giftdev\vernew11.py", line 147, in <module>
    tags = get_tags(clients['cognito-idp'], 'cognito-idp', pool_arn)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\f37yhcs\Desktop\pulled\giftdev\vernew11.py", line 124, in get_tags
    return {tag['Key']: tag['Value'] for tag in response.get('UserPools', [])}
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\f37yhcs\Desktop\pulled\giftdev\vernew11.py", line 124, in <dictcomp>
    return {tag['Key']: tag['Value'] for tag in response.get('UserPools', [])}
            ~~~^^^^^^^
KeyError: 'Key'







import boto3
import csv

from botocore.exceptions import ClientError

regions = ['us-east-1']  # List of regions
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

def paginate_boto3_results(client, method, key):
    results = []
    paginator = client.get_paginator(method)
    page_iterator = paginator.paginate(PaginationConfig={'MaxItems': 1000})

    for page in paginator.paginate():
        results.extend(page.get(key, []))
    return results


def fetch_cognito_user_pools(client):
    results = []
    paginator = client.get_paginator('list_user_pools')
    for page in paginator.paginate(MaxResults=60):
        results.extend(page.get('UserPools', []))
    return results

def fetch_cognito_identity_pools(client):
    results = []
    paginator = client.get_paginator('list_identity_pools')
    for page in paginator.paginate(MaxResults=60):
        results.extend(page.get('IdentityPools', []))
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
        user_pools = fetch_cognito_user_pools(clients['cognito-idp'])
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
        identity_pools = fetch_cognito_identity_pools(clients['cognito-identity'])
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
            'ResourceType': 'RDS DB Instance',
            'ResourceArn': instance['DBInstanceArn'],
            'ResourceName': instance['DBInstanceIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch RDS DB clusters
    rds_clusters = paginate_boto3_results(clients['rds'], 'describe_db_clusters', 'DBClusters')
    for cluster in rds_clusters:
        tags = get_tags(clients['rds'], 'rds', cluster['DBClusterArn'])
        resources.append({
            'ResourceType': 'RDS DB Cluster',
            'ResourceArn': cluster['DBClusterArn'],
            'ResourceName': cluster['DBClusterIdentifier'],
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
            'ResourceArn': f"arn:aws:elasticloadbalancing:{region}:{account_number}:loadbalancer/{elb['LoadBalancerName']}",
            'ResourceName': elb['LoadBalancerName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Application Load Balancers
    albs = paginate_boto3_results(clients['elbv2'], 'describe_load_balancers', 'LoadBalancers')
    for alb in albs:
        tags = get_tags(clients['elbv2'], 'elbv2', alb['LoadBalancerArn'])
        resources.append({
            'ResourceType': 'Application Load Balancer',
            'ResourceArn': alb['LoadBalancerArn'],
            'ResourceName': alb['LoadBalancerName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch ECS clusters
    ecs_clusters = paginate_boto3_results(clients['ecs'], 'list_clusters', 'clusterArns')
    for cluster_arn in ecs_clusters:
        tag_response = clients['ecs'].list_tags_for_resource(resourceArn=cluster_arn)
        cluster_tags = tag_response.get('tags', [])
        fiserv_tags = {tag['key']: tag['value'] for tag in cluster_tags}
        resources.append({
            'ResourceType': 'ECS Cluster',
            'ResourceArn': cluster_arn,
            'ResourceName': cluster_arn.split('/')[-1],
            'Region': region,
            'Tags': fiserv_tags
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
        topic_arn = topic['TopicArn']
        tags = get_tags(clients['sns'], 'sns', topic_arn)
        resources.append({
            'ResourceType': 'SNS Topic',
            'ResourceArn': topic_arn,
            'ResourceName': topic_arn.split(':')[-1],
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
        cluster_arn = f"arn:aws:redshift:{region}:{account_number}:cluster/{cluster['ClusterIdentifier']}"
        tags = get_tags(clients['redshift'], 'redshift', cluster_arn)
        resources.append({
            'ResourceType': 'Redshift Cluster',
            'ResourceArn': cluster_arn,
            'ResourceName': cluster['ClusterIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch DMS replication tasks
    dms_tasks = paginate_boto3_results(clients['dms'], 'describe_replication_tasks', 'ReplicationTasks')
    for task in dms_tasks:
        task_arn = task['ReplicationTaskArn']
        tags = get_tags(clients['dms'], 'dms', task_arn)
        resources.append({
            'ResourceType': 'DMS Replication Task',
            'ResourceArn': task_arn,
            'ResourceName': task['ReplicationTaskIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch SecretsManager secrets
    secrets = paginate_boto3_results(clients['secretsmanager'], 'list_secrets', 'SecretList')
    for secret in secrets:
        secret_arn = secret['ARN']
        tags = get_tags(clients['secretsmanager'], 'secretsmanager', secret_arn)
        resources.append({
            'ResourceType': 'SecretsManager Secret',
            'ResourceArn': secret_arn,
            'ResourceName': secret['Name'],
            'Region': region,
            'Tags': tags
        })

    # Fetch ElastiCache clusters
    elasticache_clusters = paginate_boto3_results(clients['elasticache'], 'describe_cache_clusters', 'CacheClusters')
    for cluster in elasticache_clusters:
        cluster_arn = f"arn:aws:elasticache:{region}:{account_number}:cluster:{cluster['CacheClusterId']}"
        tags = get_tags(clients['elasticache'], 'elasticache', cluster_arn)
        resources.append({
            'ResourceType': 'ElastiCache Cluster',
            'ResourceArn': cluster_arn,
            'ResourceName': cluster['CacheClusterId'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Elasticsearch domains
    try:
        es_domains = clients['es'].list_domain_names().get('DomainNames', [])
        for domain in es_domains:
            domain_name = domain['DomainName']
            domain_arn = f"arn:aws:es:{region}:{account_number}:domain/{domain_name}"
            tags = get_tags(clients['es'], 'es', domain_arn)
            resources.append({
                'ResourceType': 'Elasticsearch Domain',
                'ResourceArn': domain_arn,
                'ResourceName': domain_name,
                'Region': region,
                'Tags': tags
            })
    except ClientError as e:
        print(f"Error fetching Elasticsearch domains: {e}")

    # Fetch Elastic Beanstalk applications
    try:
        ebs_apps = clients['elasticbeanstalk'].describe_applications().get('Applications', [])
        for app in ebs_apps:
            app_name = app['ApplicationName']
            tags = get_tags(clients['elasticbeanstalk'], 'elasticbeanstalk', f"arn:aws:elasticbeanstalk:{region}:{account_number}:application/{app_name}")
            resources.append({
                'ResourceType': 'Elastic Beanstalk Application',
                'ResourceArn': f"arn:aws:elasticbeanstalk:{region}:{account_number}:application/{app_name}",
                'ResourceName': app_name,
                'Region': region,
                'Tags': tags
            })
    except ClientError as e:
        print(f"Error fetching Elastic Beanstalk applications: {e}")

    # Fetch Elastic Beanstalk environments
    try:
        ebs_envs = clients['elasticbeanstalk'].describe_environments().get('Environments', [])
        for env in ebs_envs:
            env_name = env['EnvironmentName']
            tags = get_tags(clients['elasticbeanstalk'], 'elasticbeanstalk',
                            f"arn:aws:elasticbeanstalk:{region}:{account_number}:environment/{env_name}")
            resources.append({
                'ResourceType': 'Elastic Beanstalk Environment',
                'ResourceArn': f"arn:aws:elasticbeanstalk:{region}:{account_number}:environment/{env_name}",
                'ResourceName': env_name,
                'Region': region,
                'Tags': tags
            })
    except ClientError as e:
        print(f"Error fetching Elastic Beanstalk environments: {e}")

    # Fetch S3 buckets
    try:
        s3_buckets = clients['s3'].list_buckets().get('Buckets', [])
        for bucket in s3_buckets:
            bucket_name = bucket['Name']
            if bucket_name not in processed_s3_buckets:
                processed_s3_buckets.add(bucket_name)
                tags = get_tags(clients['s3'], 's3', bucket_name)
                resources.append({
                    'ResourceType': 'S3 Bucket',
                    'ResourceArn': f"arn:aws:s3:::{bucket_name}",
                    'ResourceName': bucket_name,
                    'Region': region,
                    'Tags': tags
                })
    except ClientError as e:
        print(f"Error fetching S3 buckets: {e}")

    # Fetch ECR repositories
    ecr_repositories = paginate_boto3_results(clients['ecr'], 'describe_repositories', 'repositories')
    for repo in ecr_repositories:
        repo_arn = repo['repositoryArn']
        tags = get_tags(clients['ecr'], 'ecr', repo_arn)
        resources.append({
            'ResourceType': 'ECR Repository',
            'ResourceArn': repo_arn,
            'ResourceName': repo['repositoryName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Route 53 hosted zones
    route53_zones = paginate_boto3_results(clients['route53'], 'list_hosted_zones', 'HostedZones')
    for zone in route53_zones:
        zone_id = zone['Id'].split('/')[-1]
        tags = get_tags(clients['route53'], 'route53', zone_id)
        resources.append({
            'ResourceType': 'Route 53 Hosted Zone',
            'ResourceArn': f"arn:aws:route53:::hostedzone/{zone_id}",
            'ResourceName': zone['Name'],
            'Region': region,
            'Tags': tags
        })

csv_headers = ['Resource Type', 'Resource ARN', 'Region', 'Resource Name', 'Account Number'] + fiserv_tag_keys

with open('all_resources_gift_dev.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(csv_headers)

    for resource in resources:
        resource_type = resource['ResourceType']
        resource_arn = resource['ResourceArn']
        resource_name = resource['ResourceName']
        tags = resource['Tags']
        region = resource['Region']  # Use the region from the resource data
        fiserv_tags = [tags.get(tag, '') for tag in fiserv_tag_keys]

        row_data = [resource_type, resource_arn, region, resource_name, account_number] + fiserv_tags
        writer.writerow(row_data)

















Traceback (most recent call last):
  File "C:\Users\f37yhcs\Desktop\pulled\giftdev\vernew11.py", line 146, in <module>
    tags = get_tags(clients['cognito-idp'], 'cognito-idp', pool_arn)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\f37yhcs\Desktop\pulled\giftdev\vernew11.py", line 123, in get_tags
    return {tag['Key']: tag['Value'] for tag in response.get('UserPools', [])}
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\f37yhcs\Desktop\pulled\giftdev\vernew11.py", line 123, in <dictcomp>
    return {tag['Key']: tag['Value'] for tag in response.get('UserPools', [])}
            ~~~^^^^^^^
KeyError: 'Key'























def paginate_boto3_results(client, method, key):
    results = []
    paginator = client.get_paginator(method)
    page_iterator = paginator.paginate(PaginationConfig={'MaxItems': 1000})
    
    for page in page_iterator:
        results.extend(page.get(key, []))
        
    return results





def fetch_cognito_user_pools(client):
    results = []
    paginator = client.get_paginator('list_user_pools')
    for page in paginator.paginate(MaxResults=60):
        results.extend(page.get('UserPools', []))
    return results

def fetch_cognito_identity_pools(client):
    results = []
    paginator = client.get_paginator('list_identity_pools')
    for page in paginator.paginate(MaxResults=60):
        results.extend(page.get('IdentityPools', []))
    return results




# Fetch Cognito User Pools
try:
    user_pools = fetch_cognito_user_pools(clients['cognito-idp'])
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
    identity_pools = fetch_cognito_identity_pools(clients['cognito-identity'])
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


















Traceback (most recent call last):
  File "C:\Users\f37yhcs\Desktop\pulled\giftdev\vernew11.py", line 124, in <module>
    user_pools = paginate_boto3_results(clients['cognito-idp'], 'list_user_pools', 'UserPools')
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\f37yhcs\Desktop\pulled\giftdev\vernew11.py", line 37, in paginate_boto3_results
    for page in paginator.paginate():
  File "C:\Users\f37yhcs\AppData\Roaming\Python\Python311\site-packages\botocore\paginate.py", line 269, in __iter__
    response = self._make_request(current_kwargs)
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\f37yhcs\AppData\Roaming\Python\Python311\site-packages\botocore\paginate.py", line 357, in _make_request
    return self._method(**current_kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\f37yhcs\AppData\Roaming\Python\Python311\site-packages\botocore\client.py", line 565, in _api_call
    return self._make_api_call(operation_name, kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\f37yhcs\AppData\Roaming\Python\Python311\site-packages\botocore\client.py", line 974, in _make_api_call
    request_dict = self._convert_to_request_dict(
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\f37yhcs\AppData\Roaming\Python\Python311\site-packages\botocore\client.py", line 1048, in _convert_to_request_dict
    request_dict = self._serializer.serialize_to_request(
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\f37yhcs\AppData\Roaming\Python\Python311\site-packages\botocore\validate.py", line 381, in serialize_to_request
    raise ParamValidationError(report=report.generate_report())
botocore.exceptions.ParamValidationError: Parameter validation failed:
Missing required parameter in input: "MaxResults"






import boto3
import csv
from botocore.exceptions import ClientError

regions = ['us-east-1']  # List of regions
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

def paginate_boto3_results(client, method, key):
    results = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate():
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
            'ResourceType': 'RDS DB Instance',
            'ResourceArn': instance['DBInstanceArn'],
            'ResourceName': instance['DBInstanceIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch RDS DB clusters
    rds_clusters = paginate_boto3_results(clients['rds'], 'describe_db_clusters', 'DBClusters')
    for cluster in rds_clusters:
        tags = get_tags(clients['rds'], 'rds', cluster['DBClusterArn'])
        resources.append({
            'ResourceType': 'RDS DB Cluster',
            'ResourceArn': cluster['DBClusterArn'],
            'ResourceName': cluster['DBClusterIdentifier'],
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
            'ResourceArn': f"arn:aws:elasticloadbalancing:{region}:{account_number}:loadbalancer/{elb['LoadBalancerName']}",
            'ResourceName': elb['LoadBalancerName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Application Load Balancers
    albs = paginate_boto3_results(clients['elbv2'], 'describe_load_balancers', 'LoadBalancers')
    for alb in albs:
        tags = get_tags(clients['elbv2'], 'elbv2', alb['LoadBalancerArn'])
        resources.append({
            'ResourceType': 'Application Load Balancer',
            'ResourceArn': alb['LoadBalancerArn'],
            'ResourceName': alb['LoadBalancerName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch ECS clusters
    ecs_clusters = paginate_boto3_results(clients['ecs'], 'list_clusters', 'clusterArns')
    for cluster_arn in ecs_clusters:
        tag_response = clients['ecs'].list_tags_for_resource(resourceArn=cluster_arn)
        cluster_tags = tag_response.get('tags', [])
        fiserv_tags = {tag['key']: tag['value'] for tag in cluster_tags}
        resources.append({
            'ResourceType': 'ECS Cluster',
            'ResourceArn': cluster_arn,
            'ResourceName': cluster_arn.split('/')[-1],
            'Region': region,
            'Tags': fiserv_tags
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
        topic_arn = topic['TopicArn']
        tags = get_tags(clients['sns'], 'sns', topic_arn)
        resources.append({
            'ResourceType': 'SNS Topic',
            'ResourceArn': topic_arn,
            'ResourceName': topic_arn.split(':')[-1],
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
        cluster_arn = f"arn:aws:redshift:{region}:{account_number}:cluster/{cluster['ClusterIdentifier']}"
        tags = get_tags(clients['redshift'], 'redshift', cluster_arn)
        resources.append({
            'ResourceType': 'Redshift Cluster',
            'ResourceArn': cluster_arn,
            'ResourceName': cluster['ClusterIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch DMS replication tasks
    dms_tasks = paginate_boto3_results(clients['dms'], 'describe_replication_tasks', 'ReplicationTasks')
    for task in dms_tasks:
        task_arn = task['ReplicationTaskArn']
        tags = get_tags(clients['dms'], 'dms', task_arn)
        resources.append({
            'ResourceType': 'DMS Replication Task',
            'ResourceArn': task_arn,
            'ResourceName': task['ReplicationTaskIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch SecretsManager secrets
    secrets = paginate_boto3_results(clients['secretsmanager'], 'list_secrets', 'SecretList')
    for secret in secrets:
        secret_arn = secret['ARN']
        tags = get_tags(clients['secretsmanager'], 'secretsmanager', secret_arn)
        resources.append({
            'ResourceType': 'SecretsManager Secret',
            'ResourceArn': secret_arn,
            'ResourceName': secret['Name'],
            'Region': region,
            'Tags': tags
        })

    # Fetch ElastiCache clusters
    elasticache_clusters = paginate_boto3_results(clients['elasticache'], 'describe_cache_clusters', 'CacheClusters')
    for cluster in elasticache_clusters:
        cluster_arn = f"arn:aws:elasticache:{region}:{account_number}:cluster:{cluster['CacheClusterId']}"
        tags = get_tags(clients['elasticache'], 'elasticache', cluster_arn)
        resources.append({
            'ResourceType': 'ElastiCache Cluster',
            'ResourceArn': cluster_arn,
            'ResourceName': cluster['CacheClusterId'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Elasticsearch domains
    try:
        es_domains = clients['es'].list_domain_names().get('DomainNames', [])
        for domain in es_domains:
            domain_name = domain['DomainName']
            domain_arn = f"arn:aws:es:{region}:{account_number}:domain/{domain_name}"
            tags = get_tags(clients['es'], 'es', domain_arn)
            resources.append({
                'ResourceType': 'Elasticsearch Domain',
                'ResourceArn': domain_arn,
                'ResourceName': domain_name,
                'Region': region,
                'Tags': tags
            })
    except ClientError as e:
        print(f"Error fetching Elasticsearch domains: {e}")

    # Fetch Elastic Beanstalk applications
    try:
        ebs_apps = clients['elasticbeanstalk'].describe_applications().get('Applications', [])
        for app in ebs_apps:
            app_name = app['ApplicationName']
            tags = get_tags(clients['elasticbeanstalk'], 'elasticbeanstalk', f"arn:aws:elasticbeanstalk:{region}:{account_number}:application/{app_name}")
            resources.append({
                'ResourceType': 'Elastic Beanstalk Application',
                'ResourceArn': f"arn:aws:elasticbeanstalk:{region}:{account_number}:application/{app_name}",
                'ResourceName': app_name,
                'Region': region,
                'Tags': tags
            })
    except ClientError as e:
        print(f"Error fetching Elastic Beanstalk applications: {e}")

    # Fetch Elastic Beanstalk environments
    try:
        ebs_envs = clients['elasticbeanstalk'].describe_environments().get('Environments', [])
        for env in ebs_envs:
            env_name = env['EnvironmentName']
            tags = get_tags(clients['elasticbeanstalk'], 'elasticbeanstalk',
                            f"arn:aws:elasticbeanstalk:{region}:{account_number}:environment/{env_name}")
            resources.append({
                'ResourceType': 'Elastic Beanstalk Environment',
                'ResourceArn': f"arn:aws:elasticbeanstalk:{region}:{account_number}:environment/{env_name}",
                'ResourceName': env_name,
                'Region': region,
                'Tags': tags
            })
    except ClientError as e:
        print(f"Error fetching Elastic Beanstalk environments: {e}")

    # Fetch S3 buckets
    try:
        s3_buckets = clients['s3'].list_buckets().get('Buckets', [])
        for bucket in s3_buckets:
            bucket_name = bucket['Name']
            if bucket_name not in processed_s3_buckets:
                processed_s3_buckets.add(bucket_name)
                tags = get_tags(clients['s3'], 's3', bucket_name)
                resources.append({
                    'ResourceType': 'S3 Bucket',
                    'ResourceArn': f"arn:aws:s3:::{bucket_name}",
                    'ResourceName': bucket_name,
                    'Region': region,
                    'Tags': tags
                })
    except ClientError as e:
        print(f"Error fetching S3 buckets: {e}")

    # Fetch ECR repositories
    ecr_repositories = paginate_boto3_results(clients['ecr'], 'describe_repositories', 'repositories')
    for repo in ecr_repositories:
        repo_arn = repo['repositoryArn']
        tags = get_tags(clients['ecr'], 'ecr', repo_arn)
        resources.append({
            'ResourceType': 'ECR Repository',
            'ResourceArn': repo_arn,
            'ResourceName': repo['repositoryName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Route 53 hosted zones
    route53_zones = paginate_boto3_results(clients['route53'], 'list_hosted_zones', 'HostedZones')
    for zone in route53_zones:
        zone_id = zone['Id'].split('/')[-1]
        tags = get_tags(clients['route53'], 'route53', zone_id)
        resources.append({
            'ResourceType': 'Route 53 Hosted Zone',
            'ResourceArn': f"arn:aws:route53:::hostedzone/{zone_id}",
            'ResourceName': zone['Name'],
            'Region': region,
            'Tags': tags
        })

csv_headers = ['Resource Type', 'Resource ARN', 'Region', 'Resource Name', 'Account Number'] + fiserv_tag_keys

with open('all_resources_gift_dev.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(csv_headers)

    for resource in resources:
        resource_type = resource['ResourceType']
        resource_arn = resource['ResourceArn']
        resource_name = resource['ResourceName']
        tags = resource['Tags']
        region = resource['Region']  # Use the region from the resource data
        fiserv_tags = [tags.get(tag, '') for tag in fiserv_tag_keys]

        row_data = [resource_type, resource_arn, region, resource_name, account_number] + fiserv_tags
        writer.writerow(row_data)
