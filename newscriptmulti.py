import boto3
import csv
from botocore.exceptions import ClientError

regions = ['us-east-1', 'us-west-1', 'eu-central-1']  # List of regions
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

    # Fetch EC2 instances
    ec2_instances = paginate_boto3_results(clients['ec2'], 'describe_instances', 'Reservations')
    for reservation in ec2_instances:
        for instance in reservation['Instances']:
            tags = get_tags(clients['ec2'], 'ec2', instance['InstanceId'])
            resources.append({
                'ResourceType': 'EC2 Instance',
                'ResourceArn': f"arn:aws:ec2:{region}:{account_number}:instance/{instance['InstanceId']}",
                'ResourceName': tags.get('Name', 'N/A'),
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
                'Tags': tags
            })
    except ClientError as e:
        print(f"Error fetching Elastic Beanstalk applications: {e}")

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
            'Tags': tags
        })

csv_headers = ['Resource Type', 'Resource ARN', 'Region', 'Resource Name', 'Account Number'] + fiserv_tag_keys

with open('all_resources.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(csv_headers)

    for resource in resources:
        resource_type = resource['ResourceType']
        resource_arn = resource['ResourceArn']
        resource_name = resource['ResourceName']
        tags = resource['Tags']
        fiserv_tags = [tags.get(tag, '') for tag in fiserv_tag_keys]

        row_data = [resource_type, resource_arn, region, resource_name, account_number] + fiserv_tags
        writer.writerow(row_data)
