import boto3
import csv

def paginate_boto3_results(client, method, result_key):
    paginator = client.get_paginator(method)
    for page in paginator.paginate():
        for item in page[result_key]:
            yield item

def get_tags(client, service, resource_arn):
    if service == 'ec2':
        response = client.describe_tags(Filters=[{'Name': 'resource-id', 'Values': [resource_arn]}])
        tags = {tag['Key']: tag['Value'] for tag in response['Tags']}
    else:
        response = client.list_tags_for_resource(ResourceArn=resource_arn)
        tags = {tag['Tags'][k]: tag['Tags'][v] for k, v in response['Tags'].items()}
    return tags

# Initialize boto3 clients for all regions and services
regions = ['us-east-1', 'us-west-1', 'us-west-2']
clients = {}
for region in regions:
    clients[region] = {
        'ec2': boto3.client('ec2', region_name=region),
        'rds': boto3.client('rds', region_name=region),
        'lambda': boto3.client('lambda', region_name=region),
        'elb': boto3.client('elb', region_name=region),
        'elbv2': boto3.client('elbv2', region_name=region),
        'ecs': boto3.client('ecs', region_name=region),
        'dynamodb': boto3.client('dynamodb', region_name=region),
        'sns': boto3.client('sns', region_name=region),
        'sqs': boto3.client('sqs', region_name=region),
        'redshift': boto3.client('redshift', region_name=region),
        'dms': boto3.client('dms', region_name=region),
        'secretsmanager': boto3.client('secretsmanager', region_name=region),
        'elasticache': boto3.client('elasticache', region_name=region),
        'es': boto3.client('es', region_name=region),
        'elasticbeanstalk': boto3.client('elasticbeanstalk', region_name=region),
        's3': boto3.client('s3', region_name=region),
        'route53': boto3.client('route53', region_name=region),
        'cognito': boto3.client('cognito-idp', region_name=region)  # Add Cognito client
    }

# Collect resources
resources = []

for region, client_dict in clients.items():
    account_number = boto3.client('sts').get_caller_identity().get('Account')

    # Fetch EC2 instances
    ec2_instances = paginate_boto3_results(client_dict['ec2'], 'describe_instances', 'Reservations')
    for reservation in ec2_instances:
        for instance in reservation['Instances']:
            tags = get_tags(client_dict['ec2'], 'ec2', instance['InstanceId'])
            resources.append({
                'ResourceType': 'EC2 Instance',
                'ResourceArn': instance['InstanceId'],
                'ResourceName': instance.get('InstanceId'),
                'Region': region,
                'Tags': tags
            })

    # Fetch RDS instances
    rds_instances = paginate_boto3_results(client_dict['rds'], 'describe_db_instances', 'DBInstances')
    for instance in rds_instances:
        tags = get_tags(client_dict['rds'], 'rds', instance['DBInstanceArn'])
        resources.append({
            'ResourceType': 'RDS Instance',
            'ResourceArn': instance['DBInstanceArn'],
            'ResourceName': instance['DBInstanceIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Lambda functions
    lambda_functions = paginate_boto3_results(client_dict['lambda'], 'list_functions', 'Functions')
    for function in lambda_functions:
        tags = get_tags(client_dict['lambda'], 'lambda', function['FunctionArn'])
        resources.append({
            'ResourceType': 'Lambda Function',
            'ResourceArn': function['FunctionArn'],
            'ResourceName': function['FunctionName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Classic Load Balancers
    elbs = paginate_boto3_results(client_dict['elb'], 'describe_load_balancers', 'LoadBalancerDescriptions')
    for elb in elbs:
        tags = get_tags(client_dict['elb'], 'elb', elb['LoadBalancerName'])
        resources.append({
            'ResourceType': 'Classic Load Balancer',
            'ResourceArn': f"arn:aws:elb:{region}:{account_number}:loadbalancer/{elb['LoadBalancerName']}",
            'ResourceName': elb['LoadBalancerName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Application and Network Load Balancers
    elbv2s = paginate_boto3_results(client_dict['elbv2'], 'describe_load_balancers', 'LoadBalancers')
    for elbv2 in elbv2s:
        tags = get_tags(client_dict['elbv2'], 'elbv2', elbv2['LoadBalancerArn'])
        resources.append({
            'ResourceType': 'Application/Network Load Balancer',
            'ResourceArn': elbv2['LoadBalancerArn'],
            'ResourceName': elbv2['LoadBalancerName'],
            'Region': region,
            'Tags': tags
        })

    # Fetch ECS clusters
    ecs_clusters = paginate_boto3_results(client_dict['ecs'], 'list_clusters', 'clusterArns')
    for cluster_arn in ecs_clusters:
        cluster_name = cluster_arn.split('/')[-1]
        tags = get_tags(client_dict['ecs'], 'ecs', cluster_arn)
        resources.append({
            'ResourceType': 'ECS Cluster',
            'ResourceArn': cluster_arn,
            'ResourceName': cluster_name,
            'Region': region,
            'Tags': tags
        })

    # Fetch DynamoDB tables
    dynamodb_tables = paginate_boto3_results(client_dict['dynamodb'], 'list_tables', 'TableNames')
    for table_name in dynamodb_tables:
        table_arn = f"arn:aws:dynamodb:{region}:{account_number}:table/{table_name}"
        tags = get_tags(client_dict['dynamodb'], 'dynamodb', table_arn)
        resources.append({
            'ResourceType': 'DynamoDB Table',
            'ResourceArn': table_arn,
            'ResourceName': table_name,
            'Region': region,
            'Tags': tags
        })

    # Fetch SNS topics
    sns_topics = paginate_boto3_results(client_dict['sns'], 'list_topics', 'Topics')
    for topic in sns_topics:
        tags = get_tags(client_dict['sns'], 'sns', topic['TopicArn'])
        resources.append({
            'ResourceType': 'SNS Topic',
            'ResourceArn': topic['TopicArn'],
            'ResourceName': topic['TopicArn'].split(':')[-1],
            'Region': region,
            'Tags': tags
        })

    # Fetch SQS queues
    sqs_queues = paginate_boto3_results(client_dict['sqs'], 'list_queues', 'QueueUrls')
    for queue_url in sqs_queues:
        tags = get_tags(client_dict['sqs'], 'sqs', queue_url)
        resources.append({
            'ResourceType': 'SQS Queue',
            'ResourceArn': queue_url,
            'ResourceName': queue_url.split('/')[-1],
            'Region': region,
            'Tags': tags
        })

    # Fetch Redshift clusters
    redshift_clusters = paginate_boto3_results(client_dict['redshift'], 'describe_clusters', 'Clusters')
    for cluster in redshift_clusters:
        tags = get_tags(client_dict['redshift'], 'redshift', cluster['ClusterIdentifier'])
        resources.append({
            'ResourceType': 'Redshift Cluster',
            'ResourceArn': cluster['ClusterIdentifier'],
            'ResourceName': cluster['ClusterIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch DMS replication instances
    dms_instances = paginate_boto3_results(client_dict['dms'], 'describe_replication_instances', 'ReplicationInstances')
    for instance in dms_instances:
        tags = get_tags(client_dict['dms'], 'dms', instance['ReplicationInstanceArn'])
        resources.append({
            'ResourceType': 'DMS Replication Instance',
            'ResourceArn': instance['ReplicationInstanceArn'],
            'ResourceName': instance['ReplicationInstanceIdentifier'],
            'Region': region,
            'Tags': tags
        })

    # Fetch SecretsManager secrets
    secrets = paginate_boto3_results(client_dict['secretsmanager'], 'list_secrets', 'SecretList')
    for secret in secrets:
        tags = get_tags(client_dict['secretsmanager'], 'secretsmanager', secret['ARN'])
        resources.append({
            'ResourceType': 'Secrets Manager Secret',
            'ResourceArn': secret['ARN'],
            'ResourceName': secret['Name'],
            'Region': region,
            'Tags': tags
        })

    # Fetch ElastiCache clusters
    elasticache_clusters = paginate_boto3_results(client_dict['elasticache'], 'describe_cache_clusters', 'CacheClusters')
    for cluster in elasticache_clusters:
        cluster_arn = f"arn:aws:elasticache:{region}:{account_number}:cluster:{cluster['CacheClusterId']}"
        try:
            tags = get_tags(client_dict['elasticache'], 'elasticache', cluster_arn)
        except Exception as e:
            print(f"Error fetching tags for elasticache {cluster['CacheClusterId']}: {e}")
            tags = {}
        resources.append({
            'ResourceType': 'ElastiCache Cluster',
            'ResourceArn': cluster_arn,
            'ResourceName': cluster['CacheClusterId'],
            'Region': region,
            'Tags': tags
        })

    # Fetch Elasticsearch domains
    es_domains = client_dict['es'].list_domain_names()['DomainNames']
    for domain in es_domains:
        domain_name = domain['DomainName']
        domain_arn = f"arn:aws:es:{region}:{account_number}:domain/{domain_name}"
        tags = get_tags(client_dict['es'], 'es', domain_arn)
        resources.append({
            'ResourceType': 'Elasticsearch Domain',
            'ResourceArn': domain_arn,
            'ResourceName': domain_name,
            'Region': region,
            'Tags': tags
        })

    # Fetch Cognito user pools
    cognito_user_pools = paginate_boto3_results(client_dict['cognito'], 'list_user_pools', 'UserPools')
    for user_pool in cognito_user_pools:
        user_pool_arn = f"arn:aws:cognito-idp:{region}:{account_number}:userpool/{user_pool['Id']}"
        tags = get_tags(client_dict['cognito'], 'cognito', user_pool_arn)
        resources.append({
            'ResourceType': 'Cognito User Pool',
            'ResourceArn': user_pool_arn,
            'ResourceName': user_pool['Name'],
            'Region': region,
            'Tags': tags
        })

# Write resources to CSV
with open('aws_resources.csv', 'w', newline='') as csvfile:
    fieldnames = ['ResourceType', 'ResourceArn', 'ResourceName', 'Region', 'Tags']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for resource in resources:
        writer.writerow(resource)

print("Resources and tags have been written to aws_resources.csv")