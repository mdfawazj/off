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

with open('all_resources.csv', 'w', newline='') as csvfile:
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
















###############################################new add


import boto3
from botocore.exceptions import ClientError

def list_aws_resources():
    regions = boto3.session.Session().get_available_regions('ec2')
    account_number = boto3.client('sts').get_caller_identity().get('Account')

    resources = []
    processed_s3_buckets = set()

    for region in regions:
        session = boto3.Session(region_name=region, verify=False)
        clients = {
            'ec2': session.client('ec2'),
            'rds': session.client('rds'),
            'lambda': session.client('lambda'),
            'elb': session.client('elb'),
            'elbv2': session.client('elbv2'),
            'ecs': session.client('ecs'),
            'dynamodb': session.client('dynamodb'),
            'sns': session.client('sns'),
            'sqs': session.client('sqs'),
            'redshift': session.client('redshift'),
            'dms': session.client('dms'),
            'secretsmanager': session.client('secretsmanager'),
            'elasticache': session.client('elasticache'),
            'es': session.client('es'),
            'elasticbeanstalk': session.client('elasticbeanstalk'),
            's3': session.client('s3'),
            'ecr': session.client('ecr'),
            'route53': session.client('route53'),
            'amplify': session.client('amplify'),
            'cognito-idp': session.client('cognito-idp')
        }

        # Fetch EC2 instances
        ec2_instances = paginate_boto3_results(clients['ec2'], 'describe_instances', 'Reservations')
        for reservation in ec2_instances:
            for instance in reservation['Instances']:
                tags = get_tags(clients['ec2'], 'ec2', instance['InstanceId'])
                resources.append({
                    'ResourceType': 'EC2 Instance',
                    'ResourceArn': instance['InstanceId'],
                    'ResourceName': instance['InstanceId'],
                    'Region': region,
                    'Tags': tags
                })

        # Fetch RDS instances
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
            cluster = clients['ecs'].describe_clusters(clusters=[cluster_arn])['clusters'][0]
            tags = get_tags(clients['ecs'], 'ecs', cluster_arn)
            resources.append({
                'ResourceType': 'ECS Cluster',
                'ResourceArn': cluster_arn,
                'ResourceName': cluster['clusterName'],
                'Region': region,
                'Tags': tags
            })

        # Fetch DynamoDB tables
        dynamodb_tables = paginate_boto3_results(clients['dynamodb'], 'list_tables', 'TableNames')
        for table_name in dynamodb_tables:
            table = clients['dynamodb'].describe_table(TableName=table_name)['Table']
            tags = get_tags(clients['dynamodb'], 'dynamodb', table['TableArn'])
            resources.append({
                'ResourceType': 'DynamoDB Table',
                'ResourceArn': table['TableArn'],
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
            tags = get_tags(clients['redshift'], 'redshift', cluster['ClusterNamespaceArn'])
            resources.append({
                'ResourceType': 'Redshift Cluster',
                'ResourceArn': cluster['ClusterNamespaceArn'],
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

        # Fetch Secrets Manager secrets
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
            tags = get_tags(clients['elasticache'], 'elasticache', cluster['ARN'])
            resources.append({
                'ResourceType': 'ElastiCache Cluster',
                'ResourceArn': cluster['ARN'],
                'ResourceName': cluster['CacheClusterId'],
                'Region': region,
                'Tags': tags
            })

        # Fetch Elasticsearch domains
        es_domains = paginate_boto3_results(clients['es'], 'list_domain_names', 'DomainNames')
        for domain in es_domains:
            domain_info = clients['es'].describe_elasticsearch_domain(DomainName=domain['DomainName'])
            tags = get_tags(clients['es'], 'es', domain_info['DomainStatus']['ARN'])
            resources.append({
                'ResourceType': 'Elasticsearch Domain',
                'ResourceArn': domain_info['DomainStatus']['ARN'],
                'ResourceName': domain['DomainName'],
                'Region': region,
                'Tags': tags
            })

        # Fetch Elastic Beanstalk applications
        elasticbeanstalk_apps = paginate_boto3_results(clients['elasticbeanstalk'], 'describe_applications', 'Applications')
        for app in elasticbeanstalk_apps:
            tags = get_tags(clients['elasticbeanstalk'], 'elasticbeanstalk', app['ApplicationArn'])
            resources.append({
                'ResourceType': 'Elastic Beanstalk Application',
                'ResourceArn': app['ApplicationArn'],
                'ResourceName': app['ApplicationName'],
                'Region': region,
                'Tags': tags
            })

        # Fetch S3 buckets
        s3_buckets = clients['s3'].list_buckets()['Buckets']
        for bucket in s3_buckets:
            if bucket['Name'] not in processed_s3_buckets:
                processed_s3_buckets.add(bucket['Name'])
                tags = get_tags(clients['s3'], 's3', bucket['Name'])
                resources.append({
                    'ResourceType': 'S3 Bucket',
                    'ResourceArn': f"arn:aws:s3:::{bucket['Name']}",
                    'ResourceName': bucket['Name'],
                    'Region': region,
                    'Tags': tags
                })

        # Fetch ECR repositories
        ecr_repos = paginate_boto3_results(clients['ecr'], 'describe_repositories', 'repositories')
        for repo in ecr_repos:
            tags = get_tags(clients['ecr'], 'ecr', repo['repositoryArn'])
            resources.append({
                'ResourceType': 'ECR Repository',
                'ResourceArn': repo['repositoryArn'],
                'ResourceName': repo['repositoryName'],
                'Region': region,
                'Tags': tags
            })

        # Fetch Route 53 hosted zones
        route53_zones = paginate_boto3_results(clients['route53'], 'list_hosted_zones', 'HostedZones')
        for zone in route53_zones:
            tags = get_tags(clients['route53'], 'route53', zone['Id'])
            resources.append({
                'ResourceType': 'Route 53 Hosted Zone',
                'ResourceArn': zone['Id'],
                'ResourceName': zone['Name'],
                'Region': region,
                'Tags': tags
            })

        # Fetch Amplify apps
        amplify_apps = paginate_boto3_results(clients['amplify'], 'list_apps', 'apps')
        for app in amplify_apps:
            tags = get_tags(clients['amplify'], 'amplify', app['appArn'])
            resources.append({
                'ResourceType': 'Amplify App',
                'ResourceArn': app['appArn'],
                'ResourceName': app['name'],
                'Region': region,
                'Tags': tags
            })

        # Fetch Cognito User Pools
        cognito_user_pools = paginate_boto3_results(clients['cognito-idp'], 'list_user_pools', 'UserPools', MaxResults=60)
        for pool in cognito_user_pools:
            tags = get_tags(clients['cognito-idp'], 'cognito-idp', pool['Id'])
            resources.append({
                'ResourceType': 'Cognito User Pool',
                'ResourceArn': pool['Id'],
                'ResourceName': pool['Name'],
                'Region': region,
                'Tags': tags
            })

    return resources

# Function to get tags for a resource
def get_tags(client, service, resource_arn):
    try:
        if service in ['ec2', 'rds', 'lambda', 's3', 'ecr', 'dynamodb']:
            response = client.list_tags_for_resource(ResourceName=resource_arn)
        elif service == 'sqs':
            response = client.list_queue_tags(QueueUrl=resource_arn)
        elif service == 'route53':
            response = client.list_tags_for_resource(ResourceType='hostedzone', ResourceId=resource_arn.split('/')[-1])
        elif service == 'es':
            response = client.list_tags(ARN=resource_arn)
        else:
            response = client.list_tags_for_resource(ResourceArn=resource_arn)

        return response.get('Tags', [])
    except ClientError as e:
        print(f"Error fetching tags for {resource_arn}: {e}")
        return []

# Function to paginate through boto3 results
def paginate_boto3_results(client, operation, result_key, **kwargs):
    paginator = client.get_paginator(operation)
    result = []
    for page in paginator.paginate(**kwargs):
        result.extend(page[result_key])
    return result

# Main execution
if __name__ == "__main__":
    resources = list_aws_resources()
    for resource in resources:
        print(resource)


