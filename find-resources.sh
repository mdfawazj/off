#!/bin/bash

# List of all regions
regions=$(aws ec2 describe-regions --query "Regions[].RegionName" --output text)

# List of resource types (space-separated for AWS CLI compatibility)
resource_types="AWS::Lambda::Function AWS::EC2::Instance AWS::Route53::Domain AWS::ElasticLoadBalancing::LoadBalancer AWS::ElasticLoadBalancingV2::LoadBalancer AWS::ECS::Cluster AWS::S3::Bucket AWS::ElasticBeanstalk::Application AWS::RDS::DBCluster AWS::RDS::DBInstance AWS::DynamoDB::Table AWS::SNS::Topic AWS::SQS::Queue AWS::Redshift::Cluster AWS::DMS::ReplicationTask AWS::SecretsManager::Secret AWS::ElastiCache::CacheCluster AWS::Elasticsearch::Domain"

# Function to get resources for a specific region and resource types
get_resources() {
    local region=$1
    echo "Fetching resources in region: $region"
    aws resourcegroupstaggingapi get-resources \
        --region "$region" \
        --resource-type-filters $resource_types \
        --query "ResourceTagMappingList[*].ResourceARN" \
        --output text
}

# Loop through all regions and get resources
for region in $regions; do
    get_resources "$region"
done
