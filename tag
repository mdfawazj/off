#!/bin/bash

# List all resources using AWS Resource Explorer
resources=$(aws resource-explorer-2 search --query-string "" --output json)

# Parse the ARNs of the resources
arns=$(echo $resources | jq -r '.Results[].ARN')

# Get tags for each resource
for arn in $arns; do
    echo "Resource ARN: $arn"
    tags=$(aws resourcegroupstaggingapi get-resources --resource-arn-list $arn --output json)
    echo "Tags: $(echo $tags | jq '.ResourceTagMappingList[].Tags')"
    echo "----------------------------------"
done
