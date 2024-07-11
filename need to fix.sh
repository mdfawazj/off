#!/bin/bash

# Function to process the output file
process_output() {
    sed -i -r -e 'N; s/\nTAGS, //; P; D' "$1"
}

get_resources () {
    resource_types="lambda:function ec2:instance route53:domain elasticloadbalancing:loadbalancer ecs:cluster ecr:repository s3:bucket elasticbeanstalk:application rds:cluster rds:db dynamodb:table sns:topic sqs:queue redshift:cluster dms:replication-task secretsmanager:secret elasticache:cluster es:domain"

    # Function to get resources and their tags for a specific region
    get_resources_and_tags() {
        local region=$1
        aws resourcegroupstaggingapi get-resources \
            --region "$region" \
            --resource-type-filters $resource_types \
            --query "ResourceTagMappingList[].[{ResourceARN: ResourceARN, Tags: Tags[*].join(' ', [Key, Value])}]" \
            --max-items 1000 \
            --output text \
            --no-verify-ssl
    }

    # List of all regions
    regions=$(aws ec2 describe-regions --query "Regions[].RegionName" --output text --no-verify-ssl)

    output_file="temporary_output_file"

    # Loop through all regions and get resources and combine tags with ResourceARN on the same line
    for region in $regions; do
        get_resources_and_tags "$region"
    done > "$output_file"

    # Process the output file to join TAGS lines with the previous line
    process_output "$output_file"

    final_output_file="temp_output"

    # Move the processed output to the final file
    mv "$output_file" "$final_output_file"
    echo "Final processed output saved in $final_output_file"
}

create_CSV_file () {
    echo "creating CSV file"
    output_file="temp_output"
    output_file2="final_output.csv"

    # Remove existing final_output2.csv if it exists
    if [ -f "$output_file2" ]; then
        echo "resource_type,resource_name,arn,region,account,tags_line" > "$output_file2"
        else 
        echo "resource_type,resource_name,arn,region,account,tags_line" > "$output_file2"
    fi

    # Initialize variables to store values
    arn=""
    resource_type=""
    region=""
    account=""
    resource_name=""
    tags_line=""

    # Read each line from temp_output
    while IFS= read -r line; do
        if [[ $line == arn* ]]; then
            if [ -n "$arn" ]; then
                # Append accumulated values to the previous ARN line
                echo "$resource_type,$resource_name,$arn,$region,$account $tags_line" >> "$output_file2"
            fi
            IFS=':' read -r -a arr <<<"$line"
            resource_type="${arr[2]}"
            region="${arr[3]}"
            account="${arr[4]}"
            resource_name="${arr[-1]}"
            arn="$line"
            tags_line=""
        elif [[ $line == TAGS* ]]; then
            tags_line+="$(echo "$line" | sed 's/TAGS/,/') "
        fi
    done < "$output_file"

    # Append the last ARN line along with accumulated tags
    if [ -n "$arn" ]; then
        echo "$resource_type,$resource_name,$arn,$region,$account $tags_line" >> "$output_file2"
    fi
    account=$(aws sts get-caller-identity --query "Account" --output text --no-verify-ssl)
    echo "Running filter"
    cat final_output.csv |grep -v "App TW" > $account.filtered.csv
    mv final_output.csv $account.csv
    echo $account_filtered.csv $account.csv
}

get_resources
create_CSV_file
