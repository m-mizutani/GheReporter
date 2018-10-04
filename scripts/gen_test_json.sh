#!/bin/bash

PARAM_FILE=${PARAM_FILE:="param.cfg"}
StackName=`grep StackName $PARAM_FILE | cut -d = -f 2`
SecretArn=`grep SecretArn $PARAM_FILE | cut -d = -f 2`

Resources=`aws cloudformation describe-stack-resources --stack-name $StackName | jq '.StackResources[]'`
CacheTable=`echo $Resources | jq 'select(.LogicalResourceId == "CacheTable")'`
CacheTableName=`echo $CacheTable | jq .PhysicalResourceId -r`
Region=`echo $CacheTable | jq .StackId -r | cut -d ':' -f 4`

ReportResultsArn=`echo $Resources | jq 'select(.LogicalResourceId == "ReportResults") | .PhysicalResourceId' -r`

cat <<EOF > test.json
{
  "region": "$Region",
  "table_name": "$CacheTableName",
  "secret_arn": "$SecretArn"
}
EOF

