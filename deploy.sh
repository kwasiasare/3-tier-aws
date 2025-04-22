#!/bin/bash

STACK_NAME="MyInfraStack"
TEMPLATE_FILE="3-tier-aws-architecture.yaml"
REGION="us-east-2"

echo "Deploying CloudFormation stack: $STACK_NAME"

aws cloudformation deploy \
  --stack-name $STACK_NAME \
  --template-file $TEMPLATE_FILE \
  --capabilities CAPABILITY_NAMED_IAM \
  --region $REGION \
  --parameter-overrides \
    VpcCIDR=10.0.0.0/16 \
    PublicSubnet1CIDR=10.0.1.0/24 \
    PublicSubnet2CIDR=10.0.2.0/24 \
    PrivateSubnet1CIDR=10.0.3.0/24 \
    PrivateSubnet2CIDR=10.0.4.0/24

echo "Deployment complete."
