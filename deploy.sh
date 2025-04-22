#!/bin/bash
STACK_NAME="MyInfraStack"
TEMPLATE_FILE="3-tier-aws-architecture.yaml"
REGION="us-east-2"
HOSTED_ZONE_ID="Z0273345Q8A2HWTFBAY4"
DOMAIN_NAME="spreadcom.org"
SUBDOMAIN="app"
BUCKET_NAME="employee-photo-bucket-$(date +%Y%m%d-%H%M%S)"

echo "Using S3 bucket name: $BUCKET_NAME"
echo "Deploying CloudFormation stack: $STACK_NAME"
aws cloudformation deploy \
  --stack-name $STACK_NAME \
  --template-file $TEMPLATE_FILE \
  --capabilities CAPABILITY_NAMED_IAM \
  --capabilities CAPABILITY_IAM \
  --region $REGION \
  --parameter-overrides \
    VpcCIDR=10.0.0.0/16 \
    PublicSubnet1CIDR=10.0.1.0/24 \
    PublicSubnet2CIDR=10.0.2.0/24 \
    PrivateSubnet1CIDR=10.0.3.0/24 \
    PrivateSubnet2CIDR=10.0.4.0/24 \
    HostedZoneId=$HOSTED_ZONE_ID \
    DomainName=$DOMAIN_NAME \
    SubDomain=$SUBDOMAIN \
    BucketName=$BUCKET_NAME

echo "Deployment complete."
echo "S3 bucket created: $BUCKET_NAME"