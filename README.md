# 3-tier-aws

CloudFormation template for 3 tier architecture

Well-Architected Three-Tier AWS Architecture Hosting an Employee DatabaseThis infrastructure follows the AWS Well-Architected Framework to ensure high availability, scalability, and security across all components. It implements a robust three-tier architecture:

1. Presentation Tier (Frontend Layer)
Elastic Load Balancer (ALB) distributes traffic evenly across EC2 instances running in multiple private subnets across availability zones.
ALB ensures high availability and automatically redirects traffic away from unhealthy instances.
Route 53 provides DNS resolution with an alias record that maps a custom domain to the ALB DNS name.
2. Application Tier (Business Logic Layer)
EC2 instances launched via an Auto Scaling Group ensure scalability, with min 2, max 4 instances across 2 private subnets.
User data scripts provision application code on launch.
IAM roles are attached to these EC2s, allowing secure interaction with AWS services like S3 and DynamoDB.
3. Data Tier (Database Layer)
Amazon DynamoDB hosts the Employee database with id as the partition key.
DynamoDB is chosen for its scalability, low latency, and managed infrastructure.
The EC2 application layer performs PutItem, GetItem, and Query operations securely via IAM.

Security & Networking
A custom VPC spans 2 availability zones and includes:
	2 public subnets (for NAT Gateway and ALB)
	2 private subnets (for EC2 and internal app logic)
Security Groups restrict inbound/outbound traffic based on tier-specific rules.
IAM policies provide least-privilege access to required AWS services.
CloudFormation templates are used to provision the entire infrastructure in a reproducible and automated way.
CodePipeline + CodeBuild enables CI/CD for infrastructure deployment.
