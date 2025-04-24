# Provider configuration
provider "aws" {
  region = var.region
}

# Variables 
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
  validation {
    condition     = can(regex("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/)(1[6-9]|2[0-4])$", var.vpc_cidr))
    error_message = "CIDR block parameter must be in the form x.x.x.x/16-24."
  }
}

variable "public_subnet1_cidr" {
  description = "CIDR block for the first public subnet"
  type        = string
  default     = "10.0.1.0/24"
  validation {
    condition     = can(regex("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/)(1[6-9]|2[0-8])$", var.public_subnet1_cidr))
    error_message = "CIDR block parameter must be in the form x.x.x.x/16-28."
  }
}

variable "public_subnet2_cidr" {
  description = "CIDR block for the second public subnet"
  type        = string
  default     = "10.0.2.0/24"
  validation {
    condition     = can(regex("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/)(1[6-9]|2[0-8])$", var.public_subnet2_cidr))
    error_message = "CIDR block parameter must be in the form x.x.x.x/16-28."
  }
}

variable "private_subnet1_cidr" {
  description = "CIDR block for the first private subnet"
  type        = string
  default     = "10.0.3.0/24"
  validation {
    condition     = can(regex("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/)(1[6-9]|2[0-8])$", var.private_subnet1_cidr))
    error_message = "CIDR block parameter must be in the form x.x.x.x/16-28."
  }
}

variable "private_subnet2_cidr" {
  description = "CIDR block for the second private subnet"
  type        = string
  default     = "10.0.4.0/24"
  validation {
    condition     = can(regex("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/)(1[6-9]|2[0-8])$", var.private_subnet2_cidr))
    error_message = "CIDR block parameter must be in the form x.x.x.x/16-28."
  }
}

variable "bucket_name" {
  description = "Name for the S3 bucket to store employee photos"
  type        = string
  default     = "employee-photo-bucket-ka-2025-04-14"
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "Bucket name must be between 3 and 63 characters, contain only lowercase letters, numbers, hyphens, and cannot start or end with a hyphen."
  }
}

variable "domain_name" {
  description = "Your domain name"
  type        = string
  default     = "spreadcom.org"
}

variable "hosted_zone_id" {
  description = "The Route53 Hosted Zone ID to use for DNS records"
  type        = string
}

variable "subdomain" {
  description = "Subdomain prefix for application"
  type        = string
  default     = "app"
  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$", var.subdomain))
    error_message = "Subdomain must be a valid DNS label."
  }
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
  validation {
    condition     = contains(["t2.micro", "t2.small", "t2.medium", "t3.micro", "t3.small", "t3.medium"], var.instance_type)
    error_message = "Must be a valid EC2 instance type from the allowed list."
  }
}

variable "min_capacity" {
  description = "Minimum number of instances in the Auto Scaling Group"
  type        = number
  default     = 2
  validation {
    condition     = var.min_capacity >= 1 && var.min_capacity <= 10
    error_message = "Min capacity must be between 1 and 10."
  }
}

variable "max_capacity" {
  description = "Maximum number of instances in the Auto Scaling Group"
  type        = number
  default     = 4
  validation {
    condition     = var.max_capacity >= 1 && var.max_capacity <= 20
    error_message = "Max capacity must be between 1 and 20."
  }
}

variable "desired_capacity" {
  description = "Desired number of instances in the Auto Scaling Group"
  type        = number
  default     = 2
  validation {
    condition     = var.desired_capacity >= 1 && var.desired_capacity <= 10
    error_message = "Desired capacity must be between 1 and 10."
  }
}

variable "environment_name" {
  description = "Environment type for tagging and naming resources"
  type        = string
  default     = "Production"
  validation {
    condition     = contains(["Development", "Staging", "Production"], var.environment_name)
    error_message = "Environment name must be one of: Development, Staging, Production."
  }
}

# Local variables
locals {
  ami_ids = {
    us-east-1 = "ami-0cff7528ff583bf9a"
    us-east-2 = "ami-02d1e544b84bf7502"
    us-west-1 = "ami-0d9858aa3c6322f73"
    us-west-2 = "ami-098e42ae54c764c35"
    eu-west-1 = "ami-0fd8802f94ed1c969"
  }
  
  ami_id = local.ami_ids[var.region]
}

# S3 Bucket for Employee Photos
resource "aws_s3_bucket" "employee_photos" {
  bucket = var.bucket_name
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-employee-photos"
  }
}

resource "aws_s3_bucket_versioning" "employee_photos" {
  bucket = aws_s3_bucket.employee_photos.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "employee_photos" {
  bucket = aws_s3_bucket.employee_photos.id

  rule {
    id     = "TransitionToGlacierAndEventuallyExpire"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "employee_photos" {
  bucket = aws_s3_bucket.employee_photos.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "employee_photos" {
  bucket = aws_s3_bucket.employee_photos.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "employee_photos" {
  bucket = aws_s3_bucket.employee_photos.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "employee_photos" {
  depends_on = [aws_s3_bucket_ownership_controls.employee_photos]
  
  bucket = aws_s3_bucket.employee_photos.id
  acl    = "private"
}

# S3 Bucket Policy
resource "aws_s3_bucket_policy" "employee_photos" {
  bucket = aws_s3_bucket.employee_photos.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.ec2_role.arn
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.employee_photos.arn,
          "${aws_s3_bucket.employee_photos.arn}/*"
        ]
      }
    ]
  })
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-VPC"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-IGW"
  }
}

# Public Subnets
resource "aws_subnet" "public1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet1_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-PublicSubnet1"
  }
}

resource "aws_subnet" "public2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet2_cidr
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-PublicSubnet2"
  }
}

# Private Subnets
resource "aws_subnet" "private1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet1_cidr
  availability_zone = data.aws_availability_zones.available.names[0]
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-PrivateSubnet1"
  }
}

resource "aws_subnet" "private2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet2_cidr
  availability_zone = data.aws_availability_zones.available.names[1]
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-PrivateSubnet2"
  }
}

# Elastic IP for NAT Gateway
resource "aws_eip" "nat" {
  domain = "vpc"
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-NAT-EIP"
  }
  
  depends_on = [aws_internet_gateway.igw]
}

# NAT Gateway
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public1.id
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-NATGateway"
  }
}

# Route Tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-PublicRouteTable"
  }
}

resource "aws_route" "public_igw" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-PrivateRouteTable"
  }
}

resource "aws_route" "private_nat" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat.id
}

# Route Table Associations
resource "aws_route_table_association" "public1" {
  subnet_id      = aws_subnet.public1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public2" {
  subnet_id      = aws_subnet.public2.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private1" {
  subnet_id      = aws_subnet.private1.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private2" {
  subnet_id      = aws_subnet.private2.id
  route_table_id = aws_route_table.private.id
}

# Security Groups
resource "aws_security_group" "alb" {
  name        = "${var.environment_name}-ALB-SG"
  description = "Allow inbound HTTP from internet"
  vpc_id      = aws_vpc.main.id
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-ALB-SG"
  }
}

resource "aws_security_group" "ec2" {
  name        = "${var.environment_name}-EC2-SG"
  description = "Allow HTTP from ALB only"
  vpc_id      = aws_vpc.main.id
  
  ingress {
    from_port                = 80
    to_port                  = 80
    protocol                 = "tcp"
    security_groups          = [aws_security_group.alb.id]
  }
  
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-EC2-SG"
  }
}

# IAM Role
resource "aws_iam_role" "ec2_role" {
  name = "${var.environment_name}-EC2-Role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  
  managed_policy_arns = ["arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"]
  
  tags = {
    Environment = var.environment_name
  }
}

resource "aws_iam_policy" "s3_dynamodb_access" {
  name        = "${var.environment_name}-S3DynamoDBAccess"
  description = "Allow access to S3 and DynamoDB"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "s3_dynamodb_access" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.s3_dynamodb_access.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.environment_name}-EC2-Profile"
  role = aws_iam_role.ec2_role.name
}

# CloudWatch Logs
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/aws/ec2/${var.environment_name}-FlaskApp"
  retention_in_days = 7
}

# DynamoDB Table
resource "aws_dynamodb_table" "employees" {
  name           = "employees"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"
  
  attribute {
    name = "id"
    type = "S"
  }
  
  point_in_time_recovery {
    enabled = true
  }
  
  server_side_encryption {
    enabled = true
  }
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-EmployeesTable"
  }
}

# Data sources
data "aws_availability_zones" "available" {}

# Launch Template
resource "aws_launch_template" "app" {
  name_prefix   = "${var.environment_name}-app-"
  image_id      = local.ami_id
  instance_type = var.instance_type
  
  iam_instance_profile {
    arn = aws_iam_instance_profile.ec2_profile.arn
  }
  
  block_device_mappings {
    device_name = "/dev/xvda"
    
    ebs {
      volume_size           = 20
      volume_type           = "gp3"
      delete_on_termination = true
      encrypted             = true
    }
  }
  
  network_interfaces {
    security_groups = [aws_security_group.ec2.id]
  }
  
  tag_specifications {
    resource_type = "instance"
    
    tags = {
      Environment = var.environment_name
      Name        = "${var.environment_name}-WebServer"
    }
  }
  
  user_data = base64encode(<<-EOF
    #!/bin/bash -ex
    yum update -y
    yum install -y aws-cfn-bootstrap amazon-cloudwatch-agent
    
    # Install required packages
    yum install -y python3-pip wget unzip
    
    # Download and install app
    wget https://aws-tc-largeobjects.s3-us-west-2.amazonaws.com/DEV-AWS-MO-GCNv2/FlaskApp.zip
    unzip FlaskApp.zip
    pip3 install -r FlaskApp/requirements.txt
    
    # Configure CloudWatch agent
    cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'EOT'
    {
      "logs": {
        "logs_collected": {
          "files": {
            "collect_list": [
              {
                "file_path": "/var/log/messages",
                "log_group_name": "${aws_cloudwatch_log_group.app_logs.name}",
                "log_stream_name": "{instance_id}/system",
                "timezone": "UTC"
              },
              {
                "file_path": "/home/ec2-user/FlaskApp/app.log",
                "log_group_name": "${aws_cloudwatch_log_group.app_logs.name}",
                "log_stream_name": "{instance_id}/application",
                "timezone": "UTC"
              }
            ]
          }
        }
      },
      "metrics": {
        "metrics_collected": {
          "mem": {
            "measurement": [
              "mem_used_percent"
            ]
          },
          "swap": {
            "measurement": [
              "swap_used_percent"
            ]
          }
        }
      }
    }
    EOT
    
    # Start CloudWatch agent
    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s
    
    # Create a health check endpoint
    mkdir -p /home/ec2-user/FlaskApp
    cat > /home/ec2-user/FlaskApp/health.py <<'EOT'
    import os
    from flask import Flask, jsonify
    
    app = Flask(__name__)
    
    @app.route("/health")
    def health():
        return jsonify({"status": "healthy"})
    
    if __name__ == "__main__":
        app.run(host="0.0.0.0", port=8080)
    EOT
    
    # Start the health check service
    cd /home/ec2-user
    nohup python3 FlaskApp/health.py > FlaskApp/health.log 2>&1 &
    
    # Start the main Flask application
    cd /home/ec2-user/FlaskApp
    export PHOTOS_BUCKET=${var.bucket_name}
    export AWS_DEFAULT_REGION=${var.region}
    export DYNAMO_MODE=on
    export FLASK_APP=application.py
    nohup flask run --host=0.0.0.0 --port=80 > app.log 2>&1 &
  EOF
  )
}

# ALB Target Group
resource "aws_lb_target_group" "app" {
  name     = "${var.environment_name}-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
  
  health_check {
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 5
  }
  
  deregistration_delay = 60
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-TargetGroup"
  }
}

# Application Load Balancer
resource "aws_lb" "app" {
  name               = "${var.environment_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public1.id, aws_subnet.public2.id]
  
  enable_deletion_protection = false
  
  idle_timeout = 60
  
  drop_invalid_header_fields = true
  
  tags = {
    Environment = var.environment_name
    Name        = "${var.environment_name}-ALB"
  }
}

# ALB Listener
resource "aws_lb_listener" "app" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "app" {
  name                      = "${var.environment_name}-asg"
  min_size                  = var.min_capacity
  max_size                  = var.max_capacity
  desired_capacity          = var.desired_capacity
  vpc_zone_identifier       = [aws_subnet.private1.id, aws_subnet.private2.id]
  health_check_type         = "ELB"
  health_check_grace_period = 300
  target_group_arns         = [aws_lb_target_group.app.arn]
  
  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
  
  tag {
    key                 = "Environment"
    value               = var.environment_name
    propagate_at_launch = true
  }
  
  tag {
    key                 = "Name"
    value               = "${var.environment_name}-ASG-Instance"
    propagate_at_launch = true
  }
  
  depends_on = [aws_internet_gateway.igw]
}

# Auto Scaling Policy
resource "aws_autoscaling_policy" "cpu_policy" {
  name                   = "${var.environment_name}-cpu-policy"
  policy_type            = "TargetTrackingScaling"
  autoscaling_group_name = aws_autoscaling_group.app.name
  
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

# Route53 Record
resource "aws_route53_record" "app" {
  zone_id = var.hosted_zone_id
  name    = "${var.subdomain}.${var.domain_name}"
  type    = "A"
  
  alias {
    name                   = aws_lb.app.dns_name
    zone_id                = aws_lb.app.zone_id
    evaluate_target_health = true
  }
}

# Outputs
output "alb_dns" {
  description = "DNS of ALB"
  value       = aws_lb.app.dns_name
}

output "alb_zone_id" {
  description = "Canonical Hosted Zone ID of ALB"
  value       = aws_lb.app.zone_id
}

output "bucket_name" {
  description = "S3 Bucket Name"
  value       = aws_s3_bucket.employee_photos.id
}

output "app_url" {
  description = "Application URL"
  value       = "http://${var.subdomain}.${var.domain_name}"
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "dynamodb_table_name" {
  description = "DynamoDB Table Name"
  value       = aws_dynamodb_table.employees.name
}
