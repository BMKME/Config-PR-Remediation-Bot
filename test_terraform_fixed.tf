# Test Terraform configuration with intentional misconfigurations
# This file is used for PoC testing of the Config-to-PR Bot

resource "aws_s3_bucket" "test_bucket" {
  bucket = "my-test-bucket-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "test_bucket_pab" {
  bucket = aws_s3_bucket.test_bucket.id

  # MISCONFIGURATION: Public access should be blocked
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "test_sg" {
  name_prefix = "test-sg"
  description = "Test security group with misconfigurations"

  # MISCONFIGURATION: Unrestricted SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access from anywhere"
  }

  # MISCONFIGURATION: Unrestricted RDP access
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP access from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "test_instance" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t2.micro"
  
  # MISCONFIGURATION: No detailed monitoring
  monitoring = true
  
  # MISCONFIGURATION: Not EBS optimized
  ebs_optimized = true
  
  vpc_security_group_ids = [aws_security_group.test_sg.id]
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}