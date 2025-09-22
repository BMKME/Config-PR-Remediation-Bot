# Copyright 2024 Manus AI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Remediation code generator for compliance violations
"""

import logging
import json
from typing import Dict, Any, List, Optional
from jinja2 import Template

logger = logging.getLogger(__name__)

class RemediationGenerator:
    """Generator for creating remediation code based on compliance violations"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Map rule IDs to remediation functions
        self.remediation_handlers = {
            'cis_2_1_1': self.fix_s3_public_access_block,
            'cis_2_1_2': self.fix_s3_public_read,
            'cis_2_1_3': self.fix_s3_public_write,
            'cis_2_1_4': self.fix_s3_ssl_requests_only,
            'cis_1_1': self.fix_root_user_access_keys,
            'cis_4_1': self.fix_security_group_unrestricted_access,
            'cis_4_2': self.fix_security_group_ssh_access,
            'cis_4_3': self.fix_security_group_rdp_access,
            'nist_pr_ac_1': self.fix_access_control_policy,
            'nist_pr_ac_3': self.fix_remote_access_management,
            'nist_pr_ac_4': self.fix_access_permissions,
            'nist_pr_ds_1': self.fix_data_at_rest_protection,
            'nist_pr_ds_2': self.fix_data_in_transit_protection,
            'nist_pr_ip_1': self.fix_baseline_configuration,
            'nist_de_cm_1': self.fix_network_monitoring,
            'nist_rs_rp_1': self.fix_response_plan
        }
    
    def generate_fixes(self, violations: List[Dict[str, Any]], config_type: str) -> Dict[str, Any]:
        """
        Generate remediation code for a list of violations
        
        Args:
            violations: List of violation dictionaries
            config_type: Type of configuration (terraform, kubernetes, json)
            
        Returns:
            Dict containing generated fixes
        """
        self.logger.info(f"Starting analysis for {len(violations)} violations")
        
        fixes = []
        summary = {
            'total_violations': len(violations),
            'fixable_violations': 0,
            'unfixable_violations': 0,
            'fixes_generated': 0
        }
        
        for violation in violations:
            try:
                fix = self._generate_fix(violation, config_type)
                if fix:
                    fixes.append(fix)
                    summary['fixable_violations'] += 1
                    summary['fixes_generated'] += 1
                else:
                    summary['unfixable_violations'] += 1
                    
            except Exception as e:
                self.logger.error(f"Error generating fix for violation {violation.get('rule_id', 'unknown')}: {str(e)}")
                summary['unfixable_violations'] += 1
        
        result = {
            'config_type': config_type,
            'summary': summary,
            'fixes': fixes,
            'instructions': self._generate_instructions(fixes, config_type)
        }
        
        self.logger.info(f"Generated {len(fixes)} fixes for {config_type} configuration")
        return result
    
    def _generate_fix(self, violation: Dict[str, Any], config_type: str) -> Optional[Dict[str, Any]]:
        """
        Generate a fix for a single violation
        """
        
        rule_id = violation.get('rule_id')
        if rule_id not in self.remediation_handlers:
            self.logger.warning(f"No remediation handler for rule: {rule_id}")
            return None
        
        try:
            handler = self.remediation_handlers[rule_id]
            return handler(violation, config_type)
        except Exception as e:
            self.logger.error(f"Error in remediation handler for {rule_id}: {str(e)}")
            return None
    
    def fix_s3_public_access_block(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for S3 public access block violation
        """
        
        if config_type == 'terraform':
            bucket_name = violation.get('resource_name', 'example-bucket')
            
            template = Template('''
resource "aws_s3_bucket_public_access_block" "{{ bucket_name }}_pab" {
  bucket = aws_s3_bucket.{{ bucket_name }}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
''')
            
            code = template.render(bucket_name=bucket_name)
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'add_resource',
                'resource_type': 'aws_s3_bucket_public_access_block',
                'resource_name': f'{bucket_name}_pab',
                'code': code.strip(),
                'description': f'Add public access block configuration for S3 bucket {bucket_name}',
                'file_path': 'main.tf',
                'explanation': 'This configuration blocks all public access to the S3 bucket, preventing accidental data exposure.'
            }
        
        return None
    
    def fix_s3_public_read(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for S3 public read access violation
        """
        
        if config_type == 'terraform':
            bucket_name = violation.get('resource_name', 'example-bucket')
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'modify_resource',
                'resource_type': 'aws_s3_bucket_policy',
                'resource_name': bucket_name,
                'code': '# Remove or modify statements that grant public read access (Principal: "*" with s3:GetObject)',
                'description': f'Remove public read access from S3 bucket policy for {bucket_name}',
                'file_path': 'main.tf',
                'explanation': 'Remove policy statements that allow public read access to prevent unauthorized data access.'
            }
        
        return None
    
    def fix_s3_public_write(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for S3 public write access violation
        """
        
        if config_type == 'terraform':
            bucket_name = violation.get('resource_name', 'example-bucket')
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'modify_resource',
                'resource_type': 'aws_s3_bucket_policy',
                'resource_name': bucket_name,
                'code': '# Remove or modify statements that grant public write access (Principal: "*" with s3:PutObject, s3:DeleteObject)',
                'description': f'Remove public write access from S3 bucket policy for {bucket_name}',
                'file_path': 'main.tf',
                'explanation': 'Remove policy statements that allow public write access to prevent unauthorized data modification.'
            }
        
        return None
    
    def fix_s3_ssl_requests_only(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for S3 SSL requests only violation
        """
        
        if config_type == 'terraform':
            bucket_name = violation.get('resource_name', 'example-bucket')
            
            template = Template('''
resource "aws_s3_bucket_policy" "{{ bucket_name }}_ssl_only" {
  bucket = aws_s3_bucket.{{ bucket_name }}.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureConnections"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.{{ bucket_name }}.arn,
          "${aws_s3_bucket.{{ bucket_name }}.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
''')
            
            code = template.render(bucket_name=bucket_name)
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'add_resource',
                'resource_type': 'aws_s3_bucket_policy',
                'resource_name': f'{bucket_name}_ssl_only',
                'code': code.strip(),
                'description': f'Add SSL-only policy for S3 bucket {bucket_name}',
                'file_path': 'main.tf',
                'explanation': 'This policy denies all requests that are not made over HTTPS, ensuring data in transit is encrypted.'
            }
        
        return None
    
    def fix_root_user_access_keys(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for root user access keys violation
        """
        
        return {
            'rule_id': violation['rule_id'],
            'fix_type': 'manual_action',
            'resource_type': 'aws_provider',
            'resource_name': 'aws',
            'code': '# Remove hardcoded AWS credentials from provider configuration\n# Use IAM roles, instance profiles, or environment variables instead',
            'description': 'Remove hardcoded AWS credentials from configuration',
            'file_path': 'main.tf',
            'explanation': 'Hardcoded credentials pose a security risk. Use IAM roles or environment variables for authentication.'
        }
    
    def fix_security_group_unrestricted_access(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for security group unrestricted access violation
        """
        
        if config_type == 'terraform':
            sg_name = violation.get('resource_name', 'example-sg')
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'modify_resource',
                'resource_type': 'aws_security_group',
                'resource_name': sg_name,
                'code': '# Replace "0.0.0.0/0" with specific IP ranges or security group references\n# Example: cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12"]',
                'description': f'Restrict CIDR blocks in security group {sg_name}',
                'file_path': 'main.tf',
                'explanation': 'Replace unrestricted access (0.0.0.0/0) with specific IP ranges following the principle of least privilege.'
            }
        
        return None
    
    def fix_security_group_ssh_access(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for security group SSH access violation
        """
        
        if config_type == 'terraform':
            sg_name = violation.get('resource_name', 'example-sg')
            
            template = Template('''
# Replace unrestricted SSH access with restricted access
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # Replace with your office/VPN IP range
  description = "SSH access from trusted networks only"
}
''')
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'modify_resource',
                'resource_type': 'aws_security_group',
                'resource_name': sg_name,
                'code': template.render().strip(),
                'description': f'Restrict SSH access in security group {sg_name}',
                'file_path': 'main.tf',
                'explanation': 'Restrict SSH access to specific IP ranges or use a bastion host for secure access.'
            }
        
        return None
    
    def fix_security_group_rdp_access(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for security group RDP access violation
        """
        
        if config_type == 'terraform':
            sg_name = violation.get('resource_name', 'example-sg')
            
            template = Template('''
# Replace unrestricted RDP access with restricted access
ingress {
  from_port   = 3389
  to_port     = 3389
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # Replace with your office/VPN IP range
  description = "RDP access from trusted networks only"
}
''')
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'modify_resource',
                'resource_type': 'aws_security_group',
                'resource_name': sg_name,
                'code': template.render().strip(),
                'description': f'Restrict RDP access in security group {sg_name}',
                'file_path': 'main.tf',
                'explanation': 'Restrict RDP access to specific IP ranges or use a VPN for secure access.'
            }
        
        return None
    
    def fix_access_control_policy(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for access control policy violation
        """
        
        return {
            'rule_id': violation['rule_id'],
            'fix_type': 'modify_resource',
            'resource_type': 'aws_iam_policy',
            'resource_name': violation.get('resource_name', 'example-policy'),
            'code': '# Replace wildcard permissions (*:*) with specific actions and resources\n# Apply principle of least privilege',
            'description': 'Restrict IAM policy permissions',
            'file_path': 'main.tf',
            'explanation': 'Replace overly broad permissions with specific actions and resources needed for the role.'
        }
    
    def fix_remote_access_management(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for remote access management violation
        """
        
        # This is similar to security group fixes
        return self.fix_security_group_ssh_access(violation, config_type)
    
    def fix_access_permissions(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for access permissions violation
        """
        
        if config_type == 'terraform':
            user_name = violation.get('resource_name', 'example-user')
            
            template = Template('''
# Replace direct user policy attachment with group membership
resource "aws_iam_group_membership" "{{ user_name }}_membership" {
  name = "{{ user_name }}-membership"
  users = [aws_iam_user.{{ user_name }}.name]
  group = aws_iam_group.developers.name  # Replace with appropriate group
}

# Remove the aws_iam_user_policy_attachment resource
''')
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'replace_resource',
                'resource_type': 'aws_iam_group_membership',
                'resource_name': f'{user_name}_membership',
                'code': template.render(user_name=user_name).strip(),
                'description': f'Replace direct policy attachment with group membership for user {user_name}',
                'file_path': 'main.tf',
                'explanation': 'Use IAM groups for permission management instead of direct user policy attachments.'
            }
        
        return None
    
    def fix_data_at_rest_protection(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for data at rest protection violation
        """
        
        if config_type == 'terraform':
            resource_type = violation.get('resource_type')
            resource_name = violation.get('resource_name', 'example-resource')
            
            if resource_type == 'aws_s3_bucket':
                template = Template('''
resource "aws_s3_bucket_server_side_encryption_configuration" "{{ resource_name }}_encryption" {
  bucket = aws_s3_bucket.{{ resource_name }}.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}
''')
                
                return {
                    'rule_id': violation['rule_id'],
                    'fix_type': 'add_resource',
                    'resource_type': 'aws_s3_bucket_server_side_encryption_configuration',
                    'resource_name': f'{resource_name}_encryption',
                    'code': template.render(resource_name=resource_name).strip(),
                    'description': f'Add server-side encryption for S3 bucket {resource_name}',
                    'file_path': 'main.tf',
                    'explanation': 'Enable server-side encryption to protect data at rest.'
                }
            elif resource_type == 'aws_ebs_volume':
                template = Template('''
resource "aws_ebs_volume" "{{ resource_name }}" {
  # ... existing configuration ...
  encrypted = true
  kms_key_id = "arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID" # Replace with your KMS key ARN
}
''')
                
                return {
                    'rule_id': violation['rule_id'],
                    'fix_type': 'modify_resource',
                    'resource_type': 'aws_ebs_volume',
                    'resource_name': resource_name,
                    'code': template.render(resource_name=resource_name).strip(),
                    'description': f'Enable encryption for EBS volume {resource_name}',
                    'file_path': 'main.tf',
                    'explanation': 'Enable encryption for EBS volumes to protect data at rest. Consider using a customer-managed KMS key.'
                }
        
        return None
    
    def fix_data_in_transit_protection(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for data in transit protection violation
        """
        
        if config_type == 'terraform':
            listener_name = violation.get('resource_name', 'example-listener')
            
            template = Template('''
resource "aws_lb_listener" "{{ listener_name }}" {
  # ... existing configuration ...
  protocol = "HTTPS"
  port = 443
  ssl_policy = "ELBSecurityPolicy-2016-08"
  certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERT_ID" # Replace with your ACM certificate ARN
}
''')
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'modify_resource',
                'resource_type': 'aws_lb_listener',
                'resource_name': listener_name,
                'code': template.render(listener_name=listener_name).strip(),
                'description': f'Configure HTTPS listener for load balancer {listener_name}',
                'file_path': 'main.tf',
                'explanation': 'Use HTTPS for load balancer listeners to encrypt data in transit.'
            }
        
        return None
    
    def fix_baseline_configuration(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for baseline configuration violation
        """
        
        if config_type == 'terraform':
            resource_type = violation.get('resource_type')
            resource_name = violation.get('resource_name', 'example-instance')
            
            if resource_type == 'aws_instance':
                # Assuming the violation is for missing monitoring or EBS optimization
                if 'monitoring' in violation.get('description', ''):
                    template = Template('''
resource "aws_instance" "{{ resource_name }}" {
  # ... existing configuration ...
  monitoring = true
}
''')
                    return {
                        'rule_id': violation['rule_id'],
                        'fix_type': 'modify_resource',
                        'resource_type': 'aws_instance',
                        'resource_name': resource_name,
                        'code': template.render(resource_name=resource_name).strip(),
                        'description': f'Enable detailed monitoring for EC2 instance {resource_name}',
                        'file_path': 'main.tf',
                        'explanation': 'Enable detailed monitoring for better visibility into instance performance and health.'
                    }
                elif 'EBS optimized' in violation.get('description', ''):
                    template = Template('''
resource "aws_instance" "{{ resource_name }}" {
  # ... existing configuration ...
  ebs_optimized = true
}
''')
                    return {
                        'rule_id': violation['rule_id'],
                        'fix_type': 'modify_resource',
                        'resource_type': 'aws_instance',
                        'resource_name': resource_name,
                        'code': template.render(resource_name=resource_name).strip(),
                        'description': f'Enable EBS optimization for EC2 instance {resource_name}',
                        'file_path': 'main.tf',
                        'explanation': 'Enable EBS optimization for better I/O performance with EBS volumes.'
                    }
        
        return None
    
    def fix_network_monitoring(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for network monitoring violation (VPC Flow Logs)
        """
        
        if config_type == 'terraform':
            vpc_name = violation.get('resource_name', 'example-vpc')
            
            template = Template('''
resource "aws_flow_log" "{{ vpc_name }}_flow_log" {
  log_destination      = aws_s3_bucket.flow_log_bucket.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.{{ vpc_name }}.id
  log_destination_type = "s3"
}

resource "aws_s3_bucket" "flow_log_bucket" {
  bucket = "{{ vpc_name }}-flow-logs-{{ random_id }}" # Replace with a unique bucket name
  acl    = "private"

  versioning {
    enabled = true
  }
}

resource "aws_s3_bucket_policy" "flow_log_bucket_policy" {
  bucket = aws_s3_bucket.flow_log_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSLogDeliveryWrite"
        Effect    = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action = [
          "s3:PutObject",
          "s3:GetBucketAcl",
          "s3:PutObjectAcl"
        ]
        Resource = [
          aws_s3_bucket.flow_log_bucket.arn,
          "${aws_s3_bucket.flow_log_bucket.arn}/*"
        ]
      },
      {
        Sid       = "AWSLogDeliveryCheck"
        Effect    = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.flow_log_bucket.arn
      }
    ]
  })
}
''')
            
            # Need a way to generate random_id or take it from context
            code = template.render(vpc_name=vpc_name, random_id='abcdef123456') # Placeholder for random_id
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'add_resource',
                'resource_type': 'aws_flow_log',
                'resource_name': f'{vpc_name}_flow_log',
                'code': code.strip(),
                'description': f'Enable VPC Flow Logs for VPC {vpc_name}',
                'file_path': 'main.tf',
                'explanation': 'Enable VPC Flow Logs to monitor network traffic and detect anomalies.'
            }
        
        return None
    
    def fix_response_plan(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Generate fix for incident response plan violation (CloudTrail)
        """
        
        if config_type == 'terraform':
            trail_name = violation.get('resource_name', 'example-cloudtrail')
            
            template = Template('''
resource "aws_cloudtrail" "{{ trail_name }}" {
  name                          = "{{ trail_name }}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  # Optional: Enable CloudWatch Logs for real-time monitoring
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cloudtrail_log_group.arn
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch_role.arn
}

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "{{ trail_name }}-cloudtrail-{{ random_id }}" # Replace with a unique bucket name
  acl    = "private"

  versioning {
    enabled = true
  }
}

resource "aws_cloudwatch_log_group" "cloudtrail_log_group" {
  name = "CloudTrail/{{ trail_name }}"
  retention_in_days = 90
}

resource "aws_iam_role" "cloudtrail_cloudwatch_role" {
  name = "cloudtrail-cloudwatch-role-{{ random_id }}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_policy" {
  name = "cloudtrail-cloudwatch-policy-{{ random_id }}"
  role = aws_iam_role.cloudtrail_cloudwatch_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect = "Allow"
        Resource = "${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"
      }
    ]
  })
}
''')
            
            code = template.render(trail_name=trail_name, random_id='abcdef123456') # Placeholder for random_id
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'add_resource',
                'resource_type': 'aws_cloudtrail',
                'resource_name': trail_name,
                'code': code.strip(),
                'description': f'Configure AWS CloudTrail for {trail_name}',
                'file_path': 'main.tf',
                'explanation': 'Configure AWS CloudTrail to enable logging and monitoring of AWS API calls, essential for incident response.'
            }
        
        return None
    
    def _generate_instructions(self, fixes: List[Dict[str, Any]], config_type: str) -> str:
        """
        Generate human-readable instructions for applying fixes
        """
        instructions = []
        
        if not fixes:
            return "No automated fixes were generated. Manual review is required."
        
        instructions.append(f"## Remediation Instructions for {config_type.upper()} Configuration\n")
        instructions.append("The following automated fixes have been generated. Please review them carefully before applying.\n")
        
        for i, fix in enumerate(fixes):
            instructions.append(f"### Fix {i+1}: {fix['description']}\n")
            instructions.append(f"**Rule ID:** {fix['rule_id']}\n")
            instructions.append(f"**Resource Type:** {fix['resource_type']}\n")
            instructions.append(f"**Resource Name:** {fix['resource_name']}\n")
            instructions.append(f"**Explanation:** {fix['explanation']}\n")
            instructions.append(f"**Suggested File:** {fix['file_path']}\n")
            instructions.append("```terraform\n" if config_type == 'terraform' else "```yaml\n")
            instructions.append(f"{fix['code']}\n")
            instructions.append("```\n")
            instructions.append("\n")
            
        instructions.append("## Manual Review and Application\n")
        instructions.append("1.  **Review the generated code:** Carefully examine each fix to ensure it aligns with your infrastructure requirements and does not introduce unintended side effects.\n")
        instructions.append("2.  **Apply the changes:** Copy the generated code into the specified files in your repository.\n")
        instructions.append("3.  **Test the changes:** Deploy the updated configuration to a staging environment and thoroughly test its functionality and security posture.\n")
        instructions.append("4.  **Commit and Deploy:** Once satisfied, commit the changes to your version control system and deploy to production.\n")
        instructions.append("\n**Important:** For critical issues, consider manual remediation and thorough testing before applying automated fixes.\n")
        
        return "\n".join(instructions)



