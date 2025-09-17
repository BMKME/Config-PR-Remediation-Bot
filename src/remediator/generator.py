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
        self.logger.info(f"Generating fixes for {len(violations)} violations")
        
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
        """Generate a fix for a single violation"""
        
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
        """Generate fix for S3 public access block violation"""
        
        if config_type == 'terraform':
            bucket_name = violation.get('resource_name', 'example-bucket')
            
            template = Template('''
resource "aws_s3_bucket_public_access_block" "{{ bucket_name }}_pab" {
  bucket = aws_s3_bucket.{{ bucket_name }}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}''')
            
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
        """Generate fix for S3 public read access violation"""
        
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
        """Generate fix for S3 public write access violation"""
        
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
        """Generate fix for S3 SSL requests only violation"""
        
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
}''')
            
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
        """Generate fix for root user access keys violation"""
        
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
        """Generate fix for security group unrestricted access violation"""
        
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
        """Generate fix for security group SSH access violation"""
        
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
}''')
            
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
        """Generate fix for security group RDP access violation"""
        
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
}''')
            
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
        """Generate fix for access control policy violation"""
        
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
        """Generate fix for remote access management violation"""
        
        # This is similar to security group fixes
        return self.fix_security_group_ssh_access(violation, config_type)
    
    def fix_access_permissions(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """Generate fix for access permissions violation"""
        
        if config_type == 'terraform':
            user_name = violation.get('resource_name', 'example-user')
            
            template = Template('''
# Replace direct user policy attachment with group membership
resource "aws_iam_group_membership" "{{ user_name }}_membership" {
  name = "{{ user_name }}-membership"
  users = [aws_iam_user.{{ user_name }}.name]
  group = aws_iam_group.developers.name  # Replace with appropriate group
}

# Remove the aws_iam_user_policy_attachment resource''')
            
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
        """Generate fix for data at rest protection violation"""
        
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
}''')
                
                return {
                    'rule_id': violation['rule_id'],
                    'fix_type': 'add_resource',
                    'resource_type': 'aws_s3_bucket_server_side_encryption_configuration',
                    'resource_name': f'{resource_name}_encryption',
                    'code': template.render(resource_name=resource_name).strip(),
                    'description': f'Add server-side encryption for S3 bucket {resource_name}',
                    'file_path': 'main.tf',
                    'explanation': 'Enable server-side encryption to protect data at rest in S3.'
                }
            
            elif resource_type == 'aws_ebs_volume':
                return {
                    'rule_id': violation['rule_id'],
                    'fix_type': 'modify_resource',
                    'resource_type': 'aws_ebs_volume',
                    'resource_name': resource_name,
                    'code': 'encrypted = true',
                    'description': f'Enable encryption for EBS volume {resource_name}',
                    'file_path': 'main.tf',
                    'explanation': 'Enable EBS volume encryption to protect data at rest.'
                }
        
        return None
    
    def fix_data_in_transit_protection(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """Generate fix for data in transit protection violation"""
        
        if config_type == 'terraform':
            resource_name = violation.get('resource_name', 'example-listener')
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'modify_resource',
                'resource_type': 'aws_lb_listener',
                'resource_name': resource_name,
                'code': 'protocol = "HTTPS"\nport = "443"\ncertificate_arn = "arn:aws:acm:region:account:certificate/certificate-id"',
                'description': f'Change load balancer listener {resource_name} to use HTTPS',
                'file_path': 'main.tf',
                'explanation': 'Use HTTPS with SSL certificate to encrypt data in transit.'
            }
        
        return None
    
    def fix_baseline_configuration(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """Generate fix for baseline configuration violation"""
        
        if config_type == 'terraform':
            resource_name = violation.get('resource_name', 'example-instance')
            config_path = violation.get('config_path', '')
            
            if 'monitoring' in config_path:
                return {
                    'rule_id': violation['rule_id'],
                    'fix_type': 'modify_resource',
                    'resource_type': 'aws_instance',
                    'resource_name': resource_name,
                    'code': 'monitoring = true',
                    'description': f'Enable detailed monitoring for EC2 instance {resource_name}',
                    'file_path': 'main.tf',
                    'explanation': 'Enable detailed monitoring for better visibility into instance performance.'
                }
            
            elif 'ebs_optimized' in config_path:
                return {
                    'rule_id': violation['rule_id'],
                    'fix_type': 'modify_resource',
                    'resource_type': 'aws_instance',
                    'resource_name': resource_name,
                    'code': 'ebs_optimized = true',
                    'description': f'Enable EBS optimization for EC2 instance {resource_name}',
                    'file_path': 'main.tf',
                    'explanation': 'Enable EBS optimization for better storage performance.'
                }
        
        return None
    
    def fix_network_monitoring(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """Generate fix for network monitoring violation"""
        
        if config_type == 'terraform':
            vpc_name = violation.get('resource_name', 'example-vpc')
            
            template = Template('''
resource "aws_flow_log" "{{ vpc_name }}_flow_log" {
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.flow_log_group.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.{{ vpc_name }}.id
}

resource "aws_cloudwatch_log_group" "flow_log_group" {
  name              = "/aws/vpc/flowlogs"
  retention_in_days = 30
}

resource "aws_iam_role" "flow_log_role" {
  name = "flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "flow_log_policy" {
  name = "flow-log-policy"
  role = aws_iam_role.flow_log_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}''')
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'add_resource',
                'resource_type': 'aws_flow_log',
                'resource_name': f'{vpc_name}_flow_log',
                'code': template.render(vpc_name=vpc_name).strip(),
                'description': f'Add VPC flow logs for {vpc_name}',
                'file_path': 'main.tf',
                'explanation': 'Enable VPC flow logs to monitor network traffic for security analysis.'
            }
        
        return None
    
    def fix_response_plan(self, violation: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """Generate fix for response plan violation"""
        
        if config_type == 'terraform':
            template = Template('''
resource "aws_cloudtrail" "main_trail" {
  name           = "main-cloudtrail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_bucket.bucket

  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/*"]
    }
  }

  enable_logging = true
}

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = "my-cloudtrail-bucket-${random_id.bucket_suffix.hex}"
  force_destroy = true
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}''')
            
            return {
                'rule_id': violation['rule_id'],
                'fix_type': 'add_resource',
                'resource_type': 'aws_cloudtrail',
                'resource_name': 'main_trail',
                'code': template.render().strip(),
                'description': 'Add CloudTrail for audit logging',
                'file_path': 'main.tf',
                'explanation': 'Enable CloudTrail to log API calls for security monitoring and incident response.'
            }
        
        return None
    
    def _generate_instructions(self, fixes: List[Dict[str, Any]], config_type: str) -> List[str]:
        """Generate human-readable instructions for applying fixes"""
        
        instructions = [
            f"Instructions for applying {len(fixes)} remediation fixes:",
            "",
            "1. Review each fix carefully before applying",
            "2. Test changes in a development environment first",
            "3. Apply fixes in order of severity (Critical > High > Medium > Low)",
            "4. Validate configurations after applying fixes",
            ""
        ]
        
        if config_type == 'terraform':
            instructions.extend([
                "Terraform-specific instructions:",
                "- Run 'terraform plan' to preview changes",
                "- Run 'terraform apply' to apply changes",
                "- Use 'terraform validate' to check syntax",
                ""
            ])
        
        # Group fixes by type
        fix_types = {}
        for fix in fixes:
            fix_type = fix.get('fix_type', 'unknown')
            if fix_type not in fix_types:
                fix_types[fix_type] = []
            fix_types[fix_type].append(fix)
        
        for fix_type, type_fixes in fix_types.items():
            if fix_type == 'add_resource':
                instructions.append(f"Add {len(type_fixes)} new resources:")
                for fix in type_fixes:
                    instructions.append(f"  - {fix['resource_type']}.{fix['resource_name']}")
            elif fix_type == 'modify_resource':
                instructions.append(f"Modify {len(type_fixes)} existing resources:")
                for fix in type_fixes:
                    instructions.append(f"  - {fix['resource_type']}.{fix['resource_name']}")
            elif fix_type == 'manual_action':
                instructions.append(f"Manual actions required for {len(type_fixes)} items:")
                for fix in type_fixes:
                    instructions.append(f"  - {fix['description']}")
        
        return instructions

