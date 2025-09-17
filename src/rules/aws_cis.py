"""
AWS CIS Benchmark compliance rules
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class AWSCISRules:
    """AWS CIS Benchmark compliance rules implementation"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.rules = {
            'cis_2_1_1': self.check_s3_bucket_public_access_block,
            'cis_2_1_2': self.check_s3_bucket_public_read,
            'cis_2_1_3': self.check_s3_bucket_public_write,
            'cis_2_1_4': self.check_s3_bucket_ssl_requests_only,
            'cis_1_1': self.check_root_user_access_keys,
            'cis_1_2': self.check_root_user_mfa,
            'cis_1_3': self.check_unused_credentials,
            'cis_4_1': self.check_security_group_unrestricted_access,
            'cis_4_2': self.check_security_group_ssh_access,
            'cis_4_3': self.check_security_group_rdp_access
        }
    
    def get_available_rules(self) -> List[str]:
        """Get list of available rule IDs"""
        return list(self.rules.keys())
    
    def check_rule(self, rule_id: str, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check a specific rule against parsed configuration
        
        Args:
            rule_id: CIS rule identifier
            parsed_config: Parsed configuration data
            
        Returns:
            List of violations found
        """
        if rule_id not in self.rules:
            self.logger.warning(f"Unknown rule ID: {rule_id}")
            return []
        
        try:
            return self.rules[rule_id](parsed_config)
        except Exception as e:
            self.logger.error(f"Error checking rule {rule_id}: {str(e)}")
            return []
    
    def check_s3_bucket_public_access_block(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        CIS 2.1.1: Ensure S3 bucket public access block is enabled
        """
        violations = []
        
        # Find S3 buckets
        for resource_key, resource in parsed_config.get('resources', {}).items():
            if resource.get('type') == 'aws_s3_bucket':
                bucket_name = resource.get('name', 'unknown')
                
                # Check if public access block is configured
                public_access_block = None
                for pab_key, pab_resource in parsed_config.get('resources', {}).items():
                    if (pab_resource.get('type') == 'aws_s3_bucket_public_access_block' and
                        pab_resource.get('config', {}).get('bucket') == bucket_name):
                        public_access_block = pab_resource
                        break
                
                if not public_access_block:
                    violations.append({
                        'rule_id': 'cis_2_1_1',
                        'rule_name': 'S3 bucket public access block',
                        'severity': 'HIGH',
                        'resource_type': 'aws_s3_bucket',
                        'resource_name': bucket_name,
                        'resource_key': resource_key,
                        'description': 'S3 bucket does not have public access block configured',
                        'remediation': 'Add aws_s3_bucket_public_access_block resource',
                        'config_path': f'resources.{resource_key}'
                    })
                else:
                    # Check if all public access block settings are enabled
                    config = public_access_block.get('config', {})
                    required_settings = {
                        'block_public_acls': True,
                        'block_public_policy': True,
                        'ignore_public_acls': True,
                        'restrict_public_buckets': True
                    }
                    
                    for setting, required_value in required_settings.items():
                        if config.get(setting) != required_value:
                            violations.append({
                                'rule_id': 'cis_2_1_1',
                                'rule_name': 'S3 bucket public access block',
                                'severity': 'HIGH',
                                'resource_type': 'aws_s3_bucket_public_access_block',
                                'resource_name': bucket_name,
                                'resource_key': public_access_block.get('name', ''),
                                'description': f'S3 bucket public access block setting {setting} should be {required_value}',
                                'remediation': f'Set {setting} = {required_value}',
                                'config_path': f'resources.{pab_key}.config.{setting}'
                            })
        
        return violations
    
    def check_s3_bucket_public_read(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        CIS 2.1.2: Ensure S3 bucket policy does not allow public read access
        """
        violations = []
        
        for resource_key, resource in parsed_config.get('resources', {}).items():
            if resource.get('type') == 'aws_s3_bucket_policy':
                bucket_name = resource.get('config', {}).get('bucket', 'unknown')
                policy = resource.get('config', {}).get('policy', {})
                
                # Check for public read access in policy
                if self._has_public_access(policy, ['s3:GetObject', 's3:GetObjectVersion']):
                    violations.append({
                        'rule_id': 'cis_2_1_2',
                        'rule_name': 'S3 bucket public read access',
                        'severity': 'HIGH',
                        'resource_type': 'aws_s3_bucket_policy',
                        'resource_name': bucket_name,
                        'resource_key': resource_key,
                        'description': 'S3 bucket policy allows public read access',
                        'remediation': 'Remove public read permissions from bucket policy',
                        'config_path': f'resources.{resource_key}.config.policy'
                    })
        
        return violations
    
    def check_s3_bucket_public_write(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        CIS 2.1.3: Ensure S3 bucket policy does not allow public write access
        """
        violations = []
        
        for resource_key, resource in parsed_config.get('resources', {}).items():
            if resource.get('type') == 'aws_s3_bucket_policy':
                bucket_name = resource.get('config', {}).get('bucket', 'unknown')
                policy = resource.get('config', {}).get('policy', {})
                
                # Check for public write access in policy
                if self._has_public_access(policy, ['s3:PutObject', 's3:PutObjectAcl', 's3:DeleteObject']):
                    violations.append({
                        'rule_id': 'cis_2_1_3',
                        'rule_name': 'S3 bucket public write access',
                        'severity': 'CRITICAL',
                        'resource_type': 'aws_s3_bucket_policy',
                        'resource_name': bucket_name,
                        'resource_key': resource_key,
                        'description': 'S3 bucket policy allows public write access',
                        'remediation': 'Remove public write permissions from bucket policy',
                        'config_path': f'resources.{resource_key}.config.policy'
                    })
        
        return violations
    
    def check_s3_bucket_ssl_requests_only(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        CIS 2.1.4: Ensure S3 bucket policy requires SSL requests only
        """
        violations = []
        
        # Find S3 buckets
        s3_buckets = set()
        for resource_key, resource in parsed_config.get('resources', {}).items():
            if resource.get('type') == 'aws_s3_bucket':
                s3_buckets.add(resource.get('name', 'unknown'))
        
        # Check bucket policies for SSL enforcement
        buckets_with_ssl_policy = set()
        for resource_key, resource in parsed_config.get('resources', {}).items():
            if resource.get('type') == 'aws_s3_bucket_policy':
                bucket_name = resource.get('config', {}).get('bucket', 'unknown')
                policy = resource.get('config', {}).get('policy', {})
                
                if self._has_ssl_enforcement(policy):
                    buckets_with_ssl_policy.add(bucket_name)
        
        # Report buckets without SSL enforcement
        for bucket_name in s3_buckets:
            if bucket_name not in buckets_with_ssl_policy:
                violations.append({
                    'rule_id': 'cis_2_1_4',
                    'rule_name': 'S3 bucket SSL requests only',
                    'severity': 'MEDIUM',
                    'resource_type': 'aws_s3_bucket',
                    'resource_name': bucket_name,
                    'resource_key': f'aws_s3_bucket.{bucket_name}',
                    'description': 'S3 bucket does not enforce SSL-only requests',
                    'remediation': 'Add bucket policy to deny non-SSL requests',
                    'config_path': f'resources.aws_s3_bucket.{bucket_name}'
                })
        
        return violations
    
    def check_root_user_access_keys(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        CIS 1.1: Ensure root user access keys do not exist
        """
        violations = []
        
        # This check would typically require AWS API calls to check actual root user keys
        # For configuration analysis, we can check for hardcoded root credentials
        for resource_key, resource in parsed_config.get('resources', {}).items():
            config = resource.get('config', {})
            
            # Check for potential root user credentials in provider configuration
            if resource.get('type') == 'aws' and 'providers' in parsed_config:
                for provider_name, provider_configs in parsed_config['providers'].items():
                    if provider_name == 'aws':
                        for provider_config in provider_configs:
                            if ('access_key' in provider_config or 'secret_key' in provider_config):
                                violations.append({
                                    'rule_id': 'cis_1_1',
                                    'rule_name': 'Root user access keys',
                                    'severity': 'CRITICAL',
                                    'resource_type': 'aws_provider',
                                    'resource_name': 'aws',
                                    'resource_key': 'provider.aws',
                                    'description': 'Hardcoded AWS credentials detected in provider configuration',
                                    'remediation': 'Use IAM roles, instance profiles, or environment variables instead',
                                    'config_path': 'providers.aws'
                                })
        
        return violations
    
    def check_root_user_mfa(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        CIS 1.2: Ensure MFA is enabled for root user
        """
        # This would require AWS API calls to check actual MFA status
        # Configuration analysis cannot determine this
        return []
    
    def check_unused_credentials(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        CIS 1.3: Ensure credentials unused for 90 days are disabled
        """
        # This would require AWS API calls to check credential usage
        # Configuration analysis cannot determine this
        return []
    
    def check_security_group_unrestricted_access(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        CIS 4.1: Ensure security groups do not allow unrestricted access
        """
        violations = []
        
        for resource_key, resource in parsed_config.get('resources', {}).items():
            if resource.get('type') == 'aws_security_group':
                sg_name = resource.get('name', 'unknown')
                config = resource.get('config', {})
                
                # Check ingress rules
                for rule in config.get('ingress', []):
                    cidr_blocks = rule.get('cidr_blocks', [])
                    if '0.0.0.0/0' in cidr_blocks:
                        violations.append({
                            'rule_id': 'cis_4_1',
                            'rule_name': 'Security group unrestricted access',
                            'severity': 'HIGH',
                            'resource_type': 'aws_security_group',
                            'resource_name': sg_name,
                            'resource_key': resource_key,
                            'description': f'Security group allows unrestricted access (0.0.0.0/0) on port {rule.get("from_port", "unknown")}',
                            'remediation': 'Restrict CIDR blocks to specific IP ranges',
                            'config_path': f'resources.{resource_key}.config.ingress'
                        })
        
        return violations
    
    def check_security_group_ssh_access(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        CIS 4.2: Ensure security groups do not allow unrestricted SSH access
        """
        violations = []
        
        for resource_key, resource in parsed_config.get('resources', {}).items():
            if resource.get('type') == 'aws_security_group':
                sg_name = resource.get('name', 'unknown')
                config = resource.get('config', {})
                
                # Check ingress rules for SSH (port 22)
                for rule in config.get('ingress', []):
                    from_port = rule.get('from_port')
                    to_port = rule.get('to_port')
                    cidr_blocks = rule.get('cidr_blocks', [])
                    
                    if (from_port == 22 or to_port == 22) and '0.0.0.0/0' in cidr_blocks:
                        violations.append({
                            'rule_id': 'cis_4_2',
                            'rule_name': 'Security group SSH access',
                            'severity': 'HIGH',
                            'resource_type': 'aws_security_group',
                            'resource_name': sg_name,
                            'resource_key': resource_key,
                            'description': 'Security group allows unrestricted SSH access (port 22) from 0.0.0.0/0',
                            'remediation': 'Restrict SSH access to specific IP ranges or use bastion hosts',
                            'config_path': f'resources.{resource_key}.config.ingress'
                        })
        
        return violations
    
    def check_security_group_rdp_access(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        CIS 4.3: Ensure security groups do not allow unrestricted RDP access
        """
        violations = []
        
        for resource_key, resource in parsed_config.get('resources', {}).items():
            if resource.get('type') == 'aws_security_group':
                sg_name = resource.get('name', 'unknown')
                config = resource.get('config', {})
                
                # Check ingress rules for RDP (port 3389)
                for rule in config.get('ingress', []):
                    from_port = rule.get('from_port')
                    to_port = rule.get('to_port')
                    cidr_blocks = rule.get('cidr_blocks', [])
                    
                    if (from_port == 3389 or to_port == 3389) and '0.0.0.0/0' in cidr_blocks:
                        violations.append({
                            'rule_id': 'cis_4_3',
                            'rule_name': 'Security group RDP access',
                            'severity': 'HIGH',
                            'resource_type': 'aws_security_group',
                            'resource_name': sg_name,
                            'resource_key': resource_key,
                            'description': 'Security group allows unrestricted RDP access (port 3389) from 0.0.0.0/0',
                            'remediation': 'Restrict RDP access to specific IP ranges or use VPN',
                            'config_path': f'resources.{resource_key}.config.ingress'
                        })
        
        return violations
    
    def _has_public_access(self, policy: Dict[str, Any], actions: List[str]) -> bool:
        """Check if policy allows public access for specified actions"""
        if not isinstance(policy, dict):
            return False
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal')
                action = statement.get('Action', [])
                
                # Check if principal allows public access
                if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                    # Check if any of the specified actions are allowed
                    if isinstance(action, str):
                        action = [action]
                    
                    for allowed_action in action:
                        if allowed_action in actions or allowed_action == '*':
                            return True
        
        return False
    
    def _has_ssl_enforcement(self, policy: Dict[str, Any]) -> bool:
        """Check if policy enforces SSL-only requests"""
        if not isinstance(policy, dict):
            return False
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if (statement.get('Effect') == 'Deny' and
                statement.get('Principal') == '*'):
                
                condition = statement.get('Condition', {})
                bool_condition = condition.get('Bool', {})
                
                if bool_condition.get('aws:SecureTransport') == 'false':
                    return True
        
        return False

