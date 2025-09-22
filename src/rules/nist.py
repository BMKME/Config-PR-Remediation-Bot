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
NIST Cybersecurity Framework compliance rules
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class NISTRules:
    """NIST Cybersecurity Framework compliance rules implementation"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.rules = {
            "nist_pr_ac_1": self.check_access_control_policy,
            "nist_pr_ac_3": self.check_remote_access_management,
            "nist_pr_ac_4": self.check_access_permissions,
            "nist_pr_ds_1": self.check_data_at_rest_protection,
            "nist_pr_ds_2": self.check_data_in_transit_protection,
            "nist_pr_ip_1": self.check_baseline_configuration,
            "nist_de_cm_1": self.check_network_monitoring,
            "nist_rs_rp_1": self.check_response_plan
        }
    
    def get_available_rules(self) -> List[str]:
        """
        Get list of available rule IDs
        """
        return list(self.rules.keys())
    
    def check_rule(self, rule_id: str, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check a specific rule against parsed configuration
        
        Args:
            rule_id: NIST rule identifier
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
    
    def check_access_control_policy(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        NIST PR.AC-1: Access control policy and procedures
        Check for proper IAM policies and access controls
        """
        violations = []
        
        # Check for IAM policies with overly broad permissions
        for resource_key, resource in parsed_config.get("resources", {}).items():
            if resource.get("type") == "aws_iam_policy":
                policy_name = resource.get("name", "unknown")
                policy_document = resource.get("config", {}).get("policy", {})
                
                if self._has_admin_access(policy_document):
                    violations.append({
                        "rule_id": "nist_pr_ac_1",
                        "rule_name": "Access control policy",
                        "severity": "HIGH",
                        "resource_type": "aws_iam_policy",
                        "resource_name": policy_name,
                        "resource_key": resource_key,
                        "description": "IAM policy grants administrative access (*:*)",
                        "remediation": "Apply principle of least privilege and restrict permissions",
                        "config_path": f"resources.{resource_key}.config.policy"
                    })
        
        return violations
    
    def check_remote_access_management(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        NIST PR.AC-3: Remote access is managed
        Check for secure remote access configurations
        """
        violations = []
        
        # Check security groups for unrestricted remote access
        for resource_key, resource in parsed_config.get("resources", {}).items():
            if resource.get("type") == "aws_security_group":
                sg_name = resource.get("name", "unknown")
                config = resource.get("config", {})
                
                # Check for unrestricted SSH/RDP access
                for rule in config.get("ingress", []):
                    from_port = rule.get("from_port")
                    to_port = rule.get("to_port")
                    cidr_blocks = rule.get("cidr_blocks", [])
                    
                    if "0.0.0.0/0" in cidr_blocks:
                        if from_port == 22 or to_port == 22:
                            violations.append({
                                "rule_id": "nist_pr_ac_3",
                                "rule_name": "Remote access management",
                                "severity": "HIGH",
                                "resource_type": "aws_security_group",
                                "resource_name": sg_name,
                                "resource_key": resource_key,
                                "description": "Security group allows unrestricted SSH access",
                                "remediation": "Restrict SSH access to specific IP ranges and implement VPN",
                                "config_path": f"resources.{resource_key}.config.ingress"
                            })
                        elif from_port == 3389 or to_port == 3389:
                            violations.append({
                                "rule_id": "nist_pr_ac_3",
                                "rule_name": "Remote access management",
                                "severity": "HIGH",
                                "resource_type": "aws_security_group",
                                "resource_name": sg_name,
                                "resource_key": resource_key,
                                "description": "Security group allows unrestricted RDP access",
                                "remediation": "Restrict RDP access to specific IP ranges and implement VPN",
                                "config_path": f"resources.{resource_key}.config.ingress"
                            })
        
        return violations
    
    def check_access_permissions(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        NIST PR.AC-4: Access permissions are managed
        Check for proper access permission management
        """
        violations = []
        
        # Check for IAM users with direct policy attachments (should use groups)
        for resource_key, resource in parsed_config.get("resources", {}).items():
            if resource.get("type") == "aws_iam_user_policy_attachment":
                user_name = resource.get("config", {}).get("user", "unknown")
                policy_arn = resource.get("config", {}).get("policy_arn", "unknown")
                
                violations.append({
                    "rule_id": "nist_pr_ac_4",
                    "rule_name": "Access permissions management",
                    "severity": "MEDIUM",
                    "resource_type": "aws_iam_user_policy_attachment",
                    "resource_name": user_name,
                    "resource_key": resource_key,
                    "description": "IAM user has direct policy attachment instead of group membership",
                    "remediation": "Use IAM groups for permission management instead of direct user attachments",
                    "config_path": f"resources.{resource_key}"
                })
        
        return violations
    
    def check_data_at_rest_protection(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        NIST PR.DS-1: Data-at-rest is protected
        Check for encryption of data at rest
        """
        violations = []
        
        # Check S3 buckets for encryption
        for resource_key, resource in parsed_config.get("resources", {}).items():
            if resource.get("type") == "aws_s3_bucket":
                bucket_name = resource.get("name", "unknown")
                
                # Check if bucket has server-side encryption
                encryption_found = False
                for enc_key, enc_resource in parsed_config.get("resources", {}).items():
                    if (enc_resource.get("type") == "aws_s3_bucket_server_side_encryption_configuration" and
                        enc_resource.get("config", {}).get("bucket") == bucket_name):
                        encryption_found = True
                        break
                
                if not encryption_found:
                    violations.append({
                        "rule_id": "nist_pr_ds_1",
                        "rule_name": "Data-at-rest protection",
                        "severity": "HIGH",
                        "resource_type": "aws_s3_bucket",
                        "resource_name": bucket_name,
                        "resource_key": resource_key,
                        "description": "S3 bucket does not have server-side encryption configured",
                        "remediation": "Enable server-side encryption for S3 bucket",
                        "config_path": f"resources.{resource_key}"
                    })
        
        # Check EBS volumes for encryption
        for resource_key, resource in parsed_config.get("resources", {}).items():
            if resource.get("type") == "aws_ebs_volume":
                volume_name = resource.get("name", "unknown")
                encrypted = resource.get("config", {}).get("encrypted", False)
                
                if not encrypted:
                    violations.append({
                        "rule_id": "nist_pr_ds_1",
                        "rule_name": "Data-at-rest protection",
                        "severity": "HIGH",
                        "resource_type": "aws_ebs_volume",
                        "resource_name": volume_name,
                        "resource_key": resource_key,
                        "description": "EBS volume is not encrypted",
                        "remediation": "Enable encryption for EBS volume",
                        "config_path": f"resources.{resource_key}.config.encrypted"
                    })
        
        return violations
    
    def check_data_in_transit_protection(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        NIST PR.DS-2: Data-in-transit is protected
        Check for encryption of data in transit
        """
        violations = []
        
        # Check load balancers for HTTPS listeners
        for resource_key, resource in parsed_config.get("resources", {}).items():
            if resource.get("type") == "aws_lb_listener":
                listener_name = resource.get("name", "unknown")
                protocol = resource.get("config", {}).get("protocol", "")
                port = resource.get("config", {}).get("port", 0)
                
                if protocol == "HTTP" and port == 80:
                    violations.append({
                        "rule_id": "nist_pr_ds_2",
                        "rule_name": "Data-in-transit protection",
                        "severity": "MEDIUM",
                        "resource_type": "aws_lb_listener",
                        "resource_name": listener_name,
                        "resource_key": resource_key,
                        "description": "Load balancer listener uses HTTP instead of HTTPS",
                        "remediation": "Configure HTTPS listener with SSL certificate",
                        "config_path": f"resources.{resource_key}.config.protocol"
                    })
        
        return violations
    
    def check_baseline_configuration(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        NIST PR.IP-1: A baseline configuration is created and maintained
        Check for consistent and secure baseline configurations
        """
        violations = []
        
        # Check EC2 instances for consistent configuration
        instance_configs = {}
        for resource_key, resource in parsed_config.get("resources", {}).items():
            if resource.get("type") == "aws_instance":
                instance_name = resource.get("name", "unknown")
                config = resource.get("config", {})
                
                # Check for missing security configurations
                if not config.get("monitoring"):
                    violations.append({
                        "rule_id": "nist_pr_ip_1",
                        "rule_name": "Baseline configuration",
                        "severity": "MEDIUM",
                        "resource_type": "aws_instance",
                        "resource_name": instance_name,
                        "resource_key": resource_key,
                        "description": "EC2 instance does not have detailed monitoring enabled",
                        "remediation": "Enable detailed monitoring for EC2 instance",
                        "config_path": f"resources.{resource_key}.config.monitoring"
                    })
                
                if not config.get("ebs_optimized"):
                    violations.append({
                        "rule_id": "nist_pr_ip_1",
                        "rule_name": "Baseline configuration",
                        "severity": "LOW",
                        "resource_type": "aws_instance",
                        "resource_name": instance_name,
                        "resource_key": resource_key,
                        "description": "EC2 instance is not EBS optimized",
                        "remediation": "Enable EBS optimization for better performance",
                        "config_path": f"resources.{resource_key}.config.ebs_optimized"
                    })
        
        return violations
    
    def check_network_monitoring(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        NIST DE.CM-1: The network is monitored
        Check for network monitoring configurations
        """
        violations = []
        
        # Check for VPC Flow Logs
        vpcs = set()
        flow_logs = set()
        
        # Collect VPCs
        for resource_key, resource in parsed_config.get("resources", {}).items():
            if resource.get("type") == "aws_vpc":
                vpcs.add(resource.get("name", "unknown"))
        
        # Collect VPCs with flow logs
        for resource_key, resource in parsed_config.get("resources", {}).items():
            if resource.get("type") == "aws_flow_log":
                resource_id = resource.get("config", {}).get("resource_id", "")
                if resource_id:
                    flow_logs.add(resource_id)
        
        # Check for VPCs without flow logs
        for vpc_name in vpcs:
            if vpc_name not in flow_logs:
                violations.append({
                    "rule_id": "nist_de_cm_1",
                    "rule_name": "Network monitoring",
                    "severity": "MEDIUM",
                    "resource_type": "aws_vpc",
                    "resource_name": vpc_name,
                    "resource_key": f"aws_vpc.{vpc_name}",
                    "description": "VPC does not have flow logs enabled",
                    "remediation": "Enable VPC flow logs for network monitoring",
                    "config_path": f"resources.aws_vpc.{vpc_name}"
                })
        
        return violations
    
    def check_response_plan(self, parsed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        NIST RS.RP-1: Response plan is executed
        Check for incident response configurations
        """
        violations = []
        
        # Check for CloudTrail logging
        cloudtrail_found = False
        for resource_key, resource in parsed_config.get("resources", {}).items():
            if resource.get("type") == "aws_cloudtrail":
                cloudtrail_found = True
                
                # Check if CloudTrail is properly configured
                config = resource.get("config", {})
                if not config.get("enable_logging", True):
                    violations.append({
                        "rule_id": "nist_rs_rp_1",
                        "rule_name": "Response plan execution",
                        "severity": "HIGH",
                        "resource_type": "aws_cloudtrail",
                        "resource_name": resource.get("name", "unknown"),
                        "resource_key": resource_key,
                        "description": "CloudTrail logging is disabled",
                        "remediation": "Enable CloudTrail logging for audit trail",
                        "config_path": f"resources.{resource_key}.config.enable_logging"
                    })
        
        if not cloudtrail_found:
            violations.append({
                "rule_id": "nist_rs_rp_1",
                "rule_name": "Response plan execution",
                "severity": "HIGH",
                "resource_type": "aws_cloudtrail",
                "resource_name": "N/A",
                "resource_key": "N/A",
                "description": "CloudTrail is not configured",
                "remediation": "Configure AWS CloudTrail for logging and monitoring",
                "config_path": "N/A"
            })
        
        return violations
    
    def _has_admin_access(self, policy_document: Dict[str, Any]) -> bool:
        """
        Helper to check if an IAM policy grants administrative access
        """
        if not policy_document or "Statement" not in policy_document:
            return False
        
        for statement in policy_document["Statement"]:
            effect = statement.get("Effect")
            actions = statement.get("Action")
            resources = statement.get("Resource")
            
            if effect == "Allow" and actions == "*" and resources == "*":
                return True
        return False



