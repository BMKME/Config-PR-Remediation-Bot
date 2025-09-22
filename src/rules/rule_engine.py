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
Rule Engine for scalable compliance rules
Supports dynamic rule loading and multi-framework compliance
"""

import logging
import json
import yaml
from typing import Dict, Any, List, Optional, Callable
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Framework(Enum):
    CIS = "CIS"
    NIST = "NIST"
    SOC2 = "SOC2"
    ISO27001 = "ISO27001"
    COBIT = "COBIT"
    OCTAVE = "OCTAVE"
    AWS_SECURITY = "AWS_SECURITY"
    CUSTOM = "CUSTOM"

@dataclass
class ComplianceRule:
    """Data class for compliance rules"""
    rule_id: str
    name: str
    description: str
    severity: Severity
    framework: Framework
    resource_types: List[str]
    check_function: str
    fix_function: Optional[str] = None
    enabled: bool = True
    tags: List[str] = None
    references: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.references is None:
            self.references = []

class RuleChecker(ABC):
    """Abstract base class for rule checkers"""
    
    @abstractmethod
    def check(self, resource: Dict[str, Any], config: Dict[str, Any]) -> bool:
        """Check if resource violates the rule"""
        pass
    
    @abstractmethod
    def get_violation_details(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Get details about the violation"""
        pass

class RuleFixer(ABC):
    """Abstract base class for rule fixers"""
    
    @abstractmethod
    def fix(self, resource: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Fix the violation and return the fixed resource"""
        pass
    
    @abstractmethod
    def get_fix_description(self) -> str:
        """Get description of what the fix does"""
        pass

class ScalableRuleEngine:
    """Scalable rule engine for compliance checking"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.rules: Dict[str, ComplianceRule] = {}
        self.checkers: Dict[str, RuleChecker] = {}
        self.fixers: Dict[str, RuleFixer] = {}
        self._load_built_in_rules()
    
    def _load_built_in_rules(self):
        """Load built-in compliance rules"""
        
        # S3 Public Access Rules
        self.register_rule(ComplianceRule(
            rule_id="cis_2_1_1",
            name="S3 Bucket Public Access Block",
            description="Ensure S3 bucket public access block is configured",
            severity=Severity.HIGH,
            framework=Framework.CIS,
            resource_types=["aws_s3_bucket_public_access_block"],
            check_function="check_s3_public_access_block",
            fix_function="fix_s3_public_access_block",
            tags=["s3", "public-access", "data-protection"],
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
            ]
        ))
        
        self.register_rule(ComplianceRule(
            rule_id="cis_2_1_2",
            name="S3 Bucket ACL",
            description="Ensure S3 bucket ACL is not public",
            severity=Severity.HIGH,
            framework=Framework.CIS,
            resource_types=["aws_s3_bucket"],
            check_function="check_s3_bucket_acl",
            fix_function="fix_s3_bucket_acl",
            tags=["s3", "acl", "public-access"],
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html"
            ]
        ))
        
        # Security Group Rules
        self.register_rule(ComplianceRule(
            rule_id="cis_4_2",
            name="Security Group SSH Access",
            description="Ensure security groups do not allow unrestricted SSH access",
            severity=Severity.HIGH,
            framework=Framework.CIS,
            resource_types=["aws_security_group"],
            check_function="check_sg_ssh_access",
            fix_function="fix_sg_ssh_access",
            tags=["security-group", "ssh", "network-security"],
            references=[
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules.html"
            ]
        ))
        
        self.register_rule(ComplianceRule(
            rule_id="cis_4_3",
            name="Security Group RDP Access",
            description="Ensure security groups do not allow unrestricted RDP access",
            severity=Severity.HIGH,
            framework=Framework.CIS,
            resource_types=["aws_security_group"],
            check_function="check_sg_rdp_access",
            fix_function="fix_sg_rdp_access",
            tags=["security-group", "rdp", "network-security"],
            references=[
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules.html"
            ]
        ))
        
        # EC2 Instance Rules
        self.register_rule(ComplianceRule(
            rule_id="nist_pr_ip_1",
            name="EC2 Instance Monitoring",
            description="Ensure EC2 instances have detailed monitoring enabled",
            severity=Severity.MEDIUM,
            framework=Framework.NIST,
            resource_types=["aws_instance"],
            check_function="check_ec2_monitoring",
            fix_function="fix_ec2_monitoring",
            tags=["ec2", "monitoring", "observability"],
            references=[
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch.html"
            ]
        ))
        
        self.register_rule(ComplianceRule(
            rule_id="nist_pr_ip_2",
            name="EC2 Instance EBS Optimization",
            description="Ensure EC2 instances are EBS optimized when supported",
            severity=Severity.MEDIUM,
            framework=Framework.NIST,
            resource_types=["aws_instance"],
            check_function="check_ec2_ebs_optimization",
            fix_function="fix_ec2_ebs_optimization",
            tags=["ec2", "ebs", "performance"],
            references=[
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-optimized.html"
            ]
        ))
        
        # Register built-in checkers and fixers
        self._register_built_in_checkers()
        self._register_built_in_fixers()
    
    def register_rule(self, rule: ComplianceRule):
        """Register a compliance rule"""
        self.rules[rule.rule_id] = rule
        self.logger.info(f"Registered rule: {rule.rule_id} - {rule.name}")
    
    def register_checker(self, rule_id: str, checker: RuleChecker):
        """Register a rule checker"""
        self.checkers[rule_id] = checker
        self.logger.info(f"Registered checker for rule: {rule_id}")
    
    def register_fixer(self, rule_id: str, fixer: RuleFixer):
        """Register a rule fixer"""
        self.fixers[rule_id] = fixer
        self.logger.info(f"Registered fixer for rule: {rule_id}")
    
    def load_rules_from_file(self, file_path: str):
        """Load rules from YAML or JSON file"""
        
        try:
            with open(file_path, "r") as f:
                if file_path.endswith(".yaml") or file_path.endswith(".yml"):
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
            
            for rule_data in data.get("rules", []):
                rule = ComplianceRule(
                    rule_id=rule_data["rule_id"],
                    name=rule_data["name"],
                    description=rule_data["description"],
                    severity=Severity(rule_data["severity"]),
                    framework=Framework(rule_data["framework"]),
                    resource_types=rule_data["resource_types"],
                    check_function=rule_data["check_function"],
                    fix_function=rule_data.get("fix_function"),
                    enabled=rule_data.get("enabled", True),
                    tags=rule_data.get("tags", []),
                    references=rule_data.get("references", [])
                )
                self.register_rule(rule)
            
            self.logger.info(f"Loaded {len(data.get("rules", []))} rules from {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to load rules from {file_path}: {str(e)}")
    
    def get_rules_by_framework(self, framework: Framework) -> List[ComplianceRule]:
        """Get all rules for a specific framework"""
        return [rule for rule in self.rules.values() if rule.framework == framework and rule.enabled]
    
    def get_rules_by_resource_type(self, resource_type: str) -> List[ComplianceRule]:
        """Get all rules applicable to a resource type"""
        return [rule for rule in self.rules.values() 
                if resource_type in rule.resource_types and rule.enabled]
    
    def get_rules_by_severity(self, severity: Severity) -> List[ComplianceRule]:
        """Get all rules of a specific severity"""
        return [rule for rule in self.rules.values() if rule.severity == severity and rule.enabled]
    
    def check_resource(self, resource_type: str, resource_data: Dict[str, Any], 
                      config: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Check a resource against applicable rules
        """
        
        if config is None:
            config = {}
        
        violations = []
        applicable_rules = self.get_rules_by_resource_type(resource_type)
        
        for rule in applicable_rules:
            try:
                checker = self.checkers.get(rule.rule_id)
                if checker and checker.check(resource_data, config):
                    violation_details = checker.get_violation_details(resource_data)
                    violations.append({
                        "rule_id": rule.rule_id,
                        "rule_name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity.value,
                        "framework": rule.framework.value,
                        "resource_type": resource_type,
                        "tags": rule.tags,
                        "references": rule.references,
                        "violation_details": violation_details
                    })
            except Exception as e:
                self.logger.error(f"Error checking rule {rule.rule_id}: {str(e)}")
        
        return violations
    
    def fix_violations(self, violations: List[Dict[str, Any]], 
                      resource_data: Dict[str, Any], config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Fix violations and return the fixed resource data
        """
        
        if config is None:
            config = {}
        
        fixed_data = resource_data.copy()
        fixes_applied = []
        
        for violation in violations:
            rule_id = violation["rule_id"]
            fixer = self.fixers.get(rule_id)
            
            if fixer:
                try:
                    fixed_data = fixer.fix(fixed_data, config)
                    fixes_applied.append({
                        "rule_id": rule_id,
                        "description": fixer.get_fix_description(),
                        "severity": violation["severity"]
                    })
                except Exception as e:
                    self.logger.error(f"Error fixing violation {rule_id}: {str(e)}")
        
        return {
            "fixed_data": fixed_data,
            "fixes_applied": fixes_applied
        }
    
    def get_compliance_summary(self, framework: Framework = None) -> Dict[str, Any]:
        """
        Get compliance summary statistics
        """
        
        rules_to_check = self.rules.values()
        if framework:
            rules_to_check = self.get_rules_by_framework(framework)
        
        summary = {
            "total_rules": len(list(rules_to_check)),
            "enabled_rules": len([r for r in rules_to_check if r.enabled]),
            "by_severity": {
                "CRITICAL": len([r for r in rules_to_check if r.severity == Severity.CRITICAL]),
                "HIGH": len([r for r in rules_to_check if r.severity == Severity.HIGH]),
                "MEDIUM": len([r for r in rules_to_check if r.severity == Severity.MEDIUM]),
                "LOW": len([r for r in rules_to_check if r.severity == Severity.LOW]),
                "INFO": len([r for r in rules_to_check if r.severity == Severity.INFO])
            },
            "by_framework": {}
        }
        
        for fw in Framework:
            fw_rules = [r for r in rules_to_check if r.framework == fw]
            summary["by_framework"][fw.value] = len(fw_rules)
        
        return summary
    
    def export_rules(self, file_path: str, format: str = "yaml"):
        """
        Export rules to file
        """
        
        rules_data = {
            "rules": []
        }
        
        for rule in self.rules.values():
            rule_dict = {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity.value,
                "framework": rule.framework.value,
                "resource_types": rule.resource_types,
                "check_function": rule.check_function,
                "fix_function": rule.fix_function,
                "enabled": rule.enabled,
                "tags": rule.tags,
                "references": rule.references
            }
            rules_data["rules"].append(rule_dict)
        
        try:
            with open(file_path, "w") as f:
                if format.lower() == "yaml":
                    yaml.dump(rules_data, f, default_flow_style=False)
                else:
                    json.dump(rules_data, f, indent=2)
            
            self.logger.info(f"Exported {len(self.rules)} rules to {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to export rules: {str(e)}")
    
    def _register_built_in_checkers(self):
        """
        Register built-in rule checkers
        """
        
        # S3 checkers would be implemented here
        # For brevity, showing structure only
        pass
    
    def _register_built_in_fixers(self):
        """
        Register built-in rule fixers
        """
        
        # S3 fixers would be implemented here
        # For brevity, showing structure only
        pass


