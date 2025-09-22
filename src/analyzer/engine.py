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
Configuration analysis engine for compliance checking
"""

import logging
from typing import Dict, Any, List, Optional
from rules.aws_cis import AWSCISRules
from rules.nist import NISTRules

logger = logging.getLogger(__name__)

class AnalyzerEngine:
    """Main engine for analyzing configurations against compliance rules"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Initialize rule engines
        self.aws_cis = AWSCISRules()
        self.nist = NISTRules()
        
        # Map rule prefixes to engines
        self.rule_engines = {
            "cis": self.aws_cis,
            "nist": self.nist
        }
    
    def analyze(self, parsed_config: Dict[str, Any], config_type: str, rules: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Analyze parsed configuration against compliance rules
        
        Args:
            parsed_config: Parsed configuration data
            config_type: Type of configuration (terraform, kubernetes, json)
            rules: Optional list of specific rules to check (defaults to all)
            
        Returns:
            Dict containing analysis results
        """
        self.logger.info(f"Starting analysis for {config_type} configuration")
        
        # Get rules to check
        if rules is None:
            rules = self.get_available_rules()
        
        violations = []
        rule_results = {}
        
        # Check each rule
        for rule_id in rules:
            try:
                rule_violations = self._check_rule(rule_id, parsed_config, config_type)
                violations.extend(rule_violations)
                rule_results[rule_id] = {
                    "violations_count": len(rule_violations),
                    "status": "FAIL" if rule_violations else "PASS"
                }
                
                self.logger.debug(f"Rule {rule_id}: {len(rule_violations)} violations")
                
            except Exception as e:
                self.logger.error(f"Error checking rule {rule_id}: {str(e)}")
                rule_results[rule_id] = {
                    "violations_count": 0,
                    "status": "ERROR",
                    "error": str(e)
                }
        
        # Calculate summary statistics
        total_rules = len(rules)
        passed_rules = sum(1 for result in rule_results.values() if result["status"] == "PASS")
        failed_rules = sum(1 for result in rule_results.values() if result["status"] == "FAIL")
        error_rules = sum(1 for result in rule_results.values() if result["status"] == "ERROR")
        
        # Categorize violations by severity
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for violation in violations:
            severity = violation.get("severity", "MEDIUM")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        result = {
            "config_type": config_type,
            "analysis_timestamp": self._get_timestamp(),
            "summary": {
                "total_rules_checked": total_rules,
                "rules_passed": passed_rules,
                "rules_failed": failed_rules,
                "rules_error": error_rules,
                "total_violations": len(violations),
                "severity_breakdown": severity_counts,
                "compliance_score": round((passed_rules / total_rules) * 100, 2) if total_rules > 0 else 0
            },
            "rule_results": rule_results,
            "violations": violations,
            "recommendations": self._generate_recommendations(violations)
        }
        
        self.logger.info(f"Analysis completed: {len(violations)} violations found, {result["summary"]["compliance_score"]}% compliance")
        
        return result
    
    def _check_rule(self, rule_id: str, parsed_config: Dict[str, Any], config_type: str) -> List[Dict[str, Any]]:
        """
        Check a specific rule against the configuration
        """
        
        # Determine which rule engine to use based on rule prefix
        rule_prefix = rule_id.split("_")[0]
        
        if rule_prefix in self.rule_engines:
            engine = self.rule_engines[rule_prefix]
            return engine.check_rule(rule_id, parsed_config)
        else:
            self.logger.warning(f"No engine found for rule prefix: {rule_prefix}")
            return []
    
    def get_available_rules(self) -> List[str]:
        """
        Get list of all available rules
        """
        all_rules = []
        
        # Collect rules from all engines
        for engine in self.rule_engines.values():
            all_rules.extend(engine.get_available_rules())
        
        return sorted(all_rules)
    
    def get_rules_by_framework(self, framework: str) -> List[str]:
        """
        Get rules for a specific compliance framework
        
        Args:
            framework: Framework name (cis, nist)
            
        Returns:
            List of rule IDs for the framework
        """
        if framework.lower() in self.rule_engines:
            return self.rule_engines[framework.lower()].get_available_rules()
        else:
            return []
    
    def _generate_recommendations(self, violations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate high-level recommendations based on violations
        """
        recommendations = []
        
        # Count violations by type
        violation_types = {}
        for violation in violations:
            resource_type = violation.get("resource_type", "unknown")
            if resource_type not in violation_types:
                violation_types[resource_type] = []
            violation_types[resource_type].append(violation)
        
        # Generate recommendations for common issues
        if "aws_s3_bucket" in violation_types:
            s3_violations = violation_types["aws_s3_bucket"]
            recommendations.append({
                "category": "S3 Security",
                "priority": "HIGH",
                "description": f"Found {len(s3_violations)} S3 security issues",
                "action": "Review S3 bucket configurations for public access, encryption, and access policies",
                "affected_resources": len(s3_violations)
            })
        
        if "aws_security_group" in violation_types:
            sg_violations = violation_types["aws_security_group"]
            recommendations.append({
                "category": "Network Security",
                "priority": "HIGH",
                "description": f"Found {len(sg_violations)} security group issues",
                "action": "Restrict security group rules to follow principle of least privilege",
                "affected_resources": len(sg_violations)
            })
        
        if "aws_iam_policy" in violation_types:
            iam_violations = violation_types["aws_iam_policy"]
            recommendations.append({
                "category": "Access Management",
                "priority": "CRITICAL",
                "description": f"Found {len(iam_violations)} IAM policy issues",
                "action": "Review IAM policies and apply principle of least privilege",
                "affected_resources": len(iam_violations)
            })
        
        # Add general recommendations based on severity
        critical_count = sum(1 for v in violations if v.get("severity") == "CRITICAL")
        high_count = sum(1 for v in violations if v.get("severity") == "HIGH")
        
        if critical_count > 0:
            recommendations.append({
                "category": "Critical Issues",
                "priority": "CRITICAL",
                "description": f"Found {critical_count} critical security issues",
                "action": "Address critical issues immediately as they pose significant security risks",
                "affected_resources": critical_count
            })
        
        if high_count > 0:
            recommendations.append({
                "category": "High Priority Issues",
                "priority": "HIGH",
                "description": f"Found {high_count} high priority security issues",
                "action": "Address high priority issues in the next maintenance window",
                "affected_resources": high_count
            })
        
        return recommendations
    
    def _get_timestamp(self) -> str:
        """
        Get current timestamp in ISO format
        """
        from datetime import datetime
        return datetime.utcnow().isoformat() + "Z"
    
    def validate_configuration(self, parsed_config: Dict[str, Any], config_type: str) -> Dict[str, Any]:
        """
        Validate configuration structure and content
        
        Args:
            parsed_config: Parsed configuration data
            config_type: Type of configuration
            
        Returns:
            Dict containing validation results
        """
        validation_results = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "info": []
        }
        
        # Basic structure validation
        if not isinstance(parsed_config, dict):
            validation_results["valid"] = False
            validation_results["errors"].append("Configuration must be a dictionary")
            return validation_results
        
        # Configuration type specific validation
        if config_type == "terraform":
            if "resources" not in parsed_config:
                validation_results["warnings"].append("No resources found in Terraform configuration")
            else:
                resource_count = len(parsed_config["resources"])
                validation_results["info"].append(f"Found {resource_count} resources in configuration")
        
        elif config_type == "kubernetes":
            if "resources" not in parsed_config:
                validation_results["warnings"].append("No resources found in Kubernetes configuration")
            else:
                resource_count = len(parsed_config["resources"])
                validation_results["info"].append(f"Found {resource_count} Kubernetes resources")
        
        elif config_type == "json":
            config_subtype = parsed_config.get("type", "unknown")
            validation_results["info"].append(f"Detected JSON configuration type: {config_subtype}")
        
        return validation_results


