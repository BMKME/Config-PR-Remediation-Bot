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
Multi-file scanner for repository-wide compliance analysis
Supports scanning all Terraform files in a repository
"""

import logging
import os
import glob
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import concurrent.futures
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Data class for scan results"""
    file_path: str
    violations: List[Dict[str, Any]]
    fixes: List[Dict[str, Any]]
    scan_time: float
    file_size: int
    success: bool
    error: Optional[str] = None

class MultiFileScanner:
    """Scanner for multiple configuration files in a repository"""
    
    def __init__(self, analyzer_engine, remediator):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.analyzer = analyzer_engine
        self.remediator = remediator
        
        # Supported file patterns
        self.file_patterns = {
            "terraform": ["*.tf", "*.tfvars"],
            "kubernetes": ["*.yaml", "*.yml"],
            "json": ["*.json"],
            "docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]
        }
    
    def scan_repository(self, repo_path: str, config_types: List[str] = None, 
                       exclude_patterns: List[str] = None, 
                       max_workers: int = 4) -> Dict[str, Any]:
        """
        Scan entire repository for compliance issues
        
        Args:
            repo_path: Path to repository root
            config_types: List of config types to scan (default: all)
            exclude_patterns: Patterns to exclude from scanning
            max_workers: Maximum number of worker threads
            
        Returns:
            Dict containing scan results
        """
        
        if config_types is None:
            config_types = list(self.file_patterns.keys())
        
        if exclude_patterns is None:
            exclude_patterns = [
                ".git/*",
                "node_modules/*",
                ".terraform/*",
                "*.tfstate*",
                ".vscode/*",
                ".idea/*"
            ]
        
        self.logger.info(f"Starting repository scan: {repo_path}")
        
        # Find all files to scan
        files_to_scan = self._find_files_to_scan(repo_path, config_types, exclude_patterns)
        
        if not files_to_scan:
            return {
                "success": True,
                "files_scanned": 0,
                "total_violations": 0,
                "results": [],
                "summary": {
                    "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                    "by_file_type": {},
                    "scan_time": 0
                }
            }
        
        self.logger.info(f"Found {len(files_to_scan)} files to scan")
        
        # Scan files in parallel
        scan_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(self._scan_single_file, file_info): file_info 
                for file_info in files_to_scan
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_info = future_to_file[future]
                try:
                    result = future.result()
                    scan_results.append(result)
                except Exception as e:
                    self.logger.error(f"Error scanning {file_info["path"]}: {str(e)}")
                    scan_results.append(ScanResult(
                        file_path=file_info["path"],
                        violations=[],
                        fixes=[],
                        scan_time=0,
                        file_size=file_info["size"],
                        success=False,
                        error=str(e)
                    ))
        
        # Generate summary
        summary = self._generate_scan_summary(scan_results)
        
        return {
            "success": True,
            "files_scanned": len(scan_results),
            "total_violations": summary["total_violations"],
            "results": [self._result_to_dict(r) for r in scan_results],
            "summary": summary
        }
    
    def scan_directory(self, directory_path: str, recursive: bool = True, 
                      config_type: str = "terraform") -> Dict[str, Any]:
        """
        Scan a specific directory for configuration files
        
        Args:
            directory_path: Path to directory
            recursive: Whether to scan subdirectories
            config_type: Type of configuration files to scan
            
        Returns:
            Dict containing scan results
        """
        
        if not os.path.exists(directory_path):
            return {
                "success": False,
                "error": f"Directory not found: {directory_path}",
                "results": []
            }
        
        # Find files in directory
        files_to_scan = []
        patterns = self.file_patterns.get(config_type, ["*"])
        
        for pattern in patterns:
            if recursive:
                search_pattern = os.path.join(directory_path, "**", pattern)
                files = glob.glob(search_pattern, recursive=True)
            else:
                search_pattern = os.path.join(directory_path, pattern)
                files = glob.glob(search_pattern)
            
            for file_path in files:
                if os.path.isfile(file_path):
                    files_to_scan.append({
                        "path": file_path,
                        "type": config_type,
                        "size": os.path.getsize(file_path)
                    })
        
        # Scan files
        scan_results = []
        for file_info in files_to_scan:
            result = self._scan_single_file(file_info)
            scan_results.append(result)
        
        # Generate summary
        summary = self._generate_scan_summary(scan_results)
        
        return {
            "success": True,
            "directory": directory_path,
            "files_scanned": len(scan_results),
            "total_violations": summary["total_violations"],
            "results": [self._result_to_dict(r) for r in scan_results],
            "summary": summary
        }
    
    def _find_files_to_scan(self, repo_path: str, config_types: List[str], 
                           exclude_patterns: List[str]) -> List[Dict[str, Any]]:
        """
        Find all files to scan in repository
        """
        
        files_to_scan = []
        
        for config_type in config_types:
            patterns = self.file_patterns.get(config_type, [])
            
            for pattern in patterns:
                search_pattern = os.path.join(repo_path, "**", pattern)
                files = glob.glob(search_pattern, recursive=True)
                
                for file_path in files:
                    if os.path.isfile(file_path):
                        # Check if file should be excluded
                        relative_path = os.path.relpath(file_path, repo_path)
                        
                        should_exclude = False
                        for exclude_pattern in exclude_patterns:
                            if self._matches_pattern(relative_path, exclude_pattern):
                                should_exclude = True
                                break
                        
                        if not should_exclude:
                            files_to_scan.append({
                                "path": file_path,
                                "relative_path": relative_path,
                                "type": config_type,
                                "size": os.path.getsize(file_path)
                            })
        
        return files_to_scan
    
    def _matches_pattern(self, file_path: str, pattern: str) -> bool:
        """
        Check if file path matches exclusion pattern
        """
        
        import fnmatch
        return fnmatch.fnmatch(file_path, pattern)
    
    def _scan_single_file(self, file_info: Dict[str, Any]) -> ScanResult:
        """
        Scan a single file for compliance issues
        """
        
        import time
        start_time = time.time()
        
        file_path = file_info["path"]
        config_type = file_info["type"]
        
        try:
            # Read file content
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Skip empty files
            if not content.strip():
                return ScanResult(
                    file_path=file_path,
                    violations=[],
                    fixes=[],
                    scan_time=time.time() - start_time,
                    file_size=file_info["size"],
                    success=True
                )
            
            # Analyze content
            analysis_result = self.analyzer.analyze_content(content, config_type)
            
            violations = analysis_result.get("violations", [])
            
            # Generate fixes if violations found
            fixes = []
            if violations:
                remediation_result = self.remediator.generate_fixes(violations, config_type)
                fixes = remediation_result.get("fixes", [])
            
            return ScanResult(
                file_path=file_path,
                violations=violations,
                fixes=fixes,
                scan_time=time.time() - start_time,
                file_size=file_info["size"],
                success=True
            )
            
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {str(e)}")
            return ScanResult(
                file_path=file_path,
                violations=[],
                fixes=[],
                scan_time=time.time() - start_time,
                file_size=file_info["size"],
                success=False,
                error=str(e)
            )
    
    def _generate_scan_summary(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """
        Generate summary of scan results
        """
        
        total_violations = sum(len(r.violations) for r in scan_results)
        total_fixes = sum(len(r.fixes) for r in scan_results)
        total_scan_time = sum(r.scan_time for r in scan_results)
        successful_scans = sum(1 for r in scan_results if r.success)
        
        # Count by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for result in scan_results:
            for violation in result.violations:
                severity = violation.get("severity", "MEDIUM")
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        # Count by file type
        file_type_counts = {}
        for result in scan_results:
            file_ext = Path(result.file_path).suffix.lower()
            if file_ext not in file_type_counts:
                file_type_counts[file_ext] = {
                    "files": 0,
                    "violations": 0,
                    "fixes": 0
                }
            file_type_counts[file_ext]["files"] += 1
            file_type_counts[file_ext]["violations"] += len(result.violations)
            file_type_counts[file_ext]["fixes"] += len(result.fixes)
        
        # Top violations by rule
        rule_violations = {}
        for result in scan_results:
            for violation in result.violations:
                rule_id = violation.get("rule_id", "unknown")
                if rule_id not in rule_violations:
                    rule_violations[rule_id] = {
                        "count": 0,
                        "rule_name": violation.get("rule_name", "Unknown"),
                        "severity": violation.get("severity", "MEDIUM")
                    }
                rule_violations[rule_id]["count"] += 1
        
        # Sort by count
        top_violations = sorted(
            rule_violations.items(),
            key=lambda x: x[1]["count"],
            reverse=True
        )[:10]
        
        return {
            "total_violations": total_violations,
            "total_fixes": total_fixes,
            "total_scan_time": round(total_scan_time, 2),
            "successful_scans": successful_scans,
            "failed_scans": len(scan_results) - successful_scans,
            "by_severity": severity_counts,
            "by_file_type": file_type_counts,
            "top_violations": [
                {
                    "rule_id": rule_id,
                    "rule_name": data["rule_name"],
                    "count": data["count"],
                    "severity": data["severity"]
                }
                for rule_id, data in top_violations
            ],
            "compliance_score": self._calculate_compliance_score(scan_results)
        }
    
    def _calculate_compliance_score(self, scan_results: List[ScanResult]) -> float:
        """
        Calculate overall compliance score
        """
        
        if not scan_results:
            return 100.0
        
        total_files = len(scan_results)
        files_with_violations = sum(1 for r in scan_results if r.violations)
        
        if total_files == 0:
            return 100.0
        
        compliance_score = ((total_files - files_with_violations) / total_files) * 100
        return round(compliance_score, 2)
    
    def _result_to_dict(self, result: ScanResult) -> Dict[str, Any]:
        """
        Convert ScanResult to dictionary
        """
        
        return {
            "file_path": result.file_path,
            "violations": result.violations,
            "fixes": result.fixes,
            "scan_time": result.scan_time,
            "file_size": result.file_size,
            "success": result.success,
            "error": result.error,
            "violation_count": len(result.violations),
            "fix_count": len(result.fixes)
        }
    
    def generate_scan_report(self, scan_results: Dict[str, Any], 
                           output_path: str, format: str = "json") -> bool:
        """
        Generate scan report in specified format
        """
        
        try:
            if format.lower() == "json":
                import json
                with open(output_path, "w") as f:
                    json.dump(scan_results, f, indent=2)
            
            elif format.lower() == "yaml":
                import yaml
                with open(output_path, "w") as f:
                    yaml.dump(scan_results, f, default_flow_style=False)
            
            elif format.lower() == "html":
                self._generate_html_report(scan_results, output_path)
            
            elif format.lower() == "csv":
                self._generate_csv_report(scan_results, output_path)
            
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            self.logger.info(f"Scan report generated: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate report: {str(e)}")
            return False
    
    def _generate_html_report(self, scan_results: Dict[str, Any], output_path: str):
        """
        Generate HTML report
        """
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Compliance Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; }
                .violation { background: #ffe6e6; padding: 10px; margin: 5px 0; border-radius: 3px; }
                .fix { background: #e6ffe6; padding: 10px; margin: 5px 0; border-radius: 3px; }
                .severity-critical { border-left: 5px solid #d32f2f; }
                .severity-high { border-left: 5px solid #ff9800; }
                .severity-medium { border-left: 5px solid #ffeb3b; }
                .severity-low { border-left: 5px solid #2196f3; }
                .severity-info { border-left: 5px solid #9e9e9e; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>Compliance Scan Report</h1>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Total Files Scanned:</strong> {{ total_files_scanned }}</p>
                <p><strong>Total Violations:</strong> {{ total_violations }}</p>
                <p><strong>Total Fixes Generated:</strong> {{ total_fixes }}</p>
                <p><strong>Compliance Score:</strong> {{ compliance_score }}%</p>
                
                <h3>Violations by Severity:</h3>
                <ul>
                    <li>Critical: {{ severity_critical }}</li>
                    <li>High: {{ severity_high }}</li>
                    <li>Medium: {{ severity_medium }}</li>
                    <li>Low: {{ severity_low }}</li>
                    <li>Info: {{ severity_info }}</li>
                </ul>
            </div>
            
            <h2>Detailed Results</h2>
            {% for result in results %}
                <h3>File: {{ result.file_path }} ({{ result.file_size }} bytes)</h3>
                {% if result.success %}
                    <p style="color: green;">Scan Successful ({{ result.scan_time }} seconds)</p>
                    {% if result.violations %}
                        <h4>Violations:</h4>
                        {% for violation in result.violations %}
                            <div class="violation severity-{{ violation.severity | lower }}">
                                <strong>Rule ID:</strong> {{ violation.rule_id }}<br>
                                <strong>Severity:</strong> {{ violation.severity }}<br>
                                <strong>Description:</strong> {{ violation.description }}<br>
                                <strong>Remediation:</strong> {{ violation.remediation }}<br>
                                <strong>Config Path:</strong> {{ violation.config_path }}
                            </div>
                        {% endfor %}
                    {% else %}
                        <p>No violations found.</p>
                    {% endif %}
                    
                    {% if result.fixes %}
                        <h4>Fixes Generated:</h4>
                        {% for fix in result.fixes %}
                            <div class="fix">
                                <strong>Rule ID:</strong> {{ fix.rule_id }}<br>
                                <strong>Description:</strong> {{ fix.description }}
                            </div>
                        {% endfor %}
                    {% endif %}
                {% else %}
                    <p style="color: red;">Scan Failed: {{ result.error }}</p>
                {% endif %}
                <hr>
            {% endfor %}
        </body>
        </html>
        """
        
        # Simple templating for now
        html_content = html_template
        
        summary = scan_results["summary"]
        html_content = html_content.replace("{{ total_files_scanned }}", str(scan_results["files_scanned"]))
        html_content = html_content.replace("{{ total_violations }}", str(summary["total_violations"]))
        html_content = html_content.replace("{{ total_fixes }}", str(summary["total_fixes"]))
        html_content = html_content.replace("{{ compliance_score }}", str(summary["compliance_score"]))
        html_content = html_content.replace("{{ severity_critical }}", str(summary["by_severity"]["CRITICAL"]))
        html_content = html_content.replace("{{ severity_high }}", str(summary["by_severity"]["HIGH"]))
        html_content = html_content.replace("{{ severity_medium }}", str(summary["by_severity"]["MEDIUM"]))
        html_content = html_content.replace("{{ severity_low }}", str(summary["by_severity"]["LOW"]))
        html_content = html_content.replace("{{ severity_info }}", str(summary["by_severity"]["INFO"]))
        
        detailed_results_html = []
        for result in scan_results["results"]:
            file_html = f"""
                <h3>File: {result["file_path"]} ({result["file_size"]} bytes)</h3>
                """
            if result["success"]:
                file_html += f"<p style=\"color: green;\">Scan Successful ({result["scan_time"]} seconds)</p>\n"
                if result["violations"]:
                    file_html += "<h4>Violations:</h4>\n"
                    for violation in result["violations"]:
                        file_html += f"""
                            <div class="violation severity-{violation["severity"].lower()}">
                                <strong>Rule ID:</strong> {violation["rule_id"]}<br>
                                <strong>Severity:</strong> {violation["severity"]}<br>
                                <strong>Description:</strong> {violation["description"]}<br>
                                <strong>Remediation:</strong> {violation["remediation"]}<br>
                                <strong>Config Path:</strong> {violation["config_path"]}
                            </div>
                            """
                else:
                    file_html += "<p>No violations found.</p>\n"
                
                if result["fixes"]:
                    file_html += "<h4>Fixes Generated:</h4>\n"
                    for fix in result["fixes"]:
                        file_html += f"""
                            <div class="fix">
                                <strong>Rule ID:</strong> {fix["rule_id"]}<br>
                                <strong>Description:</strong> {fix["description"]}
                            </div>
                            """
            else:
                file_html += f"<p style=\"color: red;\">Scan Failed: {result["error"]}</p>\n"
            file_html += "<hr>\n"
            detailed_results_html.append(file_html)
            
        html_content = html_content.replace("{% for result in results %}", "".join(detailed_results_html))
        html_content = html_content.replace("{% endfor %}", "")
        
        with open(output_path, "w") as f:
            f.write(html_content)
    
    def _generate_csv_report(self, scan_results: Dict[str, Any], output_path: str):
        """
        Generate CSV report
        """
        
        import csv
        
        headers = [
            "File Path", "Success", "Error", "Violation Count", "Fix Count",
            "Rule ID", "Rule Name", "Severity", "Description", "Remediation", "Config Path"
        ]
        
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for result in scan_results["results"]:
                if result["violations"]:
                    for violation in result["violations"]:
                        writer.writerow([
                            result["file_path"],
                            result["success"],
                            result["error"],
                            result["violation_count"],
                            result["fix_count"],
                            violation["rule_id"],
                            violation["rule_name"],
                            violation["severity"],
                            violation["description"],
                            violation["remediation"],
                            violation["config_path"]
                        ])
                else:
                    writer.writerow([
                        result["file_path"],
                        result["success"],
                        result["error"],
                        result["violation_count"],
                        result["fix_count"],
                        "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"
                    ])



