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
GitLab Merge Request Bot for creating remediation MRs
"""

import logging
import os
from typing import Dict, Any, List, Optional
import gitlab
from datetime import datetime

logger = logging.getLogger(__name__)

class GitLabPRBot:
    """GitLab integration for creating merge requests with remediation code"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.gitlab_token = os.getenv("GITLAB_TOKEN")
        self.gitlab_url = os.getenv("GITLAB_URL", "https://gitlab.com")
        self.gitlab = None
        
        if self.gitlab_token:
            try:
                self.gitlab = gitlab.Gitlab(self.gitlab_url, private_token=self.gitlab_token)
                self.gitlab.auth()
                self.logger.info("GitLab client initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize GitLab client: {str(e)}")
        else:
            self.logger.warning("GITLAB_TOKEN not found in environment variables")
    
    def create_pr(self, repository: str, branch: str, title: str, description: str, 
                  fixes: List[Dict[str, Any]], files: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Create a merge request with remediation fixes
        
        Args:
            repository: Repository name or ID
            branch: Branch name for the MR
            title: MR title
            description: MR description
            fixes: List of fix dictionaries
            files: List of file changes
            
        Returns:
            Dict containing MR creation results
        """
        if not self.gitlab:
            return {
                "success": False,
                "error": "GitLab client not initialized. Check GITLAB_TOKEN.",
                "pr_url": None
            }
        
        try:
            self.logger.info(f"Creating MR for repository {repository}")
            
            # Get project
            project = self.gitlab.projects.get(repository)
            
            # Get default branch
            default_branch = project.default_branch
            
            # Create new branch from default branch
            project.branches.create({
                "branch": branch,
                "ref": default_branch
            })
            
            # Apply file changes
            for file_change in files:
                file_path = file_change["path"]
                file_content = file_change["content"]
                
                try:
                    # Try to get existing file
                    existing_file = project.files.get(file_path=file_path, ref=branch)
                    
                    # Update existing file
                    existing_file.content = file_content
                    existing_file.save(branch=branch, commit_message=f"Update {file_path} with compliance fixes")
                    
                except gitlab.exceptions.GitlabGetError:
                    # File doesn't exist, create new file
                    project.files.create({
                        "file_path": file_path,
                        "branch": branch,
                        "content": file_content,
                        "commit_message": f"Add {file_path} with compliance fixes"
                    })
            
            # Generate MR description with fix details
            mr_description = self._generate_mr_description(description, fixes)
            
            # Create merge request
            mr = project.mergerequests.create({
                "source_branch": branch,
                "target_branch": default_branch,
                "title": title,
                "description": mr_description
            })
            
            # Add labels
            self._add_mr_labels(mr, fixes)
            
            result = {
                "success": True,
                "mr_iid": mr.iid,
                "pr_url": mr.web_url,
                "branch": branch,
                "fixes_applied": len(fixes),
                "files_changed": len(files)
            }
            
            self.logger.info(f"Successfully created MR !{mr.iid}: {mr.web_url}")
            return result
            
        except gitlab.exceptions.GitlabError as e:
            self.logger.error(f"GitLab API error: {str(e)}")
            return {
                "success": False,
                "error": f"GitLab API error: {str(e)}",
                "pr_url": None
            }
        except Exception as e:
            self.logger.error(f"Unexpected error creating MR: {str(e)}")
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "pr_url": None
            }
    
    def _generate_mr_description(self, description: str, fixes: List[Dict[str, Any]]) -> str:
        """
        Generate detailed MR description with fix information
        """
        
        description_parts = [
            "## Compliance Remediation",
            "",
            description,
            "",
            "## Summary of Changes",
            ""
        ]
        
        # Group fixes by severity
        severity_groups = {}
        for fix in fixes:
            # Extract severity from rule_id or default to MEDIUM
            severity = "MEDIUM"  # Default
            if "rule_id" in fix:
                # You could map rule_ids to severities here
                pass
            
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(fix)
        
        # Add fixes by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if severity in severity_groups:
                description_parts.append(f"### {severity} Priority Fixes ({len(severity_groups[severity])})")
                description_parts.append("")
                
                for fix in severity_groups[severity]:
                    description_parts.append(f"- **{fix.get("rule_id", "Unknown")}": {fix.get("description", "No description")}")
                    if fix.get("explanation"):
                        description_parts.append(f"  - {fix["explanation"]}")
                
                description_parts.append("")
        
        # Add statistics
        description_parts.extend([
            "## Fix Statistics",
            "",
            f"- Total fixes applied: {len(fixes)}",
            f"- Resources modified: {len(set(fix.get("resource_name", "unknown") for fix in fixes))}",
            f"- Fix types: {len(set(fix.get("fix_type", "unknown") for fix in fixes))}",
            "",
            "## Testing Instructions",
            "",
            "1. Review all changes carefully",
            "2. Run `terraform plan` to preview infrastructure changes",
            "3. Test in a development environment first",
            "4. Run compliance checks to verify fixes",
            "",
            "## Compliance Frameworks",
            "",
            "This MR addresses violations from:",
            "- CIS Benchmarks",
            "- NIST Cybersecurity Framework",
            "",
            "---",
            f"*Generated by Config-to-PR Remediation Bot on {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC*"
        ])
        
        return "\n".join(description_parts)
    
    def _add_mr_labels(self, mr, fixes: List[Dict[str, Any]]):
        """
        Add appropriate labels to the MR
        """
        
        labels = ["compliance", "security", "automated-fix"]
        
        # Add severity-based labels
        has_critical = any("critical" in fix.get("rule_id", "").lower() for fix in fixes)
        has_high = any("high" in fix.get("rule_id", "").lower() for fix in fixes)
        
        if has_critical:
            labels.append("critical")
        elif has_high:
            labels.append("high-priority")
        else:
            labels.append("medium-priority")
        
        # Add framework labels
        has_cis = any(fix.get("rule_id", "").startswith("cis_") for fix in fixes)
        has_nist = any(fix.get("rule_id", "").startswith("nist_") for fix in fixes)
        
        if has_cis:
            labels.append("cis-benchmark")
        if has_nist:
            labels.append("nist-framework")
        
        try:
            # Update MR with labels
            mr.labels = labels
            mr.save()
            
        except Exception as e:
            self.logger.error(f"Error adding labels: {str(e)}")
    
    def get_project_info(self, repository: str) -> Dict[str, Any]:
        """
        Get information about a project
        """
        
        if not self.gitlab:
            return {"error": "GitLab client not initialized"}
        
        try:
            project = self.gitlab.projects.get(repository)
            
            return {
                "name": project.name,
                "path_with_namespace": project.path_with_namespace,
                "default_branch": project.default_branch,
                "visibility": project.visibility,
                "issues_enabled": project.issues_enabled,
                "merge_requests_enabled": project.merge_requests_enabled,
                "wiki_enabled": project.wiki_enabled,
                "open_issues_count": project.open_issues_count,
                "forks_count": project.forks_count,
                "star_count": project.star_count
            }
            
        except gitlab.exceptions.GitlabError as e:
            return {"error": f"GitLab API error: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}
    
    def list_branches(self, repository: str) -> List[str]:
        """
        List all branches in a project
        """
        
        if not self.gitlab:
            return []
        
        try:
            project = self.gitlab.projects.get(repository)
            branches = [branch.name for branch in project.branches.list()]
            return branches
            
        except Exception as e:
            self.logger.error(f"Error listing branches: {str(e)}")
            return []


