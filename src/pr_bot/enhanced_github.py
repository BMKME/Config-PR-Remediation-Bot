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
Enhanced GitHub PR Bot with improved security, error handling, and features
"""

import logging
import os
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
from github import Github, GithubException
import json

logger = logging.getLogger(__name__)

class EnhancedGitHubPRBot:
    """Enhanced GitHub integration with improved security and features"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.github = None
        self.audit_log = []
        
        if self.github_token:
            try:
                self.github = Github(self.github_token)
                self.logger.info("Enhanced GitHub client initialized successfully")
                self._log_action("github_client_initialized", {"timestamp": datetime.utcnow().isoformat()})
            except Exception as e:
                self.logger.error(f"Failed to initialize GitHub client: {str(e)}")
                self._log_action("github_client_init_failed", {"error": str(e)})
        else:
            self.logger.warning("GITHUB_TOKEN not found in environment variables")
    
    def create_pr_with_improvements(self, repository: str, title: str, description: str, 
                                  fixes: List[Dict[str, Any]], files: List[Dict[str, str]],
                                  dry_run: bool = False, notify_webhook: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a pull request with enhanced features
        
        Args:
            repository: Repository name in format "owner/repo"
            title: PR title
            description: PR description
            fixes: List of fix dictionaries
            files: List of file changes
            dry_run: If True, only show what would be done without creating PR
            notify_webhook: Optional webhook URL for notifications
            
        Returns:
            Dict containing PR creation results
        """
        if not self.github:
            return {
                "success": False,
                "error": "GitHub client not initialized. Check GITHUB_TOKEN.",
                "pr_url": None
            }
        
        # Generate unique branch name with timestamp and UUID
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        unique_id = str(uuid.uuid4())[:8]
        branch_name = f"auto-fix-compliance-{timestamp}-{unique_id}"
        
        # Log the action
        self._log_action("pr_creation_started", {
            "repository": repository,
            "branch": branch_name,
            "fixes_count": len(fixes),
            "dry_run": dry_run
        })
        
        if dry_run:
            return self._generate_dry_run_preview(repository, branch_name, title, description, fixes, files)
        
        try:
            self.logger.info(f"Creating PR for repository {repository}")
            
            # Get repository
            repo = self.github.get_repo(repository)
            
            # Check if branch already exists (collision detection)
            try:
                existing_branch = repo.get_branch(branch_name)
                if existing_branch:
                    # Generate new branch name
                    branch_name = f"auto-fix-compliance-{timestamp}-{unique_id}-retry"
                    self.logger.warning(f"Branch collision detected, using new name: {branch_name}")
            except GithubException:
                # Branch doesn't exist, which is what we want
                pass
            
            # Get default branch
            default_branch = repo.default_branch
            
            # Check for idempotency - see if similar PR already exists
            existing_prs = self._check_existing_prs(repo, fixes)
            if existing_prs:
                return {
                    "success": False,
                    "error": f"Similar PR already exists: {existing_prs[0]["html_url"]}",
                    "existing_pr": existing_prs[0],
                    "pr_url": existing_prs[0]["html_url"]
                }
            
            # Create new branch from default branch
            default_branch_ref = repo.get_git_ref(f"heads/{default_branch}")
            new_branch_ref = repo.create_git_ref(
                ref=f"refs/heads/{branch_name}",
                sha=default_branch_ref.object.sha
            )
            
            # Apply file changes with error handling
            files_changed = []
            for file_change in files:
                try:
                    result = self._apply_file_change(repo, file_change, branch_name)
                    if result:
                        files_changed.append(result)
                except Exception as e:
                    self.logger.error(f"Failed to apply change to {file_change["path"]}: {str(e)}")
                    # Continue with other files
            
            if not files_changed:
                return {
                    "success": False,
                    "error": "No files were successfully changed",
                    "pr_url": None
                }
            
            # Generate enhanced PR body
            pr_body = self._generate_enhanced_pr_body(description, fixes, files_changed)
            
            # Create pull request
            pr = repo.create_pull(
                title=title,
                body=pr_body,
                head=branch_name,
                base=default_branch
            )
            
            # Add enhanced labels and metadata
            self._add_enhanced_labels(pr, fixes)
            
            # Add rollback instructions as comment
            self._add_rollback_comment(pr, branch_name)
            
            # Send webhook notification if provided
            if notify_webhook:
                self._send_webhook_notification(notify_webhook, pr, fixes)
            
            result = {
                "success": True,
                "pr_number": pr.number,
                "pr_url": pr.html_url,
                "branch": branch_name,
                "fixes_applied": len(fixes),
                "files_changed": len(files_changed),
                "rollback_instructions": f"To rollback: git revert {pr.merge_commit_sha} (after merge)",
                "audit_trail": self.audit_log[-5:]  # Last 5 audit entries
            }
            
            self.logger.info(f"Successfully created enhanced PR #{pr.number}: {pr.html_url}")
            self._log_action("pr_created_successfully", result)
            
            return result
            
        except GithubException as e:
            error_msg = f"GitHub API error: {str(e)}"
            self.logger.error(error_msg)
            self._log_action("pr_creation_failed", {"error": error_msg})
            return {
                "success": False,
                "error": error_msg,
                "pr_url": None
            }
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            self.logger.error(error_msg)
            self._log_action("pr_creation_failed", {"error": error_msg})
            return {
                "success": False,
                "error": error_msg,
                "pr_url": None
            }
    
    def _generate_dry_run_preview(self, repository: str, branch_name: str, title: str, 
                                description: str, fixes: List[Dict[str, Any]], 
                                files: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Generate a preview of what would be done in dry-run mode
        """
        
        preview = {
            "success": True,
            "dry_run": True,
            "repository": repository,
            "branch_name": branch_name,
            "pr_title": title,
            "pr_description": description,
            "fixes_to_apply": len(fixes),
            "files_to_change": len(files),
            "changes_preview": []
        }
        
        for file_change in files:
            preview["changes_preview"].append({
                "file": file_change["path"],
                "action": "create" if file_change.get("new_file") else "update",
                "size": len(file_change["content"])
            })
        
        self._log_action("dry_run_preview_generated", preview)
        return preview
    
    def _check_existing_prs(self, repo, fixes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Check for existing PRs with similar fixes to avoid duplicates
        """
        
        try:
            # Get open PRs with auto-fix label
            open_prs = repo.get_pulls(state="open")
            
            similar_prs = []
            for pr in open_prs:
                # Check if PR has auto-fix label
                pr_labels = [label.name for label in pr.labels]
                if "auto-fix" in pr_labels or "automated-fix" in pr_labels:
                    # Check if it's addressing similar issues
                    pr_body = pr.body or ""
                    fix_rules = [fix.get("rule_id", "") for fix in fixes]
                    
                    # Simple check if any rule IDs are mentioned in PR body
                    if any(rule_id in pr_body for rule_id in fix_rules if rule_id):
                        similar_prs.append({
                            "number": pr.number,
                            "title": pr.title,
                            "html_url": pr.html_url,
                            "created_at": pr.created_at.isoformat()
                        })
            
            return similar_prs
            
        except Exception as e:
            self.logger.error(f"Error checking existing PRs: {str(e)}")
            return []
    
    def _apply_file_change(self, repo, file_change: Dict[str, str], branch: str) -> Optional[Dict[str, Any]]:
        """
        Apply a single file change with error handling
        """
        
        file_path = file_change["path"]
        file_content = file_change["content"]
        
        try:
            # Try to get existing file
            try:
                existing_file = repo.get_contents(file_path, ref=branch)
                
                # Update existing file
                repo.update_file(
                    path=file_path,
                    message=f"Auto-fix: Update {file_path} with compliance fixes",
                    content=file_content,
                    sha=existing_file.sha,
                    branch=branch
                )
                
                return {
                    "path": file_path,
                    "action": "updated",
                    "size": len(file_content)
                }
                
            except GithubException as e:
                if e.status == 404:
                    # File doesn't exist, create new file
                    repo.create_file(
                        path=file_path,
                        message=f"Auto-fix: Add {file_path} with compliance fixes",
                        content=file_content,
                        branch=branch
                    )
                    
                    return {
                        "path": file_path,
                        "action": "created",
                        "size": len(file_content)
                    }
                else:
                    raise e
                    
        except Exception as e:
            self.logger.error(f"Failed to apply change to {file_path}: {str(e)}")
            return None
    
    def _generate_enhanced_pr_body(self, description: str, fixes: List[Dict[str, Any]], 
                                 files_changed: List[Dict[str, Any]]) -> str:
        """
        Generate enhanced PR body with detailed information
        """
        
        body_parts = [
            "## 🔒 Automated Compliance Remediation",
            "",
            description,
            "",
            "## 📋 Summary of Changes",
            ""
        ]
        
        # Group fixes by severity and type
        severity_groups = {}
        for fix in fixes:
            severity = fix.get("severity", "MEDIUM")
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(fix)
        
        # Add fixes by severity with emojis
        severity_emojis = {
            "CRITICAL": "🚨",
            "HIGH": "⚠️",
            "MEDIUM": "⚡",
            "LOW": "ℹ️"
        }
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if severity in severity_groups:
                emoji = severity_emojis.get(severity, "•")
                body_parts.append(f"### {emoji} {severity} Priority Fixes ({len(severity_groups[severity])})")
                body_parts.append("")
                
                for fix in severity_groups[severity]:
                    rule_id = fix.get("rule_id", "Unknown")
                    description = fix.get("description", "No description")
                    body_parts.append(f"- **{rule_id}**: {description}")
                    if fix.get("explanation"):
                        body_parts.append(f"  - {fix["explanation"]}")
                
                body_parts.append("")
        
        # Add file changes summary
        body_parts.extend([
            "## 📁 Files Modified",
            ""
        ])
        
        for file_info in files_changed:
            action_emoji = "✏️" if file_info["action"] == "updated" else "📄"
            body_parts.append(f"- {action_emoji} `{file_info["path"]}` ({file_info["action"]}, {file_info["size"]} bytes)")
        
        # Add statistics and metadata
        body_parts.extend([
            "",
            "## 📊 Fix Statistics",
            "",
            f"- Total fixes applied: {len(fixes)}",
            f"- Files modified: {len(files_changed)}",
            f"- Fix types: {len(set(fix.get("type", "unknown") for fix in fixes))}",
            f"- Compliance frameworks: {", ".join(set(fix.get("framework", "Unknown") for fix in fixes))}",
            "",
            "## 🧪 Testing Instructions",
            "",
            "1. **Review Changes**: Carefully review all modifications",
            "2. **Validate Syntax**: Run `terraform validate` to check syntax",
            "3. **Plan Changes**: Run `terraform plan` to preview infrastructure changes",
            "4. **Test Environment**: Deploy to development environment first",
            "5. **Compliance Check**: Run compliance scans to verify fixes",
            "",
            "## 🔄 Rollback Instructions",
            "",
            "If issues arise after merging:",
            "1. Create a revert PR: `git revert <merge-commit-sha>`",
            "2. Or manually restore previous configuration",
            "3. Contact the security team for assistance",
            "",
            "## 🏷️ Compliance Frameworks",
            "",
            "This PR addresses violations from:",
            "- CIS Benchmarks",
            "- NIST Cybersecurity Framework",
            "- AWS Security Best Practices",
            "",
            "---",
            f"🤖 *Generated by Enhanced Config-to-PR Remediation Bot*",
            f"📅 *Created: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC*",
            f"🔍 *Audit ID: {str(uuid.uuid4())[:8]}*"
        ])
        
        return "\n".join(body_parts)
    
    def _add_enhanced_labels(self, pr, fixes: List[Dict[str, Any]]):
        """
        Add enhanced labels with better categorization
        """
        
        labels = ["auto-fix", "security", "compliance"]
        
        # Add severity-based label
        has_critical = any(fix.get("severity") == "CRITICAL" for fix in fixes)
        has_high = any(fix.get("severity") == "HIGH" for fix in fixes)
        has_medium = any(fix.get("severity") == "MEDIUM" for fix in fixes)
        has_low = any(fix.get("severity") == "LOW" for fix in fixes)
        
        if has_critical:
            labels.append("severity/critical")
        elif has_high:
            labels.append("severity/high")
        elif has_medium:
            labels.append("severity/medium")
        elif has_low:
            labels.append("severity/low")
        
        # Add framework labels
        frameworks = set(fix.get("framework", "Unknown") for fix in fixes)
        for framework in frameworks:
            labels.append(f"framework/{framework.lower()}")
            
        # Add resource type labels
        resource_types = set(fix.get("resource_type", "Unknown") for fix in fixes)
        for r_type in resource_types:
            labels.append(f"resource/{r_type.lower()}")
            
        try:
            repo = pr.base.repo
            existing_labels = {label.name for label in repo.get_labels()}
            
            for label_name in labels:
                if label_name not in existing_labels:
                    try:
                        color = self._get_label_color(label_name)
                        repo.create_label(name=label_name, color=color)
                        self.logger.info(f"Created label: {label_name}")
                    except GithubException:
                        pass # Label might already exist or permission issue
            
            pr.add_to_labels(*labels)
            
        except Exception as e:
            self.logger.error(f"Error adding enhanced labels: {str(e)}")
            
    def _add_rollback_comment(self, pr, branch_name: str):
        """
        Add a comment with rollback instructions
        """
        
        rollback_comment = f"""
## 🔄 Rollback Instructions

Should this change need to be reverted after merging, you can:

1.  **Revert the Merge Commit**: `git revert -m 1 <merge-commit-sha>`
2.  **Manually Revert**: Checkout the previous state of the affected files and commit.

Alternatively, you can revert the branch `{branch_name}` before merging.

Contact the security team or infrastructure team if you require assistance with the rollback process.
"""
        try:
            pr.create_issue_comment(rollback_comment)
        except Exception as e:
            self.logger.error(f"Error adding rollback comment: {str(e)}")
            
    def _send_webhook_notification(self, webhook_url: str, pr, fixes: List[Dict[str, Any]]):
        """
        Send a notification to a specified webhook URL (e.g., Slack)
        """
        
        import requests
        
        try:
            payload = {
                "text": f"🤖 Automated PR Created: {pr.title}",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Automated PR Created: <{pr.html_url}|{pr.title}>*"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Repository:*\n`{pr.base.repo.full_name}`"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Branch:*\n`{pr.head.ref}`"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Fixes Applied:*\n{len(fixes)}"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Summary of Fixes:*\n" + "\n".join([f"• {fix.get("rule_id", "Unknown")}: {fix.get("description", "")}" for fix in fixes])
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "View PR"
                                },
                                "style": "primary",
                                "url": pr.html_url
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload)
            response.raise_for_status()
            self.logger.info(f"Webhook notification sent to {webhook_url}")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error sending webhook notification: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected error in webhook notification: {str(e)}")
            
    def _get_label_color(self, label_name: str) -> str:
        """
        Get appropriate color for label
        """
        
        color_map = {
            "auto-fix": "0E8A16",        # Green
            "security": "B60205",        # Red
            "compliance": "006B75",      # Teal
            "severity/critical": "D93F0B", # Dark Orange
            "severity/high": "FBCA04",    # Yellow
            "severity/medium": "FEF2C0",  # Light Yellow
            "severity/low": "BFDADC",     # Light Blue
            "framework/cis": "5319E7",    # Purple
            "framework/nist": "0052CC",   # Blue
            "resource/aws_s3_bucket": "F9D0C4", # Light Pink
            "resource/aws_security_group": "C5DEF5", # Light Blue
            "resource/aws_iam_policy": "BFDADC", # Light Green
            "resource/aws_instance": "E4E669", # Olive
            "resource/aws_ebs_volume": "FAD8C7", # Peach
            "resource/aws_lb_listener": "C2E0C6", # Mint Green
            "resource/aws_flow_log": "D4C5F9", # Lavender
            "resource/aws_cloudtrail": "FFD3B5" # Light Orange
        }
        
        return color_map.get(label_name, "ededed") # Default light gray

    def _log_action(self, event: str, details: Dict[str, Any]):
        """
        Log an action to the audit trail
        """
        self.audit_log.append({"event": event, "details": details, "timestamp": datetime.utcnow().isoformat()})
        self.logger.info(f"Audit Log: {event} - {details}")



