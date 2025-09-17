"""
GitHub Pull Request Bot for creating remediation PRs
"""

import logging
import os
from typing import Dict, Any, List, Optional
from github import Github, GithubException
from datetime import datetime

logger = logging.getLogger(__name__)

class GitHubPRBot:
    """GitHub integration for creating pull requests with remediation code"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.github = None
        
        if self.github_token:
            try:
                self.github = Github(self.github_token)
                self.logger.info("GitHub client initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize GitHub client: {str(e)}")
        else:
            self.logger.warning("GITHUB_TOKEN not found in environment variables")
    
    def create_pr(self, repository: str, branch: str, title: str, description: str, 
                  fixes: List[Dict[str, Any]], files: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Create a pull request with remediation fixes
        
        Args:
            repository: Repository name in format "owner/repo"
            branch: Branch name for the PR
            title: PR title
            description: PR description
            fixes: List of fix dictionaries
            files: List of file changes
            
        Returns:
            Dict containing PR creation results
        """
        if not self.github:
            return {
                'success': False,
                'error': 'GitHub client not initialized. Check GITHUB_TOKEN.',
                'pr_url': None
            }
        
        try:
            self.logger.info(f"Creating PR for repository {repository}")
            
            # Get repository
            repo = self.github.get_repo(repository)
            
            # Get default branch
            default_branch = repo.default_branch
            
            # Create new branch from default branch
            default_branch_ref = repo.get_git_ref(f"heads/{default_branch}")
            new_branch_ref = repo.create_git_ref(
                ref=f"refs/heads/{branch}",
                sha=default_branch_ref.object.sha
            )
            
            # Apply file changes
            for file_change in files:
                file_path = file_change['path']
                file_content = file_change['content']
                
                try:
                    # Try to get existing file
                    existing_file = repo.get_contents(file_path, ref=branch)
                    
                    # Update existing file
                    repo.update_file(
                        path=file_path,
                        message=f"Update {file_path} with compliance fixes",
                        content=file_content,
                        sha=existing_file.sha,
                        branch=branch
                    )
                    
                except GithubException as e:
                    if e.status == 404:
                        # File doesn't exist, create new file
                        repo.create_file(
                            path=file_path,
                            message=f"Add {file_path} with compliance fixes",
                            content=file_content,
                            branch=branch
                        )
                    else:
                        raise e
            
            # Generate PR body with fix details
            pr_body = self._generate_pr_body(description, fixes)
            
            # Create pull request
            pr = repo.create_pull(
                title=title,
                body=pr_body,
                head=branch,
                base=default_branch
            )
            
            # Add inline comments for each fix
            self._add_inline_comments(repo, pr, fixes)
            
            # Add labels
            self._add_pr_labels(pr, fixes)
            
            result = {
                'success': True,
                'pr_number': pr.number,
                'pr_url': pr.html_url,
                'branch': branch,
                'fixes_applied': len(fixes),
                'files_changed': len(files)
            }
            
            self.logger.info(f"Successfully created PR #{pr.number}: {pr.html_url}")
            return result
            
        except GithubException as e:
            self.logger.error(f"GitHub API error: {str(e)}")
            return {
                'success': False,
                'error': f'GitHub API error: {str(e)}',
                'pr_url': None
            }
        except Exception as e:
            self.logger.error(f"Unexpected error creating PR: {str(e)}")
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
                'pr_url': None
            }
    
    def _generate_pr_body(self, description: str, fixes: List[Dict[str, Any]]) -> str:
        """Generate detailed PR body with fix information"""
        
        body_parts = [
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
            severity = 'MEDIUM'  # Default
            if 'rule_id' in fix:
                # You could map rule_ids to severities here
                pass
            
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(fix)
        
        # Add fixes by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_groups:
                body_parts.append(f"### {severity} Priority Fixes ({len(severity_groups[severity])})")
                body_parts.append("")
                
                for fix in severity_groups[severity]:
                    body_parts.append(f"- **{fix.get('rule_id', 'Unknown')}**: {fix.get('description', 'No description')}")
                    if fix.get('explanation'):
                        body_parts.append(f"  - {fix['explanation']}")
                
                body_parts.append("")
        
        # Add statistics
        body_parts.extend([
            "## Fix Statistics",
            "",
            f"- Total fixes applied: {len(fixes)}",
            f"- Resources modified: {len(set(fix.get('resource_name', 'unknown') for fix in fixes))}",
            f"- Fix types: {len(set(fix.get('fix_type', 'unknown') for fix in fixes))}",
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
            "This PR addresses violations from:",
            "- CIS Benchmarks",
            "- NIST Cybersecurity Framework",
            "",
            "---",
            f"*Generated by Config-to-PR Remediation Bot on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*"
        ])
        
        return "\n".join(body_parts)
    
    def _add_inline_comments(self, repo, pr, fixes: List[Dict[str, Any]]):
        """Add inline comments to PR for each fix"""
        
        try:
            # Get PR commits
            commits = list(pr.get_commits())
            if not commits:
                return
            
            latest_commit = commits[-1]
            
            # Add comments for each fix
            for fix in fixes:
                file_path = fix.get('file_path', 'main.tf')
                explanation = fix.get('explanation', 'Compliance fix applied')
                rule_id = fix.get('rule_id', 'unknown')
                
                comment_body = f"**{rule_id}**: {explanation}"
                
                try:
                    # Create review comment (inline comment)
                    pr.create_review_comment(
                        body=comment_body,
                        commit=latest_commit,
                        path=file_path,
                        line=1  # Default to line 1 since we don't have exact line numbers
                    )
                except GithubException as e:
                    # If inline comment fails, add as regular comment
                    self.logger.warning(f"Failed to add inline comment for {rule_id}: {str(e)}")
                    pr.create_issue_comment(f"**Fix Applied - {rule_id}**\n\n{explanation}\n\nFile: `{file_path}`")
                    
        except Exception as e:
            self.logger.error(f"Error adding inline comments: {str(e)}")
    
    def _add_pr_labels(self, pr, fixes: List[Dict[str, Any]]):
        """Add appropriate labels to the PR"""
        
        labels = ['compliance', 'security', 'automated-fix']
        
        # Add severity-based labels
        has_critical = any('critical' in fix.get('rule_id', '').lower() for fix in fixes)
        has_high = any('high' in fix.get('rule_id', '').lower() for fix in fixes)
        
        if has_critical:
            labels.append('critical')
        elif has_high:
            labels.append('high-priority')
        else:
            labels.append('medium-priority')
        
        # Add framework labels
        has_cis = any(fix.get('rule_id', '').startswith('cis_') for fix in fixes)
        has_nist = any(fix.get('rule_id', '').startswith('nist_') for fix in fixes)
        
        if has_cis:
            labels.append('cis-benchmark')
        if has_nist:
            labels.append('nist-framework')
        
        try:
            # Get repository to access labels
            repo = pr.base.repo
            
            # Check which labels exist and create missing ones
            existing_labels = {label.name for label in repo.get_labels()}
            
            for label_name in labels:
                if label_name not in existing_labels:
                    try:
                        # Create label with appropriate color
                        color = self._get_label_color(label_name)
                        repo.create_label(name=label_name, color=color)
                        self.logger.info(f"Created label: {label_name}")
                    except GithubException:
                        # Label might already exist or we don't have permission
                        pass
            
            # Add labels to PR
            pr.add_to_labels(*labels)
            
        except Exception as e:
            self.logger.error(f"Error adding labels: {str(e)}")
    
    def _get_label_color(self, label_name: str) -> str:
        """Get appropriate color for label"""
        
        color_map = {
            'compliance': 'blue',
            'security': 'red',
            'automated-fix': 'green',
            'critical': 'darkred',
            'high-priority': 'orange',
            'medium-priority': 'yellow',
            'cis-benchmark': 'purple',
            'nist-framework': 'navy'
        }
        
        return color_map.get(label_name, 'lightgray')
    
    def get_repository_info(self, repository: str) -> Dict[str, Any]:
        """Get information about a repository"""
        
        if not self.github:
            return {'error': 'GitHub client not initialized'}
        
        try:
            repo = self.github.get_repo(repository)
            
            return {
                'name': repo.name,
                'full_name': repo.full_name,
                'default_branch': repo.default_branch,
                'private': repo.private,
                'has_issues': repo.has_issues,
                'has_projects': repo.has_projects,
                'has_wiki': repo.has_wiki,
                'open_issues_count': repo.open_issues_count,
                'forks_count': repo.forks_count,
                'stargazers_count': repo.stargazers_count
            }
            
        except GithubException as e:
            return {'error': f'GitHub API error: {str(e)}'}
        except Exception as e:
            return {'error': f'Unexpected error: {str(e)}'}
    
    def list_branches(self, repository: str) -> List[str]:
        """List all branches in a repository"""
        
        if not self.github:
            return []
        
        try:
            repo = self.github.get_repo(repository)
            branches = [branch.name for branch in repo.get_branches()]
            return branches
            
        except Exception as e:
            self.logger.error(f"Error listing branches: {str(e)}")
            return []

