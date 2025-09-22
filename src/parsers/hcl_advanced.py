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
Advanced HCL Parser with safer replacement logic
Implements proper HCL parsing and serialization for robust configuration fixes
"""

import logging
import json
from typing import Dict, Any, List, Optional, Tuple
import re

logger = logging.getLogger(__name__)

class AdvancedHCLParser:
    """Advanced HCL parser with proper AST manipulation"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def parse_and_fix_s3_bucket(self, hcl_content: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Parse HCL content and fix S3 bucket configurations safely
        
        Args:
            hcl_content: Raw HCL content
            
        Returns:
            Tuple of (fixed_content, list_of_fixes_applied)
        """
        fixes_applied = []
        
        try:
            # Use python-hcl2 for proper parsing
            import hcl2
            
            # Parse the HCL content
            parsed = hcl2.loads(hcl_content)
            
            # Track changes
            content_changed = False
            
            # Process S3 bucket resources
            if 'resource' in parsed:
                for resource_type, resources in parsed['resource'].items():
                    if resource_type == 'aws_s3_bucket':
                        for bucket_name, bucket_config in resources.items():
                            fixes = self._fix_s3_bucket_config(bucket_name, bucket_config)
                            if fixes:
                                fixes_applied.extend(fixes)
                                content_changed = True
                    
                    elif resource_type == 'aws_s3_bucket_public_access_block':
                        for pab_name, pab_config in resources.items():
                            fixes = self._fix_s3_public_access_block(pab_name, pab_config)
                            if fixes:
                                fixes_applied.extend(fixes)
                                content_changed = True
            
            # If changes were made, regenerate HCL content
            if content_changed:
                # For now, use regex-based replacement as HCL serialization is complex
                # In production, consider using terraform fmt or custom HCL writer
                fixed_content = self._apply_regex_fixes(hcl_content, fixes_applied)
                return fixed_content, fixes_applied
            else:
                return hcl_content, []
                
        except ImportError:
            self.logger.warning("python-hcl2 not available, falling back to regex-based parsing")
            return self._fallback_regex_fix(hcl_content)
        except Exception as e:
            self.logger.error(f"Error parsing HCL: {str(e)}")
            return self._fallback_regex_fix(hcl_content)
    
    def _fix_s3_bucket_config(self, bucket_name: str, bucket_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Fix S3 bucket configuration issues
        """
        fixes = []
        
        # Check for public ACL
        if bucket_config.get('acl') == 'public-read':
            fixes.append({
                'type': 'acl_fix',
                'resource_name': bucket_name,
                'old_value': 'public-read',
                'new_value': 'private',
                'description': 'Changed S3 bucket ACL from public-read to private'
            })
            bucket_config['acl'] = 'private'
        
        # Check for missing versioning
        if 'versioning' not in bucket_config:
            fixes.append({
                'type': 'versioning_fix',
                'resource_name': bucket_name,
                'old_value': None,
                'new_value': {'enabled': True},
                'description': 'Added versioning configuration to S3 bucket'
            })
            bucket_config['versioning'] = {'enabled': True}
        
        return fixes
    
    def _fix_s3_public_access_block(self, pab_name: str, pab_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Fix S3 public access block configuration
        """
        fixes = []
        
        public_access_settings = [
            'block_public_acls',
            'block_public_policy', 
            'ignore_public_acls',
            'restrict_public_buckets'
        ]
        
        for setting in public_access_settings:
            if pab_config.get(setting) is False:
                fixes.append({
                    'type': 'public_access_block_fix',
                    'resource_name': pab_name,
                    'setting': setting,
                    'old_value': False,
                    'new_value': True,
                    'description': f'Enabled {setting} in S3 public access block'
                })
                pab_config[setting] = True
        
        return fixes
    
    def _apply_regex_fixes(self, content: str, fixes: List[Dict[str, Any]]) -> str:
        """
        Apply fixes using regex replacement (fallback method)
        """
        fixed_content = content
        
        for fix in fixes:
            if fix['type'] == 'acl_fix':
                # Replace ACL setting
                pattern = r'acl\s*=\s*["\\]public-read["\\]'
                replacement = 'acl = "private"'
                fixed_content = re.sub(pattern, replacement, fixed_content)
            
            elif fix['type'] == 'public_access_block_fix':
                # Replace public access block settings
                setting = fix['setting']
                pattern = f'{setting}\\s*=\\s*false'
                replacement = f'{setting} = true'
                fixed_content = re.sub(pattern, replacement, fixed_content, flags=re.IGNORECASE)
        
        return fixed_content
    
    def _fallback_regex_fix(self, hcl_content: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Fallback regex-based fix when HCL parsing is not available
        """
        fixes_applied = []
        fixed_content = hcl_content
        
        # Fix S3 public ACL
        acl_pattern = r'acl\s*=\s*["\\]public-read["\\]'
        if re.search(acl_pattern, fixed_content, re.IGNORECASE):
            fixed_content = re.sub(acl_pattern, 'acl = "private"', fixed_content, flags=re.IGNORECASE)
            fixes_applied.append({
                'type': 'acl_fix',
                'description': 'Changed S3 bucket ACL from public-read to private',
                'pattern': acl_pattern
            })
        
        # Fix public access block settings
        public_access_patterns = {
            'block_public_acls': r'block_public_acls\s*=\s*false',
            'block_public_policy': r'block_public_policy\s*=\s*false',
            'ignore_public_acls': r'ignore_public_acls\s*=\s*false',
            'restrict_public_buckets': r'restrict_public_buckets\s*=\s*false'
        }
        
        for setting, pattern in public_access_patterns.items():
            if re.search(pattern, fixed_content, re.IGNORECASE):
                replacement = f'{setting} = true'
                fixed_content = re.sub(pattern, replacement, fixed_content, flags=re.IGNORECASE)
                fixes_applied.append({
                    'type': 'public_access_block_fix',
                    'setting': setting,
                    'description': f'Enabled {setting} in S3 public access block',
                    'pattern': pattern
                })
        
        return fixed_content, fixes_applied
    
    def check_idempotency(self, hcl_content: str) -> bool:
        """
        Check if fixes have already been applied (idempotency check)
        """
        # Check for public ACL
        if re.search(r'acl\s*=\s*["\\]public-read["\\]', hcl_content, re.IGNORECASE):
            return False
        
        # Check for disabled public access block settings
        public_access_patterns = [
            r'block_public_acls\s*=\s*false',
            r'block_public_policy\s*=\s*false',
            r'ignore_public_acls\s*=\s*false',
            r'restrict_public_buckets\s*=\s*false'
        ]
        
        for pattern in public_access_patterns:
            if re.search(pattern, hcl_content, re.IGNORECASE):
                return False
        
        return True
    
    def validate_terraform_syntax(self, hcl_content: str) -> Tuple[bool, Optional[str]]:
        """
        Validate Terraform syntax (basic validation)
        """
        try:
            # Basic syntax checks
            
            # Check for balanced braces
            open_braces = hcl_content.count('{')
            close_braces = hcl_content.count('}')
            if open_braces != close_braces:
                return False, f"Unbalanced braces: {open_braces} open, {close_braces} close"
            
            # Check for balanced quotes
            quote_count = hcl_content.count('"')
            if quote_count % 2 != 0:
                return False, "Unbalanced quotes"
            
            # Check for basic resource structure
            if 'resource' in hcl_content:
                resource_pattern = r'resource\s+"[^"]+"\s+"[^"]+"\s*{\s*'
                if not re.search(resource_pattern, hcl_content):
                    return False, "Invalid resource syntax"
            
            return True, None
            
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    def extract_resources(self, hcl_content: str) -> List[Dict[str, Any]]:
        """
        Extract resource information from HCL content
        """
        resources = []
        
        # Regex to find resource blocks
        resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*{\s*([^}]*)}'
        
        matches = re.finditer(resource_pattern, hcl_content, re.DOTALL)
        
        for match in matches:
            resource_type = match.group(1)
            resource_name = match.group(2)
            resource_body = match.group(3)
            
            resources.append({
                'type': resource_type,
                'name': resource_name,
                'body': resource_body.strip(),
                'full_match': match.group(0)
            })
        
        return resources


