"""
Basic authentication and authorization manager
"""

import logging
import os
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class AuthManager:
    """Basic authentication manager for API access"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def validate_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Basic request validation
        
        Args:
            request_data: Request data to validate
            
        Returns:
            Dict with validation results
        """
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Basic input validation
        if not isinstance(request_data, dict):
            validation_result['valid'] = False
            validation_result['errors'].append('Request data must be a dictionary')
            return validation_result
        
        # Check for required fields based on endpoint
        if 'config_content' in request_data:
            content = request_data['config_content']
            if not content or not isinstance(content, str):
                validation_result['valid'] = False
                validation_result['errors'].append('config_content must be a non-empty string')
        
        if 'config_type' in request_data:
            config_type = request_data['config_type']
            valid_types = ['terraform', 'kubernetes', 'json']
            if config_type not in valid_types:
                validation_result['valid'] = False
                validation_result['errors'].append(f'config_type must be one of: {", ".join(valid_types)}')
        
        return validation_result
    
    def check_github_token(self) -> bool:
        """Check if GitHub token is available"""
        return bool(os.getenv('GITHUB_TOKEN'))
    
    def sanitize_input(self, input_data: str) -> str:
        """Basic input sanitization"""
        if not isinstance(input_data, str):
            return str(input_data)
        
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '&', '"', "'", '`']
        sanitized = input_data
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        return sanitized.strip()

