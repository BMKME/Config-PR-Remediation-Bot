"""
Basic secrets management
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

class SecretsManager:
    """Basic secrets manager for environment variables"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get secret from environment variables
        
        Args:
            key: Environment variable key
            default: Default value if not found
            
        Returns:
            Secret value or default
        """
        value = os.getenv(key, default)
        
        if value is None:
            self.logger.warning(f"Secret {key} not found in environment")
        
        return value
    
    def validate_secrets(self) -> Dict[str, bool]:
        """Validate that required secrets are available"""
        
        required_secrets = {
            'GITHUB_TOKEN': False,
            'GITLAB_TOKEN': False,  # Optional
            'VAULT_TOKEN': False,   # Optional
            'AWS_ACCESS_KEY_ID': False,  # Optional
        }
        
        for secret_key in required_secrets:
            required_secrets[secret_key] = bool(os.getenv(secret_key))
        
        return required_secrets

