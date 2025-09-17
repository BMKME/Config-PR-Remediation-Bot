"""
JSON configuration parser
"""

import logging
import json
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class JSONParser:
    """Parser for JSON configuration files"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def parse(self, content: str) -> Dict[str, Any]:
        """
        Parse JSON content and return structured data
        
        Args:
            content: JSON configuration content as string
            
        Returns:
            Dict containing parsed configuration
            
        Raises:
            ValueError: If content cannot be parsed
        """
        try:
            self.logger.debug("Parsing JSON content")
            
            # Parse JSON content
            parsed = json.loads(content)
            
            # Determine configuration type and structure
            result = {
                'type': self._detect_config_type(parsed),
                'raw': parsed,
                'resources': {},
                'metadata': {}
            }
            
            # Process based on detected type
            if result['type'] == 'aws_config':
                result = self._parse_aws_config(parsed)
            elif result['type'] == 'azure_config':
                result = self._parse_azure_config(parsed)
            elif result['type'] == 'gcp_config':
                result = self._parse_gcp_config(parsed)
            elif result['type'] == 'kubernetes_config':
                result = self._parse_kubernetes_config(parsed)
            else:
                # Generic JSON structure
                result = self._parse_generic_config(parsed)
            
            self.logger.info(f"Successfully parsed JSON as {result['type']} with {len(result.get('resources', {}))} resources")
            return result
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse JSON content: {str(e)}")
            raise ValueError(f"Invalid JSON content: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected error parsing JSON: {str(e)}")
            raise ValueError(f"Failed to parse JSON: {str(e)}")
    
    def _detect_config_type(self, parsed: Dict[str, Any]) -> str:
        """Detect the type of configuration based on structure"""
        
        # Check for AWS CloudFormation
        if 'AWSTemplateFormatVersion' in parsed or 'Resources' in parsed:
            return 'aws_cloudformation'
        
        # Check for AWS Config
        if 'configurationItems' in parsed or 'resourceType' in parsed:
            return 'aws_config'
        
        # Check for Azure Resource Manager
        if '$schema' in parsed and 'azure' in parsed.get('$schema', '').lower():
            return 'azure_config'
        
        # Check for GCP Deployment Manager
        if 'resources' in parsed and isinstance(parsed['resources'], list):
            if any('type' in resource and 'gcp' in str(resource.get('type', '')).lower() 
                   for resource in parsed['resources']):
                return 'gcp_config'
        
        # Check for Kubernetes
        if 'apiVersion' in parsed and 'kind' in parsed:
            return 'kubernetes_config'
        
        return 'generic'
    
    def _parse_aws_config(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AWS configuration"""
        result = {
            'type': 'aws_config',
            'resources': {},
            'metadata': {},
            'raw': parsed
        }
        
        # Handle CloudFormation template
        if 'Resources' in parsed:
            for resource_name, resource_config in parsed['Resources'].items():
                resource_key = f"{resource_config.get('Type', 'Unknown')}.{resource_name}"
                result['resources'][resource_key] = {
                    'name': resource_name,
                    'type': resource_config.get('Type'),
                    'properties': resource_config.get('Properties', {}),
                    'metadata': resource_config.get('Metadata', {}),
                    'depends_on': resource_config.get('DependsOn', [])
                }
        
        # Handle AWS Config items
        elif 'configurationItems' in parsed:
            for item in parsed['configurationItems']:
                resource_key = f"{item.get('resourceType', 'Unknown')}.{item.get('resourceId', 'unknown')}"
                result['resources'][resource_key] = {
                    'id': item.get('resourceId'),
                    'type': item.get('resourceType'),
                    'name': item.get('resourceName'),
                    'configuration': item.get('configuration', {}),
                    'tags': item.get('tags', {}),
                    'region': item.get('awsRegion'),
                    'account_id': item.get('awsAccountId')
                }
        
        return result
    
    def _parse_azure_config(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Azure configuration"""
        result = {
            'type': 'azure_config',
            'resources': {},
            'metadata': {
                'schema': parsed.get('$schema'),
                'content_version': parsed.get('contentVersion')
            },
            'raw': parsed
        }
        
        if 'resources' in parsed:
            for resource in parsed['resources']:
                resource_name = resource.get('name', 'unnamed')
                resource_type = resource.get('type', 'Unknown')
                resource_key = f"{resource_type}.{resource_name}"
                
                result['resources'][resource_key] = {
                    'name': resource_name,
                    'type': resource_type,
                    'api_version': resource.get('apiVersion'),
                    'location': resource.get('location'),
                    'properties': resource.get('properties', {}),
                    'tags': resource.get('tags', {}),
                    'depends_on': resource.get('dependsOn', [])
                }
        
        return result
    
    def _parse_gcp_config(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GCP configuration"""
        result = {
            'type': 'gcp_config',
            'resources': {},
            'metadata': {},
            'raw': parsed
        }
        
        if 'resources' in parsed:
            for resource in parsed['resources']:
                resource_name = resource.get('name', 'unnamed')
                resource_type = resource.get('type', 'Unknown')
                resource_key = f"{resource_type}.{resource_name}"
                
                result['resources'][resource_key] = {
                    'name': resource_name,
                    'type': resource_type,
                    'properties': resource.get('properties', {}),
                    'metadata': resource.get('metadata', {})
                }
        
        return result
    
    def _parse_kubernetes_config(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Kubernetes configuration"""
        result = {
            'type': 'kubernetes_config',
            'resources': {},
            'metadata': {},
            'raw': parsed
        }
        
        kind = parsed.get('kind', 'Unknown')
        metadata = parsed.get('metadata', {})
        name = metadata.get('name', 'unnamed')
        namespace = metadata.get('namespace', 'default')
        
        resource_key = f"{kind}.{namespace}.{name}"
        result['resources'][resource_key] = {
            'kind': kind,
            'apiVersion': parsed.get('apiVersion'),
            'metadata': metadata,
            'spec': parsed.get('spec', {}),
            'data': parsed.get('data', {}),
            'raw': parsed
        }
        
        return result
    
    def _parse_generic_config(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Parse generic JSON configuration"""
        result = {
            'type': 'generic',
            'resources': {},
            'metadata': {
                'keys': list(parsed.keys()) if isinstance(parsed, dict) else [],
                'structure': 'dict' if isinstance(parsed, dict) else 'list' if isinstance(parsed, list) else 'other'
            },
            'raw': parsed
        }
        
        # Try to extract resource-like structures
        if isinstance(parsed, dict):
            for key, value in parsed.items():
                if isinstance(value, dict):
                    result['resources'][key] = value
        
        return result
    
    def get_resource_attribute(self, resource_config: Dict[str, Any], attribute_path: str, default: Any = None) -> Any:
        """
        Get a nested attribute from resource configuration
        
        Args:
            resource_config: Resource configuration dict
            attribute_path: Dot-separated path to attribute
            default: Default value if attribute not found
            
        Returns:
            Attribute value or default
        """
        try:
            current = resource_config
            for part in attribute_path.split('.'):
                if part.isdigit():
                    current = current[int(part)]
                else:
                    current = current[part]
            return current
        except (KeyError, TypeError, IndexError, ValueError):
            return default

