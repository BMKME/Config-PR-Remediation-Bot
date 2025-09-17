"""
Kubernetes YAML configuration parser
"""

import logging
import yaml
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class YAMLParser:
    """Parser for Kubernetes YAML configuration files"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def parse(self, content: str) -> Dict[str, Any]:
        """
        Parse YAML content and return structured data
        
        Args:
            content: YAML configuration content as string
            
        Returns:
            Dict containing parsed configuration
            
        Raises:
            ValueError: If content cannot be parsed
        """
        try:
            self.logger.debug("Parsing YAML content")
            
            # Parse YAML content (supports multiple documents)
            documents = list(yaml.safe_load_all(content))
            
            # Organize by Kubernetes resource types
            result = {
                'resources': {},
                'metadata': {
                    'document_count': len(documents),
                    'namespaces': set(),
                    'kinds': set()
                }
            }
            
            for i, doc in enumerate(documents):
                if not doc:  # Skip empty documents
                    continue
                
                # Extract basic Kubernetes resource information
                kind = doc.get('kind', 'Unknown')
                api_version = doc.get('apiVersion', 'Unknown')
                metadata = doc.get('metadata', {})
                name = metadata.get('name', f'unnamed-{i}')
                namespace = metadata.get('namespace', 'default')
                
                # Create resource key
                resource_key = f"{kind}.{namespace}.{name}"
                
                # Store resource
                result['resources'][resource_key] = {
                    'kind': kind,
                    'apiVersion': api_version,
                    'metadata': metadata,
                    'spec': doc.get('spec', {}),
                    'data': doc.get('data', {}),
                    'stringData': doc.get('stringData', {}),
                    'rules': doc.get('rules', []),
                    'subjects': doc.get('subjects', []),
                    'roleRef': doc.get('roleRef', {}),
                    'raw': doc  # Keep original document for reference
                }
                
                # Update metadata
                result['metadata']['namespaces'].add(namespace)
                result['metadata']['kinds'].add(kind)
            
            # Convert sets to lists for JSON serialization
            result['metadata']['namespaces'] = list(result['metadata']['namespaces'])
            result['metadata']['kinds'] = list(result['metadata']['kinds'])
            
            self.logger.info(f"Successfully parsed YAML with {len(result['resources'])} resources")
            return result
            
        except yaml.YAMLError as e:
            self.logger.error(f"Failed to parse YAML content: {str(e)}")
            raise ValueError(f"Invalid YAML content: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected error parsing YAML: {str(e)}")
            raise ValueError(f"Failed to parse YAML: {str(e)}")
    
    def extract_resources_by_kind(self, parsed_config: Dict[str, Any], kind: str) -> Dict[str, Any]:
        """
        Extract all resources of a specific Kubernetes kind
        
        Args:
            parsed_config: Parsed configuration from parse()
            kind: Kubernetes resource kind (e.g., 'Deployment', 'Service')
            
        Returns:
            Dict of resources of the specified kind
        """
        resources = {}
        for resource_key, resource_data in parsed_config.get('resources', {}).items():
            if resource_data['kind'] == kind:
                resources[resource_key] = resource_data
        
        return resources
    
    def extract_resources_by_namespace(self, parsed_config: Dict[str, Any], namespace: str) -> Dict[str, Any]:
        """
        Extract all resources in a specific namespace
        
        Args:
            parsed_config: Parsed configuration from parse()
            namespace: Kubernetes namespace
            
        Returns:
            Dict of resources in the specified namespace
        """
        resources = {}
        for resource_key, resource_data in parsed_config.get('resources', {}).items():
            if resource_data['metadata'].get('namespace', 'default') == namespace:
                resources[resource_key] = resource_data
        
        return resources
    
    def get_resource_attribute(self, resource_config: Dict[str, Any], attribute_path: str, default: Any = None) -> Any:
        """
        Get a nested attribute from resource configuration
        
        Args:
            resource_config: Resource configuration dict
            attribute_path: Dot-separated path to attribute (e.g., 'spec.containers.0.image')
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
    
    def has_label(self, resource_config: Dict[str, Any], label_key: str, label_value: Optional[str] = None) -> bool:
        """
        Check if resource has a specific label
        
        Args:
            resource_config: Resource configuration dict
            label_key: Label key to check
            label_value: Optional label value to match
            
        Returns:
            True if label exists (and matches value if provided)
        """
        labels = resource_config.get('metadata', {}).get('labels', {})
        
        if label_key not in labels:
            return False
        
        if label_value is not None:
            return labels[label_key] == label_value
        
        return True
    
    def has_annotation(self, resource_config: Dict[str, Any], annotation_key: str, annotation_value: Optional[str] = None) -> bool:
        """
        Check if resource has a specific annotation
        
        Args:
            resource_config: Resource configuration dict
            annotation_key: Annotation key to check
            annotation_value: Optional annotation value to match
            
        Returns:
            True if annotation exists (and matches value if provided)
        """
        annotations = resource_config.get('metadata', {}).get('annotations', {})
        
        if annotation_key not in annotations:
            return False
        
        if annotation_value is not None:
            return annotations[annotation_key] == annotation_value
        
        return True

