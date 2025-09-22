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
Terraform HCL configuration parser
"""

import logging
import hcl2
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class HCLParser:
    """Parser for Terraform HCL configuration files"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def parse(self, content: str) -> Dict[str, Any]:
        """
        Parse HCL content and return structured data
        
        Args:
            content: HCL configuration content as string
            
        Returns:
            Dict containing parsed configuration
            
        Raises:
            ValueError: If content cannot be parsed
        """
        try:
            self.logger.debug("Parsing HCL content")
            
            # Parse HCL content
            parsed = hcl2.loads(content)
            
            # Extract and organize resources
            result = {
                'resources': {},
                'data_sources': {},
                'variables': {},
                'outputs': {},
                'providers': {},
                'terraform': {},
                'locals': {},
                'modules': {}
            }
            
            # Process resources
            if 'resource' in parsed:
                for resource_type, resources in parsed['resource'].items():
                    for resource_name, resource_config in resources.items():
                        resource_key = f"{resource_type}.{resource_name}"
                        result['resources'][resource_key] = {
                            'type': resource_type,
                            'name': resource_name,
                            'config': resource_config
                        }
            
            # Process data sources
            if 'data' in parsed:
                for data_type, data_sources in parsed['data'].items():
                    for data_name, data_config in data_sources.items():
                        data_key = f"data.{data_type}.{data_name}"
                        result['data_sources'][data_key] = {
                            'type': data_type,
                            'name': data_name,
                            'config': data_config
                        }
            
            # Process variables
            if 'variable' in parsed:
                for var_name, var_config in parsed['variable'].items():
                    result['variables'][var_name] = var_config
            
            # Process outputs
            if 'output' in parsed:
                for output_name, output_config in parsed['output'].items():
                    result['outputs'][output_name] = output_config
            
            # Process providers
            if 'provider' in parsed:
                for provider_name, provider_configs in parsed['provider'].items():
                    if isinstance(provider_configs, list):
                        result['providers'][provider_name] = provider_configs
                    else:
                        result['providers'][provider_name] = [provider_configs]
            
            # Process terraform block
            if 'terraform' in parsed:
                result['terraform'] = parsed['terraform']
            
            # Process locals
            if 'locals' in parsed:
                result['locals'] = parsed['locals']
            
            # Process modules
            if 'module' in parsed:
                for module_name, module_config in parsed['module'].items():
                    result['modules'][module_name] = module_config
            
            self.logger.info(f"Successfully parsed HCL with {len(result['resources'])} resources")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to parse HCL content: {str(e)}")
            raise ValueError(f"Invalid HCL content: {str(e)}")
    
    def extract_resource_by_type(self, parsed_config: Dict[str, Any], resource_type: str) -> Dict[str, Any]:
        """
        Extract all resources of a specific type
        
        Args:
            parsed_config: Parsed configuration from parse()
            resource_type: Type of resource to extract (e.g., 'aws_s3_bucket')
            
        Returns:
            Dict of resources of the specified type
        """
        resources = {}
        for resource_key, resource_data in parsed_config.get('resources', {}).items():
            if resource_data['type'] == resource_type:
                resources[resource_key] = resource_data
        
        return resources
    
    def get_resource_attribute(self, resource_config: Dict[str, Any], attribute_path: str, default: Any = None) -> Any:
        """
        Get a nested attribute from resource configuration
        
        Args:
            resource_config: Resource configuration dict
            attribute_path: Dot-separated path to attribute (e.g., 'config.bucket')
            default: Default value if attribute not found
            
        Returns:
            Attribute value or default
        """
        try:
            current = resource_config
            for part in attribute_path.split('.'):
                current = current[part]
            return current
        except (KeyError, TypeError):
            return default



