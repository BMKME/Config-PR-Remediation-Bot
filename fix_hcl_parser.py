#!/usr/bin/env python3
"""
Fix for HCL parser issue - handle provider configurations correctly
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from parsers.hcl import HCLParser

def test_hcl_parsing():
    """Test HCL parsing with the test file"""
    
    parser = HCLParser()
    
    # Read the test file
    with open('test_terraform.tf', 'r') as f:
        content = f.read()
    
    try:
        result = parser.parse(content)
        print("HCL parsing successful!")
        print(f"Found {len(result['resources'])} resources")
        
        for resource_key, resource_data in result['resources'].items():
            print(f"  - {resource_key}: {resource_data['type']}")
        
        return result
        
    except Exception as e:
        print(f"HCL parsing failed: {str(e)}")
        return None

if __name__ == '__main__':
    test_hcl_parsing()

