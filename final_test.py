#!/usr/bin/env python3
"""
Final integration test for Config-to-PR Bot
"""

import json
import requests
import time
from datetime import datetime

def test_api_endpoints():
    """Test all API endpoints"""
    
    base_url = "http://localhost:5000"
    
    print("=" * 60)
    print("Config-to-PR Bot - Final Integration Test")
    print("=" * 60)
    
    # Test data
    test_terraform = '''
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}

resource "aws_s3_bucket_public_access_block" "test" {
  bucket = aws_s3_bucket.test.id
  block_public_acls = false
  block_public_policy = false
}

resource "aws_security_group" "test" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
    
    results = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'tests': []
    }
    
    # Test 1: Health Check
    print("\n1. Testing Health Check...")
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Health check passed: {data['service']} v{data['version']}")
            results['tests'].append({
                'name': 'health_check',
                'status': 'PASS',
                'response_code': response.status_code,
                'data': data
            })
        else:
            print(f"   ❌ Health check failed: {response.status_code}")
            results['tests'].append({
                'name': 'health_check',
                'status': 'FAIL',
                'response_code': response.status_code
            })
    except Exception as e:
        print(f"   ❌ Health check error: {str(e)}")
        results['tests'].append({
            'name': 'health_check',
            'status': 'ERROR',
            'error': str(e)
        })
    
    # Test 2: Rules Endpoint
    print("\n2. Testing Rules Endpoint...")
    try:
        response = requests.get(f"{base_url}/rules", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Rules endpoint passed: {data['total_rules']} rules available")
            results['tests'].append({
                'name': 'rules',
                'status': 'PASS',
                'response_code': response.status_code,
                'rules_count': data['total_rules']
            })
        else:
            print(f"   ❌ Rules endpoint failed: {response.status_code}")
            results['tests'].append({
                'name': 'rules',
                'status': 'FAIL',
                'response_code': response.status_code
            })
    except Exception as e:
        print(f"   ❌ Rules endpoint error: {str(e)}")
        results['tests'].append({
            'name': 'rules',
            'status': 'ERROR',
            'error': str(e)
        })
    
    # Test 3: Analysis Endpoint
    print("\n3. Testing Analysis Endpoint...")
    try:
        payload = {
            'config_content': test_terraform,
            'config_type': 'terraform'
        }
        response = requests.post(f"{base_url}/analyze", json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            violations = data['summary']['total_violations']
            score = data['summary']['compliance_score']
            print(f"   ✅ Analysis passed: {violations} violations, {score}% compliance")
            results['tests'].append({
                'name': 'analysis',
                'status': 'PASS',
                'response_code': response.status_code,
                'violations': violations,
                'compliance_score': score
            })
        else:
            print(f"   ❌ Analysis failed: {response.status_code}")
            results['tests'].append({
                'name': 'analysis',
                'status': 'FAIL',
                'response_code': response.status_code
            })
    except Exception as e:
        print(f"   ❌ Analysis error: {str(e)}")
        results['tests'].append({
            'name': 'analysis',
            'status': 'ERROR',
            'error': str(e)
        })
    
    # Test 4: Full Analysis Endpoint
    print("\n4. Testing Full Analysis Endpoint...")
    try:
        payload = {
            'config_content': test_terraform,
            'config_type': 'terraform',
            'apply_fixes': True
        }
        response = requests.post(f"{base_url}/full-analysis", json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            violations = data['analysis']['summary']['total_violations']
            fixes = len(data['remediation']['fixes']) if data['remediation'] else 0
            has_fixed_content = bool(data['fixed_content'])
            print(f"   ✅ Full analysis passed: {violations} violations, {fixes} fixes, fixed content: {has_fixed_content}")
            results['tests'].append({
                'name': 'full_analysis',
                'status': 'PASS',
                'response_code': response.status_code,
                'violations': violations,
                'fixes': fixes,
                'has_fixed_content': has_fixed_content
            })
        else:
            print(f"   ❌ Full analysis failed: {response.status_code}")
            results['tests'].append({
                'name': 'full_analysis',
                'status': 'FAIL',
                'response_code': response.status_code
            })
    except Exception as e:
        print(f"   ❌ Full analysis error: {str(e)}")
        results['tests'].append({
            'name': 'full_analysis',
            'status': 'ERROR',
            'error': str(e)
        })
    
    # Summary
    passed_tests = sum(1 for test in results['tests'] if test['status'] == 'PASS')
    total_tests = len(results['tests'])
    
    print(f"\n" + "=" * 60)
    print(f"Test Results: {passed_tests}/{total_tests} tests passed")
    print("=" * 60)
    
    # Save results
    with open('final_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Test results saved to: final_test_results.json")
    
    return results

if __name__ == '__main__':
    # Wait a moment for server to be ready
    print("Waiting for server to be ready...")
    time.sleep(2)
    
    test_api_endpoints()

