#!/usr/bin/env python3
"""
Improved Config-to-PR Remediation Bot
Main application with fixes from PoC testing
"""

import os
import sys
import re
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup simple logging to avoid import conflicts
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

class SimpleConfigAnalyzer:
    """Simplified configuration analyzer for reliable PoC functionality"""
    
    def __init__(self):
        self.patterns = {
            'cis_2_1_1': {
                'name': 'S3 Public Access Block',
                'pattern': r'block_public_\w+\s*=\s*false',
                'severity': 'HIGH',
                'description': 'S3 bucket public access block setting is disabled'
            },
            'cis_4_2': {
                'name': 'SSH Access Control',
                'pattern': r'from_port\s*=\s*22.*cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
                'severity': 'HIGH',
                'description': 'Security group allows unrestricted SSH access'
            },
            'cis_4_3': {
                'name': 'RDP Access Control',
                'pattern': r'from_port\s*=\s*3389.*cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
                'severity': 'HIGH',
                'description': 'Security group allows unrestricted RDP access'
            },
            'nist_pr_ip_1': {
                'name': 'Baseline Configuration',
                'pattern': r'monitoring\s*=\s*false|ebs_optimized\s*=\s*false',
                'severity': 'MEDIUM',
                'description': 'EC2 instance missing baseline configuration'
            }
        }
    
    def analyze_content(self, content: str, config_type: str = 'terraform') -> dict:
        """Analyze configuration content for violations"""
        
        violations = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for rule_id, rule_info in self.patterns.items():
                if re.search(rule_info['pattern'], line, re.IGNORECASE):
                    violations.append({
                        'rule_id': rule_id,
                        'rule_name': rule_info['name'],
                        'severity': rule_info['severity'],
                        'line_number': line_num,
                        'line_content': line.strip(),
                        'description': rule_info['description'],
                        'config_type': config_type
                    })
        
        # Calculate summary
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for violation in violations:
            severity = violation.get('severity', 'MEDIUM')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        total_rules = len(self.patterns)
        failed_rules = len(set(v['rule_id'] for v in violations))
        passed_rules = total_rules - failed_rules
        compliance_score = round((passed_rules / total_rules) * 100, 2) if total_rules > 0 else 0
        
        return {
            'config_type': config_type,
            'analysis_timestamp': datetime.utcnow().isoformat() + 'Z',
            'summary': {
                'total_rules_checked': total_rules,
                'rules_passed': passed_rules,
                'rules_failed': failed_rules,
                'total_violations': len(violations),
                'severity_breakdown': severity_counts,
                'compliance_score': compliance_score
            },
            'violations': violations
        }

class SimpleRemediator:
    """Simplified remediation generator"""
    
    def __init__(self):
        self.fixes = {
            'cis_2_1_1': {
                'type': 'replace',
                'pattern': r'block_public_(\w+)\s*=\s*false',
                'replacement': r'block_public_\1 = true',
                'description': 'Enable S3 public access block setting'
            },
            'cis_4_2': {
                'type': 'replace',
                'pattern': r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
                'replacement': 'cidr_blocks = ["10.0.0.0/8"]  # Restricted to private networks',
                'description': 'Restrict SSH access to private networks'
            },
            'cis_4_3': {
                'type': 'replace',
                'pattern': r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
                'replacement': 'cidr_blocks = ["10.0.0.0/8"]  # Restricted to private networks',
                'description': 'Restrict RDP access to private networks'
            },
            'nist_pr_ip_1': {
                'type': 'replace',
                'pattern': r'(monitoring|ebs_optimized)\s*=\s*false',
                'replacement': r'\1 = true',
                'description': 'Enable baseline configuration setting'
            }
        }
    
    def generate_fixes(self, violations: list, config_type: str = 'terraform') -> dict:
        """Generate fixes for violations"""
        
        fixes = []
        
        for violation in violations:
            rule_id = violation['rule_id']
            if rule_id in self.fixes:
                fix_info = self.fixes[rule_id]
                fixes.append({
                    'rule_id': rule_id,
                    'violation_line': violation['line_number'],
                    'fix_type': fix_info['type'],
                    'pattern': fix_info['pattern'],
                    'replacement': fix_info['replacement'],
                    'description': fix_info['description'],
                    'explanation': f"Line {violation['line_number']}: {fix_info['description']}"
                })
        
        return {
            'config_type': config_type,
            'summary': {
                'total_violations': len(violations),
                'fixable_violations': len(fixes),
                'unfixable_violations': len(violations) - len(fixes)
            },
            'fixes': fixes
        }
    
    def apply_fixes(self, content: str, fixes: list) -> str:
        """Apply fixes to content"""
        
        fixed_content = content
        
        for fix in fixes:
            if fix['fix_type'] == 'replace':
                fixed_content = re.sub(
                    fix['pattern'], 
                    fix['replacement'], 
                    fixed_content, 
                    flags=re.IGNORECASE
                )
        
        return fixed_content

# Initialize components
analyzer = SimpleConfigAnalyzer()
remediator = SimpleRemediator()

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Config-to-PR Remediation Bot (Improved)',
        'version': '0.2.0',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    })

@app.route('/analyze', methods=['POST'])
def analyze_configuration():
    """Analyze configuration for compliance issues"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        config_content = data.get('config_content')
        config_type = data.get('config_type', 'terraform')
        
        if not config_content:
            return jsonify({'error': 'config_content is required'}), 400
        
        # Analyze configuration
        analysis_results = analyzer.analyze_content(config_content, config_type)
        
        logger.info(f"Analysis completed: {analysis_results['summary']['total_violations']} violations found")
        
        return jsonify(analysis_results)
        
    except Exception as e:
        logger.error(f"Error analyzing configuration: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/remediate', methods=['POST'])
def generate_remediation():
    """Generate remediation for violations"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        violations = data.get('violations', [])
        config_type = data.get('config_type', 'terraform')
        
        if not violations:
            return jsonify({'error': 'violations list is required'}), 400
        
        # Generate fixes
        remediation_results = remediator.generate_fixes(violations, config_type)
        
        logger.info(f"Generated {len(remediation_results['fixes'])} fixes")
        
        return jsonify(remediation_results)
        
    except Exception as e:
        logger.error(f"Error generating remediation: {str(e)}")
        return jsonify({'error': f'Remediation generation failed: {str(e)}'}), 500

@app.route('/fix', methods=['POST'])
def apply_fixes():
    """Apply fixes to configuration content"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        config_content = data.get('config_content')
        fixes = data.get('fixes', [])
        
        if not config_content or not fixes:
            return jsonify({'error': 'config_content and fixes are required'}), 400
        
        # Apply fixes
        fixed_content = remediator.apply_fixes(config_content, fixes)
        
        result = {
            'original_content': config_content,
            'fixed_content': fixed_content,
            'fixes_applied': len(fixes),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        logger.info(f"Applied {len(fixes)} fixes to configuration")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error applying fixes: {str(e)}")
        return jsonify({'error': f'Fix application failed: {str(e)}'}), 500

@app.route('/full-analysis', methods=['POST'])
def full_analysis():
    """Complete analysis and remediation in one call"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        config_content = data.get('config_content')
        config_type = data.get('config_type', 'terraform')
        apply_fixes_flag = data.get('apply_fixes', False)
        
        if not config_content:
            return jsonify({'error': 'config_content is required'}), 400
        
        # Step 1: Analyze
        analysis_results = analyzer.analyze_content(config_content, config_type)
        
        # Step 2: Generate fixes if violations found
        remediation_results = None
        fixed_content = None
        
        if analysis_results['violations']:
            remediation_results = remediator.generate_fixes(analysis_results['violations'], config_type)
            
            # Step 3: Apply fixes if requested
            if apply_fixes_flag and remediation_results['fixes']:
                fixed_content = remediator.apply_fixes(config_content, remediation_results['fixes'])
        
        result = {
            'analysis': analysis_results,
            'remediation': remediation_results,
            'fixed_content': fixed_content,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        logger.info(f"Full analysis completed: {len(analysis_results['violations'])} violations, {len(remediation_results['fixes']) if remediation_results else 0} fixes")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in full analysis: {str(e)}")
        return jsonify({'error': f'Full analysis failed: {str(e)}'}), 500

@app.route('/rules', methods=['GET'])
def get_rules():
    """Get available compliance rules"""
    try:
        rules = []
        for rule_id, rule_info in analyzer.patterns.items():
            rules.append({
                'rule_id': rule_id,
                'name': rule_info['name'],
                'severity': rule_info['severity'],
                'description': rule_info['description']
            })
        
        return jsonify({
            'total_rules': len(rules),
            'rules': rules
        })
        
    except Exception as e:
        logger.error(f"Error getting rules: {str(e)}")
        return jsonify({'error': f'Failed to get rules: {str(e)}'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting Improved Config-to-PR Remediation Bot on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)

