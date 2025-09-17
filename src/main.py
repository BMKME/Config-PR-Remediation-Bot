#!/usr/bin/env python3
"""
Config-to-PR Remediation Bot
Main application entry point
"""

import os
import sys
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Add src directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parsers.hcl import HCLParser
from parsers.yaml import YAMLParser
from parsers.json import JSONParser
from analyzer.engine import AnalyzerEngine
from remediator.generator import RemediationGenerator
from pr_bot.github import GitHubPRBot
from security.auth import AuthManager
from logging.setup import setup_logging

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Initialize components
hcl_parser = HCLParser()
yaml_parser = YAMLParser()
json_parser = JSONParser()
analyzer = AnalyzerEngine()
remediator = RemediationGenerator()
github_bot = GitHubPRBot()
auth_manager = AuthManager()

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Config-to-PR Remediation Bot',
        'version': '0.1.0'
    })

@app.route('/analyze', methods=['POST'])
def analyze_configuration():
    """
    Analyze configuration files for compliance issues
    
    Expected JSON payload:
    {
        "config_type": "terraform|kubernetes|json",
        "config_content": "configuration file content as string",
        "rules": ["rule1", "rule2"] (optional, defaults to all rules)
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        config_type = data.get('config_type')
        config_content = data.get('config_content')
        rules = data.get('rules', [])
        
        if not config_type or not config_content:
            return jsonify({'error': 'config_type and config_content are required'}), 400
        
        # Parse configuration based on type
        if config_type == 'terraform':
            parsed_config = hcl_parser.parse(config_content)
        elif config_type == 'kubernetes':
            parsed_config = yaml_parser.parse(config_content)
        elif config_type == 'json':
            parsed_config = json_parser.parse(config_content)
        else:
            return jsonify({'error': 'Unsupported config_type. Use: terraform, kubernetes, or json'}), 400
        
        # Analyze for compliance issues
        analysis_results = analyzer.analyze(parsed_config, config_type, rules)
        
        logger.info(f"Analysis completed for {config_type} configuration. Found {len(analysis_results.get('violations', []))} violations.")
        
        return jsonify(analysis_results)
        
    except Exception as e:
        logger.error(f"Error analyzing configuration: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/remediate', methods=['POST'])
def generate_remediation():
    """
    Generate remediation code for identified violations
    
    Expected JSON payload:
    {
        "violations": [list of violations from analyze endpoint],
        "config_type": "terraform|kubernetes|json"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        violations = data.get('violations', [])
        config_type = data.get('config_type')
        
        if not violations or not config_type:
            return jsonify({'error': 'violations and config_type are required'}), 400
        
        # Generate remediation code
        remediation_results = remediator.generate_fixes(violations, config_type)
        
        logger.info(f"Generated {len(remediation_results.get('fixes', []))} remediation fixes.")
        
        return jsonify(remediation_results)
        
    except Exception as e:
        logger.error(f"Error generating remediation: {str(e)}")
        return jsonify({'error': f'Remediation generation failed: {str(e)}'}), 500

@app.route('/create-pr', methods=['POST'])
def create_pull_request():
    """
    Create a pull request with remediation code
    
    Expected JSON payload:
    {
        "repository": "owner/repo-name",
        "branch": "feature-branch-name",
        "title": "PR title",
        "description": "PR description",
        "fixes": [list of fixes from remediate endpoint],
        "files": [{"path": "file/path", "content": "file content"}]
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        repository = data.get('repository')
        branch = data.get('branch')
        title = data.get('title')
        description = data.get('description')
        fixes = data.get('fixes', [])
        files = data.get('files', [])
        
        if not all([repository, branch, title, fixes]):
            return jsonify({'error': 'repository, branch, title, and fixes are required'}), 400
        
        # Create pull request
        pr_result = github_bot.create_pr(
            repository=repository,
            branch=branch,
            title=title,
            description=description,
            fixes=fixes,
            files=files
        )
        
        logger.info(f"Created pull request: {pr_result.get('pr_url')}")
        
        return jsonify(pr_result)
        
    except Exception as e:
        logger.error(f"Error creating pull request: {str(e)}")
        return jsonify({'error': f'PR creation failed: {str(e)}'}), 500

@app.route('/rules', methods=['GET'])
def get_available_rules():
    """Get list of available compliance rules"""
    try:
        rules = analyzer.get_available_rules()
        return jsonify({'rules': rules})
    except Exception as e:
        logger.error(f"Error getting rules: {str(e)}")
        return jsonify({'error': f'Failed to get rules: {str(e)}'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting Config-to-PR Remediation Bot on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)

