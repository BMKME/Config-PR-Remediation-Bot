
# 🔒 Config-to-PR Remediation Bot

## Automated Compliance Scanner & Remediation System

![Bot Logo](https://via.placeholder.com/800x200/007acc/ffffff?text=Config-to-PR+Remediation+Bot)

## 🚀 Overview

The Config-to-PR Remediation Bot is an advanced, AI-powered system designed to automatically detect and fix misconfigurations in infrastructure-as-code (IaC) files. It ensures continuous compliance with security benchmarks (CIS, NIST, etc.) by analyzing configuration files, generating remediation code, and creating automated Pull Requests (PRs) to apply the fixes. This bot significantly reduces manual effort, accelerates security posture improvements, and maintains a robust audit trail.

### Key Features:

*   **Automated Misconfiguration Detection**: Scans Terraform HCL, Kubernetes YAML, and JSON configurations for violations against predefined compliance rules.
*   **Intelligent Remediation Generation**: Automatically generates code to fix identified misconfigurations.
*   **Automated Pull Request Creation**: Creates well-structured GitHub Pull Requests with detailed descriptions, labels, and rollback instructions.
*   **Scalable Rule Engine**: Supports multiple compliance frameworks (CIS, NIST, SOC2, ISO27001, COBIT, OCTAVE) with an extensible rule definition system.
*   **Multi-File & Repository Scanning**: Capable of scanning entire repositories and multiple configuration files in parallel.
*   **Idempotency Checks**: Prevents redundant PRs by checking if fixes have already been applied.
*   **Enhanced Security & Auditability**: Includes comprehensive audit logging, secure branch naming, and detailed PR metadata.
*   **Web Dashboard**: A user-friendly web interface for real-time scanning, analysis, and system monitoring.
*   **Extensible Architecture**: Designed for easy integration with CI/CD pipelines, Slack/webhook notifications, and custom compliance rules.

## ⚙️ Installation Guide

Follow these steps to set up and run the Config-to-PR Remediation Bot locally or in a development environment.

### Prerequisites

*   Python 3.8+
*   `pip` (Python package installer)
*   `git`
*   A GitHub Personal Access Token (PAT) with `repo` scope permissions. [Generate one here](https://github.com/settings/tokens/new).

### Step-by-Step Setup

1.  **Clone the Repository**

    First, clone the bot's GitHub repository to your local machine:

    ```bash
    git clone https://github.com/BMKME/Config-PR-Remediation-Bot.git
    cd Config-PR-Remediation-Bot
    ```

2.  **Create a Virtual Environment** (Recommended)

    It's good practice to use a virtual environment to manage dependencies:

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install Dependencies**

    Install all required Python packages:

    ```bash
    pip install -r requirements.txt
    ```

    _Note: The `requirements.txt` file will be updated with all necessary packages including `hcl2`, `PyGithub`, `Flask`, `Flask-CORS`, `python-dotenv`, `PyYAML`, and `requests`._

4.  **Configure Environment Variables**

    The bot requires a GitHub Personal Access Token for PR creation. Create a `.env` file in the root directory of the project based on `.env.example`:

    ```bash
    cp .env.example .env
    ```

    Edit the `.env` file and add your GitHub PAT:

    ```ini
    GITHUB_TOKEN="your_github_personal_access_token_here"
    FLASK_DEBUG="True" # Set to False for production
    PORT="5000"
    ```

    Replace `"your_github_personal_access_token_here"` with your actual GitHub Personal Access Token.

## 🚀 Usage

The bot can be interacted with via its Flask API or through its web dashboard.

### 1. Starting the Bot

To start the Flask application, run:

```bash
python enhanced_main.py
```

The bot will start on `http://0.0.0.0:5000` (or the port specified in your `.env` file).

### 2. Web Dashboard

Access the interactive web dashboard by navigating to `http://localhost:5000/dashboard` in your web browser.

From the dashboard, you can:

*   **Analyze Configuration**: Paste configuration content (Terraform, Kubernetes YAML, JSON) and get instant compliance analysis.
*   **Analyze & Generate Fixes**: Get analysis results along with generated remediation code.
*   **Scan Repository**: (Future/Advanced) Initiate a scan of a local repository path for compliance issues across multiple files.

### 3. API Endpoints

The bot exposes several REST API endpoints for programmatic interaction:

*   **`GET /`**: Health check endpoint. Returns the bot's status and component availability.

    ```bash
    curl http://localhost:5000/
    ```

*   **`GET /dashboard`**: Serves the web dashboard HTML.

*   **`POST /analyze`**: Analyzes provided configuration content for compliance violations.

    **Request Body (JSON):**
    ```json
    {
        "config_content": "resource \"aws_s3_bucket\" \"my_bucket\" { acl = \"public-read\" }",
        "config_type": "terraform" 
    }
    ```

    **Response (JSON):** Contains violations found and a compliance summary.

*   **`POST /full-analysis`**: (Not explicitly shown in `enhanced_main.py` but implied by dashboard `analyzeWithFixes` function) Analyzes configuration and generates fixes.

    **Request Body (JSON):**
    ```json
    {
        "config_content": "resource \"aws_s3_bucket\" \"my_bucket\" { acl = \"public-read\" }",
        "config_type": "terraform",
        "apply_fixes": true
    }
    ```

    **Response (JSON):** Contains analysis, remediation details, and `fixed_content`.

*   **`POST /scan-repository`**: Scans a specified local repository path for compliance issues across multiple files.

    **Request Body (JSON):**
    ```json
    {
        "repo_path": "/path/to/your/repo",
        "config_types": ["terraform", "kubernetes"],
        "exclude_patterns": [".git/*", "node_modules/*"]
    }
    ```

    **Response (JSON):** Detailed scan results and summary.

*   **`POST /create-pr`**: Creates an enhanced Pull Request on GitHub with generated fixes.

    **Request Body (JSON):**
    ```json
    {
        "repository": "your-github-username/your-repo-name",
        "title": "Automated Compliance Fix: S3 Public Access",
        "description": "Fixes public S3 bucket ACL and enables public access block.",
        "fixes": [
            { "rule_id": "cis_2_1_2", "severity": "HIGH", "description": "S3 public ACL" }
        ],
        "files": [
            {
                "path": "path/to/misconfigured.tf",
                "content": "resource \"aws_s3_bucket\" \"my_bucket\" { acl = \"private\" }"
            }
        ],
        "dry_run": false,
        "notify_webhook": "https://your-slack-webhook-url.com"
    }
    ```

    **Response (JSON):** PR details or dry-run preview.

*   **`GET /rules`**: Retrieves information about the loaded compliance rules and frameworks.

    ```bash
    curl http://localhost:5000/rules
    ```

*   **`GET /audit-log`**: Retrieves the internal audit log of GitHub actions performed by the bot.

    ```bash
    curl http://localhost:5000/audit-log
    ```

## 💡 Advanced Features & Customization

### Scalable Rule Engine

The bot uses a `ScalableRuleEngine` (`src/rules/rule_engine.py`) that allows for easy definition and management of compliance rules. Rules are defined as `ComplianceRule` objects, specifying `rule_id`, `severity`, `framework`, `resource_types`, and `check_function`/`fix_function` references.

*   **Adding New Rules**: You can extend the `_load_built_in_rules` method or load rules from external YAML/JSON files using `load_rules_from_file`.
*   **Custom Checkers/Fixers**: Implement `RuleChecker` and `RuleFixer` abstract classes to define custom logic for detecting and fixing violations.

### Multi-File Scanner

The `MultiFileScanner` (`src/scanner/multi_file_scanner.py`) can scan entire directories or repositories. It supports parallel processing for efficiency and can be configured to scan specific file types and exclude patterns.

### Enhanced GitHub PR Bot

The `EnhancedGitHubPRBot` (`src/pr_bot/enhanced_github.py`) provides robust GitHub integration:

*   **Idempotency**: Prevents duplicate PRs for the same fixes.
*   **Branch Naming**: Generates unique branch names using timestamps and UUIDs.
*   **PR Labels**: Automatically adds labels like `security`, `auto-fix`, `compliance`, and severity-based labels.
*   **Detailed PR Body**: Includes summaries of fixes, files modified, testing instructions, rollback guidance, and audit trail links.
*   **Error Handling**: Robust error handling for GitHub API interactions.
*   **Audit Logging**: Logs all significant actions for compliance and traceability.
*   **Webhook Notifications**: Can send notifications to external systems (e.g., Slack) upon PR creation.

### Security Considerations

*   **Least Privilege**: It is highly recommended to use a GitHub App with minimal necessary permissions instead of a Personal Access Token for production deployments.
*   **Secrets Management**: Environment variables (`.env`) are used for local development. For production, integrate with a secure secrets management solution (e.g., AWS Secrets Manager, HashiCorp Vault).
*   **Input Validation**: All API endpoints perform basic input validation.

## 🤝 Contributing

We welcome contributions to enhance the Config-to-PR Remediation Bot! Please follow these steps:

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/your-feature-name`).
3.  Implement your changes and add relevant tests.
4.  Ensure your code adheres to the project's coding standards.
5.  Commit your changes (`git commit -m 'feat: Add new feature X'`).
6.  Push to the branch (`git push origin feature/your-feature-name`).
7.  Open a Pull Request, describing your changes in detail.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.



