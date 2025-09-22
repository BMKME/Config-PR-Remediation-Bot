## 🤝 Contributing to the IaC Auto-Remediation Platform

We welcome and appreciate your contributions to the IaC Auto-Remediation Platform! Whether it's a bug report, a new feature, improved documentation, or a code fix, your help is invaluable. Please take a moment to review this document to make the contribution process as smooth as possible.

### Code of Conduct

This project and everyone participating in it is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [Your Contact Email/Website].

### How to Contribute

1.  **Fork the Repository**
    Start by forking the `ai-remediation-platform` repository to your GitHub account.

2.  **Clone Your Fork**
    Clone your forked repository to your local machine:
    ```bash
    git clone https://github.com/YOUR_GITHUB_USERNAME/ai-remediation-platform.git
    cd ai-remediation-platform
    ```

3.  **Create a New Branch**
    Create a new branch for your feature or bug fix. Use a descriptive name:
    ```bash
    git checkout -b feature/your-feature-name # For new features
    git checkout -b bugfix/issue-description  # For bug fixes
    ```

4.  **Set Up Your Development Environment**
    Follow the [Installation Guide](docs/installation.md) in the `README.md` to set up your local development environment.

5.  **Make Your Changes**
    Implement your feature or fix the bug. Ensure your code adheres to the project's coding standards and best practices.

6.  **Add Tests**
    For new features, add unit and/or integration tests. For bug fixes, add a test that reproduces the bug and then passes after your fix.

7.  **Run Tests**
    Ensure all existing tests pass, along with your new tests.
    ```bash
    pytest
    ```

8.  **Update Documentation**
    If your changes introduce new features or modify existing behavior, please update the relevant documentation (e.g., `README.md`, `docs/installation.md`, `docs/api_reference.md`).

9.  **Commit Your Changes**
    Commit your changes with a clear and concise commit message. Follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification (e.g., `feat: add new S3 public access rule`, `fix: resolve HCL parsing error`).

    ```bash
    git commit -m 'feat: add new feature X'
    ```

10. **Sign the Contributor License Agreement (CLA)**
    This project uses a Contributor License Agreement (CLA) to ensure that all contributions can be used under our dual-licensing model. You will be prompted to sign the CLA when you open your first Pull Request. Your contribution cannot be merged until the CLA is signed.

11. **Push to Your Fork**
    Push your changes to your forked repository:
    ```bash
    git push origin feature/your-feature-name
    ```

12. **Open a Pull Request (PR)**
    Go to the original `ai-remediation-platform` repository on GitHub and open a new Pull Request from your branch. Provide a detailed description of your changes, why they are necessary, and any relevant context.

### Dual Licensing and CLA

This project is dual-licensed under Apache 2.0 and a Commercial License. To ensure we can distribute your contributions under both licenses, we require all contributors to sign a Contributor License Agreement (CLA). This does not change your ownership of your contributions but grants us the necessary rights to include them in the project.

### Reporting Bugs

If you find a bug, please open an issue on GitHub. Provide as much detail as possible, including steps to reproduce, expected behavior, and actual behavior.

### Feature Requests

We'd love to hear your ideas for new features! Please open an issue on GitHub to propose new features or improvements.

Thank you for contributing to the IaC Auto-Remediation Platform!

