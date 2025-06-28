# LeakHawk

<<<<<<< HEAD
Runtime Secrets Detection for AWS Lambda and ECS environments.

## Overview

LeakHawk is a Python-based tool that helps developers detect and protect against exposed secrets in AWS Lambda functions and ECS tasks. It provides real-time monitoring of environment variables and sends instant alerts to Slack when secrets are accessed during runtime.

## Features

- **CLI-based scanning** of AWS Lambda functions and ECS tasks for secrets in environment variables
- **Runtime protection** that monitors access to sensitive environment variables
- **Real-time Slack alerts** when secrets are accessed during execution
- **Detailed reporting** of which AWS account and resources contain secrets
- **Environment variable scanning** to detect common secret patterns
- **Custom regex patterns** for organization-specific secret detection
- **Predefined patterns** for hundreds of common API keys, tokens, and credentials

## Installation

```sh
pip install leakhawk
```

## Usage

### Configuration

Set up your Slack webhook for notifications:

```sh
leakhawk config --set-slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### Scanning for Secrets

Scan Lambda functions in a specific region:

```sh
leakhawk scan --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --region us-east-1 --lambda
```

Scan ECS tasks:

```sh
leakhawk scan --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --region us-east-1 --ecs
```

You can also use environment variables for AWS credentials:

```sh
export AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY
export AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY
leakhawk scan --region us-east-1
```

### Deploying Runtime Protection

Protect a Lambda function:

```sh
leakhawk protect --resource-type lambda --resource-id my-function-name --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

Protect an ECS task:

```sh
leakhawk protect --resource-type ecs --resource-id my-task-definition-arn --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### Managing Custom Regex Patterns

Add a custom regex pattern:

```sh
leakhawk pattern add --pattern "my_company_secret_.*" --name "Company Secret" --severity critical
```

List all custom patterns:

```sh
leakhawk pattern list
```

Remove a custom pattern:

```sh
leakhawk pattern remove --pattern "my_company_secret_.*"
```

Import patterns from a YAML file:

```sh
leakhawk pattern import --file patterns.yaml
```

Export patterns to a YAML file:

```sh
leakhawk pattern export --file my_patterns.yaml
```

### Importing Predefined Patterns

LeakHawk comes with a script to import predefined patterns:

```sh
python import_patterns.py patterns.yaml
```

## How It Works

LeakHawk uses two main approaches to detect secrets:

1. **Static scanning**: Analyzes environment variables in Lambda functions and ECS tasks to identify potential secrets based on naming patterns.

2. **Runtime protection**: Injects monitoring code that intercepts access to environment variables during execution and sends real-time alerts when sensitive variables are accessed.

The runtime protection works by:

- Creating a proxy around `os.environ` that monitors access to variables
- Detecting sensitive variable names using pattern matching
- Sending real-time alerts to Slack with detailed information
- Optionally masking secret values or blocking execution

### Custom Pattern Detection

LeakHawk allows you to define your own regex patterns for detecting organization-specific secrets. These patterns are stored in your local configuration and are used alongside the built-in patterns during scanning and runtime protection.

For example, if your organization uses a specific naming convention for API keys like `MYCOMPANY_API_KEY_*`, you can add a custom pattern to detect these:

```bash
leakhawk pattern add --pattern "mycompany_api_key_.*" --name "MyCompany API Key" --severity critical
```

## License

MIT
=======
<div align="center">

![LeakHawk Logo](https://via.placeholder.com/200x100/2E86AB/FFFFFF?text=LeakHawk)

**Runtime Secrets Detection for AWS Lambda and ECS environments**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![AWS](https://img.shields.io/badge/AWS-Lambda%20%7C%20ECS-orange.svg)](https://aws.amazon.com)

</div>

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Scanning for Secrets](#scanning-for-secrets)
  - [Runtime Protection](#runtime-protection)
  - [Pattern Management](#pattern-management)
- [Advanced Usage](#advanced-usage)
- [Architecture](#architecture)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Overview

LeakHawk is a comprehensive Python-based security tool designed to detect and protect against exposed secrets in AWS Lambda functions and ECS tasks. It provides both static analysis of environment variables and real-time runtime protection with instant alerting capabilities.

### Why LeakHawk?

- **Proactive Security**: Detect secrets before they cause security incidents
- **Real-time Monitoring**: Get instant alerts when secrets are accessed during runtime
- **Comprehensive Coverage**: Supports both Lambda and ECS environments
- **Customizable**: Add your own patterns for organization-specific secrets
- **Easy Integration**: Simple CLI interface with Slack integration

## Features

### 🔍 **Static Scanning**
- CLI-based scanning of AWS Lambda functions and ECS tasks
- Detection of secrets in environment variables using pattern matching
- Support for hundreds of predefined secret patterns
- Custom regex patterns for organization-specific secrets
- Detailed reporting with severity levels

### 🛡️ **Runtime Protection**
- Real-time monitoring of environment variable access
- Automatic injection of protection code into Lambda functions
- Configurable response actions (alert, mask, or block)
- Integration with AWS Lambda layers

### 📊 **Reporting & Alerting**
- Detailed reports showing which resources contain secrets
- Real-time Slack notifications with contextual information
- JSON and table output formats
- Filtering and exclusion capabilities

### ⚙️ **Configuration Management**
- Import/export pattern libraries
- Persistent configuration storage
- Support for multiple AWS profiles
- Customizable severity levels

## Prerequisites

### System Requirements
- **Python**: 3.8 or higher
- **Operating System**: Linux, macOS, or Windows
- **Memory**: Minimum 512MB RAM
- **Network**: Internet access for AWS API calls

### AWS Requirements
- **AWS Account**: Valid AWS account with appropriate permissions
- **IAM Permissions**: The following permissions are required:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "lambda:ListFunctions",
          "lambda:GetFunction",
          "lambda:UpdateFunctionConfiguration",
          "ecs:ListTaskDefinitions",
          "ecs:DescribeTaskDefinition",
          "sts:GetCallerIdentity"
        ],
        "Resource": "*"
      }
    ]
  }
  ```

### Optional Requirements
- **Slack Workspace**: For real-time notifications (webhook URL required)
- **AWS CLI**: For easier credential management

## Installation

### Method 1: Install from PyPI (Recommended)

```bash
pip install leakhawk
```

### Method 2: Install from Source

```bash
# Clone the repository
git clone https://github.com/your-org/leakhawk.git
cd leakhawk

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  
# On Windows: 
source venv\Scripts\activate

# Install in development mode
pip install -e .
```

### Method 3: Using Virtual Environment

```bash
# Create and activate virtual environment
python -m venv leakhawk-env
source leakhawk-env/bin/activate  # On Windows: leakhawk-env\Scripts\activate

# Install LeakHawk
pip install leakhawk

# Verify installation
leakhawk --help
```

### Verify Installation

```bash
# Check if LeakHawk is installed correctly
leakhawk --version

# View available commands
leakhawk --help
```

## Quick Start

### 1. Set up AWS Credentials

```bash
# Option 1: Environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1

# Option 2: AWS CLI (if installed)
aws configure

# Option 3: Use IAM roles (for EC2/Lambda execution)
```

### 2. Configure Slack Notifications (Optional)

```bash
leakhawk config --set-slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### 3. Run Your First Scan

```bash
# Scan Lambda functions in us-east-1
leakhawk scan --region us-east-1 --lambda

# Scan with higher severity threshold to reduce noise
leakhawk scan --region us-east-1 --lambda --min-severity high
```

### 4. View Results

```bash
# Example output:
RESOURCE NAME                  TYPE       AWS ACCOUNT     ENV VARIABLE              SEVERITY   VALUE PREVIEW
-------------------------------------------------------------------------------------------------------------
my-payment-function           lambda     123456789012    API_KEY                   HIGH       sk-1234567890abcdef...
user-service-lambda           lambda     123456789012    DATABASE_PASSWORD         CRITICAL   p@ssw0rd123...
```

## Configuration

### Global Configuration

LeakHawk stores configuration in `~/.leakhawk/config.json`. You can manage settings using the CLI:

```bash
# View current configuration
leakhawk config

# Set Slack webhook
leakhawk config --set-slack-webhook https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX

# Set default AWS profile
leakhawk config --set-aws-profile production
```

### Configuration File Structure

```json
{
  "slack_webhook": "https://hooks.slack.com/services/...",
  "aws_profile": "default",
  "custom_patterns": [
    {
      "pattern": "mycompany_api_.*",
      "name": "MyCompany API Key",
      "severity": "critical"
    }
  ]
}
```

## Usage

### Scanning for Secrets

#### Basic Scanning

```bash
# Scan Lambda functions
leakhawk scan --region us-east-1 --lambda

# Scan ECS tasks
leakhawk scan --region us-east-1 --ecs

# Scan both Lambda and ECS
leakhawk scan --region us-east-1

# Scan multiple regions
leakhawk scan --region us-east-1 --lambda
leakhawk scan --region eu-west-1 --lambda
```

#### Advanced Scanning Options

```bash
# Filter by severity level
leakhawk scan --region us-east-1 --min-severity critical

# Exclude configuration references
leakhawk scan --region us-east-1 --exclude-references

# Exclude specific patterns
leakhawk scan --region us-east-1 --exclude-pattern ".*_TABLE_NAME" --exclude-pattern ".*_URL"

# Output as JSON for programmatic processing
leakhawk scan --region us-east-1 --output json > scan_results.json

# Verify findings to reduce false positives
leakhawk scan --region us-east-1 --verify
```

#### Using AWS Credentials

```bash
# Method 1: Command line arguments
leakhawk scan --access-key AKIA... --secret-key ... --region us-east-1

# Method 2: Environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
leakhawk scan --region us-east-1

# Method 3: AWS profiles
leakhawk config --set-aws-profile production
leakhawk scan --region us-east-1

# Method 4: Session tokens (for temporary credentials)
leakhawk scan --access-key AKIA... --secret-key ... --session-token ... --region us-east-1
```

### Runtime Protection

#### Protecting Lambda Functions

```bash
# Basic protection
leakhawk protect --resource-type lambda --resource-id my-function-name

# With custom Slack webhook
leakhawk protect \
  --resource-type lambda \
  --resource-id my-function-name \
  --slack-webhook https://hooks.slack.com/services/...

# With specific AWS credentials
leakhawk protect \
  --access-key AKIA... \
  --secret-key ... \
  --resource-type lambda \
  --resource-id my-function-name \
  --region us-west-2
```

#### Protecting ECS Tasks

```bash
# Protect ECS task definition
leakhawk protect \
  --resource-type ecs \
  --resource-id arn:aws:ecs:us-east-1:123456789012:task-definition/my-task:1

# With notifications
leakhawk protect \
  --resource-type ecs \
  --resource-id my-task-definition \
  --slack-webhook https://hooks.slack.com/services/...
```

### Pattern Management

#### Adding Custom Patterns

```bash
# Add a simple pattern
leakhawk pattern add \
  --pattern "mycompany_api_key_.*" \
  --name "MyCompany API Key" \
  --severity critical

# Add multiple patterns
leakhawk pattern add --pattern "internal_token_.*" --name "Internal Token" --severity high
leakhawk pattern add --pattern ".*_private_key" --name "Private Key" --severity critical
leakhawk pattern add --pattern "oauth_secret_.*" --name "OAuth Secret" --severity medium
```

#### Managing Pattern Libraries

```bash
# List all custom patterns
leakhawk pattern list

# Import patterns from YAML file
leakhawk pattern import --file company_patterns.yaml

# Export current patterns
leakhawk pattern export --file backup_patterns.yaml

# Remove a specific pattern
leakhawk pattern remove --pattern "old_pattern_.*"
```

#### Pattern File Format

Create a `patterns.yaml` file:

```yaml
patterns:
  - pattern:
      name: "Company API Key"
      regex: "company_api_[A-Za-z0-9]{32}"
      confidence: "critical"
      description: "Internal company API keys"
      
  - pattern:
      name: "Database Password"
      regex: "(?i)db_pass(word)?\\s*[=:]\\s*([A-Za-z0-9@#$%^&*]{8,})"
      confidence: "high"
      description: "Database passwords in environment variables"
```

## Advanced Usage

### Filtering and Exclusions

```bash
# Complex filtering example
leakhawk scan \
  --region us-east-1 \
  --min-severity medium \
  --exclude-references \
  --exclude-pattern ".*_TABLE_NAME" \
  --exclude-pattern ".*_BUCKET_NAME" \
  --exclude-pattern ".*_QUEUE_URL" \
  --verify

# Scan specific function patterns
leakhawk scan \
  --region us-east-1 \
  --lambda \
  --exclude-pattern "test-.*" \
  --exclude-pattern "dev-.*"
```

### Batch Operations

```bash
# Scan multiple regions and combine results
regions=("us-east-1" "us-west-2" "eu-west-1")
for region in "${regions[@]}"; do
  echo "Scanning region: $region"
  leakhawk scan --region "$region" --output json >> all_results.json
done

# Protect multiple functions
functions=("payment-processor" "user-service" "notification-service")
for func in "${functions[@]}"; do
  leakhawk protect --resource-type lambda --resource-id "$func"
done
```

### Integration with CI/CD

```bash
#!/bin/bash
# ci_security_scan.sh

set -e

echo "Running LeakHawk security scan..."

# Run scan and capture results
leakhawk scan \
  --region us-east-1 \
  --min-severity high \
  --exclude-references \
  --output json > scan_results.json

# Check if any high-severity secrets were found
high_severity_count=$(jq '[.[] | select(.severity == "high" or .severity == "critical")] | length' scan_results.json)

if [ "$high_severity_count" -gt 0 ]; then
  echo "❌ Found $high_severity_count high-severity secrets!"
  echo "Please review and fix before deploying:"
  jq -r '.[] | select(.severity == "high" or .severity == "critical") | "\(.resource_name): \(.environment_variable) (\(.severity))"' scan_results.json
  exit 1
else
  echo "✅ No high-severity secrets found"
fi
```

### Programmatic Usage

```python
#!/usr/bin/env python3
"""
Example: Using LeakHawk programmatically
"""

import json
import subprocess
import sys

def scan_aws_resources(region, min_severity="medium"):
    """Scan AWS resources for secrets."""
    cmd = [
        "leakhawk", "scan",
        "--region", region,
        "--min-severity", min_severity,
        "--exclude-references",
        "--output", "json"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running LeakHawk: {e}")
        return []

def main():
    """Main function."""
    regions = ["us-east-1", "us-west-2", "eu-west-1"]
    all_findings = []
    
    for region in regions:
        print(f"Scanning {region}...")
        findings = scan_aws_resources(region)
        all_findings.extend(findings)
    
    # Process findings
    critical_findings = [f for f in all_findings if f["severity"] == "critical"]
    
    if critical_findings:
        print(f"🚨 Found {len(critical_findings)} critical secrets!")
        for finding in critical_findings:
            print(f"  - {finding['resource_name']}: {finding['environment_variable']}")
        sys.exit(1)
    else:
        print("✅ No critical secrets found")

if __name__ == "__main__":
    main()
>>>>>>> cb4ca57 (Initial commit with updated README.md)
