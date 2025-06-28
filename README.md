# LeakHawk

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
