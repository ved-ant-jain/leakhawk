#!/usr/bin/env python3
"""
LeakHawk - Runtime Secrets Detection for AWS

A tool to detect and monitor secrets in AWS Lambda and ECS environments.
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, List, Optional, Any
import re

from leakhawk.aws_scanner import AWSScanner
from leakhawk.runtime_protection import RuntimeProtection
from leakhawk.slack_notifier import SlackNotifier
from leakhawk.config import LeakHawkConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("leakhawk")


def setup_argparse() -> argparse.ArgumentParser:
    """Set up command line argument parser."""
    parser = argparse.ArgumentParser(
        description="LeakHawk - Runtime Secrets Detection for AWS"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan AWS resources for secrets")
    scan_parser.add_argument(
        "--access-key", 
        help="AWS Access Key ID"
    )
    scan_parser.add_argument(
        "--secret-key", 
        help="AWS Secret Access Key"
    )
    scan_parser.add_argument(
        "--session-token", 
        help="AWS Session Token (optional)"
    )
    scan_parser.add_argument(
        "--region", 
        default="us-east-1",
        help="AWS Region to scan"
    )
    scan_parser.add_argument(
        "--output", 
        choices=["json", "table"], 
        default="table",
        help="Output format"
    )
    scan_parser.add_argument(
        "--lambda", 
        dest="scan_lambda",
        action="store_true", 
        help="Scan Lambda functions"
    )
    scan_parser.add_argument(
        "--ecs", 
        dest="scan_ecs",
        action="store_true", 
        help="Scan ECS tasks"
    )
    scan_parser.add_argument(
        "--exclude-pattern", 
        action="append",
        help="Exclude findings matching this pattern (can be used multiple times)"
    )
    scan_parser.add_argument(
        "--min-severity", 
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity level to include in results"
    )
    scan_parser.add_argument(
        "--exclude-references",
        action="store_true",
        help="Exclude environment variables that reference secrets rather than containing them"
    )
    scan_parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify findings to reduce false positives"
    )
    
    # Protect command
    protect_parser = subparsers.add_parser(
        "protect", 
        help="Deploy runtime protection to AWS resources"
    )
    protect_parser.add_argument(
        "--access-key", 
        help="AWS Access Key ID"
    )
    protect_parser.add_argument(
        "--secret-key", 
        help="AWS Secret Access Key"
    )
    protect_parser.add_argument(
        "--session-token", 
        help="AWS Session Token (optional)"
    )
    protect_parser.add_argument(
        "--region", 
        default="us-east-1",
        help="AWS Region"
    )
    protect_parser.add_argument(
        "--resource-type", 
        choices=["lambda", "ecs"],
        required=True,
        help="Resource type to protect"
    )
    protect_parser.add_argument(
        "--resource-id", 
        required=True,
        help="Resource ID to protect (function name for Lambda, task definition ARN for ECS)"
    )
    protect_parser.add_argument(
        "--slack-webhook", 
        help="Slack webhook URL for notifications"
    )
    
    # Config command
    config_parser = subparsers.add_parser(
        "config", 
        help="Configure LeakHawk settings"
    )
    config_parser.add_argument(
        "--set-slack-webhook", 
        help="Set Slack webhook URL"
    )
    config_parser.add_argument(
        "--set-aws-profile", 
        help="Set AWS profile name"
    )
    
    # Pattern command
    pattern_parser = subparsers.add_parser(
        "pattern", 
        help="Manage custom regex patterns for secret detection"
    )
    pattern_subparsers = pattern_parser.add_subparsers(dest="pattern_command", help="Pattern command")
    
    # Add pattern command
    add_pattern_parser = pattern_subparsers.add_parser(
        "add", 
        help="Add a custom regex pattern"
    )
    add_pattern_parser.add_argument(
        "--pattern", 
        required=True,
        help="Regex pattern string"
    )
    add_pattern_parser.add_argument(
        "--name", 
        required=True,
        help="Human-readable name for the pattern"
    )
    add_pattern_parser.add_argument(
        "--severity", 
        choices=["critical", "high", "medium", "low"],
        default="high",
        help="Severity level"
    )
    
    # Remove pattern command
    remove_pattern_parser = pattern_subparsers.add_parser(
        "remove", 
        help="Remove a custom regex pattern"
    )
    remove_pattern_parser.add_argument(
        "--pattern", 
        required=True,
        help="Regex pattern string to remove"
    )
    
    # List patterns command
    list_patterns_parser = pattern_subparsers.add_parser(
        "list", 
        help="List all custom regex patterns"
    )
    
    # Import patterns command
    import_patterns_parser = pattern_subparsers.add_parser(
        "import", 
        help="Import regex patterns from a YAML file"
    )
    import_patterns_parser.add_argument(
        "--file", 
        required=True,
        help="Path to YAML file with patterns"
    )
    
    # Export patterns command
    export_patterns_parser = pattern_subparsers.add_parser(
        "export", 
        help="Export regex patterns to a YAML file"
    )
    export_patterns_parser.add_argument(
        "--file", 
        help="Path to export patterns to (default: ~/.leakhawk/patterns.yaml)"
    )
    
    return parser


def handle_scan_command(args: argparse.Namespace) -> None:
    """Handle the scan command."""
    # Get AWS credentials
    access_key = args.access_key or os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = args.secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY")
    session_token = args.session_token or os.environ.get("AWS_SESSION_TOKEN")
    
    if not access_key or not secret_key:
        logger.error("AWS credentials not provided. Use --access-key and --secret-key or set environment variables.")
        sys.exit(1)
    
    # Get custom patterns from config
    config = LeakHawkConfig()
    custom_patterns = config.get_custom_patterns()
    
    # Create AWS scanner
    scanner = AWSScanner(
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
        region=args.region,
        custom_patterns=custom_patterns
    )
    
    # Determine what to scan
    scan_lambda = args.scan_lambda
    scan_ecs = args.scan_ecs
    
    # If neither is specified, scan both
    if not scan_lambda and not scan_ecs:
        scan_lambda = True
        scan_ecs = True
    
    # Perform scan
    results = []
    
    if scan_lambda:
        logger.info(f"Scanning Lambda functions in region {args.region}...")
        lambda_results = scanner.scan_lambda_functions()
        results.extend(lambda_results)
        logger.info(f"Found {len(lambda_results)} Lambda functions with potential secrets")
    
    if scan_ecs:
        logger.info(f"Scanning ECS tasks in region {args.region}...")
        ecs_results = scanner.scan_ecs_tasks()
        results.extend(ecs_results)
        logger.info(f"Found {len(ecs_results)} ECS tasks with potential secrets")
    
    # Apply filters to results
    filtered_results = []
    severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_severity_level = severity_levels.get(args.min_severity, 0)

    for result in results:
        # Apply severity filter
        result_severity = result["severity"].lower()
        if severity_levels.get(result_severity, 0) < min_severity_level:
            continue
        
        # Apply pattern exclusion filter
        if args.exclude_pattern:
            skip = False
            for pattern in args.exclude_pattern:
                if re.search(pattern, result["environment_variable"], re.IGNORECASE):
                    skip = True
                    break
            if skip:
                continue
        
        # Apply reference exclusion filter
        if args.exclude_references and result.get("is_reference", False):
            continue
        
        filtered_results.append(result)

    # Replace original results with filtered results
    results = filtered_results
    
    # Output results
    if args.output == "json":
        print(json.dumps(results, indent=2))
    else:
        if not results:
            print("No secrets found in the scanned resources.")
            return
        
        # Print table header with value preview
        print("\n{:<30} {:<10} {:<15} {:<30} {:<10} {:<25}".format(
            "RESOURCE NAME", "TYPE", "AWS ACCOUNT", "ENV VARIABLE", "SEVERITY", "VALUE PREVIEW"
        ))
        print("-" * 125)

        # Print table rows
        for result in results:
            print("{:<30} {:<10} {:<15} {:<30} {:<10} {:<25}".format(
                result["resource_name"][:30],
                result["resource_type"],
                result["account_id"][:15],
                result["environment_variable"][:30],
                result["severity"].upper(),
                result.get("value_preview", "")[:25]
            ))
        
        print("\nTotal findings:", len(results))
        print("\nTip: Use --exclude-references to filter out configuration paths")
        print("Tip: Use --min-severity high to see only high-priority findings")


def handle_protect_command(args: argparse.Namespace) -> None:
    """Handle the protect command."""
    # Get AWS credentials
    access_key = args.access_key or os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = args.secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY")
    session_token = args.session_token or os.environ.get("AWS_SESSION_TOKEN")
    
    if not access_key or not secret_key:
        logger.error("AWS credentials not provided. Use --access-key and --secret-key or set environment variables.")
        sys.exit(1)
    
    # Get custom patterns from config
    config = LeakHawkConfig()
    custom_patterns = config.get_custom_patterns()
    
    # Create AWS scanner
    scanner = AWSScanner(
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
        region=args.region,
        custom_patterns=custom_patterns
    )
    
    # Create runtime protection
    protection = RuntimeProtection(custom_patterns=custom_patterns)
    
    # Get account ID
    account_id = scanner.get_account_id()
    
    # Deploy protection
    if args.resource_type == "lambda":
        logger.info(f"Deploying protection to Lambda function {args.resource_id}...")
        success = protection.protect_lambda_function(
            scanner=scanner,
            function_name=args.resource_id,
            slack_webhook=args.slack_webhook,
            account_id=account_id,
            region=args.region
        )
    else:  # ecs
        logger.info(f"Deploying protection to ECS task {args.resource_id}...")
        success = protection.protect_ecs_task(
            scanner=scanner,
            task_definition_arn=args.resource_id,
            slack_webhook=args.slack_webhook,
            account_id=account_id,
            region=args.region
        )
    
    if success:
        logger.info(f"Successfully deployed protection to {args.resource_type} {args.resource_id}")
    else:
        logger.error(f"Failed to deploy protection to {args.resource_type} {args.resource_id}")
        sys.exit(1)


def handle_config_command(args: argparse.Namespace) -> None:
    """Handle the config command."""
    config = LeakHawkConfig()
    
    if args.set_slack_webhook:
        config.set_slack_webhook(args.set_slack_webhook)
        logger.info("Slack webhook URL configured successfully")
    
    if args.set_aws_profile:
        config.set_aws_profile(args.set_aws_profile)
        logger.info(f"AWS profile set to {args.set_aws_profile}")
    
    # If no arguments provided, show current config
    if not args.set_slack_webhook and not args.set_aws_profile:
        current_config = config.get_config()
        print("\nCurrent Configuration:")
        print("-" * 50)
        print(f"AWS Profile: {current_config.get('aws_profile', 'Not set')}")
        
        slack_webhook = current_config.get('slack_webhook', 'Not set')
        if slack_webhook != 'Not set':
            # Mask the webhook URL for security
            masked_webhook = slack_webhook[:10] + "..." + slack_webhook[-5:]
            print(f"Slack Webhook: {masked_webhook}")
        else:
            print(f"Slack Webhook: {slack_webhook}")
        
        print("-" * 50)


def handle_pattern_command(args: argparse.Namespace) -> None:
    """Handle the pattern command."""
    config = LeakHawkConfig()
    
    if args.pattern_command == "add":
        success = config.add_custom_pattern(
            pattern=args.pattern,
            name=args.name,
            severity=args.severity
        )
        
        if success:
            logger.info(f"Added custom pattern: {args.pattern}")
        else:
            logger.error(f"Failed to add custom pattern: {args.pattern}")
            sys.exit(1)
    
    elif args.pattern_command == "remove":
        success = config.remove_custom_pattern(args.pattern)
        
        if success:
            logger.info(f"Removed custom pattern: {args.pattern}")
        else:
            logger.error(f"Pattern not found: {args.pattern}")
            sys.exit(1)
    
    elif args.pattern_command == "list":
        patterns = config.get_custom_patterns()
        
        if not patterns:
            print("No custom patterns configured.")
            return
        
        print("\nCustom Patterns:")
        print("-" * 80)
        print("{:<40} {:<20} {:<10}".format("PATTERN", "NAME", "SEVERITY"))
        print("-" * 80)
        
        for pattern in patterns:
            print("{:<40} {:<20} {:<10}".format(
                pattern["pattern"][:40],
                pattern["name"][:20],
                pattern["severity"].upper()
            ))
        
        print("-" * 80)
        print(f"Total patterns: {len(patterns)}")
    
    elif args.pattern_command == "import":
        count = config.import_patterns_from_file(args.file)
        
        if count > 0:
            logger.info(f"Successfully imported {count} patterns from {args.file}")
        else:
            logger.error(f"Failed to import patterns from {args.file}")
            sys.exit(1)
    
    elif args.pattern_command == "export":
        file_path = args.file or str(config.patterns_file)
        success = config.save_patterns_to_file()
        
        if success:
            logger.info(f"Successfully exported patterns to {file_path}")
        else:
            logger.error(f"Failed to export patterns to {file_path}")
            sys.exit(1)
    
    else:
        logger.error("Unknown pattern command")
        sys.exit(1)


def main() -> None:
    """Main entry point for the CLI."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    if args.command == "scan":
        handle_scan_command(args)
    elif args.command == "protect":
        handle_protect_command(args)
    elif args.command == "config":
        handle_config_command(args)
    elif args.command == "pattern":
        handle_pattern_command(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
