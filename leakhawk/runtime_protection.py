"""
Runtime Protection module for LeakHawk.

This module handles deploying runtime protection to AWS resources.
"""

import logging
import json
from typing import Dict, Optional, Any, List

from leakhawk.aws_scanner import AWSScanner

logger = logging.getLogger("leakhawk.runtime_protection")


class RuntimeProtection:
    """Runtime protection for AWS resources."""
    
    def __init__(self, custom_patterns: Optional[List[Dict[str, str]]] = None):
        """Initialize the runtime protection.
        
        Args:
            custom_patterns: List of custom regex patterns (optional)
        """
        self.custom_patterns = custom_patterns or []
    
    def generate_lambda_layer(
        self, 
        scanner: AWSScanner,
        slack_webhook: Optional[str] = None,
        account_id: str = "unknown",
        region: str = "us-east-1"
    ) -> str:
        """Generate a Lambda layer for runtime protection.
        
        Args:
            scanner: AWSScanner instance
            slack_webhook: Slack webhook URL for notifications
            account_id: AWS account ID
            region: AWS region
            
        Returns:
            ARN of the created Lambda layer
        """
        # In a real implementation, this would:
        # 1. Create a zip file with the runtime protection code
        # 2. Upload it to S3
        # 3. Create a Lambda layer from the S3 object
        # 4. Return the layer ARN
        
        # For this example, we'll just return a placeholder
        return f"arn:aws:lambda:{region}:{account_id}:layer:leakhawk-protection:1"
    
    def generate_runtime_protection_code(
        self,
        resource_type: str,
        resource_name: str,
        slack_webhook: Optional[str] = None,
        account_id: str = "unknown",
        region: str = "us-east-1"
    ) -> str:
        """Generate runtime protection code.
        
        Args:
            resource_type: Type of resource (lambda or ecs)
            resource_name: Name of the resource
            slack_webhook: Slack webhook URL for notifications
            account_id: AWS account ID
            region: AWS region
            
        Returns:
            Python code for runtime protection
        """
        # Configuration for the runtime protection
        config = {
            "enabled": True,
            "alert_on_detection": True,
            "block_execution": False,
            "mask_secrets": True,
            "notification_endpoints": {
                "slack": slack_webhook
            },
            "resource_info": {
                "name": resource_name,
                "type": resource_type,
                "account_id": account_id,
                "region": region
            }
        }
        
        # Combine default and custom patterns
        secret_patterns = [
            (r"api[_-]?key", "API Key", "high"),
            (r"auth[_-]?token", "Auth Token", "high"),
            (r"secret", "Secret", "critical"),
            (r"password", "Password", "high"),
            (r"credential", "Credential", "high"),
            (r"private[_-]?key", "Private Key", "critical"),
            (r"access[_-]?key", "Access Key", "critical"),
            (r"connection[_-]?string", "Connection String", "high"),
            (r"jwt", "JWT Token", "medium"),
            (r"token", "Token", "medium"),
            (r"key", "Key", "medium"),
        ]
        
        # Add custom patterns
        for pattern in self.custom_patterns:
            secret_patterns.append(
                (pattern["pattern"], pattern["name"], pattern["severity"])
            )
        
        # Convert patterns to JSON for embedding in code
        patterns_json = json.dumps(secret_patterns)
        
        # Python code for runtime protection
        code = f"""
# LeakHawk Runtime Protection
import os
import json
import re
import traceback
import urllib.request
from functools import wraps

# Configuration
LEAKHAWK_CONFIG = {json.dumps(config, indent=2)}

# Original environment variables
ORIGINAL_ENV = dict(os.environ)

# Patterns for detecting secrets
SECRET_PATTERNS = {patterns_json}

def is_sensitive_variable(name):
    \"\"\"Check if a variable name indicates it might contain a secret.\"\"\"
    name_lower = name.lower()
    
    for pattern, _, _ in SECRET_PATTERNS:
        if re.search(pattern, name_lower):
            return True
    
    return False

def mask_secret(value):
    \"\"\"Mask a secret value.\"\"\"
    if not value:
        return value
    
    if len(value) <= 4:
        return "****"
    
    return value[:2] + "****" + value[-2:]

def get_execution_context():
    \"\"\"Get the current execution context.\"\"\"
    return {{
        "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME"),
        "function_version": os.environ.get("AWS_LAMBDA_FUNCTION_VERSION"),
        "memory_limit_mb": os.environ.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE"),
        "log_group_name": os.environ.get("AWS_LAMBDA_LOG_GROUP_NAME"),
        "log_stream_name": os.environ.get("AWS_LAMBDA_LOG_STREAM_NAME"),
        "aws_request_id": os.environ.get("_X_AMZN_TRACE_ID")
    }}

def send_slack_notification(webhook_url, data):
    \"\"\"Send a notification to Slack.\"\"\"
    if not webhook_url:
        return False
    
    try:
        # Create Slack message payload
        payload = {{
            "text": f"🚨 *LeakHawk Alert*: Secret detected in {{data['resource_info']['name']}}",
            "blocks": [
                {{
                    "type": "header",
                    "text": {{
                        "type": "plain_text",
                        "text": "🚨 LeakHawk Secret Detection Alert",
                        "emoji": True
                    }}
                }},
                {{
                    "type": "section",
                    "fields": [
                        {{
                            "type": "mrkdwn",
                            "text": f"*Resource:*\\n{{data['resource_info']['name']}}"
                        }},
                        {{
                            "type": "mrkdwn",
                            "text": f"*Type:*\\n{{data['resource_info']['type']}}"
                        }},
                        {{
                            "type": "mrkdwn",
                            "text": f"*AWS Account:*\\n{{data['resource_info']['account_id']}}"
                        }},
                        {{
                            "type": "mrkdwn",
                            "text": f"*Region:*\\n{{data['resource_info']['region']}}"
                        }}
                    ]
                }},
                {{
                    "type": "section",
                    "fields": [
                        {{
                            "type": "mrkdwn",
                            "text": f"*Environment Variable:*\\n`{{data['variable']}}`"
                        }},
                        {{
                            "type": "mrkdwn",
                            "text": f"*Detected At:*\\n{{data['timestamp']}}"
                        }}
                    ]
                }},
                {{
                    "type": "section",
                    "text": {{
                        "type": "mrkdwn",
                        "text": f"*Request ID:*\\n{{data['execution_context']['aws_request_id'] or 'N/A'}}"
                    }}
                }},
                {{
                    "type": "divider"
                }},
                {{
                    "type": "context",
                    "elements": [
                        {{
                            "type": "mrkdwn",
                            "text": "This alert was generated by LeakHawk Runtime Protection"
                        }}
                    ]
                }}
            ]
        }}
        
        # Send the request
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={{'Content-Type': 'application/json'}}
        )
        
        with urllib.request.urlopen(req) as response:
            return response.status == 200
    
    except Exception as e:
        print(f"Error sending Slack notification: {{e}}")
        return False

def log_access_attempt(variable, value=None):
    \"\"\"Log an attempt to access a sensitive variable.\"\"\"
    import datetime
    
    # Create context for the alert
    context = {{
        "variable": variable,
        "timestamp": datetime.datetime.now().isoformat(),
        "stack_trace": traceback.format_stack(),
        "resource_info": LEAKHAWK_CONFIG["resource_info"],
        "execution_context": get_execution_context()
    }}
    
    # Log the access attempt
    print(f"LeakHawk: Detected access to sensitive variable {{variable}}")
    
    # Send notification if configured
    if LEAKHAWK_CONFIG["notification_endpoints"]["slack"]:
        send_slack_notification(
            LEAKHAWK_CONFIG["notification_endpoints"]["slack"],
            context
        )

# Create a custom dictionary to monitor environment variable access
class EnvironmentMonitor(dict):
    def __getitem__(self, key):
        # Check if the key is a sensitive variable
        if is_sensitive_variable(key):
            # Log the access attempt
            log_access_attempt(key)
            
            # Get the original value
            value = ORIGINAL_ENV.get(key)
            
            # If configured to mask secrets, return a masked version
            if LEAKHAWK_CONFIG["mask_secrets"]:
                return mask_secret(value)
            
            # If configured to block execution, raise an exception
            if LEAKHAWK_CONFIG["block_execution"]:
                raise RuntimeError(f"Access to sensitive variable {{key}} blocked by LeakHawk")
        
        # Return the original value
        return ORIGINAL_ENV.get(key)

# Replace os.environ with our monitored version
os.environ = EnvironmentMonitor(os.environ)

# Lambda handler wrapper for runtime protection
def leakhawk_lambda_wrapper(handler):
    @wraps(handler)
    def wrapper(event, context):
        try:
            # Call the original handler
            return handler(event, context)
        except Exception as e:
            # Log the exception
            print(f"LeakHawk: Exception in Lambda handler: {{e}}")
            raise
    
    return wrapper
"""
        return code
    
    def protect_lambda_function(
        self,
        scanner: AWSScanner,
        function_name: str,
        slack_webhook: Optional[str] = None,
        account_id: str = "unknown",
        region: str = "us-east-1"
    ) -> bool:
        """Deploy runtime protection to a Lambda function.
        
        Args:
            scanner: AWSScanner instance
            function_name: Name of the Lambda function
            slack_webhook: Slack webhook URL for notifications
            account_id: AWS account ID
            region: AWS region
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get the function configuration
            function = scanner.lambda_client.get_function(
                FunctionName=function_name
            )
            
            # Generate runtime protection code
            protection_code = self.generate_runtime_protection_code(
                resource_type="lambda",
                resource_name=function_name,
                slack_webhook=slack_webhook,
                account_id=account_id,
                region=region
            )
            
            # In a real implementation, this would:
            # 1. Create a Lambda layer with the protection code
            # 2. Add the layer to the function
            # 3. Update the function configuration to use the layer
            
            # For this example, we'll just log what would happen
            logger.info(f"Would deploy runtime protection to Lambda function {function_name}")
            
            # For demonstration purposes, let's assume it was successful
            return True
        
        except Exception as e:
            logger.error(f"Error protecting Lambda function {function_name}: {e}")
            return False
    
    def protect_ecs_task(
        self,
        scanner: AWSScanner,
        task_definition_arn: str,
        slack_webhook: Optional[str] = None,
        account_id: str = "unknown",
        region: str = "us-east-1"
    ) -> bool:
        """Deploy runtime protection to an ECS task.
        
        Args:
            scanner: AWSScanner instance
            task_definition_arn: ARN of the ECS task definition
            slack_webhook: Slack webhook URL for notifications
            account_id: AWS account ID
            region: AWS region
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get the task definition
            task_def = scanner.ecs_client.describe_task_definition(
                taskDefinition=task_definition_arn
            )["taskDefinition"]
            
            task_name = task_definition_arn.split("/")[-1].split(":")[0]
            
            # Generate runtime protection code
            protection_code = self.generate_runtime_protection_code(
                resource_type="ecs",
                resource_name=task_name,
                slack_webhook=slack_webhook,
                account_id=account_id,
                region=region
            )
            
            # In a real implementation, this would:
            # 1. Create a new container image with the protection code
            # 2. Update the task definition to use the new image
            # 3. Register the new task definition
            
            # For this example, we'll just log what would happen
            logger.info(f"Would deploy runtime protection to ECS task {task_name}")
            
            # For demonstration purposes, let's assume it was successful
            return True
        
        except Exception as e:
            logger.error(f"Error protecting ECS task {task_definition_arn}: {e}")
            return False
