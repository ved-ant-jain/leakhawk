#!/usr/bin/env python3
"""
Add specific patterns to LeakHawk for the secrets shown in the screenshot.
"""

import logging
from leakhawk.config import LeakHawkConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("add_specific_patterns")

def add_specific_patterns():
    """Add specific patterns for the secrets shown in the screenshot."""
    config = LeakHawkConfig()
    
    # Define patterns
    patterns = [
        {
            "pattern": r"(?i)intercom_secret\s*[=:]\s*([A-Za-z0-9]{40})",
            "name": "Intercom Secret",
            "severity": "high",
            "description": "Intercom API Secret used for authentication with Intercom services"
        },
        {
            "pattern": r"sk-[A-Za-z0-9]{48}",
            "name": "OpenAI API Key",
            "severity": "critical",
            "description": "OpenAI API Key used for accessing OpenAI services like GPT models"
        },
        {
            "pattern": r"(?i)rulesearchstring_found_in_code\s*[=:]\s*([A-Za-z0-9]{30})",
            "name": "RuleSearchString",
            "severity": "medium",
            "description": "Rule search string used for code analysis"
        },
        {
            "pattern": r"(?i)base64_entropy_auth0_regular_web_app_client_ids\s*[=:]\s*([A-Za-z0-9]{32})",
            "name": "AUTH0 Regular Web App Client IDs",
            "severity": "high",
            "description": "AUTH0 Client IDs for regular web applications"
        },
        {
            "pattern": r"(?i)base64_entropy_gia_app_client_id\s*[=:]\s*([A-Za-z0-9]{32})",
            "name": "GIA App Client ID",
            "severity": "high",
            "description": "GIA Application Client ID for authentication"
        },
        {
            "pattern": r"(?i)base64_entropy_zoom_client_secret\s*[=:]\s*([A-Za-z0-9]{32})",
            "name": "Zoom Client Secret",
            "severity": "high",
            "description": "Zoom Client Secret used for Zoom API integration"
        },
        {
            "pattern": r"dapi[0-9a-f]{40}",
            "name": "Databricks Authentication Token",
            "severity": "critical",
            "description": "Databricks Authentication Token used for accessing Databricks services"
        }
    ]
    
    # Add each pattern
    success_count = 0
    for pattern_data in patterns:
        success = config.add_custom_pattern(
            pattern=pattern_data["pattern"],
            name=pattern_data["name"],
            severity=pattern_data["severity"]
        )
        
        if success:
            logger.info(f"Successfully added pattern: {pattern_data['name']}")
            success_count += 1
        else:
            logger.error(f"Failed to add pattern: {pattern_data['name']}")
    
    logger.info(f"Added {success_count} out of {len(patterns)} patterns")
    
    # List all patterns
    all_patterns = config.get_custom_patterns()
    logger.info(f"Total patterns in configuration: {len(all_patterns)}")

if __name__ == "__main__":
    add_specific_patterns()
