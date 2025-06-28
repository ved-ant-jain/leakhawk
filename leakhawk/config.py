"""
Configuration module for LeakHawk.

This module handles configuration management.
"""

import json
import logging
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger("leakhawk.config")


class LeakHawkConfig:
    """Configuration manager for LeakHawk."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """Initialize the configuration manager.
        
        Args:
            config_dir: Directory to store configuration files
        """
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            # Use ~/.leakhawk by default
            self.config_dir = Path.home() / ".leakhawk"
        
        # Create config directory if it doesn't exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Config file path
        self.config_file = self.config_dir / "config.json"
        
        # Patterns file path
        self.patterns_file = self.config_dir / "patterns.yaml"
        
        # Load or create config
        self.config = self._load_config()
        
        # Initialize custom patterns if not present
        if "custom_patterns" not in self.config:
            self.config["custom_patterns"] = []
            self._save_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file.
        
        Returns:
            Configuration dictionary
        """
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"Invalid config file: {self.config_file}")
                return {}
        else:
            return {}
    
    def _save_config(self) -> None:
        """Save configuration to file."""
        with open(self.config_file, "w") as f:
            json.dump(self.config, f, indent=2)
    
    def get_config(self) -> Dict[str, Any]:
        """Get the current configuration.
        
        Returns:
            Configuration dictionary
        """
        return self.config
    
    def set_slack_webhook(self, webhook_url: str) -> None:
        """Set the Slack webhook URL.
        
        Args:
            webhook_url: Slack webhook URL
        """
        self.config["slack_webhook"] = webhook_url
        self._save_config()
    
    def get_slack_webhook(self) -> Optional[str]:
        """Get the Slack webhook URL.
        
        Returns:
            Slack webhook URL or None if not set
        """
        return self.config.get("slack_webhook")
    
    def set_aws_profile(self, profile_name: str) -> None:
        """Set the AWS profile name.
        
        Args:
            profile_name: AWS profile name
        """
        self.config["aws_profile"] = profile_name
        self._save_config()
    
    def get_aws_profile(self) -> Optional[str]:
        """Get the AWS profile name.
        
        Returns:
            AWS profile name or None if not set
        """
        return self.config.get("aws_profile")
    
    def add_custom_pattern(self, pattern: str, name: str, severity: str) -> bool:
        """Add a custom regex pattern for secret detection.
        
        Args:
            pattern: Regex pattern string
            name: Human-readable name for the pattern
            severity: Severity level (critical, high, medium, low)
            
        Returns:
            True if successful, False otherwise
        """
        # Validate severity
        if severity not in ["critical", "high", "medium", "low"]:
            logger.error(f"Invalid severity level: {severity}")
            return False
        
        # Validate pattern (try to compile it)
        try:
            import re
            re.compile(pattern)
        except re.error as e:
            logger.error(f"Invalid regex pattern: {e}")
            return False
        
        # Add the pattern
        if "custom_patterns" not in self.config:
            self.config["custom_patterns"] = []
        
        # Check if pattern already exists
        for i, p in enumerate(self.config["custom_patterns"]):
            if p["pattern"] == pattern:
                # Update existing pattern
                self.config["custom_patterns"][i] = {
                    "pattern": pattern,
                    "name": name,
                    "severity": severity
                }
                self._save_config()
                return True
        
        # Add new pattern
        self.config["custom_patterns"].append({
            "pattern": pattern,
            "name": name,
            "severity": severity
        })
        self._save_config()
        return True
    
    def remove_custom_pattern(self, pattern: str) -> bool:
        """Remove a custom regex pattern.
        
        Args:
            pattern: Regex pattern string to remove
            
        Returns:
            True if removed, False if not found
        """
        if "custom_patterns" not in self.config:
            return False
        
        initial_length = len(self.config["custom_patterns"])
        self.config["custom_patterns"] = [
            p for p in self.config["custom_patterns"] if p["pattern"] != pattern
        ]
        
        if len(self.config["custom_patterns"]) < initial_length:
            self._save_config()
            return True
        
        return False
    
    def get_custom_patterns(self) -> List[Dict[str, str]]:
        """Get all custom regex patterns.
        
        Returns:
            List of pattern dictionaries
        """
        return self.config.get("custom_patterns", [])
    
    def import_patterns_from_yaml(self, yaml_content: str) -> int:
        """Import patterns from YAML content.
        
        Args:
            yaml_content: YAML content with patterns
            
        Returns:
            Number of patterns imported
        """
        try:
            data = yaml.safe_load(yaml_content)
            if not data or "patterns" not in data:
                logger.error("Invalid YAML format: 'patterns' key not found")
                return 0
            
            patterns = data["patterns"]
            count = 0
            
            for pattern_entry in patterns:
                if "pattern" not in pattern_entry:
                    continue
                
                pattern_data = pattern_entry["pattern"]
                if "name" not in pattern_data or "regex" not in pattern_data or "confidence" not in pattern_data:
                    continue
                
                name = pattern_data["name"]
                regex = pattern_data["regex"]
                confidence = pattern_data["confidence"]
                
                # Map confidence to severity
                severity_map = {
                    "critical": "critical",
                    "high": "high",
                    "medium": "medium",
                    "low": "low"
                }
                severity = severity_map.get(confidence, "medium")
                
                if self.add_custom_pattern(regex, name, severity):
                    count += 1
            
            return count
        except Exception as e:
            logger.error(f"Error importing patterns: {e}")
            return 0
    
    def import_patterns_from_file(self, file_path: str) -> int:
        """Import patterns from a YAML file.
        
        Args:
            file_path: Path to YAML file
            
        Returns:
            Number of patterns imported
        """
        try:
            with open(file_path, "r") as f:
                yaml_content = f.read()
            
            return self.import_patterns_from_yaml(yaml_content)
        except Exception as e:
            logger.error(f"Error reading patterns file: {e}")
            return 0
    
    def save_patterns_to_file(self) -> bool:
        """Save all patterns to the patterns file.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            patterns_data = {
                "patterns": [
                    {
                        "pattern": {
                            "name": p["name"],
                            "regex": p["pattern"],
                            "confidence": p["severity"]
                        }
                    }
                    for p in self.get_custom_patterns()
                ]
            }
            
            with open(self.patterns_file, "w") as f:
                yaml.dump(patterns_data, f, default_flow_style=False)
            
            return True
        except Exception as e:
            logger.error(f"Error saving patterns to file: {e}")
            return False
