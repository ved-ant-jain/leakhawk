"""
Verification module for LeakHawk.

This module handles verification of potential secrets to reduce false positives.
"""

import re
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger("leakhawk.verification")

class SecretVerifier:
    """Verifier for potential secrets to reduce false positives."""
    
    @staticmethod
    def is_secret_reference(value: str) -> bool:
        """Check if a value is a reference to a secret rather than the secret itself.
        
        Args:
            value: The value to check
            
        Returns:
            True if the value is a reference, False otherwise
        """
        if not value:
            return False
        
        # Check for common secret reference patterns
        reference_patterns = [
            # AWS Parameter Store and Secrets Manager references
            r"^/\w+/\w+",  # e.g., /prod/jwt_secret
            r"^arn:aws:(secretsmanager|ssm):",  # AWS ARNs
            
            # Environment-specific references
            r"^\${.*}$",  # e.g., ${SECRET_NAME}
            r"^%\w+%$",  # e.g., %SECRET_NAME%
            
            # Placeholder values
            r"^(placeholder|changeme|yourkey|yoursecret|example|sample|test|demo)$",
            
            # References to files
            r"^file://",
            r"^@\w+\.json$",
            
            # URLs and endpoints
            r"^https?://",
            r"^ftp://",
            r"^sftp://",
            
            # Service names and identifiers
            r"^[a-z0-9-]+$",  # Simple service names like "payments", "users"
            
            # Table names and resource identifiers
            r"^[a-z0-9-]+-[a-z0-9-]+$",  # e.g., "prod-gp-payments"
        ]
        
        for pattern in reference_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return True
        
        # Check if it's a path-like structure
        if value.startswith('/') and len(value.split('/')) >= 3:
            return True
        
        # Check if it's clearly a configuration value (contains common config patterns)
        config_indicators = [
            'prod-', 'dev-', 'staging-', 'test-',
            '.amazonaws.com', '.com', '.org', '.net',
            'table', 'bucket', 'queue', 'topic', 'stream'
        ]
        
        for indicator in config_indicators:
            if indicator in value.lower():
                return True
        
        return False
    
    @staticmethod
    def is_high_entropy_string(value: str) -> bool:
        """Check if a string has high entropy, indicating it might be a secret.
        
        Args:
            value: The string to check
            
        Returns:
            True if the string has high entropy, False otherwise
        """
        if not value or len(value) < 8:
            return False
        
        # Simple entropy calculation
        import math
        from collections import Counter
        
        entropy = 0
        for count in Counter(value).values():
            p = count / len(value)
            entropy -= p * math.log2(p)
        
        # Strings with entropy > 3.5 are likely to be secrets
        return entropy > 3.5
    
    @staticmethod
    def verify_finding(finding: Dict[str, Any], env_value: Optional[str] = None) -> bool:
        """Verify if a finding is a true positive.
        
        Args:
            finding: The finding to verify
            env_value: The environment variable value (optional)
            
        Returns:
            True if the finding is likely a true positive, False otherwise
        """
        # If we don't have the value, we can't verify
        if env_value is None:
            return True
        
        # Check if it's a reference
        if SecretVerifier.is_secret_reference(env_value):
            return False
        
        # Check for high entropy (likely a real secret)
        if SecretVerifier.is_high_entropy_string(env_value):
            return True
        
        # Default to true positive if we can't determine
        return True
