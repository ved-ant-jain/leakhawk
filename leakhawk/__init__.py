"""
LeakHawk - Runtime Secrets Detection for AWS.

A tool to detect and monitor secrets in AWS Lambda and ECS environments.
"""

__version__ = "0.1.0"

# Import the main function from the leakhawk module
from .leakhawk import main

# Export the main function
__all__ = ['main']
