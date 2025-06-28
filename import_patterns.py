#!/usr/bin/env python3
"""
Import patterns from a YAML file into LeakHawk.
"""

import argparse
import logging
import sys
from leakhawk.config import LeakHawkConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("import_patterns")

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Import patterns from a YAML file into LeakHawk"
    )
    parser.add_argument(
        "file",
        help="Path to YAML file with patterns"
    )
    args = parser.parse_args()
    
    config = LeakHawkConfig()
    count = config.import_patterns_from_file(args.file)
    
    if count > 0:
        logger.info(f"Successfully imported {count} patterns from {args.file}")
    else:
        logger.error(f"Failed to import patterns from {args.file}")
        sys.exit(1)

if __name__ == "__main__":
    main()
