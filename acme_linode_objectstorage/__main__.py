#!/usr/bin/env python3
"""
Entry point for running acme_linode_objectstorage as a module.
Usage: python -m acme_linode_objectstorage
"""

import sys

# Import main from the CLI module (your current __main__.py should be renamed to cli.py)
from acme_linode_objectstorage.cli import main

if __name__ == "__main__":
    sys.exit(main())
