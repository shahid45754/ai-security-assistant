#!/usr/bin/env python3
"""
Run the security incident assistant CLI.
"""

import sys
import asyncio
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

from app.cli.console import run_console


if __name__ == "__main__":
    asyncio.run(run_console())
