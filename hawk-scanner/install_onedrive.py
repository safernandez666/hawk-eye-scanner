#!/usr/bin/env python3
"""
Install the OneDrive connector into the hawk_scanner package.

This script:
1. Copies onedrive.py into hawk_scanner/commands/
2. Registers 'onedrive' in the data_sources list in system.py

Run this after pip install hawk_scanner:
    python install_onedrive.py
"""

import importlib
import os
import shutil
import re
import sys


def main():
    # Find hawk_scanner install location
    try:
        import hawk_scanner
        pkg_dir = os.path.dirname(hawk_scanner.__file__)
    except ImportError:
        print("ERROR: hawk_scanner is not installed")
        sys.exit(1)

    commands_dir = os.path.join(pkg_dir, "commands")
    system_py = os.path.join(pkg_dir, "internals", "system.py")

    # 1. Copy onedrive.py into commands/
    src = os.path.join(os.path.dirname(__file__), "onedrive.py")
    dst = os.path.join(commands_dir, "onedrive.py")
    shutil.copy2(src, dst)
    print(f"Copied onedrive.py -> {dst}")

    # 2. Register 'onedrive' in data_sources list
    with open(system_py, "r") as f:
        content = f.read()

    if "'onedrive'" not in content:
        # Add 'onedrive' to the data_sources list
        content = content.replace(
            "data_sources = [",
            "data_sources = ['onedrive', ",
        )
        with open(system_py, "w") as f:
            f.write(content)
        print(f"Registered 'onedrive' in {system_py}")
    else:
        print("'onedrive' already registered in data_sources")

    print("OneDrive connector installed successfully!")


if __name__ == "__main__":
    main()
