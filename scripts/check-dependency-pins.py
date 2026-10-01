#!/usr/bin/env python3
"""Compatibility entry point for the shared main/revision policy check."""
import os
from pathlib import Path
import runpy

root = Path(__file__).resolve().parent.parent
os.chdir(root)
runpy.run_path(root / ".github/check-first-party.py", run_name="__main__")
