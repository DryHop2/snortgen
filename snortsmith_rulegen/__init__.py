"""
snortsmith_rulegen

A CLI-assisted Snort rule generator that supports both interactive and batch modes.
"""

from .snortsmith import run, run_interactive
from .batch import run_batch

__all__ = [
    "run",
    "run_interactive",
    "run_batch"
]