"""
env-scanner – Detect exposed secrets in .env files.

Exposes the public API surface:
  - scan_file       : scan a single file, returns List[Finding]
  - scan_directory  : walk a directory, returns ScanResult
  - scan_single_file: scan one explicitly named file, returns ScanResult
  - Finding         : dataclass representing one detected secret
  - ScanResult      : aggregated scan output
  - PATTERNS        : list of all detection pattern dicts
"""

__version__ = "1.0.0"
__author__ = "Or Chetrit"
__license__ = "MIT"

from .scanner import Finding, ScanResult, scan_directory, scan_file, scan_single_file
from .patterns import PATTERNS

__all__ = [
    "Finding",
    "ScanResult",
    "scan_file",
    "scan_directory",
    "scan_single_file",
    "PATTERNS",
    "__version__",
]
