"""
Core scanning logic for env-scanner.

Provides functions to:
  - scan a single .env file and return a list of Finding objects
  - walk a directory tree and scan every .env file found
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .patterns import PATTERNS, CRITICAL, WARNING


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Represents a single secret detected in an env file."""

    file_path: str
    line_number: int
    variable_name: str
    secret_type: str
    severity: str          # 'critical' | 'warning'
    raw_value: str         # the matched (redacted) value shown to user
    remediation: str


@dataclass
class ScanResult:
    """Aggregated results for one or more files."""

    findings: List[Finding] = field(default_factory=list)
    files_scanned: List[str] = field(default_factory=list)
    clean_files: List[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == WARNING)

    @property
    def total_findings(self) -> int:
        return len(self.findings)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Matches the key part of a KEY=VALUE env line to extract the variable name.
_KEY_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")

# Redact value – keep up to 4 chars then mask the rest so it gives a hint
# without exposing the full secret.
def _redact(value: str, keep: int = 4) -> str:
    """Return a partially redacted version of *value* for display."""
    if len(value) <= keep:
        return "*" * len(value)
    return value[0:keep] + "*" * min(len(value) - keep, 20)  # type: ignore


def _extract_variable_name(line: str) -> Optional[str]:
    """Return the variable name from a KEY=VALUE line, or None."""
    match = _KEY_RE.match(line)
    return match.group(1) if match else None


def _is_comment_or_blank(line: str) -> bool:
    """Return True if the line is empty or a comment."""
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


# ---------------------------------------------------------------------------
# Core scan function
# ---------------------------------------------------------------------------

def scan_file(file_path: str | Path) -> List[Finding]:
    """
    Scan a single .env file and return a list of Finding objects.

    Lines that are blank or start with ``#`` are ignored.
    For each non-comment line every pattern is tested; all matches are
    reported (a single line may contain multiple secrets).
    """
    file_path = Path(file_path)
    findings: List[Finding] = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        # Return a synthetic finding describing the I/O error so the caller
        # can surface it to the user.
        findings.append(
            Finding(
                file_path=str(file_path),
                line_number=0,
                variable_name="N/A",
                secret_type="File Read Error",
                severity=WARNING,
                raw_value=f"[OS Error {exc.errno}]",  # errno only – avoid leaking full path
                remediation="Check file permissions.",
            )
        )
        return findings

    for line_number, line in enumerate(content.splitlines(), start=1):
        if _is_comment_or_blank(line):
            continue

        variable_name = _extract_variable_name(line) or "UNKNOWN"

        for pattern in PATTERNS:
            match = pattern["regex"].search(line)
            if not match:
                continue

            # The matched value is typically in the *last* capture group.
            groups = match.groups()
            matched_value = groups[-1] if groups else match.group(0)

            findings.append(
                Finding(
                    file_path=str(file_path),
                    line_number=line_number,
                    variable_name=variable_name,
                    secret_type=pattern["name"],
                    severity=pattern["severity"],
                    raw_value=_redact(matched_value),
                    remediation=pattern["remediation"],
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Directory walk
# ---------------------------------------------------------------------------

# Filename patterns considered as env files.
_ENV_FILENAME_PATTERNS = re.compile(
    r"^\.env"            # .env, .env.local, .env.production …
    r"|^\.environment$"  # .environment
    r"|^env$"            # plain 'env' file
    r"|\.env$"           # something.env
    r"|\.env\.",         # something.env.something
    re.IGNORECASE,
)

# Directories to always skip.
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".tox",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
}


def _is_env_file(name: str) -> bool:
    """Return True if *name* looks like an env file."""
    return bool(_ENV_FILENAME_PATTERNS.search(name))


def scan_directory(directory: str | Path, recursive: bool = True) -> ScanResult:
    """
    Walk *directory* and scan every env file found.

    Parameters
    ----------
    directory:
        Root directory to search.
    recursive:
        When True (default), descend into subdirectories.

    Returns
    -------
    ScanResult
        Aggregated results for all files found.
    """
    directory = Path(directory).resolve()
    result = ScanResult()

    if recursive:
        walk_iter = os.walk(directory)
    else:
        # Single-level: synthesise a single (root, dirs, files) tuple.
        try:
            entries = list(os.scandir(directory))
        except OSError:
            entries = []
        dirs = [e.name for e in entries if e.is_dir()]
        files = [e.name for e in entries if e.is_file()]
        walk_iter = iter([(str(directory), dirs, files)])

    for root, dirs, files in walk_iter:
        # Prune skipped directories in-place so os.walk won't descend.
        new_dirs = [d for d in dirs if d not in _SKIP_DIRS and not d.endswith(".egg-info")]
        dirs.clear()
        dirs.extend(new_dirs)

        for filename in files:
            if not _is_env_file(filename):
                continue

            file_path = os.path.join(root, filename)
            result.files_scanned.append(file_path)

            file_findings = scan_file(file_path)
            if file_findings:
                result.findings.extend(file_findings)
            else:
                result.clean_files.append(file_path)

    return result


def scan_single_file(file_path: str | Path) -> ScanResult:
    """
    Scan a single, explicitly specified file regardless of its name.

    Wraps :func:`scan_file` and returns a :class:`ScanResult`.
    """
    result = ScanResult()
    fp = str(file_path)
    result.files_scanned.append(fp)

    findings = scan_file(file_path)
    if findings:
        result.findings.extend(findings)
    else:
        result.clean_files.append(fp)

    return result
