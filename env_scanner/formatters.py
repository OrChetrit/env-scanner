"""
Color-coded terminal output for env-scanner.

Severity mapping
----------------
  critical  → RED   (bold)
  warning   → YELLOW
  clean     → GREEN

Each Finding is printed as a structured block with:
  - File path + line number
  - Variable name
  - Secret type detected
  - Severity badge
  - Redacted value snippet
  - Remediation hint

A summary table is printed after all findings.
"""

from __future__ import annotations

from typing import Dict, List

import colorama
from colorama import Fore, Style

from .patterns import CRITICAL, WARNING
from .scanner import Finding, ScanResult

# Initialise colorama (no-op on terminals that already support ANSI)
colorama.init(autoreset=True)


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def _red(text: str) -> str:
    return Fore.RED + Style.BRIGHT + text + Style.RESET_ALL


def _yellow(text: str) -> str:
    return Fore.YELLOW + Style.BRIGHT + text + Style.RESET_ALL


def _green(text: str) -> str:
    return Fore.GREEN + Style.BRIGHT + text + Style.RESET_ALL


def _cyan(text: str) -> str:
    return Fore.CYAN + text + Style.RESET_ALL


def _white_bold(text: str) -> str:
    return Style.BRIGHT + text + Style.RESET_ALL


def _dim(text: str) -> str:
    return Style.DIM + text + Style.RESET_ALL


def _severity_label(severity: str) -> str:
    if severity == CRITICAL:
        return _red(" CRITICAL ")
    if severity == WARNING:
        return _yellow(" WARNING  ")
    return _green("   OK     ")


def _severity_color(severity: str, text: str) -> str:
    if severity == CRITICAL:
        return _red(text)
    if severity == WARNING:
        return _yellow(text)
    return _green(text)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
  _____            ___
 | ____|_ ____   _/ __|  ___ __ _ _ __  _ __   ___ _ __
 |  _| | '_ \ \ / /\__ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |___| | | \ V / ___) | (_| (_| | | | | | | |  __/ |
 |_____|_| |_|\_/ |____/ \___\__,_|_| |_|_| |_|\___|_|

"""


def print_banner() -> None:
    """Print the ASCII art banner."""
    print(_cyan(BANNER))
    print(_dim("  Scanning your .env files for exposed secrets and credentials.\n"))


# ---------------------------------------------------------------------------
# Finding formatter
# ---------------------------------------------------------------------------

_SEPARATOR = _dim("─" * 72)
_THICK_SEP = _dim("═" * 72)


def _format_finding(finding: Finding, index: int) -> str:
    """Return a formatted multi-line string for a single Finding."""
    lines: List[str] = []

    lines.append(_SEPARATOR)

    header = (
        f"  [{index}] "
        + _severity_label(finding.severity)
        + "  "
        + _white_bold(finding.secret_type)
    )
    lines.append(header)

    lines.append(
        f"      {_dim('File       :')} "
        + _cyan(finding.file_path)
        + _dim(f"  line {finding.line_number}")
    )
    lines.append(
        f"      {_dim('Variable   :')} "
        + _white_bold(finding.variable_name)
    )
    lines.append(
        f"      {_dim('Severity   :')} "
        + _severity_color(finding.severity, finding.severity.upper())
    )
    lines.append(
        f"      {_dim('Value hint :')} "
        + _dim(finding.raw_value)
    )
    lines.append(
        f"      {_dim('Remediation:')} "
        + finding.remediation
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def print_findings(result: ScanResult, show_clean: bool = True) -> None:
    """
    Pretty-print all findings in *result* to stdout.

    Parameters
    ----------
    result:
        The aggregated ScanResult to display.
    show_clean:
        When True (default), also list clean files in the summary.
    """
    if not result.files_scanned:
        print(_yellow("  No env files found in the specified location."))
        return

    # Group findings by file for nicer output.
    findings_by_file: Dict[str, List[Finding]] = {}
    for finding in result.findings:
        findings_by_file.setdefault(finding.file_path, []).append(finding)

    # Print findings grouped by file.
    global_index = 1
    for file_path, findings in findings_by_file.items():
        print()
        print(_thick_separator())
        print(f"  File: {_cyan(file_path)}")
        print(_thick_separator())

        for finding in findings:
            print(_format_finding(finding, global_index))
            global_index += 1

    # Print summary.
    print()
    print(_THICK_SEP)
    _print_summary(result, show_clean)


def _thick_separator() -> str:
    return _dim("═" * 72)


def _print_summary(result: ScanResult, show_clean: bool) -> None:
    """Print the scan summary block."""
    print(_white_bold("  SCAN SUMMARY"))
    print(_SEPARATOR)

    total = len(result.files_scanned)
    print(f"  Files scanned : {_white_bold(str(total))}")
    print(f"  Total findings: {_white_bold(str(result.total_findings))}")

    if result.critical_count:
        print(f"  Critical       : {_red(str(result.critical_count))}")
    else:
        print(f"  Critical       : {_green('0')}")

    if result.warning_count:
        print(f"  Warnings       : {_yellow(str(result.warning_count))}")
    else:
        print(f"  Warnings       : {_green('0')}")

    if show_clean and result.clean_files:
        print()
        print(_green(f"  {len(result.clean_files)} file(s) appear clean:"))
        for fp in result.clean_files:
            print(f"    {_green('✔')}  {_dim(fp)}")

    print()
    if result.total_findings == 0:
        print(_green("  ✔  No secrets detected. Great job keeping your env files clean!"))
    else:
        print(
            _red(
                f"  ✘  {result.total_findings} secret(s) detected! "
                "Review each finding and rotate affected credentials."
            )
        )
    print(_SEPARATOR)
    print()


def print_error(message: str) -> None:
    """Print an error message in red."""
    print(_red(f"  ERROR: {message}"))


def print_info(message: str) -> None:
    """Print an informational message in cyan."""
    print(_cyan(f"  {message}"))
