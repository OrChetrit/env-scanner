"""
Click-based CLI interface for env-scanner.

Entry point: ``env-scanner``

Sub-commands
------------
  scan FILE          Scan a specific .env file.
  scan --dir DIR     Recursively scan all .env files under DIR.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from .formatters import (
    print_banner,
    print_error,
    print_findings,
    print_info,
)
from .scanner import scan_directory, scan_single_file


# ---------------------------------------------------------------------------
# CLI root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(package_name="env-scanner", prog_name="env-scanner")
def cli() -> None:
    """
    env-scanner – Detect exposed secrets in .env files.

    \b
    Examples:
      env-scanner scan .env
      env-scanner scan --dir ./project
      env-scanner scan --dir . --no-recursive
    """


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@cli.command("scan")
@click.argument(
    "file",
    required=False,
    type=click.Path(exists=False, file_okay=True, dir_okay=False, readable=True),
)
@click.option(
    "--dir", "-d",
    "directory",
    default=None,
    type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True),
    help="Directory to scan recursively for .env files.",
)
@click.option(
    "--no-recursive",
    is_flag=True,
    default=False,
    help="When using --dir, only scan the top-level directory (no recursion).",
)
@click.option(
    "--no-banner",
    is_flag=True,
    default=False,
    help="Suppress the ASCII art banner.",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    default=False,
    help="Only show findings; suppress clean-file list and informational messages.",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "warning", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Filter findings by minimum severity.",
)
def scan(
    file: str | None,
    directory: str | None,
    no_recursive: bool,
    no_banner: bool,
    quiet: bool,
    severity: str,
) -> None:
    """
    Scan .env file(s) for exposed secrets and credentials.

    \b
    Usage:
      Scan a specific file:
        env-scanner scan .env
        env-scanner scan /path/to/.env.production

      Scan all .env files under a directory:
        env-scanner scan --dir ./project
        env-scanner scan --dir . --no-recursive
    """
    if not no_banner:
        print_banner()

    # Validate arguments
    if file and directory:
        print_error("Specify either a FILE or --dir, not both.")
        sys.exit(1)

    if not file and not directory:
        # Default: scan the current directory
        directory = "."

    # -----------------------------------------------------------------------
    # Run scan
    # -----------------------------------------------------------------------
    if file:
        file_path = Path(file)
        if not file_path.exists():
            print_error(f"File not found: {file}")
            sys.exit(1)
        if not file_path.is_file():
            print_error(f"Not a file: {file}")
            sys.exit(1)

        if not quiet:
            print_info(f"Scanning file: {file}")

        result = scan_single_file(file_path)

    else:
        recursive = not no_recursive
        mode = "recursively" if recursive else "non-recursively"
        if not quiet:
            print_info(f"Scanning directory {mode}: {directory}")

        result = scan_directory(directory, recursive=recursive)

    # -----------------------------------------------------------------------
    # Filter by severity if requested
    # -----------------------------------------------------------------------
    if severity != "all":
        result.findings = [
            f for f in result.findings if f.severity == severity
        ]

    # -----------------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------------
    print_findings(result, show_clean=not quiet)

    # Exit with non-zero code when secrets are found so CI pipelines can fail.
    if result.total_findings > 0:
        sys.exit(1)


# ---------------------------------------------------------------------------
# patterns command – list all supported patterns
# ---------------------------------------------------------------------------

@cli.command("patterns")
@click.option(
    "--severity",
    type=click.Choice(["critical", "warning", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Filter patterns by severity.",
)
def list_patterns(severity: str) -> None:
    """List all supported secret patterns and their severities."""
    from .patterns import PATTERNS, CRITICAL

    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)

    filtered = [
        p for p in PATTERNS
        if severity == "all" or p["severity"] == severity
    ]

    click.echo(
        Style.BRIGHT + f"\n  env-scanner detects {len(PATTERNS)} secret patterns\n" + Style.RESET_ALL
    )

    for i, pattern in enumerate(filtered, start=1):
        sev = pattern["severity"]
        color = Fore.RED if sev == CRITICAL else Fore.YELLOW
        label = f"[{sev.upper():8}]"
        click.echo(
            f"  {i:>2}. "
            + color + Style.BRIGHT + label + Style.RESET_ALL
            + "  "
            + pattern["name"]
        )

    click.echo()
