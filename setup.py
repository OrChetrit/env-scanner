"""
setup.py for env-scanner.

Install in editable/development mode:
    pip install -e .

Install normally:
    pip install .

After installation the ``env-scanner`` command will be available in PATH.
"""

from setuptools import setup, find_packages  # type: ignore
from pathlib import Path

# Read the long description from README.md
HERE = Path(__file__).parent
long_description = (HERE / "README.md").read_text(encoding="utf-8")

setup(
    name="env-scanner",
    version="1.0.0",
    author="Or Chetrit",
    description=(
        "Detect 40+ exposed secret patterns in .env files – "
        "AWS keys, database passwords, API tokens and more."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/OrChetrit/env-scanner",
    license="MIT",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Build Tools",
        "Topic :: Utilities",
    ],
    keywords=[
        "security",
        "secrets",
        "dotenv",
        "env",
        "credentials",
        "aws",
        "api-key",
        "scanner",
        "linter",
        "devops",
    ],
    packages=find_packages(exclude=["tests*", "docs*"]),
    python_requires=">=3.8",
    install_requires=[
        "click~=8.0",       # compatible with 8.x; blocks major-version jumps
        "colorama~=0.4",    # compatible with 0.4.x
        "reportlab~=4.0",   # compatible with 4.x; blocks major-version jumps
    ],
    entry_points={
        "console_scripts": [
            "env-scanner=env_scanner.cli:cli",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/OrChetrit/env-scanner/issues",
        "Source": "https://github.com/OrChetrit/env-scanner",
    },
)
