# env-scanner

> **"Exposed secrets in .env files are the #1 cause of credential leaks in production environments. env-scanner detects 40+ secret patterns across AWS, GCP, Azure, Stripe, Twilio, and database connections with severity-based color coding."**

A fast, lightweight Python CLI tool that scans `.env` files for exposed secrets and credentials — before they reach version control, CI logs, or production systems.

---

## Why env-scanner?

Every year, thousands of credentials are accidentally committed to Git repositories. A single exposed AWS Access Key can result in a six-figure cloud bill within hours. An exposed database password can hand attackers direct access to your entire dataset. env-scanner is your last line of defence — a pre-commit check, CI gate, and audit tool in one command.

---

## Features

- **40+ secret patterns** covering the most critical credential types
- **Severity-based color coding**: RED for critical, YELLOW for warnings, GREEN for clean files
- **Actionable remediation hints** for every finding
- **Recursive directory scanning** — scan entire project trees with one command
- **CI/CD friendly** — exits with code `1` when secrets are found
- **Zero bloat** — only two runtime dependencies: `click` and `colorama`
- **pip-installable** — works as a global CLI command

---

## Detected Secret Types

| Category | Patterns Detected |
|---|---|
| **AWS** | Access Key ID (`AKIA…`), Secret Access Key, Session Token |
| **GCP / Google** | API Keys (`AIza…`), Service Account JSON, Firebase Server Key |
| **Azure** | Storage Account Keys, Connection Strings, Client Secrets |
| **Stripe** | Live Secret (`sk_live_`), Publishable (`pk_live_`), Test (`sk_test_`), Webhooks |
| **GitHub** | Personal Access Tokens (`ghp_`), OAuth Tokens (`gho_`), App Tokens |
| **Slack** | Bot Tokens (`xoxb-`), User Tokens (`xoxp-`), Webhook URLs |
| **Twilio** | Account SID, Auth Token |
| **SendGrid** | API Keys (`SG.…`) |
| **Mailgun** | API Keys (`key-…`) |
| **Datadog** | API Keys, Application Keys |
| **New Relic** | License Keys |
| **NPM** | Auth Tokens (`npm_…`) |
| **Heroku** | API Keys (UUID format) |
| **DigitalOcean** | Personal Access Tokens |
| **Shopify** | Access Tokens (`shpat_`, `shpss_`) |
| **Okta** | API Tokens |
| **PayPal / Braintree** | Client Secrets, Private Keys |
| **PagerDuty** | API Keys |
| **JWT** | Signing secrets, private keys |
| **Private Keys** | RSA, EC, OpenSSH PEM headers |
| **Databases** | PostgreSQL, MySQL, MongoDB, Redis, AMQP/RabbitMQ connection strings |
| **Elasticsearch** | Passwords |
| **Generic** | `PASSWORD=`, `SECRET=`, `API_KEY=`, `TOKEN=`, `ENCRYPTION_KEY=` |

---

## Installation

### From PyPI (recommended)

```bash
pip install env-scanner
```

### From source (development)

```bash
git clone https://github.com/yourusername/env-scanner.git
cd env-scanner
pip install -e .
```

After installation, the `env-scanner` command is available globally.

---

## Usage

### Scan a specific file

```bash
env-scanner scan .env
env-scanner scan /path/to/.env.production
```

### Scan all .env files in a directory (recursive)

```bash
env-scanner scan --dir ./project
env-scanner scan --dir .
```

### Scan a directory non-recursively (top-level only)

```bash
env-scanner scan --dir . --no-recursive
```

### Filter by severity

```bash
# Only show critical findings
env-scanner scan .env --severity critical

# Only show warnings
env-scanner scan --dir . --severity warning
```

### Quiet mode (CI-friendly)

```bash
env-scanner scan .env --quiet
```

### List all supported patterns

```bash
env-scanner patterns
env-scanner patterns --severity critical
```

---

## Screenshot

```
  _____            ___
 | ____|_ ____   _/ __|  ___ __ _ _ __  _ __   ___ _ __
 |  _| | '_ \ \ / /\__ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |___| | | \ V / ___) | (_| (_| | | | | | | |  __/ |
 |_____|_| |_|\_/ |____/ \___\__,_|_| |_|_| |_|\___|_|

  Scanning your .env files for exposed secrets and credentials.

  Scanning file: .env.example

════════════════════════════════════════════════════════════════════════
  File: .env.example
════════════════════════════════════════════════════════════════════════
──────────────────────────────────────────────────────────────────────
  [1]  CRITICAL   AWS Access Key ID
        File       : .env.example  line 13
        Variable   : AWS_ACCESS_KEY_ID
        Severity   : CRITICAL
        Value hint : AKIA**********************
        Remediation: Rotate this key immediately in the AWS IAM console and audit CloudTrail for unauthorized usage.
──────────────────────────────────────────────────────────────────────
  [2]  CRITICAL   PostgreSQL Connection String
        File       : .env.example  line 22
        Variable   : DATABASE_URL
        Severity   : CRITICAL
        Value hint : post********************
        Remediation: Rotate the database password immediately and restrict network access to the DB host.

════════════════════════════════════════════════════════════════════════
  SCAN SUMMARY
──────────────────────────────────────────────────────────────────────
  Files scanned : 1
  Total findings: 28
  Critical       : 22
  Warnings       : 6

  ✘  28 secret(s) detected! Review each finding and rotate affected credentials.
──────────────────────────────────────────────────────────────────────
```

---

## CI/CD Integration

env-scanner exits with code `1` when any secrets are found, making it trivial to gate deployments.

### GitHub Actions

```yaml
name: Secret Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install env-scanner
        run: pip install env-scanner

      - name: Scan for secrets
        run: env-scanner scan --dir . --quiet
```

### Pre-commit hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: env-scanner
        name: Scan .env files for secrets
        entry: env-scanner scan
        language: system
        files: \.env
        pass_filenames: true
```

Or as a shell pre-commit hook (`.git/hooks/pre-commit`):

```bash
#!/bin/sh
env-scanner scan --dir . --quiet
if [ $? -ne 0 ]; then
  echo "ERROR: Secrets detected in .env files. Commit blocked."
  exit 1
fi
```

---

## Security Best Practices

1. **Never commit real `.env` files** — add `.env` to `.gitignore` immediately
2. **Use `.env.example`** — commit a template with dummy/blank values for documentation
3. **Use a secrets manager** — AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager, Azure Key Vault
4. **Rotate, don't just delete** — if a secret was ever committed, assume it is compromised
5. **Run env-scanner in CI** — catch secrets before they reach any remote branch
6. **Audit access logs** — after a leak, check cloud provider logs for unauthorized API calls

---

## Project Structure

```
env-scanner/
├── env_scanner/
│   ├── __init__.py      # Public API surface
│   ├── cli.py           # Click CLI commands
│   ├── scanner.py       # Core scan logic
│   ├── patterns.py      # 40+ regex patterns with severity & remediation
│   └── formatters.py    # Color-coded terminal output
├── .env.example         # Sample env file with dummy secrets (safe to commit)
├── .gitignore           # Python + .env exclusions
├── README.md
└── setup.py             # pip-installable package definition
```

---

## Python API

You can also use env-scanner programmatically:

```python
from env_scanner import scan_file, scan_directory, scan_single_file

# Scan one file
findings = scan_file(".env")
for f in findings:
    print(f.severity, f.secret_type, f.variable_name, f.line_number)

# Scan a directory
result = scan_directory("./project")
print(f"Found {result.critical_count} critical issues across {len(result.files_scanned)} files")

# Access pattern list
from env_scanner import PATTERNS
print(f"Total patterns: {len(PATTERNS)}")
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-pattern`)
3. Add your pattern to `env_scanner/patterns.py` with a name, regex, severity, and remediation hint
4. Add a test case to `.env.example`
5. Submit a pull request

### Adding a new pattern

```python
# In env_scanner/patterns.py
{
    "name": "MyService API Key",
    "regex": re.compile(r"(?i)(myservice[_\-]?api[_\-]?key)\s*=\s*['\"]?(ms_[A-Za-z0-9]{32})['\"]?"),
    "severity": CRITICAL,
    "remediation": "Revoke this key in the MyService dashboard under API Settings.",
},
```

---

## License

MIT © env-scanner contributors

---

## Disclaimer

env-scanner is a static analysis tool. It detects secrets based on known patterns and naming conventions. It may produce false positives (flagging non-sensitive values that match a pattern) or false negatives (missing secrets with unusual naming). Always combine env-scanner with a defence-in-depth secrets management strategy.
