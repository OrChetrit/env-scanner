"""
Secret detection patterns for env-scanner.

Each pattern entry is a dict with:
    name        - Human-readable name for the secret type
    regex       - Compiled regular expression to match against a .env line
    severity    - 'critical' | 'warning'
    remediation - Actionable hint shown to the user
"""

import re

# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------
CRITICAL = "critical"
WARNING = "warning"

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------
# Each regex is designed to match a *value* on a line in the form:
#   KEY=VALUE  or  KEY="VALUE"  or  KEY='VALUE'
# The patterns intentionally avoid matching commented-out lines (lines that
# start with #) – the scanner strips comments before testing.

PATTERNS = [
    # -----------------------------------------------------------------------
    # AWS
    # -----------------------------------------------------------------------
    {
        "name": "AWS Access Key ID",
        "regex": re.compile(r"(?i)(aws_access_key_id|aws_access_key)\s*=\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate this key immediately in the AWS IAM console and audit CloudTrail for unauthorized usage.",
    },
    {
        "name": "AWS Secret Access Key",
        "regex": re.compile(r"(?i)(aws_secret_access_key|aws_secret_key)\s*=\s*['\"]?([A-Za-z0-9/+]{40})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate this key in the AWS IAM console and revoke all active sessions.",
    },
    {
        "name": "AWS Session Token",
        "regex": re.compile(r"(?i)(aws_session_token)\s*=\s*['\"]?([A-Za-z0-9/+=]{100,2048})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Invalidate this session token via AWS STS and rotate the underlying credentials.",
    },
    # -----------------------------------------------------------------------
    # Stripe
    # -----------------------------------------------------------------------
    {
        "name": "Stripe Live Secret Key",
        "regex": re.compile(r"(?i)(stripe[_\-]?(secret|api)[_\-]?key|stripe[_\-]?sk)\s*=\s*['\"]?(sk_live_[0-9a-zA-Z]{24,})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Roll this key in the Stripe Dashboard under Developers → API Keys.",
    },
    {
        "name": "Stripe Live Publishable Key",
        "regex": re.compile(r"(?i)(stripe[_\-]?(publishable|public)[_\-]?key|stripe[_\-]?pk)\s*=\s*['\"]?(pk_live_[0-9a-zA-Z]{24,})['\"]?"),
        "severity": WARNING,
        "remediation": "Publishable keys are less sensitive but still identify your account. Rotate in Stripe Dashboard.",
    },
    {
        "name": "Stripe Test Secret Key",
        "regex": re.compile(r"(?i)(stripe[_\-]?(secret|api)[_\-]?key|stripe[_\-]?sk)\s*=\s*['\"]?(sk_test_[0-9a-zA-Z]{24,})['\"]?"),
        "severity": WARNING,
        "remediation": "Test keys should not be committed. Move to environment-specific secret management.",
    },
    {
        "name": "Stripe Webhook Secret",
        "regex": re.compile(r"(?i)(stripe[_\-]?webhook[_\-]?(secret|key))\s*=\s*['\"]?(whsec_[0-9a-zA-Z]{32,})['\"]?"),
        "severity": WARNING,
        "remediation": "Regenerate this webhook secret in the Stripe Dashboard.",
    },
    # -----------------------------------------------------------------------
    # Database connection strings
    # -----------------------------------------------------------------------
    {
        "name": "PostgreSQL Connection String",
        "regex": re.compile(r"(?i)(database_url|db_url|postgres_url|postgresql_url)\s*=\s*['\"]?(postgres(?:ql)?://[^\s'\"]+)['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate the database password immediately and restrict network access to the DB host.",
    },
    {
        "name": "MySQL Connection String",
        "regex": re.compile(r"(?i)(database_url|db_url|mysql_url)\s*=\s*['\"]?(mysql(?:2)?://[^\s'\"]+)['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate the database password and audit MySQL user privileges.",
    },
    {
        "name": "MongoDB Connection String",
        "regex": re.compile(r"(?i)(mongo(?:db)?_uri|mongo(?:db)?_url|database_url)\s*=\s*['\"]?(mongodb(?:\+srv)?://[^\s'\"]+)['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate the MongoDB user password and enable IP allowlisting in Atlas or your firewall.",
    },
    {
        "name": "Redis Connection String",
        "regex": re.compile(r"(?i)(redis_url|cache_url)\s*=\s*['\"]?(rediss?://[^\s'\"]+)['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate the Redis auth token and restrict access via network ACLs.",
    },
    {
        "name": "SQLite File Path with Credentials",
        "regex": re.compile(r"(?i)(database_url|db_url)\s*=\s*['\"]?(sqlite:///[^\s'\"]+)['\"]?"),
        "severity": WARNING,
        "remediation": "Ensure the SQLite file is not accessible via the web server.",
    },
    # -----------------------------------------------------------------------
    # Twilio
    # -----------------------------------------------------------------------
    {
        "name": "Twilio Account SID",
        "regex": re.compile(r"(?i)(twilio[_\-]?account[_\-]?sid)\s*=\s*['\"]?(AC[a-f0-9]{32})['\"]?"),
        "severity": WARNING,
        "remediation": "Rotate Twilio credentials in the Twilio Console under Account → API Keys.",
    },
    {
        "name": "Twilio Auth Token",
        "regex": re.compile(r"(?i)(twilio[_\-]?auth[_\-]?token)\s*=\s*['\"]?([a-f0-9]{32})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate the Twilio Auth Token in the Twilio Console immediately.",
    },
    # -----------------------------------------------------------------------
    # SendGrid
    # -----------------------------------------------------------------------
    {
        "name": "SendGrid API Key",
        "regex": re.compile(r"(?i)(sendgrid[_\-]?api[_\-]?key)\s*=\s*['\"]?(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Revoke this key in SendGrid Settings → API Keys and create a new one.",
    },
    # -----------------------------------------------------------------------
    # GitHub
    # -----------------------------------------------------------------------
    {
        "name": "GitHub Personal Access Token",
        "regex": re.compile(r"(?i)(github[_\-]?token|gh[_\-]?token|github[_\-]?pat)\s*=\s*['\"]?(ghp_[A-Za-z0-9]{36})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Revoke this token at github.com/settings/tokens immediately.",
    },
    {
        "name": "GitHub OAuth Token",
        "regex": re.compile(r"(?i)(github[_\-]?token|gh[_\-]?token)\s*=\s*['\"]?(gho_[A-Za-z0-9]{36})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Revoke this OAuth token in your GitHub application settings.",
    },
    {
        "name": "GitHub App Token",
        "regex": re.compile(r"(?i)(github[_\-]?token)\s*=\s*['\"]?(ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Revoke this GitHub App token and regenerate it in the App settings.",
    },
    # -----------------------------------------------------------------------
    # Slack
    # -----------------------------------------------------------------------
    {
        "name": "Slack Bot Token",
        "regex": re.compile(r"(?i)(slack[_\-]?(?:bot[_\-]?)?token)\s*=\s*['\"]?(xoxb-[0-9A-Za-z\-]{24,200})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Revoke this token at api.slack.com/apps and regenerate it.",
    },
    {
        "name": "Slack User Token",
        "regex": re.compile(r"(?i)(slack[_\-]?(?:user[_\-]?)?token)\s*=\s*['\"]?(xoxp-[0-9A-Za-z\-]{24,200})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Revoke this user token at api.slack.com/apps immediately.",
    },
    {
        "name": "Slack Webhook URL",
        "regex": re.compile(r"(?i)(slack[_\-]?webhook[_\-]?url)\s*=\s*['\"]?(https://hooks\.slack\.com/services/[A-Za-z0-9/]+)['\"]?"),
        "severity": WARNING,
        "remediation": "Revoke this webhook URL in your Slack app configuration.",
    },
    # -----------------------------------------------------------------------
    # Google / GCP
    # -----------------------------------------------------------------------
    {
        "name": "Google API Key",
        "regex": re.compile(r"(?i)(google[_\-]?api[_\-]?key|gcp[_\-]?api[_\-]?key)\s*=\s*['\"]?(AIza[0-9A-Za-z\-_]{35})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Restrict or delete this key in GCP Console → APIs & Services → Credentials.",
    },
    {
        "name": "GCP Service Account Key (JSON)",
        "regex": re.compile(r"(?i)(google[_\-]?application[_\-]?credentials|gcp[_\-]?credentials)\s*=\s*['\"]?(\{[^}]{0,4096}\"private_key\"[^}]{0,4096}\}|/[^\s'\"]{1,512}\.json)['\"]?"),
        "severity": CRITICAL,
        "remediation": "Delete this service account key in GCP IAM and create a new one with least-privilege.",
    },
    {
        "name": "Firebase Server Key",
        "regex": re.compile(r"(?i)(firebase[_\-]?server[_\-]?key|fcm[_\-]?server[_\-]?key)\s*=\s*['\"]?(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Regenerate this key in the Firebase Console under Project Settings.",
    },
    # -----------------------------------------------------------------------
    # Azure
    # -----------------------------------------------------------------------
    {
        "name": "Azure Storage Account Key",
        "regex": re.compile(r"(?i)(azure[_\-]?storage[_\-]?(account[_\-]?)?key|azure[_\-]?account[_\-]?key)\s*=\s*['\"]?([A-Za-z0-9+/]{86}==)['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate this key in Azure Portal → Storage Account → Access Keys.",
    },
    {
        "name": "Azure Connection String",
        "regex": re.compile(r"(?i)(azure[_\-]?storage[_\-]?connection[_\-]?string|azure[_\-]?conn[_\-]?str)\s*=\s*['\"]?(DefaultEndpointsProtocol=https;[^\s'\"]+)['\"]?"),
        "severity": CRITICAL,
        "remediation": "Regenerate this connection string in the Azure Portal.",
    },
    {
        "name": "Azure Client Secret",
        "regex": re.compile(r"(?i)(azure[_\-]?client[_\-]?secret|azure[_\-]?app[_\-]?secret)\s*=\s*['\"]?([A-Za-z0-9~.\-_]{34,})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate this client secret in Azure Active Directory → App Registrations.",
    },
    # -----------------------------------------------------------------------
    # Datadog
    # -----------------------------------------------------------------------
    {
        "name": "Datadog API Key",
        "regex": re.compile(r"(?i)(datadog[_\-]?api[_\-]?key|dd[_\-]?api[_\-]?key)\s*=\s*['\"]?([a-f0-9]{32})['\"]?"),
        "severity": WARNING,
        "remediation": "Revoke this key in Datadog → Organization Settings → API Keys.",
    },
    {
        "name": "Datadog Application Key",
        "regex": re.compile(r"(?i)(datadog[_\-]?app[_\-]?key|dd[_\-]?app[_\-]?key)\s*=\s*['\"]?([a-f0-9]{40})['\"]?"),
        "severity": WARNING,
        "remediation": "Revoke this key in Datadog → Organization Settings → Application Keys.",
    },
    # -----------------------------------------------------------------------
    # New Relic
    # -----------------------------------------------------------------------
    {
        "name": "New Relic License Key",
        "regex": re.compile(r"(?i)(new[_\-]?relic[_\-]?(license[_\-]?)?key|nr[_\-]?license[_\-]?key)\s*=\s*['\"]?([A-Za-z0-9]{40})['\"]?"),
        "severity": WARNING,
        "remediation": "Revoke this key in New Relic → API Keys and generate a new one.",
    },
    # -----------------------------------------------------------------------
    # Mailgun
    # -----------------------------------------------------------------------
    {
        "name": "Mailgun API Key",
        "regex": re.compile(r"(?i)(mailgun[_\-]?api[_\-]?key)\s*=\s*['\"]?(key-[0-9a-f]{32})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Revoke this key in the Mailgun Dashboard under API Security.",
    },
    # -----------------------------------------------------------------------
    # JWT
    # -----------------------------------------------------------------------
    {
        "name": "JWT Secret",
        "regex": re.compile(r"(?i)(jwt[_\-]?secret|jwt[_\-]?signing[_\-]?key|jwt[_\-]?private[_\-]?key)\s*=\s*['\"]?([A-Za-z0-9_\-+/=]{16,})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate the JWT secret and invalidate all outstanding tokens immediately.",
    },
    # -----------------------------------------------------------------------
    # Private keys (PEM blocks embedded in env values)
    # -----------------------------------------------------------------------
    {
        "name": "RSA Private Key",
        "regex": re.compile(r"(?i)(private[_\-]?key|rsa[_\-]?private[_\-]?key)\s*=\s*['\"]?(-----BEGIN RSA PRIVATE KEY-----)"),
        "severity": CRITICAL,
        "remediation": "Revoke and replace this RSA private key immediately; never store PEM blocks in .env files.",
    },
    {
        "name": "EC Private Key",
        "regex": re.compile(r"(?i)(private[_\-]?key|ec[_\-]?private[_\-]?key)\s*=\s*['\"]?(-----BEGIN EC PRIVATE KEY-----)"),
        "severity": CRITICAL,
        "remediation": "Revoke and replace this EC private key immediately.",
    },
    {
        "name": "OpenSSH Private Key",
        "regex": re.compile(r"(?i)(private[_\-]?key|ssh[_\-]?key)\s*=\s*['\"]?(-----BEGIN OPENSSH PRIVATE KEY-----)"),
        "severity": CRITICAL,
        "remediation": "Revoke this SSH private key and generate a new key pair.",
    },
    {
        "name": "Generic Private Key Header",
        "regex": re.compile(r"(?i)(private[_\-]?key)\s*=\s*['\"]?(-----BEGIN [A-Z ]+ PRIVATE KEY-----)"),
        "severity": CRITICAL,
        "remediation": "Revoke and replace this private key immediately.",
    },
    # -----------------------------------------------------------------------
    # Generic passwords / secrets
    # -----------------------------------------------------------------------
    {
        "name": "Generic Password",
        "regex": re.compile(r"(?i)^(password|passwd|pass|db_pass(?:word)?|database_pass(?:word)?)\s*=\s*['\"]?([^\s'\"]{6,512})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate this password and store it in a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.).",
    },
    {
        "name": "Generic Secret",
        "regex": re.compile(r"(?i)^(secret|app_secret|secret_key|api_secret)\s*=\s*['\"]?([^\s'\"]{6,512})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate this secret and store it in a dedicated secrets manager.",
    },
    {
        "name": "Generic API Key",
        "regex": re.compile(r"(?i)^(api_key|apikey|access_key|access_token|auth_token)\s*=\s*['\"]?([A-Za-z0-9_\-]{16,256})['\"]?"),
        "severity": WARNING,
        "remediation": "Rotate this credential and avoid committing API keys to version control.",
    },
    {
        "name": "Generic Token",
        "regex": re.compile(r"(?i)^(token|auth_token|bearer_token|access_token)\s*=\s*['\"]?([A-Za-z0-9_.\-]{20,512})['\"]?"),
        "severity": WARNING,
        "remediation": "Rotate this token and use a secrets manager for storage.",
    },
    # -----------------------------------------------------------------------
    # NPM / Package registry
    # -----------------------------------------------------------------------
    {
        "name": "NPM Auth Token",
        "regex": re.compile(r"(?i)(npm[_\-]?token|npm[_\-]?auth[_\-]?token)\s*=\s*['\"]?(npm_[A-Za-z0-9]{36})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Revoke this token at npmjs.com/settings/tokens.",
    },
    # -----------------------------------------------------------------------
    # Heroku
    # -----------------------------------------------------------------------
    {
        "name": "Heroku API Key",
        "regex": re.compile(r"(?i)(heroku[_\-]?api[_\-]?key)\s*=\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Revoke this key in Heroku Dashboard → Account Settings → API Key.",
    },
    # -----------------------------------------------------------------------
    # DigitalOcean
    # -----------------------------------------------------------------------
    {
        "name": "DigitalOcean Personal Access Token",
        "regex": re.compile(r"(?i)(digitalocean[_\-]?token|do[_\-]?token)\s*=\s*['\"]?([a-f0-9]{64})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Revoke this token in DigitalOcean → API → Personal Access Tokens.",
    },
    # -----------------------------------------------------------------------
    # Shopify
    # -----------------------------------------------------------------------
    {
        "name": "Shopify Access Token",
        "regex": re.compile(r"(?i)(shopify[_\-]?access[_\-]?token|shopify[_\-]?api[_\-]?key)\s*=\s*['\"]?(shpat_[A-Za-z0-9]{32}|shpss_[A-Za-z0-9]{32})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Revoke this token in Shopify Partner Dashboard → Apps.",
    },
    # -----------------------------------------------------------------------
    # PayPal / Braintree
    # -----------------------------------------------------------------------
    {
        "name": "PayPal/Braintree Access Token",
        "regex": re.compile(r"(?i)(paypal[_\-]?(?:client[_\-]?)?secret|braintree[_\-]?private[_\-]?key)\s*=\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate this credential in your PayPal/Braintree developer dashboard.",
    },
    # -----------------------------------------------------------------------
    # Okta
    # -----------------------------------------------------------------------
    {
        "name": "Okta API Token",
        "regex": re.compile(r"(?i)(okta[_\-]?api[_\-]?token|okta[_\-]?token)\s*=\s*['\"]?(00[A-Za-z0-9_\-]{40})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Revoke this token in Okta Admin Console → Security → API → Tokens.",
    },
    # -----------------------------------------------------------------------
    # PagerDuty
    # -----------------------------------------------------------------------
    {
        "name": "PagerDuty API Key",
        "regex": re.compile(r"(?i)(pagerduty[_\-]?api[_\-]?key|pd[_\-]?api[_\-]?key)\s*=\s*['\"]?([A-Za-z0-9_\-+]{18,})['\"]?"),
        "severity": WARNING,
        "remediation": "Revoke this key in PagerDuty → User Settings → API Access.",
    },
    # -----------------------------------------------------------------------
    # Elasticsearch / OpenSearch
    # -----------------------------------------------------------------------
    {
        "name": "Elasticsearch Password",
        "regex": re.compile(r"(?i)(elasticsearch[_\-]?password|elastic[_\-]?password|opensearch[_\-]?password)\s*=\s*['\"]?([^\s'\"]{8,})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Reset the Elasticsearch/OpenSearch user password and rotate the API key.",
    },
    # -----------------------------------------------------------------------
    # RabbitMQ / AMQP
    # -----------------------------------------------------------------------
    {
        "name": "AMQP / RabbitMQ Connection String",
        "regex": re.compile(r"(?i)(amqp[s]?_url|rabbitmq_url|celery_broker_url)\s*=\s*['\"]?(amqps?://[^\s'\"]+)['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate the RabbitMQ/AMQP credentials and restrict vhost permissions.",
    },
    # -----------------------------------------------------------------------
    # Encryption keys
    # -----------------------------------------------------------------------
    {
        "name": "Encryption Key / Passphrase",
        "regex": re.compile(r"(?i)(encryption[_\-]?key|encrypt[_\-]?key|aes[_\-]?key|master[_\-]?key)\s*=\s*['\"]?([A-Za-z0-9+/=]{16,})['\"]?"),
        "severity": CRITICAL,
        "remediation": "Rotate this encryption key and re-encrypt affected data with the new key.",
    },
]
