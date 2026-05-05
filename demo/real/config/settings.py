"""Application settings — accidentally hardcoded during a late-night hotfix.
NOTE: All values are intentionally fake — used only for ContextDuty demos.
"""

# Database — copy-pasted from Slack DM, never cleaned up
DB_HOST = "prod-db.us-east-1.rds.amazonaws.com"
DB_USER = "app_user"
DB_PASS = "Xk9mP2qR8vL"
DB_NAME = "myapp_prod"
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}"

# AWS credentials left in after debugging session (canonical AWS docs example — not real)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# OpenAI key committed "temporarily" (demo pattern — not a real key)
OPENAI_KEY = "sk-EXAMPLEcontextdutyDEMOkeyXXXXXXXXXXXXXXXXXXXXXXXX"

# GCP service account JSON — pasted inline for "convenience"
GCP_CREDENTIALS = {
    "type": "service_account",
    "project_id": "myapp-prod-381204",
    "private_key_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n",
    "client_email": "deploy@myapp-prod-381204.iam.gserviceaccount.com",
}

# Notification config
ADMIN_EMAIL = "priya.sharma@myapp.com"
OPS_PHONE = "+1-415-555-0182"

# GitHub token for release automation (demo pattern — not a real token)
GITHUB_TOKEN = "ghp_EXAMPLEcontextdutyDEMOXXXXXXXXXXXX123"
