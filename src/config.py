"""
config.py — Centralized configuration loader
=============================================

All settings are read from environment variables (or a .env file in the project root).
This keeps secrets out of your source code.

Copy `.env.example` → `.env` and fill in your values before running any example.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Load the .env file sitting at the project root (two levels up from src/)
# ---------------------------------------------------------------------------
_project_root = Path(__file__).resolve().parent.parent
load_dotenv(_project_root / ".env")


# ---------------------------------------------------------------------------
# Core Fluree server settings
# ---------------------------------------------------------------------------

#: Base URL of your Fluree server hosted on AWS.
#: Example: "https://my-fluree.us-east-1.elb.amazonaws.com"
#: No trailing slash.
FLUREE_BASE_URL: str = os.environ.get("FLUREE_BASE_URL", "").rstrip("/")

#: The ledger (database) you want to work with.
#: Example: "my-org/my-ledger"
FLUREE_LEDGER: str = os.environ.get("FLUREE_LEDGER", "")


# ---------------------------------------------------------------------------
# Mode A — OIDC settings
# These come from the /.well-known/fluree.json discovery document
# but you can also hard-code them here as overrides.
# ---------------------------------------------------------------------------

#: Your OIDC provider's issuer URL.
#: Example for AWS Cognito:
#:   "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXXXX"
OIDC_ISSUER: str = os.environ.get("OIDC_ISSUER", "")

#: The OAuth client_id registered for the Fluree CLI / your app.
OIDC_CLIENT_ID: str = os.environ.get("OIDC_CLIENT_ID", "")

#: The Fluree token exchange endpoint URL.
#: Example: "https://my-fluree.example.com/v1/fluree/auth/exchange"
FLUREE_EXCHANGE_URL: str = os.environ.get("FLUREE_EXCHANGE_URL", "")

#: OAuth scopes to request during login (space-separated string).
#: Fluree typically needs "openid profile"
OIDC_SCOPES: str = os.environ.get("OIDC_SCOPES", "openid profile")

#: Local port for the PKCE browser callback listener.
#: Fluree CLI default is 8400; must be allowlisted in your IdP's callback URLs.
OIDC_REDIRECT_PORT: int = int(os.environ.get("OIDC_REDIRECT_PORT", "8400"))


# ---------------------------------------------------------------------------
# Mode B — Manual Bearer Token
# ---------------------------------------------------------------------------

#: A pre-issued Fluree Bearer token.  Paste it here or put it in .env.
#: Example: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."
FLUREE_BEARER_TOKEN: str = os.environ.get("FLUREE_BEARER_TOKEN", "")


# ---------------------------------------------------------------------------
# Validation helper
# ---------------------------------------------------------------------------

def require(*names: str) -> None:
    """
    Raise a clear error if any required config values are missing.

    Usage:
        from src.config import require
        require("FLUREE_BASE_URL", "FLUREE_LEDGER")
    """
    missing = [n for n in names if not globals().get(n)]
    if missing:
        raise EnvironmentError(
            f"\n\n  Missing required configuration:\n"
            + "\n".join(f"    - {n}" for n in missing)
            + "\n\n  Add these to your .env file (copy .env.example first).\n"
        )
