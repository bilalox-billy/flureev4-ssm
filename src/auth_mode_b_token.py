"""
auth_mode_b_token.py — Mode B: Manual Bearer Token
====================================================

This module implements the simplest possible Fluree authentication:
you provide a Bearer token yourself, the client attaches it to every
request.  No browser, no IdP, no OIDC.

WHEN TO USE MODE B
──────────────────
  ✓ Local development & testing
  ✓ Service accounts / automation (CI/CD pipelines)
  ✓ You already have a long-lived token from your operator
  ✓ The server does not expose /.well-known/fluree.json
  ✓ Quick prototyping before OIDC is configured

WHAT IS A BEARER TOKEN?
────────────────────────
A Bearer token is a string (typically a JWT — JSON Web Token) that
proves your identity.  When you attach it to an HTTP request as:

    Authorization: Bearer eyJ0eXAiOiJKV1Q...

…the server decodes it, verifies the cryptographic signature, and
checks your scopes to decide what you're allowed to do.

"Bearer" means "whoever bears (holds) this token is allowed in."
Treat it like a password — don't share it or commit it to git.

WHERE DO I GET A BEARER TOKEN?
──────────────────────────────
  Option 1 — From your Fluree operator (AWS admin for your deployment).
  Option 2 — Using the Fluree CLI:
                fluree auth login --remote <name>
                # then copy the token from .fluree/config.toml
  Option 3 — Using the Fluree CLI's Ed25519 token minting tool:
                fluree token mint --key <private-key-file>
  Option 4 — If Mode A (OIDC) is set up, the exchange endpoint issues one.

REQUIRED .env VARIABLE
───────────────────────
  FLUREE_BASE_URL      https://my-fluree.example.com
  FLUREE_LEDGER        my-org/my-ledger
  FLUREE_BEARER_TOKEN  eyJ0eXAiOiJKV1Q...

STEP-BY-STEP OVERVIEW (Mode B is intentionally simple)
───────────────────────────────────────────────────────
  1. Load token from env var (or prompt the user to paste it)
  2. Validate it is not obviously wrong (not empty, looks like a JWT)
  3. Verify it by calling GET /v1/fluree/whoami
  4. Return a FlureeClient ready to use
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import getpass
import re

import src.config as cfg
from src.fluree_client import FlureeClient

# ── Colour helpers ────────────────────────────────────────────────────────────
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"

def _banner(title: str) -> None:
    width = 60
    print(f"\n{_BOLD}{_CYAN}{'═' * width}{_RESET}")
    print(f"{_BOLD}{_CYAN}  {title}{_RESET}")
    print(f"{_BOLD}{_CYAN}{'═' * width}{_RESET}\n")

def _step(n: int, msg: str) -> None:
    print(f"  {_BOLD}[Step {n}]{_RESET} {msg}")

def _ok(msg: str)   -> None: print(f"  {_GREEN}{_BOLD}✓{_RESET}  {msg}")
def _info(msg: str) -> None: print(f"  {_CYAN}→{_RESET}  {msg}")
def _warn(msg: str) -> None: print(f"  {_YELLOW}⚠{_RESET}  {msg}")
def _err(msg: str)  -> None: print(f"  {_RED}✗{_RESET}  {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# JWT structure explainer (for learning purposes)
# ─────────────────────────────────────────────────────────────────────────────

def explain_jwt(token: str) -> None:
    """
    Decode and display the contents of a JWT in a human-readable way.

    A JWT has three parts separated by dots:
        header.payload.signature

    The header and payload are base64url-encoded JSON.
    The signature proves the token hasn't been tampered with.

    Parameters
    ----------
    token : str
        A JWT Bearer token string.

    NOTE: This function only DECODES the JWT — it does NOT verify the
    signature.  Decoding is safe for debugging, but the values shown here
    must never be trusted for authorization without server-side verification.
    """
    import base64
    import json as _json

    parts = token.split(".")
    if len(parts) != 3:
        _warn("This does not look like a JWT (expected 3 dot-separated parts).")
        return

    def _decode(part: str) -> dict:
        # JWT uses base64url without padding — we need to add it back
        padding = 4 - len(part) % 4
        padded  = part + ("=" * (padding % 4))
        raw     = base64.urlsafe_b64decode(padded)
        return _json.loads(raw)

    try:
        header  = _decode(parts[0])
        payload = _decode(parts[1])
    except Exception as exc:
        _warn(f"Could not decode JWT: {exc}")
        return

    print(f"\n  {_BOLD}{'─' * 56}{_RESET}")
    print(f"  {_BOLD}  JWT Contents (decoded, NOT verified){_RESET}")
    print(f"  {_BOLD}{'─' * 56}{_RESET}\n")

    print(f"  {_BOLD}Header:{_RESET}")
    for k, v in header.items():
        print(f"    {_CYAN}{k:<20}{_RESET} {v}")

    print()
    print(f"  {_BOLD}Payload (Claims):{_RESET}")
    for k, v in payload.items():
        label = k
        # Pretty-print some well-known fields
        if k == "exp":
            import datetime
            try:
                human = datetime.datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S UTC")
                v = f"{v}  ({human})"
            except Exception:
                pass
        elif k == "iat":
            import datetime
            try:
                human = datetime.datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S UTC")
                v = f"{v}  ({human})"
            except Exception:
                pass
        print(f"    {_CYAN}{label:<30}{_RESET} {v}")

    print()
    print(f"  {_BOLD}Signature:{_RESET}  {parts[2][:30]}…  (truncated)")
    print(f"  {_BOLD}{'─' * 56}{_RESET}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Step 1  — Load the token (env var or interactive prompt)
# ─────────────────────────────────────────────────────────────────────────────

def load_token() -> str:
    """
    Load a Bearer token from the environment or prompt the user to paste one.

    Priority order:
      1. FLUREE_BEARER_TOKEN env var (from .env file)
      2. Interactive secure prompt (characters are hidden as you type)

    Returns
    -------
    str
        The raw token string (not validated yet).
    """
    _step(1, "Loading Bearer token…")

    token = cfg.FLUREE_BEARER_TOKEN

    if token:
        _ok("Bearer token loaded from FLUREE_BEARER_TOKEN env variable.")
        # Show a truncated preview so the user can confirm it looks right
        preview = token[:30] + "…" if len(token) > 30 else token
        _info(f"Token preview: {preview}")
        return token

    # Not in env — prompt interactively (characters hidden for security)
    _warn("FLUREE_BEARER_TOKEN not found in .env — entering interactive mode.")
    print()
    print("  Paste your Fluree Bearer token below (input is hidden):")
    print("  (Get it from your operator, the CLI config, or your auth system)")
    print()

    try:
        token = getpass.getpass("  Bearer token: ").strip()
    except KeyboardInterrupt:
        print()
        _err("Cancelled by user.")
        raise SystemExit(0)

    if not token:
        _err("No token provided.")
        raise SystemExit(1)

    _ok("Token received.")
    return token


# ─────────────────────────────────────────────────────────────────────────────
# Step 2  — Basic validation (sanity check before hitting the server)
# ─────────────────────────────────────────────────────────────────────────────

def validate_token_format(token: str) -> None:
    """
    Do a quick sanity check on the token format.

    This does NOT verify the cryptographic signature — only the server
    can do that.  This just catches obvious mistakes (wrong value pasted,
    token has been accidentally truncated, etc.).

    Parameters
    ----------
    token : str
        The Bearer token to check.
    """
    _step(2, "Validating token format…")

    # A JWT always has exactly 3 dot-separated Base64url sections
    jwt_pattern = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$")

    if not token:
        _err("Token is empty.")
        raise SystemExit(1)

    if token.lower().startswith("bearer "):
        _warn("Your token starts with 'Bearer ' — stripping the prefix.")
        token = token[7:].strip()

    if not jwt_pattern.match(token):
        _warn("The token does not look like a standard JWT (3 dot-separated parts).")
        _warn("It might still work if it's a non-standard token format.")
        _warn("Continuing — the server will give the final verdict.")
    else:
        _ok("Token format looks correct (3-part JWT).")
        # Teach the user what's inside their token
        print()
        print(f"  {_BOLD}Would you like to see the decoded JWT contents?{_RESET}")
        print("  (This is just for learning — the server does the real verification)")
        choice = input("  Show JWT contents? [y/N]: ").strip().lower()
        if choice == "y":
            explain_jwt(token)


# ─────────────────────────────────────────────────────────────────────────────
# Step 3  — Server-side verification via /whoami
# ─────────────────────────────────────────────────────────────────────────────

def verify_with_server(client: FlureeClient) -> bool:
    """
    Ask the Fluree server to verify your token cryptographically.

    The /whoami endpoint uses the SAME verification code path as the
    actual data endpoints (query, insert, etc.), but with no side effects.
    It always returns HTTP 200 — check the 'verified' field in the response.

    Parameters
    ----------
    client : FlureeClient
        A client already configured with the token to verify.

    Returns
    -------
    bool
        True if the server confirms the token is valid and not expired.
    """
    _step(3, "Verifying token with the Fluree server (/whoami)…")
    _info(f"GET {client.base_url}/v1/fluree/whoami")

    try:
        info = client.whoami()
    except Exception as exc:
        _err(f"Could not reach the server: {exc}")
        _warn("Is FLUREE_BASE_URL correct in your .env file?")
        return False

    if not info.get("token_present"):
        _err("Server says: no token was received. Something is wrong with the request setup.")
        return False

    if info.get("verified"):
        _ok("Server verified the token — it is cryptographically valid.")
        return True
    else:
        error = info.get("error", "unknown reason")
        _err(f"Server says token is INVALID: {error}")

        # Help the user understand common errors
        if "expired" in error.lower():
            _warn("Your token has expired.  Get a new one from your operator or re-run Mode A.")
        elif "untrusted" in error.lower() or "issuer" in error.lower():
            _warn("The token's issuer is not trusted by this server.")
            _warn("Check the server's --trusted-issuer or --jwks-issuer configuration.")
        elif "signature" in error.lower() or "invalid" in error.lower():
            _warn("The token signature is wrong.  Make sure you copied the full token.")

        return False


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point — run the full Mode B flow
# ─────────────────────────────────────────────────────────────────────────────

def run_mode_b() -> FlureeClient:
    """
    Execute the manual token authentication flow and return a ready-to-use
    FlureeClient.

    Steps
    -----
    1. Load the token from env var or interactive prompt.
    2. Validate the token format (sanity check).
    3. Verify the token with the Fluree server (/whoami).
    4. Return a configured FlureeClient.

    Returns
    -------
    FlureeClient
        An authenticated client ready to query and write data.
    """
    _banner("Mode B — Manual Bearer Token Authentication")

    cfg.require("FLUREE_BASE_URL", "FLUREE_LEDGER")

    base_url = cfg.FLUREE_BASE_URL
    ledger   = cfg.FLUREE_LEDGER

    # ── Step 1: Load token ────────────────────────────────────────────────
    token = load_token()
    print()

    # ── Step 2: Format validation ─────────────────────────────────────────
    validate_token_format(token)
    print()

    # ── Step 3: Server verification ───────────────────────────────────────
    client = FlureeClient(base_url=base_url, token=token, ledger=ledger)
    is_valid = verify_with_server(client)
    print()

    # ── Pretty-print the full whoami response ─────────────────────────────
    client.print_whoami()

    if not is_valid:
        _warn("Continuing with an invalid token — API calls will likely fail with 401.")
        _warn("Get a fresh token and update FLUREE_BEARER_TOKEN in your .env file.")
    else:
        _ok("Mode B complete — FlureeClient is ready to use!")

    return client


# ─────────────────────────────────────────────────────────────────────────────
# Example usage after authentication
# ─────────────────────────────────────────────────────────────────────────────

def demo_queries(client: FlureeClient) -> None:
    """
    Run a sequence of example operations to demonstrate the client.

    Covers:
      - Creating a ledger
      - Inserting JSON-LD data
      - Querying with SPARQL
      - Handling errors gracefully

    Parameters
    ----------
    client : FlureeClient
        An authenticated FlureeClient (from run_mode_b).
    """
    _banner("Demo Queries")

    # ── 1. Create ledger ──────────────────────────────────────────────────
    print(f"  {_BOLD}[Demo 1] Create ledger '{client.ledger}'{_RESET}")
    try:
        result = client.create_ledger()
        _ok(f"Ledger created: {result}")
    except Exception as exc:
        if "409" in str(exc) or "already" in str(exc).lower():
            _warn(f"Ledger '{client.ledger}' already exists — that's fine, continuing.")
        else:
            _err(f"Could not create ledger: {exc}")
    print()

    # ── 2. Insert data ────────────────────────────────────────────────────
    print(f"  {_BOLD}[Demo 2] Insert sample data{_RESET}")
    _info("Inserting two Person nodes with JSON-LD…")
    data = {
        "@context": {
            "ex": "http://example.org/ns/",
            "schema": "http://schema.org/"
        },
        "@graph": [
           {
                "@id": "ex:charlie", 
                "@type":       "ex:Person",
                "ex:name":     "Charlie",
                "ex:role":     "Developer",
                "ex:active":   True,
           },

           {
                "@id":         "ex:diana",
                "@type":       "ex:Person",
                "ex:name":     "Diana",
                "ex:role":     "Designer",
                "ex:active":   True,
            },
        ]
    }


    try:
        result = client.insert(data)
        _ok(f"Insert successful: {result}")
    except Exception as exc:
        _err(f"Insert failed: {exc}")
    print()

    # ── 3. JSON-LD query ─────────────────────────────────────────────────
    # Fluree v4 returns results as a list of lists:
    #   select: ["?name", "?role"]  →  rows = [["Charlie", "Developer"], ["Diana", "Designer"]]
    # Access values by index position matching the select order.
    print(f"  {_BOLD}[Demo 3] JSON-LD query — find all active persons{_RESET}")
    select_cols = ["?name", "?role"]
    query = {
        "@context": {
            "ex": "http://example.org/ns/",
        },
        "select": select_cols,
        "where": [
            {
                "@id":       "?person",
                "@type":     "ex:Person",
                "ex:name":   "?name",
                "ex:role":   "?role",
                "ex:active": True,
            }
        ],
        "orderBy": "?name",
    }
    try:
        rows = client.query(query)
        _ok(f"Query returned {len(rows)} result(s):\n")
        # Each row is a list — values align with select_cols by position
        for row in rows:
            name = row[0] if len(row) > 0 else "?"
            role = row[1] if len(row) > 1 else "?"
            print(f"    {_CYAN}{str(name):<15}{_RESET}  role={role}")
    except Exception as exc:
        _err(f"Query failed: {exc}")
    print()

    # ── 4. Error handling demo ────────────────────────────────────────────
    print(f"  {_BOLD}[Demo 4] Error handling — query a non-existent ledger{_RESET}")
    _info("Querying 'does-not-exist/ledger' to demonstrate error handling…")
    try:
        client.query(
            {"select": ["?s"], "where": [{"@id": "?s"}]},
            ledger="does-not-exist/ledger",
        )
        _warn("Unexpectedly succeeded — the ledger might actually exist.")
    except Exception as exc:
        error_str = str(exc)
        if "404" in error_str:
            _ok(
                "Got 404 as expected.\n"
                "    This means either: the ledger doesn't exist,\n"
                "    OR: your token does not have scope for it.\n"
                "    (Fluree returns 404 for both — the anti-leak security pattern.)"
            )
        elif "401" in error_str:
            _warn("Got 401 — your token is invalid or expired.")
        else:
            _warn(f"Got an unexpected error: {exc}")

    print()
    _ok("Demo complete!")


# ─────────────────────────────────────────────────────────────────────────────
# Script entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    client = run_mode_b()
    demo_queries(client)
