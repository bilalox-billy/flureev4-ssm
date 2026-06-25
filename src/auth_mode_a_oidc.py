"""
auth_mode_a_oidc.py — Mode A: OIDC Authentication
===================================================

This module implements the full OIDC (OpenID Connect) authentication flow
for Fluree as described in the Auth Contract specification.

WHAT IS OIDC?
─────────────
OIDC (OpenID Connect) is the login standard used by Google, GitHub, AWS
Cognito, Okta, Auth0, and most modern identity systems.

Instead of Fluree storing your password, it delegates the "who are you?"
question to a trusted third-party provider (your IdP).  Once the IdP
confirms you are who you say you are, it gives the CLI an "IdP token".
The CLI then trades that IdP token at Fluree's exchange endpoint for a
"Fluree-scoped Bearer token" that works on your Fluree server.

THE TWO SUB-FLOWS INSIDE OIDC
──────────────────────────────

  Sub-flow 1 — Device Code (preferred when available)
  ────────────────────────────────────────────────────
  The CLI shows you a URL and a short code on the terminal.
  You open that URL in your browser, enter the code, and log in.
  The CLI polls quietly in the background until you're done.
  No local server is needed.

  Sub-flow 2 — Auth Code + PKCE (fallback)
  ─────────────────────────────────────────
  The CLI opens your browser directly and starts a tiny local web
  server (http://127.0.0.1:8400/callback) to catch the login result.
  PKCE (Proof Key for Code Exchange) is added automatically to
  prevent code interception attacks — the CLI generates a random
  secret, proves it knows it to the IdP, so only this CLI instance
  can complete the login.

STEP-BY-STEP OVERVIEW
──────────────────────
  1. Discovery    GET /.well-known/fluree.json
                  → Learn auth config (issuer, client_id, exchange_url)

  2. OIDC Config  GET {issuer}/.well-known/openid-configuration
                  → Learn IdP endpoint URLs

  3. Login        Device code flow OR Auth Code + PKCE
                  → Receive an IdP token

  4. Exchange     POST {exchange_url}  (IdP token → Fluree Bearer token)
                  → Receive a Fluree-scoped JWT + optional refresh_token

  5. Done!        Use the FlureeClient with the new token.

REQUIRED .env VARIABLES
────────────────────────
  FLUREE_BASE_URL       https://my-fluree.example.com
  OIDC_ISSUER           https://cognito-idp.us-east-1.amazonaws.com/us-east-1_XXXX
  OIDC_CLIENT_ID        fluree-cli
  FLUREE_EXCHANGE_URL   https://my-fluree.example.com/v1/fluree/auth/exchange
  OIDC_SCOPES           openid profile   (space-separated)
  OIDC_REDIRECT_PORT    8400             (optional, default 8400)
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import hashlib
import base64
import secrets
import time
import webbrowser
import threading
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse, parse_qs
from typing import Any

import requests

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
# STEP 1  Discovery — fetch /.well-known/fluree.json
# ─────────────────────────────────────────────────────────────────────────────

def discover_fluree_config(base_url: str) -> dict:
    """
    Fetch the Fluree discovery document from /.well-known/fluree.json.

    This is the very first thing the CLI does when you add a new remote.
    The document tells us: what auth type the server supports, the OIDC
    issuer URL, the client_id, the exchange endpoint, and the API base URL.

    Parameters
    ----------
    base_url : str
        The root URL of your Fluree server (no trailing slash).

    Returns
    -------
    dict
        The full discovery document, e.g.::

            {
                "version": 1,
                "api_base_url": "https://...",
                "auth": {
                    "type": "oidc_device",
                    "issuer": "https://...",
                    "client_id": "fluree-cli",
                    "exchange_url": "https://...",
                    ...
                }
            }

    Raises
    ------
    SystemExit
        If the discovery endpoint is unreachable or returns an error.
    """
    url = f"{base_url.rstrip('/')}/.well-known/fluree.json"
    _info(f"Fetching discovery document: {url}")
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        doc = resp.json()
        _ok(f"Discovery successful  (version={doc.get('version', '?')})")
        return doc
    except requests.exceptions.ConnectionError:
        _err(f"Cannot connect to {base_url}")
        _warn("Is the server running and reachable from this machine?")
        raise SystemExit(1)
    except requests.HTTPError as exc:
        if exc.response.status_code == 404:
            _warn("Discovery endpoint not found (404).")
            _warn("The server does not expose /.well-known/fluree.json.")
            _warn("Falling back to manual token mode — use Mode B instead.")
        else:
            _err(f"HTTP error: {exc}")
        raise SystemExit(1)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2  OIDC Discovery — fetch {issuer}/.well-known/openid-configuration
# ─────────────────────────────────────────────────────────────────────────────

def discover_oidc_endpoints(issuer: str) -> dict:
    """
    Ask the Identity Provider (IdP) for its list of endpoints.

    Every OIDC-compliant IdP publishes a document at:
        {issuer}/.well-known/openid-configuration

    This document tells us where to send the login request, where to
    get tokens, and whether Device Code flow is supported.

    Parameters
    ----------
    issuer : str
        The OIDC issuer URL (from the Fluree discovery document).

    Returns
    -------
    dict
        Keys we care about:
            authorization_endpoint      — URL to open in the browser (PKCE)
            token_endpoint              — URL to exchange codes for tokens
            device_authorization_endpoint — URL for device code flow (optional)
    """
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    _info(f"Fetching OIDC configuration: {url}")
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        oidc = resp.json()
        _ok("OIDC endpoints discovered.")

        if "device_authorization_endpoint" in oidc:
            _info("Device Code flow is supported by this IdP.")
        else:
            _info("Device Code not supported — will use Auth Code + PKCE.")

        return oidc
    except Exception as exc:
        _err(f"Failed to fetch OIDC configuration: {exc}")
        raise SystemExit(1)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3a  Device Code Flow
# ─────────────────────────────────────────────────────────────────────────────

def login_device_code(
    oidc: dict,
    client_id: str,
    scopes: list[str],
) -> str:
    """
    Authenticate via the OAuth 2.0 Device Authorization flow.

    HOW IT WORKS
    ────────────
    1. We POST to `device_authorization_endpoint` with our client_id.
    2. The IdP responds with a short human-friendly code and a URL.
    3. We print those to the terminal.  You open the URL in any browser
       and type the code (or scan a QR code).
    4. We poll `token_endpoint` every few seconds.
    5. When you complete the browser login, the next poll returns your token.

    This flow is perfect for CLIs because it never needs a local server
    or to open the system browser automatically.

    Parameters
    ----------
    oidc : dict
        The OIDC configuration document (from discover_oidc_endpoints).
    client_id : str
        OAuth client ID.
    scopes : list[str]
        List of scopes to request (e.g. ["openid", "profile"]).

    Returns
    -------
    str
        The IdP access token.
    """
    device_endpoint = oidc["device_authorization_endpoint"]
    token_endpoint  = oidc["token_endpoint"]

    _step(3, "Starting Device Code flow…")

    # 3a-1: Request a device code
    resp = requests.post(
        device_endpoint,
        data={
            "client_id": client_id,
            "scope": " ".join(scopes),
        },
        timeout=10,
    )
    resp.raise_for_status()
    device = resp.json()

    verification_uri = device.get("verification_uri_complete") or device["verification_uri"]
    user_code        = device["user_code"]
    device_code      = device["device_code"]
    interval         = device.get("interval", 5)
    expires_in       = device.get("expires_in", 300)

    # 3a-2: Show the user what to do
    print()
    print(f"  {_BOLD}{'─' * 56}{_RESET}")
    print(f"  {_BOLD}  Open this URL in your browser:{_RESET}")
    print(f"  {_CYAN}  {verification_uri}{_RESET}")
    print(f"  {_BOLD}  Then enter this code:{_RESET}  {_YELLOW}{_BOLD}{user_code}{_RESET}")
    print(f"  {_BOLD}{'─' * 56}{_RESET}")
    print(f"  (Code expires in {expires_in // 60} minutes. Waiting for you…)\n")

    # 3a-3: Poll until the user logs in or the code expires
    deadline = time.time() + expires_in
    dots = [".  ", ".. ", "..."]
    dot_idx = 0

    while time.time() < deadline:
        time.sleep(interval)
        print(f"\r  {_CYAN}Waiting{dots[dot_idx % 3]}{_RESET}", end="", flush=True)
        dot_idx += 1

        poll_resp = requests.post(
            token_endpoint,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id":  client_id,
                "device_code": device_code,
            },
            timeout=10,
        )
        data = poll_resp.json()

        error = data.get("error")

        if error == "authorization_pending":
            # User hasn't finished logging in yet — keep waiting
            continue
        elif error == "slow_down":
            # IdP is asking us to back off a bit
            interval += 5
            continue
        elif error == "expired_token":
            print()
            _err("The device code expired before you logged in.")
            _warn("Re-run and complete the login faster.")
            raise SystemExit(1)
        elif error:
            print()
            _err(f"IdP error during polling: {data}")
            raise SystemExit(1)
        elif "access_token" in data:
            print()
            _ok("Browser login complete! Received IdP token.")
            return data["access_token"]

    print()
    _err("Timed out waiting for login.")
    raise SystemExit(1)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3b  Authorization Code + PKCE Flow (fallback)
# ─────────────────────────────────────────────────────────────────────────────

class _CallbackHandler(BaseHTTPRequestHandler):
    """
    Tiny HTTP request handler for the OAuth callback.

    When the browser redirects to http://127.0.0.1:{port}/callback?code=XXX,
    this handler captures the authorization code.
    """

    received_code: str | None = None

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if "code" in params:
            _CallbackHandler.received_code = params["code"][0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body style='font-family:sans-serif;text-align:center;padding:60px'>"
                b"<h2>&#10003; Login successful!</h2>"
                b"<p>You can close this browser tab and return to your terminal.</p>"
                b"</body></html>"
            )
        elif "error" in params:
            err = params.get("error", ["unknown"])[0]
            self.send_response(400)
            self.end_headers()
            self.wfile.write(f"Login error: {err}".encode())
        else:
            self.send_response(400)
            self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        pass  # suppress server access logs — they clutter the terminal


def _generate_pkce_pair() -> tuple[str, str]:
    """
    Generate a PKCE code_verifier + code_challenge pair.

    HOW PKCE WORKS
    ──────────────
    PKCE (Proof Key for Code Exchange) was designed to protect public OAuth
    clients (like CLIs and mobile apps that can't store a client secret).

    1. We generate a random 64-byte `code_verifier` string.
    2. We hash it with SHA-256 and base64url-encode it → `code_challenge`.
    3. We send `code_challenge` to the IdP with the login request.
    4. After login, we send `code_verifier` with the token exchange request.
    5. The IdP hashes our verifier and checks it matches the challenge.
       If a malicious app intercepted the `code`, it cannot use it without
       the original `code_verifier`.

    Returns
    -------
    tuple[str, str]
        (code_verifier, code_challenge)
    """
    code_verifier = secrets.token_urlsafe(64)
    digest        = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = (
        base64.urlsafe_b64encode(digest)
        .rstrip(b"=")
        .decode("ascii")
    )
    return code_verifier, code_challenge


def login_pkce(
    oidc: dict,
    client_id: str,
    scopes: list[str],
    redirect_port: int = 8400,
) -> str:
    """
    Authenticate via OAuth 2.0 Authorization Code flow with PKCE.

    HOW IT WORKS
    ────────────
    1. Generate a PKCE secret pair (verifier + challenge).
    2. Start a local HTTP server on http://127.0.0.1:{redirect_port}/callback.
    3. Open the system browser to the IdP login page.
    4. You log in normally in the browser.
    5. The IdP redirects the browser back to our local server with a ?code=...
    6. We capture the code and exchange it for an IdP access token.

    Parameters
    ----------
    oidc : dict
        OIDC configuration document.
    client_id : str
        OAuth client ID.
    scopes : list[str]
        Requested scopes.
    redirect_port : int
        Port for the local callback listener (default 8400).

    Returns
    -------
    str
        The IdP access token.
    """
    _step(3, "Starting Auth Code + PKCE flow…")

    auth_endpoint  = oidc["authorization_endpoint"]
    token_endpoint = oidc["token_endpoint"]
    redirect_uri   = f"http://127.0.0.1:{redirect_port}/callback"

    # --- PKCE ---
    code_verifier, code_challenge = _generate_pkce_pair()
    _info("Generated PKCE code_verifier + code_challenge.")

    # --- Build the browser URL ---
    login_url = auth_endpoint + "?" + urlencode({
        "response_type":         "code",
        "client_id":             client_id,
        "redirect_uri":          redirect_uri,
        "scope":                 " ".join(scopes),
        "code_challenge":        code_challenge,
        "code_challenge_method": "S256",
        "state":                 secrets.token_urlsafe(16),
    })

    # --- Start the callback server ---
    _CallbackHandler.received_code = None
    server = HTTPServer(("127.0.0.1", redirect_port), _CallbackHandler)

    server_thread = threading.Thread(target=server.handle_request, daemon=True)
    server_thread.start()

    _info(f"Local callback server started on {redirect_uri}")
    _info(f"Opening browser to IdP login page…")
    print()
    print(f"  {_BOLD}If your browser did not open automatically, paste this URL:{_RESET}")
    print(f"  {_CYAN}  {login_url}{_RESET}\n")

    webbrowser.open(login_url)

    # --- Wait for the callback ---
    print("  Waiting for login callback", end="", flush=True)
    timeout = 300
    elapsed = 0
    while _CallbackHandler.received_code is None and elapsed < timeout:
        time.sleep(1)
        elapsed += 1
        if elapsed % 5 == 0:
            print(".", end="", flush=True)

    print()

    if _CallbackHandler.received_code is None:
        _err("Timed out waiting for the browser callback.")
        raise SystemExit(1)

    auth_code = _CallbackHandler.received_code
    _ok("Browser login complete! Received authorization code.")

    # --- Exchange code for IdP token ---
    _info("Exchanging authorization code for IdP access token…")
    token_resp = requests.post(
        token_endpoint,
        data={
            "grant_type":    "authorization_code",
            "client_id":     client_id,
            "code":          auth_code,
            "redirect_uri":  redirect_uri,
            "code_verifier": code_verifier,
        },
        timeout=10,
    )

    try:
        token_resp.raise_for_status()
    except requests.HTTPError:
        _err(f"Token exchange failed: {token_resp.text}")
        raise SystemExit(1)

    token_data = token_resp.json()
    if "access_token" not in token_data:
        _err(f"IdP did not return an access_token: {token_data}")
        raise SystemExit(1)

    _ok("Received IdP access token.")
    return token_data["access_token"]


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4  Token Exchange — IdP token → Fluree Bearer token
# ─────────────────────────────────────────────────────────────────────────────

def exchange_for_fluree_token(
    exchange_url: str,
    idp_token: str,
) -> tuple[str, str | None]:
    """
    Trade your IdP token for a Fluree-scoped Bearer token.

    WHAT HAPPENS ON THE SERVER
    ──────────────────────────
    The Fluree exchange endpoint:
      1. Verifies your IdP token (cryptographic signature check).
      2. Looks up what ledgers and scopes you're entitled to.
      3. Mints (creates) a new Fluree-scoped JWT with those permissions.
      4. Returns the JWT as the access_token.

    This follows RFC 8693 (OAuth 2.0 Token Exchange).

    Parameters
    ----------
    exchange_url : str
        Full URL of the Fluree exchange endpoint.
    idp_token : str
        The access token received from the IdP after login.

    Returns
    -------
    tuple[str, str | None]
        (fluree_bearer_token, refresh_token_or_None)
    """
    _step(4, "Exchanging IdP token for Fluree Bearer token…")
    _info(f"POST {exchange_url}")

    payload = {
        "grant_type":        "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token":     idp_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
    }

    resp = requests.post(
        exchange_url,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=15,
    )

    if resp.status_code in (401, 403):
        data = resp.json()
        _err(f"Exchange rejected ({resp.status_code}): {data.get('error_description', data)}")
        _warn("Your IdP token may be invalid, or this user is not authorized.")
        raise SystemExit(1)

    try:
        resp.raise_for_status()
    except requests.HTTPError:
        _err(f"Exchange endpoint error: {resp.text}")
        raise SystemExit(1)

    result = resp.json()
    fluree_token   = result.get("access_token")
    refresh_token  = result.get("refresh_token")
    expires_in     = result.get("expires_in", "unknown")

    if not fluree_token:
        _err(f"Exchange endpoint did not return an access_token: {result}")
        raise SystemExit(1)

    _ok(f"Fluree Bearer token received! (expires in {expires_in}s)")
    if refresh_token:
        _ok("Refresh token received — silent renewal will be available.")
    else:
        _warn("No refresh token returned — you will need to re-login when the token expires.")

    return fluree_token, refresh_token


# ─────────────────────────────────────────────────────────────────────────────
# Token Refresh (bonus)
# ─────────────────────────────────────────────────────────────────────────────

def refresh_fluree_token(
    exchange_url: str,
    refresh_token: str,
) -> tuple[str, str | None]:
    """
    Silently get a new Fluree Bearer token using a stored refresh token.

    No browser interaction needed.  The CLI does this automatically on
    every 401 response when a refresh_token is available.

    Parameters
    ----------
    exchange_url : str
        The Fluree token exchange URL.
    refresh_token : str
        The refresh token previously received from the exchange endpoint.

    Returns
    -------
    tuple[str, str | None]
        (new_fluree_bearer_token, new_refresh_token_or_None)
    """
    _info("Attempting silent token refresh…")

    resp = requests.post(
        exchange_url,
        json={
            "grant_type":    "refresh_token",
            "refresh_token": refresh_token,
        },
        headers={"Content-Type": "application/json"},
        timeout=15,
    )

    if resp.status_code in (401, 403):
        _err("Refresh token is invalid or expired.  Please log in again.")
        raise SystemExit(1)

    resp.raise_for_status()
    result = resp.json()

    new_token   = result.get("access_token")
    new_refresh = result.get("refresh_token")

    if not new_token:
        _err(f"Refresh did not return an access_token: {result}")
        raise SystemExit(1)

    _ok("Token refreshed successfully.")
    return new_token, new_refresh


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point — run the full Mode A flow
# ─────────────────────────────────────────────────────────────────────────────

def run_mode_a() -> FlureeClient:
    """
    Execute the complete OIDC authentication flow and return a ready-to-use
    FlureeClient.

    This function ties together all the steps:
      1. Load config from .env
      2. Discover Fluree + OIDC endpoints
      3. Login via Device Code (or PKCE fallback)
      4. Exchange IdP token for Fluree Bearer token
      5. Verify the token works via /whoami
      6. Return a configured FlureeClient

    Returns
    -------
    FlureeClient
        An authenticated client ready to query and write data.
    """
    _banner("Mode A — OIDC Authentication")

    # --- Validate config ---
    cfg.require("FLUREE_BASE_URL", "FLUREE_LEDGER")

    # Prefer values from .env; fall back to the discovery document
    base_url     = cfg.FLUREE_BASE_URL
    exchange_url = cfg.FLUREE_EXCHANGE_URL
    issuer       = cfg.OIDC_ISSUER
    client_id    = cfg.OIDC_CLIENT_ID
    scopes       = cfg.OIDC_SCOPES.split()
    redirect_port = cfg.OIDC_REDIRECT_PORT

    # ── Step 1: Fluree discovery ──────────────────────────────────────────
    _step(1, "Fluree auth discovery…")
    fluree_doc = discover_fluree_config(base_url)
    auth_block = fluree_doc.get("auth", {})

    # Override env values only if not already set
    if not exchange_url:
        exchange_url = auth_block.get("exchange_url", "")
    if not issuer:
        issuer = auth_block.get("issuer", "")
    if not client_id:
        client_id = auth_block.get("client_id", "")
    if not scopes:
        scopes = auth_block.get("scopes", ["openid"])

    if auth_block.get("type") not in ("oidc_device", None):
        _warn(f"Server auth type is '{auth_block.get('type')}' — OIDC not supported.")
        _warn("Use Mode B (manual token) instead.")
        raise SystemExit(1)

    if not issuer or not client_id or not exchange_url:
        _err("Missing OIDC configuration.  Check your .env file:")
        _err("  OIDC_ISSUER, OIDC_CLIENT_ID, FLUREE_EXCHANGE_URL")
        raise SystemExit(1)

    print()
    _info(f"Issuer:       {issuer}")
    _info(f"Client ID:    {client_id}")
    _info(f"Exchange URL: {exchange_url}")
    _info(f"Scopes:       {' '.join(scopes)}")
    print()

    # ── Step 2: OIDC endpoint discovery ──────────────────────────────────
    _step(2, "OIDC endpoint discovery…")
    oidc = discover_oidc_endpoints(issuer)
    print()

    # ── Step 3: Login ─────────────────────────────────────────────────────
    if "device_authorization_endpoint" in oidc:
        idp_token = login_device_code(oidc, client_id, scopes)
    else:
        idp_token = login_pkce(oidc, client_id, scopes, redirect_port)

    print()

    # ── Step 4: Exchange ──────────────────────────────────────────────────
    fluree_token, refresh_token = exchange_for_fluree_token(exchange_url, idp_token)
    print()

    # ── Step 5: Verify & create client ───────────────────────────────────
    _step(5, "Verifying token with /whoami…")
    client = FlureeClient(
        base_url=base_url,
        token=fluree_token,
        ledger=cfg.FLUREE_LEDGER,
    )
    client.print_whoami()

    if refresh_token:
        _info("Tip: store the refresh_token to refresh silently when this token expires.")
        _info(f"  refresh_token = {refresh_token[:40]}…")

    _ok("Mode A complete — FlureeClient is ready to use!")
    return client


# ─────────────────────────────────────────────────────────────────────────────
# Example usage after authentication
# ─────────────────────────────────────────────────────────────────────────────

def demo_queries(client: FlureeClient) -> None:
    """
    Run a few example Fluree queries to show the client working.

    Parameters
    ----------
    client : FlureeClient
        An authenticated client (returned by run_mode_a).
    """
    _banner("Demo Queries")

    # --- 1. Create a ledger if it doesn't exist yet ---
    print(f"  {_BOLD}Creating ledger '{client.ledger}' (if not already present)…{_RESET}")
    try:
        result = client.create_ledger()
        _ok(f"Ledger created: {result}")
    except Exception as exc:
        if "409" in str(exc) or "already" in str(exc).lower():
            _warn(f"Ledger '{client.ledger}' already exists — skipping create.")
        else:
            _err(f"Create ledger failed: {exc}")

    print()

    # --- 2. Insert some sample data ---
    print(f"  {_BOLD}Inserting sample data…{_RESET}")
    sample_data = [
        {
            "@id":      "ex:alice",
            "@type":    "ex:Person",
            "ex:name":  "Alice",
            "ex:email": "alice@example.com",
            "ex:age":   30,
        },
        {
            "@id":      "ex:bob",
            "@type":    "ex:Person",
            "ex:name":  "Bob",
            "ex:email": "bob@example.com",
            "ex:age":   25,
        },
    ]
    try:
        result = client.insert(sample_data)
        _ok(f"Data inserted. Commit: {result}")
    except Exception as exc:
        _err(f"Insert failed: {exc}")

    print()

    # --- 3. Query the data back via JSON-LD query ---
    # POST /v1/fluree/query  |  Content-Type: application/json  |  fluree-ledger: {ledger}
    # Fluree v4 returns rows as lists — values align with `select` by position.
    print(f"  {_BOLD}Querying all persons (JSON-LD query)…{_RESET}")
    select_cols = ["?name", "?age"]
    try:
        rows = client.query({
            "@context": {"ex": "http://example.org/ns/"},
            "select":   select_cols,
            "where": [
                {
                    "@id":     "?person",
                    "@type":   "ex:Person",
                    "ex:name": "?name",
                    "ex:age":  "?age",
                }
            ],
            "orderBy": "?name",
        })
        _ok(f"Query returned {len(rows)} row(s):\n")
        for row in rows:
            name = row[0] if len(row) > 0 else "?"
            age  = row[1] if len(row) > 1 else "?"
            print(f"    {name:<15}  age={age}")
    except Exception as exc:
        _err(f"Query failed: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Script entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    client = run_mode_a()
    demo_queries(client)
