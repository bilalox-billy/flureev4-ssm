"""
fluree_client.py — Fluree HTTP API client
==========================================

A thin, beginner-friendly Python wrapper around the Fluree v4 HTTP API.

WIRE FORMAT (confirmed working against Fluree v4)
──────────────────────────────────────────────────

  ┌──────────────────┬───────────────────────────┬───────────────────────────────────────┐
  │ Operation        │ Endpoint                  │ Headers                               │
  ├──────────────────┼───────────────────────────┼───────────────────────────────────────┤
  │ JSON-LD query    │ POST /v1/fluree/query      │ Content-Type: application/json        │
  │                  │                           │ fluree-ledger: {ledger}               │
  │                  │                           │ Authorization: Bearer {token}         │
  ├──────────────────┼───────────────────────────┼───────────────────────────────────────┤
  │ JSON-LD insert   │ POST /v1/fluree/insert     │ Content-Type: application/json        │
  │                  │                           │ Authorization: Bearer {token}         │
  ├──────────────────┼───────────────────────────┼───────────────────────────────────────┤
  │ Create ledger    │ POST /v1/fluree/create     │ Content-Type: application/json        │
  │                  │                           │ Authorization: Bearer {token}         │
  ├──────────────────┼───────────────────────────┼───────────────────────────────────────┤
  │ Token check      │ GET  /v1/fluree/whoami     │ Authorization: Bearer {token}         │
  └──────────────────┴───────────────────────────┴───────────────────────────────────────┘

JSON-LD QUERY BODY SHAPE
─────────────────────────
    {
        "@context": { "schema": "http://schema.org/" },
        "from":     "mydb:main",          ← always added automatically from self.ledger
        "select":   ["?name", "?email"],
        "where": [
            { "@id": "?person", "@type": "schema:Person", "schema:name": "?name" }
        ]
    }

Usage:
    from src.fluree_client import FlureeClient

    client = FlureeClient(
        base_url="http://localhost:8090",
        token="eyJ...",
        ledger="mydb:main",
    )

    rows = client.query({
        "@context": {"schema": "http://schema.org/"},
        "select": ["?name"],
        "where": [{"@id": "?p", "@type": "schema:Person", "schema:name": "?name"}],
    })
"""

from __future__ import annotations

import json
from typing import Any

import requests


# ---------------------------------------------------------------------------
# Colour helpers for terminal output
# ---------------------------------------------------------------------------
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"

def _ok(msg: str)   -> str: return f"{_GREEN}{_BOLD}✓{_RESET} {msg}"
def _warn(msg: str) -> str: return f"{_YELLOW}{_BOLD}⚠{_RESET} {msg}"
def _err(msg: str)  -> str: return f"{_RED}{_BOLD}✗{_RESET} {msg}"
def _info(msg: str) -> str: return f"{_CYAN}→{_RESET} {msg}"


class FlureeAuthError(Exception):
    """Raised when the server returns 401 or 403."""


class FlureeClient:
    """
    Thin wrapper around the Fluree v4 HTTP API.

    Parameters
    ----------
    base_url : str
        Root URL of your Fluree server.  No trailing slash.
        Example: "http://localhost:8090"
                 "https://my-fluree.us-east-1.elb.amazonaws.com"

    token : str
        A valid Fluree Bearer token.

    ledger : str, optional
        Default ledger used in all operations.
        Example: "mydb:main"  or  "my-org/my-ledger"

    timeout : int
        HTTP request timeout in seconds (default 30).
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        ledger: str = "",
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token    = token
        self.ledger   = ledger
        self.timeout  = timeout

        # Base headers shared by all requests.
        # Content-Type is application/json for every Fluree v4 endpoint.
        # The fluree-ledger header is added per-request only where needed (queries).
        self._base_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _handle_error(self, resp: requests.Response) -> None:
        """Raise a clear exception on auth or HTTP errors."""
        if resp.status_code in (401, 403):
            try:
                msg = resp.json().get("error", resp.text)
            except Exception:
                msg = resp.text
            raise FlureeAuthError(
                f"Authentication error ({resp.status_code}): {msg}\n"
                "  → Your token may be expired. Re-run the auth flow."
            )
        resp.raise_for_status()

    def _post(self, path: str, body: dict, extra_headers: dict | None = None) -> Any:
        """POST JSON to a Fluree endpoint."""
        headers = {**self._base_headers, **(extra_headers or {})}
        resp = requests.post(
            self._url(path),
            headers=headers,
            json=body,
            timeout=self.timeout,
        )
        self._handle_error(resp)
        return resp.json()

    def _get(self, path: str) -> Any:
        """GET a Fluree endpoint (no body)."""
        resp = requests.get(
            self._url(path),
            headers=self._base_headers,
            timeout=self.timeout,
        )
        self._handle_error(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def whoami(self) -> dict:
        """
        Verify the current Bearer token against the server.

        Calls GET /v1/fluree/whoami — always returns HTTP 200.
        Check the `verified` field to know if the token is valid.

        Returns
        -------
        dict
            Keys: token_present, verified, auth_method, issuer,
                  subject, identity, expires_at, scopes.

        Example
        -------
            info = client.whoami()
            if info.get("verified"):
                print("Token OK!")
        """
        return self._get("/v1/fluree/whoami")

    def create_ledger(self, ledger: str | None = None) -> dict:
        """
        Create a new ledger on the server.

        POST /v1/fluree/create  with  Content-Type: application/json

        Parameters
        ----------
        ledger : str, optional
            Ledger name to create.  Defaults to self.ledger.

        Raises
        ------
        requests.HTTPError (409)
            If the ledger already exists.
        """
        name = ledger or self.ledger
        if not name:
            raise ValueError("Provide a ledger name or set self.ledger.")
        return self._post("/v1/fluree/create", {"ledger": name})

    def query(self, jsonld_query: dict, ledger: str | None = None) -> Any:
        """
        Run a JSON-LD query against a ledger.

        POST /v1/fluree/query
        Headers: Content-Type: application/json
                 fluree-ledger: {ledger}
        Body:    {"from": ledger, "@context": {...}, "select": [...], "where": [...]}

        The `from` key and `fluree-ledger` header are injected automatically —
        you don't need to include them in your query dict.

        Parameters
        ----------
        jsonld_query : dict
            A JSON-LD query object.  Supported keys:
                @context  — prefix mappings (e.g. {"schema": "http://schema.org/"})
                select    — list of variables to return (e.g. ["?name", "?age"])
                where     — list of triple patterns (JSON-LD node objects with ?vars)
                orderBy   — variable to sort by (e.g. "?name")
                limit     — max rows to return (int)
                offset    — rows to skip (int)

        ledger : str, optional
            Ledger to query.  Defaults to self.ledger.

        Returns
        -------
        list[list]
            A list of rows.  Each row is itself a list of values ordered to
            match the `select` clause positions — NOT a dict.

            Example: select ["?name", "?age"] returns:
                [
                    ["Alice", 30],
                    ["Bob",   25],
                ]

            Access by index:
                for row in rows:
                    name = row[0]
                    age  = row[1]

        Examples
        --------
        Basic SELECT:
            rows = client.query({
                "@context": {"schema": "http://schema.org/"},
                "select":   ["?name", "?email"],
                "where": [
                    {"@id": "?p", "@type": "schema:Person",
                     "schema:name": "?name", "schema:email": "?email"}
                ]
            })

        With limit and ordering:
            rows = client.query({
                "@context": {"ex": "http://example.org/ns/"},
                "select":   ["?name", "?age"],
                "where": [
                    {"@id": "?p", "@type": "ex:Person",
                     "ex:name": "?name", "ex:age": "?age"}
                ],
                "orderBy": "?name",
                "limit":   10,
            })
        """
        name = ledger or self.ledger
        if not name:
            raise ValueError("Provide a ledger name or set self.ledger.")

        # Inject "from" so the server knows which ledger to target.
        # The fluree-ledger header is the additional wire-level hint.
        body = {"from": name, **jsonld_query}

        return self._post(
            "/v1/fluree/query",
            body,
            extra_headers={"fluree-ledger": name},
        )

    def insert(self, triples: list[dict], ledger: str | None = None) -> dict:
        """
        Insert data into a ledger using JSON-LD node objects.

        POST /v1/fluree/insert  with  Content-Type: application/json

        Parameters
        ----------
        triples : list[dict]
            A list of JSON-LD node objects.

            Example:
                [
                    {
                        "@id":      "ex:alice",
                        "@type":    "ex:Person",
                        "ex:name":  "Alice",
                        "ex:age":   30,
                    }
                ]

        ledger : str, optional
            Target ledger.  Defaults to self.ledger.

        Returns
        -------
        dict
            Transaction result (includes commit hash).
        """
        name = ledger or self.ledger
        if not name:
            raise ValueError("Provide a ledger name or set self.ledger.")
        return self._post("/v1/fluree/insert", {"ledger": name, "insert": triples})

    def print_whoami(self) -> None:
        """Pretty-print token diagnostics — useful at the start of a session."""
        print(f"\n{_BOLD}{'─' * 50}{_RESET}")
        print(f"{_BOLD}  Token Diagnostics  (GET /v1/fluree/whoami){_RESET}")
        print(f"{_BOLD}{'─' * 50}{_RESET}")

        try:
            info = self.whoami()
        except Exception as exc:
            print(_err(f"Request failed: {exc}"))
            return

        if not info.get("token_present"):
            print(_warn("No token was sent to the server."))
            return

        if info.get("verified"):
            print(_ok("Token is VALID and cryptographically verified.\n"))
        else:
            print(_err(f"Token is INVALID: {info.get('error', 'unknown reason')}\n"))

        fields = [
            ("Auth method", info.get("auth_method", "—")),
            ("Issuer",      info.get("issuer",       "—")),
            ("Subject",     info.get("subject",      "—")),
            ("Identity",    info.get("identity",     "—")),
            ("Expires at",  info.get("expires_at",   "—")),
            ("Scopes",      json.dumps(info.get("scopes", {}), indent=2)),
        ]
        for label, value in fields:
            print(f"  {_CYAN}{label:<14}{_RESET} {value}")

        print(f"{_BOLD}{'─' * 50}{_RESET}\n")
