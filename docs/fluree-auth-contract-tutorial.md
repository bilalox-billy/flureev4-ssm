# Understanding the Fluree Auth Contract — A Complete Beginner's Tutorial

> **Source:** [Fluree DB v4.1 — Auth contract (CLI ↔ Server)](https://labs.flur.ee/docs/db/design/auth-contract)  
> **Level:** Absolute beginner — no prior knowledge assumed

---

## Table of Contents

1. [What is Fluree? (30-second primer)](#1-what-is-fluree-30-second-primer)
2. [What is an "Auth Contract"?](#2-what-is-an-auth-contract)
3. [The Big Picture — How Login Works in Fluree](#3-the-big-picture--how-login-works-in-fluree)
4. [The Players: CLI, Server, and the Identity Provider](#4-the-players-cli-server-and-the-identity-provider)
5. [Step 1 — Auth Discovery: The "Where Do I Log In?" Handshake](#5-step-1--auth-discovery-the-where-do-i-log-in-handshake)
6. [Step 2 — Logging In: Two Modes Explained](#6-step-2--logging-in-two-modes-explained)
7. [Step 3 — Token Exchange: Trading Your Ticket for a Badge](#7-step-3--token-exchange-trading-your-ticket-for-a-badge)
8. [Step 4 — Using the Token to Access Data](#8-step-4--using-the-token-to-access-data)
9. [Step 5 — Token Refresh: Staying Logged In Silently](#9-step-5--token-refresh-staying-logged-in-silently)
10. [Where Tokens Are Stored: The Config File](#10-where-tokens-are-stored-the-config-file)
11. [Scopes: What Are You Allowed to Do?](#11-scopes-what-are-you-allowed-to-do)
12. [Diagnosing Your Token with `/whoami`](#12-diagnosing-your-token-with-whoami)
13. [Understanding Error Messages](#13-understanding-error-messages)
14. [The Anti-Leak Security Pattern](#14-the-anti-leak-security-pattern)
15. [Full Auth Flow Diagram](#15-full-auth-flow-diagram)
16. [Implementer Checklist (If You're Building a Server)](#16-implementer-checklist-if-youre-building-a-server)
17. [Glossary — Plain-English Definitions](#17-glossary--plain-english-definitions)

---

## 1. What is Fluree? (30-second primer)

**Fluree** is a database. Not just any database — it is a *semantic*, *graph-based* database that understands relationships between data and can enforce who is allowed to read or write what.

Think of Fluree like a library:
- The **library building** = the Fluree server (stores all the books/data)
- The **library card** = your authentication token (proves who you are)
- The **librarian's rules** = the authorization scopes (says what you're allowed to access)

The **CLI** (Command-Line Interface) is simply the tool you run in your terminal to talk to this library.

---

## 2. What is an "Auth Contract"?

Imagine you're building a bridge between two cities. Both cities need to agree on: how wide the bridge should be, what vehicles can cross, and what signals mean "stop" or "go." That agreement is a **contract**.

The **Auth Contract** in Fluree is exactly that — a formal agreement between:

- The **Fluree CLI** (your terminal tool)
- Any **Fluree-compatible server** (the database server running somewhere)

The contract answers three questions:

| Question | Covered By |
|---|---|
| How does the CLI find out *how* to log in? | **Auth Discovery** |
| How does the CLI actually *get* a login token? | **Token Exchange** |
| How does the CLI *use and renew* that token? | **Token Usage & Refresh** |

> **Why does this matter?** Because any server that follows these rules will work automatically with the Fluree CLI — zero custom setup required. It's like a universal plug standard.

---

## 3. The Big Picture — How Login Works in Fluree

Before diving into details, here's the complete journey from "I want to log in" to "I can query data":

```
You (user)
   │
   │  runs: fluree auth login
   ▼
Fluree CLI
   │
   │  (1) GET /.well-known/fluree.json   ──► Fluree Server
   │                                         "Here's how to log in"
   │
   │  (2) Redirect your browser to login page
   │
   ▼
Your Browser (you log in with Google/GitHub/Cognito/etc.)
   │
   │  (3) Returns IdP token (proves you're you)
   │
   ▼
Fluree CLI
   │
   │  (4) POST /v1/fluree/auth/exchange  ──► Fluree Server
   │       "Here's my IdP token, give me a Fluree token"
   │
   │  (5) Receives Fluree Bearer Token + Refresh Token
   │
   │  (6) Saves tokens to .fluree/config.toml
   │
   ▼
You can now run queries! The CLI adds "Authorization: Bearer <token>" to every request.
```

---

## 4. The Players: CLI, Server, and the Identity Provider

### The Fluree CLI

Your command-line tool. You type commands like:
```bash
fluree auth login
fluree query --remote prod "SELECT * WHERE { ?s ?p ?o }"
```

### The Fluree Server (`fluree-server`)

The database server that stores your data and enforces who can access what. It verifies every token on every request.

### The Identity Provider (IdP)

This is a **third-party login service** — think Google, GitHub, Okta, Auth0, or AWS Cognito. It handles the actual "prove you are who you say you are" part (username + password + 2FA, etc.).

Fluree itself does **not** store your password. It trusts the IdP to do that job, then issues its own access token.

> **Real-world analogy:** Your office badge (Fluree token) is issued by HR (Fluree server) after you showed them your government ID (IdP). HR doesn't store your national ID — they just verify it once and give you a badge.

---

## 5. Step 1 — Auth Discovery: The "Where Do I Log In?" Handshake

### What is it?

When you add a new remote server to the CLI, the CLI doesn't know how that server handles authentication. It could use Google login, GitHub login, manual tokens, or something else entirely.

So the CLI asks: **"How should I authenticate with you?"**

It does this by fetching a special well-known URL:

```
GET /.well-known/fluree.json
```

> **The "well-known" concept:** This URL format (`/.well-known/...`) is an internet standard (RFC 5785). It's a predictable location on any website where a server publishes its configuration. The CLI knows to always check here first.

### What Does the Server Reply?

The server responds with a JSON document describing its authentication setup:

```json
{
  "version": 1,
  "api_base_url": "https://data.example.com/v1/fluree",
  "auth": {
    "type": "oidc_device",
    "issuer": "https://issuer.example.com",
    "client_id": "fluree-cli",
    "exchange_url": "https://data.example.com/v1/fluree/auth/exchange",
    "scopes": ["openid", "profile"],
    "redirect_port": 8400
  }
}
```

Let's decode every field:

| Field | What It Means in Plain English |
|---|---|
| `version` | The version of this discovery format. Always `1` for now. |
| `api_base_url` | The exact URL prefix where the Fluree API lives. The CLI needs this to know where to send queries. |
| `auth.type` | The *style* of login. Either `"oidc_device"` (automatic browser-based login) or `"token"` (manual token paste). |
| `auth.issuer` | The URL of your Identity Provider (e.g., your Cognito or Okta instance). |
| `auth.client_id` | A label that tells the IdP "this request is coming from the Fluree CLI". |
| `auth.exchange_url` | After logging in with the IdP, the CLI sends your IdP token here to get a Fluree-scoped token in return. |
| `auth.scopes` | The list of permissions the CLI will request from the IdP during login. |
| `auth.redirect_port` | The local port the CLI opens briefly to receive the login callback from the browser. |

### Two Auth Types Explained

| `auth.type` | What It Means | When It's Used |
|---|---|---|
| `oidc_device` | The CLI opens your browser, you log in, and the CLI receives a token automatically. | When the server supports a real login provider (Google, Cognito, Okta, etc.) |
| `token` | No automation. You manually paste a token. | Local development, simpler setups, service accounts |

### What If the Discovery Endpoint Doesn't Exist?

No problem. The CLI gracefully falls back to manual token mode:

```
Discovery endpoint absent (404 or connection error)
   └──► CLI assumes "token" type
        └──► Prompts: "Please paste your Bearer token manually"
```

---

## 6. Step 2 — Logging In: Two Modes Explained

### Mode A: OIDC Device / Browser Login (`oidc_device`)

This is the modern, secure, user-friendly login flow. Here's exactly what happens when you run:

```bash
fluree auth login --remote prod
```

**Step-by-step walkthrough:**

```
1. CLI fetches {issuer}/.well-known/openid-configuration
   (discovers the IdP's login endpoint URLs)

2a. IF the IdP supports "Device Code" flow:
    ┌─────────────────────────────────────────────┐
    │ CLI prints something like:                   │
    │                                              │
    │  Open https://login.example.com/device       │
    │  and enter code: ABCD-1234                   │
    │                                              │
    │ You go to your browser, enter the code,      │
    │ and log in normally (username + password).   │
    │                                              │
    │ The CLI polls quietly in the background      │
    │ until your browser login completes.          │
    └─────────────────────────────────────────────┘

2b. IF the IdP supports "Authorization Code + PKCE" flow:
    ┌─────────────────────────────────────────────┐
    │ CLI starts a tiny local web server on        │
    │ http://127.0.0.1:8400/callback               │
    │                                              │
    │ Opens your browser to the login page.        │
    │                                              │
    │ After you log in, the browser redirects      │
    │ back to that local server with a code.       │
    │                                              │
    │ The CLI catches the code and uses it.        │
    └─────────────────────────────────────────────┘

3. CLI has your IdP token
   → Sends it to the exchange_url
   → Gets back a Fluree-scoped Bearer token
   → Stores token in .fluree/config.toml
```

> **What is PKCE?** (Proof Key for Code Exchange) — A security technique that prevents malicious apps from stealing your login code. The CLI generates a random secret, hashes it, sends the hash to the IdP, and later proves it knows the original secret. This ensures only the CLI that started the login can complete it.

### Mode B: Manual Token (`token`)

Simple and direct:

```bash
fluree auth login --token eyJ0eXAiOiJKV1QiLCJhbGci...
```

Or the CLI prompts you to paste it. This is saved to the config file and used as-is.

---

## 7. Step 3 — Token Exchange: Trading Your Ticket for a Badge

### What is it?

After you log in with your Identity Provider (Google, Cognito, etc.), you get an **IdP token**. This token proves *who you are* to the IdP, but it means nothing to Fluree specifically.

So the CLI trades it in at the **exchange endpoint** for a **Fluree-scoped token** — a token that Fluree understands and can authorize.

> **Analogy:** You win a prize at a carnival (IdP token). You take your prize ticket to the redemption booth (exchange endpoint). The booth gives you the actual prize — a Fluree database access card (Fluree Bearer token).

### The Exchange Request

```http
POST /v1/fluree/auth/exchange HTTP/1.1
Content-Type: application/json

{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "<your-idp-access-token>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
```

Breaking it down:

| Field | What It Means |
|---|---|
| `grant_type` | Tells the server "this is a token exchange request" (a standard OAuth 2.0 phrase). |
| `subject_token` | Your IdP token — the credential you received after browser login. |
| `subject_token_type` | Tells the server what kind of token `subject_token` is (an access token vs ID token). |

### The Successful Response

```json
{
  "access_token": "eyJ0eXAiOiJKV1Q...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOi..."
}
```

| Field | What It Means |
|---|---|
| `access_token` | Your new Fluree Bearer token. This is what you attach to every API request. |
| `token_type` | Always `"Bearer"` — means "put this in the Authorization header". |
| `expires_in` | How long (in seconds) the token is valid. `3600` = 1 hour. |
| `refresh_token` | A special token used to get a *new* access token when this one expires, without logging in again. |

### What Happens Inside the Server During Exchange?

The server does these things in order:

```
1. Verify the IdP token is genuine
   (checks the IdP's cryptographic signature)

2. Look up what the user is allowed to do in Fluree
   (check their permissions/entitlements)

3. Mint (create) a new Fluree-scoped JWT
   (include the user's identity + allowed ledgers + scopes)

4. Return the JWT as access_token
```

### Error Response

If something goes wrong:

```json
{
  "error": "invalid_grant",
  "error_description": "IdP token is invalid or user is not authorized for Fluree access"
}
```

---

## 8. Step 4 — Using the Token to Access Data

Once the CLI has a Bearer token, every API request it makes includes it automatically:

```http
POST /v1/fluree/query HTTP/1.1
Authorization: Bearer eyJ0eXAiOiJKV1Q...
Content-Type: application/json

{
  "from": "my-ledger",
  "select": { "?s": ["?p", "?o"] },
  "where": [["?s", "?p", "?o"]]
}
```

The server checks:
1. Is a token present? (If not → `401 Unauthorized`)
2. Is the token valid/not expired/properly signed? (If not → `401 Unauthorized`)
3. Does the token have the right scope for this ledger? (If not → `404 Not Found`, see [anti-leak](#14-the-anti-leak-security-pattern))
4. All good? → Execute the query and return results.

---

## 9. Step 5 — Token Refresh: Staying Logged In Silently

### The Problem

Access tokens expire (usually in 1 hour). Without refresh tokens, you'd need to log in manually every hour. That would be terrible UX.

### The Solution: Refresh Tokens

If you have a `refresh_token` stored, the CLI can silently get a new access token without any user interaction:

```json
POST /v1/fluree/auth/exchange

{
  "grant_type": "refresh_token",
  "refresh_token": "eyJhbGciOi..."
}
```

The server responds with a brand-new access token (and potentially a new refresh token).

### Auto-Refresh on 401

When running commands like `fluree query`, if the server returns a `401 Unauthorized`, the CLI automatically:

```
Receives 401 from server
   │
   ├── Has a refresh_token?
   │       YES → Try silent refresh
   │                 ├── Success → Update config.toml, retry request once ✓
   │                 └── Failure → Clear tokens, print:
   │                               "Token expired. Run: fluree auth login --remote <name>"
   │
   └── No refresh_token → Print:
           "Authentication failed. Run: fluree auth login --remote <name>"
```

### Important: Replication Commands Are Different

Commands like `fluree fetch`, `fluree pull`, and `fluree push` (which copy entire ledger data) use **two separate clients internally**:

| Client | Auto-Refreshes? | Used For |
|---|---|---|
| `RemoteLedgerClient` | YES | Metadata lookups, commit pagination |
| `HttpRemoteClient` | NO | Bulk data transfer (packs) |

**Why?** Bulk data transfer requires `fluree.storage.*` scopes, which are **operator-only** permissions. Operators typically have long-lived tokens that don't expire often. If they do expire mid-transfer, the CLI fails fast and tells you to re-authenticate rather than retrying a failed transfer silently.

---

## 10. Where Tokens Are Stored: The Config File

The CLI stores all auth configuration in a TOML file at `.fluree/config.toml` in your project directory.

```toml
# A remote that uses OIDC (browser-based) login
[[remotes]]
name = "solo-prod"
type = "Http"
base_url = "https://solo.example.com"

[remotes.auth]
type = "oidc_device"
issuer = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123"
client_id = "fluree-cli"
exchange_url = "https://solo.example.com/v1/fluree/auth/exchange"
scopes = ["openid", "profile"]
redirect_port = 8400
token = "eyJ..."          # ← written automatically by 'fluree auth login'
refresh_token = "eyJ..."  # ← written automatically by 'fluree auth login'

# A remote that uses manual token input
[[remotes]]
name = "local"
type = "Http"
base_url = "http://localhost:8090"

[remotes.auth]
type = "token"
token = "eyJ..."          # ← manually provided via 'fluree auth login --token'
```

> **Security note:** This file contains sensitive tokens. Treat it like a password file. Do not commit it to version control (add `.fluree/` to your `.gitignore`).

---

## 11. Scopes: What Are You Allowed to Do?

**Scopes** are permissions embedded inside your token. They tell Fluree exactly what you're allowed to do.

### The Scope Hierarchy

```
fluree.ledger.read.*        ─── Read any ledger
fluree.ledger.read.mydb     ─── Read only "mydb"

fluree.ledger.write.*       ─── Write to any ledger
fluree.ledger.write.mydb    ─── Write only to "mydb"

fluree.events.*             ─── Subscribe to event streams

fluree.storage.*            ─── Replicate entire ledger data
                                (OPERATORS ONLY — never for regular users)
```

### The Golden Rule of Scopes

> **Regular users NEVER get `fluree.storage.*` scopes.** This scope is reserved for operators and service accounts that need to copy entire database storage. If a regular user tries `fluree pull` or `fluree fetch`, the CLI will reject it with a clear message saying to use `fluree track` instead.

### Scopes Inside the Token (JWT Claims)

A Fluree JWT (access token) contains claims like:

```json
{
  "iss": "https://issuer.example.com",
  "sub": "user@example.com",
  "exp": 1739012345,
  "iat": 1739008745,
  "fluree.identity": "did:key:z6Mk...",
  "fluree.ledger.read.*": true,
  "fluree.ledger.write.my-ledger": true
}
```

The server reads these claims to decide what the token holder can access.

---

## 12. Diagnosing Your Token with `/whoami`

### What is it?

The `GET /v1/fluree/whoami` endpoint is your **debugging best friend**. It tells you everything about your current token — whether it's valid, who it belongs to, when it expires, and what scopes it has.

### No Token Present

```bash
curl https://my-fluree-server.com/v1/fluree/whoami
```

```json
{ "token_present": false }
```

### Valid Token

```bash
curl -H "Authorization: Bearer eyJ..." https://my-fluree-server.com/v1/fluree/whoami
```

```json
{
  "token_present": true,
  "verified": true,
  "auth_method": "oidc",
  "issuer": "https://cognito-idp.us-east-1.amazonaws.com/...",
  "subject": "admin@example.com",
  "identity": "did:key:z6Mk...",
  "expires_at": 1739012345,
  "scopes": {
    "ledger_read_all": true,
    "ledger_write_all": true
  }
}
```

| Field | What It Tells You |
|---|---|
| `token_present` | Is there a token at all? |
| `verified` | Did the cryptographic signature check pass? |
| `auth_method` | How was the token signed? (`"embedded_jwk"` = Ed25519, `"oidc"` = RS256) |
| `issuer` | Which Identity Provider issued the original credential? |
| `subject` | Your user identity (usually an email or user ID). |
| `identity` | Your Fluree-specific identity (DID — Decentralized Identifier). |
| `expires_at` | Unix timestamp of when the token expires. |
| `scopes` | What you're allowed to do. |

### Invalid / Expired Token

```json
{
  "token_present": true,
  "verified": false,
  "error": "Token expired",
  "issuer": "https://cognito-idp...",
  "subject": "admin@example.com",
  "expires_at": 1738900000
}
```

> **Important:** Even when `verified: false`, the endpoint returns the decoded (but **unverified**) claims. These are useful for debugging ("ah, my token expired 2 hours ago") but you must **never use unverified claims for making authorization decisions**. They are for human eyes only.

> **This endpoint always returns HTTP 200**, even if the token is invalid. It's diagnostic, not a security gate.

---

## 13. Understanding Error Messages

### The Standard Error Shape

All errors from Fluree follow this format:

```json
{
  "error": "Bearer token required",
  "status": 401,
  "@type": "err:db/Unauthorized",
  "cause": {
    "error": "No Authorization header found",
    "status": 400,
    "@type": "err:db/JsonParse"
  }
}
```

| Field | Meaning |
|---|---|
| `error` | The main human-readable message. The CLI reads this to give you helpful hints. |
| `status` | The HTTP status code, repeated in the body for convenience. |
| `@type` | A machine-readable error code (stable across releases). |
| `cause` | An optional nested error explaining the root cause. |

### HTTP Status Codes Cheat Sheet

| Code | Name | What Happened |
|---|---|---|
| `200` | OK | Everything worked. |
| `201` | Created | Ledger was created successfully. |
| `400` | Bad Request | Your request was malformed (bad JSON, missing fields, etc.). |
| `401` | Unauthorized | No token, expired token, or bad signature. |
| `403` | Forbidden | Valid token, but you don't have permission for this action. |
| `404` | Not Found | Ledger doesn't exist — **or** your token doesn't cover it (by design, see next section). |
| `409` | Conflict | Ledger already exists, or two writes happened at the same time. |
| `500` | Server Error | Something broke on the server side. Not your fault. |

### Common 401 Error Messages and What They Mean

| Error Message | Root Cause | Fix |
|---|---|---|
| `"Bearer token required"` | No `Authorization` header was sent. | Run `fluree auth login --remote <name>` |
| `"Invalid token"` | Token is malformed or signature doesn't match. | Re-issue the token; check your signing key. |
| `"Token expired"` | The `exp` claim is in the past. | Run `fluree auth login` to refresh. |
| `"Untrusted issuer"` | The token's issuer isn't in the server's trusted list. | Check `--trusted-issuer` / `--jwks-issuer` server config. |
| `"OIDC issuer not configured"` | Token has a `kid` header but no JWKS URL is configured on the server. | Add `--jwks-issuer` to server startup config. |
| `"Token lacks storage proxy permissions"` | You tried to replicate data but your token is query-only. | Use an operator token, or use `fluree track` instead. |

---

## 14. The Anti-Leak Security Pattern

### The Problem

Imagine a bank with two types of accounts: regular accounts and secret VIP accounts. If you ask "does account #99999 exist?" and the bank replies `403 Forbidden`, you now know that account exists — you just can't access it. That's an **information leak**.

### Fluree's Solution: Always Return 404

For data endpoints (`/fluree/query`, `/fluree/update`, etc.), Fluree **always returns `404`** when you try to access a ledger you're not authorized for — whether it exists or not.

```
You query ledger "secret-project"
   │
   ├── Ledger doesn't exist → 404 Not Found
   └── Ledger exists but your token has no access → 404 Not Found (same response!)
```

This means an attacker cannot probe the server to discover which ledgers exist by watching for `403` vs `404` responses.

> **For users:** If you get a `404` on a data query, it could mean either "the ledger doesn't exist" or "your token doesn't cover this ledger." The CLI will tell you both possibilities.

---

## 15. Full Auth Flow Diagram

Here's the complete picture of how everything connects:

```
┌─────────────────────────────────────────────────────────────────┐
│                    FLUREE AUTH FLOW                              │
└─────────────────────────────────────────────────────────────────┘

     YOU                  CLI              FLUREE SERVER        IDENTITY PROVIDER
      │                    │                     │                      │
      │  fluree auth login │                     │                      │
      │───────────────────►│                     │                      │
      │                    │                     │                      │
      │                    │ GET /.well-known/fluree.json               │
      │                    │────────────────────►│                      │
      │                    │◄────────────────────│                      │
      │                    │ {"auth":{"type":"oidc_device",...}}        │
      │                    │                     │                      │
      │                    │         Discover OIDC endpoints           │
      │                    │────────────────────────────────────────►  │
      │                    │◄────────────────────────────────────────  │
      │                    │         {authorization_endpoint, ...}     │
      │                    │                     │                      │
      │  Open browser      │                     │                      │
      │◄───────────────────│                     │                      │
      │                    │                     │                      │
      │              [You log in to IdP in browser]                    │
      │                    │                     │                      │
      │  Redirect callback │                     │                      │
      │───────────────────►│                     │                      │
      │                    │                     │                      │
      │                    │ POST exchange_url (IdP token)             │
      │                    │────────────────────►│                      │
      │                    │◄────────────────────│                      │
      │                    │ {access_token, refresh_token}             │
      │                    │                     │                      │
      │                    │ Save to config.toml │                      │
      │                    │                     │                      │
      │ "Login successful" │                     │                      │
      │◄───────────────────│                     │                      │
      │                    │                     │                      │
      │  fluree query ...  │                     │                      │
      │───────────────────►│                     │                      │
      │                    │ POST /v1/fluree/query                     │
      │                    │ Authorization: Bearer <access_token>      │
      │                    │────────────────────►│                      │
      │                    │◄────────────────────│                      │
      │                    │ Query results                             │
      │◄───────────────────│                     │                      │
```

---

## 16. Implementer Checklist (If You're Building a Server)

> **Note:** This section is for developers building a Fluree-compatible server. Skip it if you're just a user.

If you're building any server that needs to work seamlessly with the Fluree CLI, you must implement these four things:

### Required

- [ ] **`GET /.well-known/fluree.json`** — Return the discovery document describing your auth setup.
- [ ] **`POST {exchange_url}`** — Accept IdP tokens and return Fluree-scoped JWTs. Also accept refresh tokens.
- [ ] **Fluree-scoped JWTs** — Your tokens must include `fluree.identity`, `fluree.ledger.*` claims and be verifiable via JWKS.
- [ ] **JWKS endpoint** — Publish your public keys so `fluree-server` can verify your tokens.

### Recommended for Great UX

- [ ] Stable error messages — Don't change the text of `"Bearer token required"`, `"Untrusted issuer"`, etc. The CLI pattern-matches on these.
- [ ] Anti-leak 404s — Return `404` (not `403`) for out-of-scope data endpoints.
- [ ] `GET /v1/fluree/whoami` — A diagnostic endpoint for token verification.

### Conformance: Required Status Codes

| Endpoint | Success | No Token | Bad Token | Wrong Scope | Not Found |
|---|---|---|---|---|---|
| `GET /.well-known/fluree.json` | `200` | n/a | n/a | n/a | `404` |
| `POST /v1/fluree/create` | `201` | `401` | `401` | `403` | n/a |
| `POST /v1/fluree/drop` | `200` | `401` | `401` | `403` | `404` |
| `POST /v1/fluree/query` | `200` | `401` | `401` | `404` | `404` |
| `POST /v1/fluree/update` | `200` | `401` | `401` | `404` | `404` |
| `POST /v1/fluree/auth/exchange` | `200` | n/a | `401` | `403` | n/a |
| `GET /v1/fluree/whoami` | `200` | `200` | `200` | n/a | n/a |

> Note: `/whoami` always returns `200` — even for invalid tokens — because it's diagnostic, not a gate.

---

## 17. Glossary — Plain-English Definitions

| Term | Definition |
|---|---|
| **Auth Contract** | The agreement between the Fluree CLI and server defining exactly how authentication works at the network level. |
| **Bearer Token** | A string (usually a JWT) that you attach to API requests to prove who you are. Like a VIP pass — whoever bears (holds) it gets in. |
| **CLI** | Command-Line Interface. A tool you run in your terminal, like `fluree query` or `fluree auth login`. |
| **Claims** | Data embedded inside a JWT. They describe who you are and what you can do. |
| **DID** | Decentralized Identifier. A globally unique ID for a user or entity, like `did:key:z6Mk...`. |
| **Exchange Endpoint** | The server-side URL that accepts your IdP token and returns a Fluree-specific token in return. |
| **IdP** | Identity Provider. A service that verifies your identity (Google, GitHub, Auth0, Cognito, Okta, etc.). |
| **JWT** | JSON Web Token. A secure, signed string that contains claims. Can be verified cryptographically. Looks like `eyJ...`. |
| **JWKS** | JSON Web Key Set. A published list of cryptographic public keys used to verify JWTs. |
| **Ledger** | Fluree's name for a database. One Fluree server can hold many ledgers. |
| **OIDC** | OpenID Connect. A standard login protocol built on top of OAuth 2.0. Used by most major identity providers. |
| **PKCE** | Proof Key for Code Exchange. A security technique for public OAuth clients (like a CLI) to prevent code interception attacks. |
| **Scope** | A permission embedded in a token. E.g., `fluree.ledger.read.*` means "read any ledger". |
| **Token Exchange** | The act of swapping an IdP token for a Fluree-scoped token. |
| **Token Refresh** | Getting a new access token silently using a refresh token, without the user needing to log in again. |
| **`/.well-known/`** | A standard URL prefix where servers publish configuration documents (defined by RFC 5785). |

---

## Summary

Here's everything in a single paragraph for your mental model:

> When you run `fluree auth login`, the CLI first **discovers** how to authenticate by fetching `/.well-known/fluree.json`. If the server supports OIDC, it opens your browser so you can log in with your identity provider (Google, Cognito, etc.). After you log in, the CLI **exchanges** your IdP token for a Fluree-scoped **JWT Bearer token** by calling the exchange endpoint. That token — containing your identity and your permissions (scopes) — is stored in `.fluree/config.toml` and attached to every subsequent API request as an `Authorization: Bearer ...` header. When the token expires, the CLI quietly **refreshes** it using a refresh token, so you stay logged in without interruption. The server enforces a strict **anti-leak** policy: unauthorized ledger access returns `404` — never `403` — to prevent existence discovery. You can inspect your token health at any time via `/v1/fluree/whoami`.

---

*Tutorial written from [Fluree DB v4.1 — Auth contract (CLI ↔ Server)](https://labs.flur.ee/docs/db/design/auth-contract)*
