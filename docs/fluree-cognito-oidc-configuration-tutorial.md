# Connecting AWS Cognito to Fluree v4 — A Beginner's Tutorial

> **Source:** [Fluree DB v4.1 — Configuration: OIDC / JWKS Token Verification](https://labs.flur.ee/docs/db/operations/configuration#oidc--jwks-token-verification)  
> **Your setup:** AWS Cognito · Region `af-south-1` · User Pool `af-south-1_u4RWjCAyw`

---

## What Are We Doing and Why?

Right now, Fluree accepts tokens that **it generates itself** (Ed25519 / self-signed JWTs).
We want Fluree to also accept tokens issued by **AWS Cognito** — so users can log in with
Cognito and immediately query the database without needing a manually created token.

Think of it like this:

```
WITHOUT this setup:                  WITH this setup:
─────────────────────                ────────────────────────────────
Fluree Server                        Fluree Server
  └─ only trusts tokens              ├─ still trusts its own tokens (unchanged)
     it signed itself                └─ ALSO trusts tokens signed by Cognito ✓
```

Fluree does this by fetching Cognito's **public keys** (called JWKS — JSON Web Key Set)
and using them to verify that a token was genuinely issued by your Cognito user pool.
The public keys are freely available — no secrets are shared.

---

## Before You Start — Key Concepts

### What is JWKS?

Every JWT (JSON Web Token) is digitally **signed** by whoever created it.
To verify the signature, you need the signer's **public key**.

Cognito publishes its public keys at a well-known URL (the JWKS endpoint):

```
https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw/.well-known/jwks.json
```

Fluree fetches this URL at startup and caches the keys for 5 minutes.
When a Cognito token arrives, Fluree checks the signature against these keys.
If it matches → token is trusted. If not → rejected.

### What is `--data-auth-mode`?

By default Fluree accepts **any request, even without a token** (`mode = none`).
To actually **require** authentication on your data endpoints (query, insert, etc.),
you set `--data-auth-mode required`.

---

## Your Cognito Values (Pre-filled)

| What | Value |
|---|---|
| **Region** | `af-south-1` |
| **User Pool ID** | `af-south-1_u4RWjCAyw` |
| **App Client ID** | `6vcbr6gnpspqkdtt8elgjeftik` |
| **Issuer URL** | `https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw` |
| **JWKS URL** | `https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw/.well-known/jwks.json` |

---

## The Three Ways to Configure Fluree

You can configure Fluree using **any one** of these three methods.
All three do exactly the same thing — pick whichever fits your deployment.

---

### Method 1 — Command-Line Flag (simplest for testing)

```bash
fluree-server \
  --jwks-issuer "https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw=https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw/.well-known/jwks.json" \
  --data-auth-mode required
```

> **Important:** The `--jwks-issuer` flag takes **both** the issuer URL and the JWKS URL
> joined with `=`. Format: `issuer_url=jwks_url`

What each flag does:

| Flag | Purpose |
|---|---|
| `--jwks-issuer "A=B"` | Trust tokens issued by `A`, verify them using public keys at `B` |
| `--data-auth-mode required` | Reject any request that doesn't carry a valid Bearer token |

---

### Method 2 — Environment Variables (recommended for Docker / ECS / EKS)

```bash
export FLUREE_JWKS_ISSUERS="https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw=https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw/.well-known/jwks.json"
export FLUREE_DATA_AUTH_MODE="required"

fluree-server
```

For **Docker Compose**, add these to your `environment:` block:

```yaml
services:
  fluree:
    image: fluree/server:latest
    environment:
      FLUREE_JWKS_ISSUERS: "https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw=https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw/.well-known/jwks.json"
      FLUREE_DATA_AUTH_MODE: "required"
    ports:
      - "8090:8090"
```

For **AWS ECS Task Definition**, add to `environment` in the container definition:

```json
{
  "environment": [
    {
      "name": "FLUREE_JWKS_ISSUERS",
      "value": "https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw=https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw/.well-known/jwks.json"
    },
    {
      "name": "FLUREE_DATA_AUTH_MODE",
      "value": "required"
    }
  ]
}
```

---

### Method 3 — Config File (recommended for permanent setups)

Create or edit `.fluree/config.toml` on the server:

```toml
[server]
listen_addr   = "0.0.0.0:8090"
storage_path  = "/var/lib/fluree"
log_level     = "info"

[server.auth.data]
mode = "required"
jwks_issuers = [
  "https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw=https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw/.well-known/jwks.json"
]
```

Then start the server normally:
```bash
fluree-server
```

---

## What Happens Inside Fluree After This Change

```
User logs in with Cognito
        │
        │  receives a Cognito JWT (RS256 signed)
        ▼
Python client sends request to Fluree
        │
        │  Authorization: Bearer eyJ...  (Cognito token)
        ▼
Fluree Server receives the request
        │
        ├─ Step 1: Read the token header → sees "kid" (key ID) field
        │          "kid" means it's an OIDC/RS256 token (not Ed25519)
        │
        ├─ Step 2: Find the issuer in the token → matches our Cognito URL
        │
        ├─ Step 3: Fetch public key from JWKS URL (cached for 5 minutes)
        │          https://...af-south-1_u4RWjCAyw/.well-known/jwks.json
        │
        ├─ Step 4: Verify the token signature using the public key
        │
        ├─ If VALID   → process the request ✓
        └─ If INVALID → return 401 Unauthorized ✗
```

> **Your existing Ed25519 tokens still work.** Fluree checks the token type automatically —
> OIDC tokens go through the Cognito verification path, Ed25519 tokens go through the
> original path. No conflict, no changes needed for existing tokens.

---

## Authentication Modes Explained

The `--data-auth-mode` flag has three possible values:

| Mode | What It Means | When to Use |
|---|---|---|
| `none` | No token required. Anyone can query. | Local development only |
| `optional` | Token accepted but not required. | Testing auth without breaking things |
| `required` | Every request must have a valid token. | **Production** |

**Recommendation:** Use `optional` first to test that Cognito tokens work, then switch to `required` when confirmed.

```bash
# Phase 1: Test that Cognito tokens are accepted (doesn't break existing requests)
--data-auth-mode optional

# Phase 2: Enforce authentication for all users
--data-auth-mode required
```

---

## JWKS Cache

Fluree caches Cognito's public keys to avoid fetching them on every request.

| Setting | Default | Meaning |
|---|---|---|
| `--jwks-cache-ttl` | `300` seconds | Keys are re-fetched every 5 minutes |
| `FLUREE_JWKS_CACHE_TTL` | `300` | Same, as environment variable |

If a token arrives with a `kid` (key ID) that isn't in the cache, Fluree immediately
fetches fresh keys from Cognito — rate-limited to once per issuer every 10 seconds.

You don't need to change this default.

---

## How to Verify It Works

After the server restarts, test with a real Cognito token:

```bash
# Replace <TOKEN> with a real Cognito access token
TOKEN="eyJ..."

curl -s \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:8090/v1/fluree/whoami
```

### Good response — token accepted:

```json
{
  "token_present": true,
  "verified": true,
  "auth_method": "oidc",
  "issuer": "https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw",
  "subject": "user@example.com",
  "expires_at": 1739012345,
  "scopes": {}
}
```

Key fields to check:
- `"verified": true` → Fluree verified the Cognito signature ✓
- `"auth_method": "oidc"` → Fluree used the JWKS/Cognito path ✓
- `"issuer"` → matches your Cognito user pool URL ✓

### Bad response — token rejected:

```json
{
  "token_present": true,
  "verified": false,
  "error": "Untrusted issuer"
}
```

This means `--jwks-issuer` was not picked up. Confirm the server restarted with the flag.

---

## Complete Minimal Production Command

This is the full command with every Cognito-related flag for your setup:

```bash
fluree-server \
  --jwks-issuer "https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw=https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw/.well-known/jwks.json" \
  --data-auth-mode required \
  --log-level info
```

Or using environment variables only (better for AWS deployments):

```bash
export FLUREE_JWKS_ISSUERS="https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw=https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw/.well-known/jwks.json"
export FLUREE_DATA_AUTH_MODE="required"
export FLUREE_LOG_LEVEL="info"

fluree-server
```
---

*Reference: [Fluree DB v4.1 Configuration — OIDC / JWKS Token Verification](https://labs.flur.ee/docs/db/operations/configuration#oidc--jwks-token-verification)*
