# DevOps Request — Fluree v4 + AWS Cognito OIDC Integration

**Requested by:** [Your Name]  
**Date:** June 2026  
**Priority:** Required to enable user authentication via AWS Cognito on the Fluree v4 service  

---

## Context

We are integrating AWS Cognito as the Identity Provider (IdP) for our Fluree v4 database service.
The goal is to allow authenticated users to obtain a Cognito JWT token and use it directly
against the Fluree API — without needing manually issued tokens.

We have already:
- ✅ Confirmed the Fluree v4 service is reachable via the proxy tunnel (`fluree-v4` in `af-south-1.dev.orixa.local`)
- ✅ Set up a Cognito User Pool with users
- ✅ Created a Cognito App Client with PKCE support
- ✅ Configured the Python client on the developer side

The only remaining piece is a **server-side configuration change** on the Fluree deployment.

---

## What Needs to Change

### 1. Add `--jwks-issuer` to the Fluree Server Startup

The Fluree server must be told to **trust JWT tokens issued by our Cognito user pool**.
This is done by adding a single startup flag:

```
--jwks-issuer https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw
```

**How it works:**  
When Fluree receives a request with a `Authorization: Bearer <token>` header, it fetches
the Cognito public keys from:

```
https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw/.well-known/jwks.json
```

and uses them to cryptographically verify the token signature. No code changes are required —
this is a native Fluree v4 feature.

---

## Cognito Details

| Field | Value |
|---|---|
| **AWS Region** | `af-south-1` |
| **User Pool ID** | `af-south-1_u4RWjCAyw` |
| **App Client ID** | `6vcbr6gnpspqkdtt8elgjeftik` |
| **Issuer URL** | `https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw` |
| **JWKS URL** | `https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw/.well-known/jwks.json` |
| **OpenID Config URL** | `https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw/.well-known/openid-configuration` |

---

## Current Fluree Service Information

| Field | Value |
|---|---|
| **Service name** | `fluree-v4` |
| **Namespace** | `af-south-1.dev.orixa.local` |
| **Region** | `af-south-1` |
| **Local tunnel port** | `8090` |
| **AWS profile used** | `bilalox` |

The service is accessed locally via:

```bash
zx scripts/proxy_connect.mts \
  --profile bilalox \
  --region af-south-1 \
  --location af-south-1 \
  --service fluree-v4 \
  --namespace af-south-1.dev.orixa.local \
  --port 8090
```

---

## Required Action

Add the following flag to the `fluree-server` startup configuration:

```bash
--jwks-issuer https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw
```

Depending on how the service is deployed, this means:

### If deployed on ECS (Task Definition)

In the container definition, update the **command** or **entrypoint** to include the flag:

```json
{
  "command": [
    "fluree-server",
    "--jwks-issuer",
    "https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw"
  ]
}
```

Or add it as an **environment variable** if the Fluree image supports `FLUREE_JWKS_ISSUER`:

```json
{
  "environment": [
    {
      "name": "FLUREE_JWKS_ISSUER",
      "value": "https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw"
    }
  ]
}
```

### If deployed on EKS / Kubernetes

Update the deployment manifest:

```yaml
containers:
  - name: fluree-v4
    args:
      - --jwks-issuer
      - https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw
```

### If deployed on EC2 (direct binary)

Update the systemd service file or startup script to include the flag:

```bash
fluree-server \
  --jwks-issuer https://cognito-idp.af-south-1.amazonaws.com/af-south-1_u4RWjCAyw
```

### If managed via CDK / Terraform / CloudFormation

Add the flag to the container command arguments in the infrastructure definition and redeploy.

---

## How to Verify It Worked

After the server restarts with the new flag, run the following `curl` from any machine
that can reach the Fluree service (or through the proxy tunnel on `localhost:8090`):

```bash
# 1. Get a Cognito token (replace with a real token from the user pool)
TOKEN="eyJ..."

# 2. Check that Fluree accepts and verifies it
curl -s \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:8090/v1/fluree/whoami | python -m json.tool
```

**Expected response (token is valid):**

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

If `"verified": true` and `"auth_method": "oidc"` — the integration is working.

**If `"verified": false` with `"error": "Untrusted issuer"`** — the flag was not picked up.
Confirm the server restarted and the flag is present.

---

## No Other Changes Required

- No code changes needed
- No new services to deploy
- No secrets or credentials to store (JWKS is a public endpoint)
- The Cognito user pool and App Client are already configured

---

## Contact

For questions about this request, contact [Your Name] or refer to the Fluree Auth Contract
specification:  
https://labs.flur.ee/docs/db/design/auth-contract
