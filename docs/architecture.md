# Authentication Architecture

## Service boundaries

| Component | Owns | Must not own |
|---|---|---|
| Website `/login` | Custom login UI and browser interaction | Sessions, client secrets, token exchange |
| Access Gateway | TLS, host/path routing, forward-auth, header filtering, traffic policy | Users, OIDC state, product data |
| Auth Service | Session API login, federated OIDC orchestration, shared session lifecycle, identity assertions | Product resource authorization |
| ZITADEL | Primary authentication, MFA, identity lifecycle | Shiguang browser session |
| Product service | Domain data and resource-level authorization | Shared login session |

## Protected request flow

1. The browser sends the opaque `__Secure-sg_session` cookie to a first-party
   subdomain.
2. Caddy removes all externally supplied identity headers.
3. Caddy calls `GET /v1/forward-auth` with the original request metadata and
   gateway-owned product policy.
4. Auth Service hashes the cookie value, loads the server-side Redis session,
   checks expiry, revocation, and required entitlement, and signs an assertion.
5. Caddy copies only `X-SG-Identity` into the upstream request and removes the
   browser cookie and bearer credentials before proxying.
6. The product validates the assertion signature, issuer, audience, expiry, and
   required claims, then performs its own resource authorization.

## Direct password login flow

1. The browser renders `/login?return_to=...` immediately; it does not begin an
   OIDC Authorization Request.
2. `POST /api/auth/login/context` validates Origin and stores a short-lived,
   encrypted, one-time transaction containing the normalized return target and
   CSRF binding.
3. `POST /api/auth/login/password` validates Origin, CSRF, rate limits, and the
   one-time transaction, then calls ZITADEL `POST /v2/sessions`.
4. Auth Service stores the returned ZITADEL session ID/token inside the
   encrypted Shiguang server-side session and sets only an opaque browser
   cookie.
5. The browser navigates to the return target taken from server-side
   transaction state.

External identity providers are separate: they use Authorization Code + PKCE
through `/api/auth/federated/start` and `/api/auth/oidc/callback`.
Feishu additionally passes through three stateless compatibility endpoints that
translate ZITADEL's generic OAuth requests to Feishu's current JSON APIs. They
validate the public Feishu App ID and never persist the Feishu App Secret,
authorization code, or access token.

## Token separation

- The ZITADEL authorization code and tokens are only visible to Auth Service.
- The shared browser cookie is opaque and has no identity claims.
- The identity assertion is short-lived and audience-bound per product.
- A product-specific API access token remains product-specific and is not used
  as the shared login session.

This gives all products one reusable login session without pretending that one
OAuth access token is valid for every application.

## Cookie policy

The production shared cookie should use:

```text
Domain=.shiguanglab.com; Path=/; Secure; HttpOnly; SameSite=Lax
```

Only the Auth Service may issue or clear it. The gateway must strip it before
requests reach product services and must prevent product upstreams from setting
parent-domain cookies.

Because a parent-domain cookie increases blast radius, all first-party
subdomains must be controlled and protected against takeover. Untrusted tenant
content must live on a separate registrable domain.

## Availability and failure behavior

- Auth Service or Redis unavailable: protected routes fail closed with `503`.
- Invalid, missing, duplicate, expired, or revoked session: `401`.
- Missing product entitlement: `403`.
- Public routes do not invoke Auth Service.

The gateway should use short auth timeouts, bounded retries only for safe
transport failures, circuit breaking, rate limits on login endpoints, and
structured access logs without cookie or token values.
