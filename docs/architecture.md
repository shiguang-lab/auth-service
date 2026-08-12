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
2. Access Gateway removes all externally supplied identity headers.
3. Access Gateway calls the canonical `POST /v1/authorize` JSON endpoint with
   the original request metadata, gateway-owned product policy, and
   `X-SG-Gateway-Token`. `GET /v1/forward-auth` remains a compatibility adapter
   for existing forward-auth proxies.
4. Auth Service hashes the cookie value, loads the server-side Redis session,
   checks expiry and revocation, refreshes platform roles when their 60-second
   cache is stale, checks required entitlement, and signs an assertion.
5. Access Gateway copies only `X-SG-Identity` into the upstream request and removes the
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

Platform-role refresh is restricted to active authorizations for the configured
platform organization and project. Successful refreshes update the optional
`platform_roles_refreshed_at` Session field. Old encrypted Session JSON omits
that field and therefore refreshes on first access without a Redis migration.
Directory failure clears `PlatformRoles` before an assertion or Session response
is produced, while ordinary entitlements such as `platform:access` remain.
Concurrent refreshes for one subject are coalesced inside each process.

An administrative role-write API is intentionally deferred. Immediate
cross-instance revocation will require a Redis `subject -> session IDs` index so
all sessions for a subject can be refreshed or revoked after a role change; no
such index or write endpoint exists in this phase.

The gateway should use short auth timeouts, bounded retries only for safe
transport failures, circuit breaking, rate limits on login endpoints, and
structured access logs without cookie or token values.
