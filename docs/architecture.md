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
Feishu additionally passes through three stateless compatibility endpoints that
translate ZITADEL's generic OAuth requests to Feishu's current JSON APIs. They
validate the public Feishu App ID and never persist the Feishu App Secret,
authorization code, or access token.

## Local product development broker

Products that run their Web and API on localhost may opt into the production
Local Broker. This is a server-to-server password grant for a configured test
account, not a browser login or an impersonation API:

1. The localhost Node proxy posts the configured login name and password to
   `POST /api/auth/local-broker`.
2. Auth Service authenticates the account with ZITADEL, stores a random opaque
   broker credential in Redis, and returns it only to the Node process.
3. The proxy refreshes through `POST /api/auth/local-broker/refresh`; Auth
   Service issues a normal short-lived identity assertion for the single
   configured product, audience, and entitlement policy.
4. The proxy removes browser `Cookie`, `Authorization`, and identity headers,
   then injects the signed assertion into localhost API/SSE/upload/download
   requests.

Browser sessions and broker credentials have distinct credential kinds and
cannot be substituted for each other. The broker routes are absent unless
`LOCAL_BROKER_ENABLED=true`; TTL is capped at 24 hours, the origin is fixed to
`PUBLIC_ORIGIN`, login attempts are rate-limited, and callers cannot choose a
subject, audience, or entitlement.

## Local product development broker

Products that run their Web and API on localhost may opt into the production
Local Broker. This is a server-to-server password grant for a configured test
account, not a browser login or an impersonation API:

1. The localhost Node proxy posts the configured login name, password, and a
   server-allowlisted `productId` to `POST /api/auth/local-broker`.
2. Auth Service authenticates the account with ZITADEL, stores a random opaque
   broker credential in Redis, and returns it only to the Node process.
3. The proxy refreshes through `POST /api/auth/local-broker/refresh`; Auth
   Service issues a normal short-lived identity assertion for the product
   policy bound to that broker credential.
4. The proxy removes browser `Cookie`, `Authorization`, and identity headers,
   then injects the signed assertion into localhost API/SSE/upload/download
   requests.

Browser sessions and broker credentials have distinct credential kinds and
cannot be substituted for each other. Each broker is bound to one product and
cannot refresh into another allowlisted product. The broker routes are absent
unless `LOCAL_BROKER_ENABLED=true`; TTL is capped at 24 hours, the origin is
fixed to `PUBLIC_ORIGIN`, login attempts are rate-limited, and callers cannot
choose a subject, audience, or entitlement.

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
