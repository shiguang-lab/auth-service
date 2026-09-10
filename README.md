# Shiguang Auth Service

Central session and authentication-decision service for Shiguang first-party
products. It is deliberately separate from the Access Gateway.

## Technology

- Go 1.26
- [Chi v5](https://github.com/go-chi/chi) for the HTTP control plane
- [go-redis v9](https://github.com/redis/go-redis) for production sessions
- [jwx v3](https://github.com/lestrrat-go/jwx) for JWT/JWS/JWK handling
- [go-oidc v3](https://github.com/coreos/go-oidc) and `x/oauth2` for OIDC and PKCE
- Caddy-compatible forward-auth responses

## Responsibilities

- Validate the opaque parent-domain session cookie.
- Store server-side sessions in Redis in production.
- Enforce coarse product entitlements supplied by trusted gateway policy.
- Issue short-lived RS256 identity assertions scoped to one product audience.
- Publish public signing keys as JWKS.
- Own direct Session API login, federated OIDC callback, logout, and session lifecycle.

Product services still enforce resource-level authorization. They never receive
the shared browser cookie or ZITADEL tokens.

## Implemented

- Canonical Access Gateway decision API: `POST /v1/authorize`
- Compatibility forward-auth adapter: `GET /v1/forward-auth`
- Missing and duplicate shared-cookie rejection
- Memory session store for tests and development
- AES-256-GCM encrypted Redis sessions and login transactions
- RS256 `sg-identity+jwt` assertions through jwx
- Public JWKS, liveness, and Redis-backed readiness
- Direct ZITADEL Session API username/password authentication with no browser OIDC round trip
- ZITADEL IDP Intent callbacks for GitHub/Google; existing links sign in directly and new identities continue in Website's custom registration page
- Feishu OAuth login through a ZITADEL generic provider and Auth Service's current-API compatibility adapter
- Parent-domain opaque session creation, inspection, and logout
- Origin validation, CSRF protection, and Redis login rate limiting
- Portal product-role aggregation plus bounded ACTIVE-user directory search for
  绘光、映光、灵光 and Points role administration
- Backward-compatible Points-only IAM endpoints and fail-closed production
  writes until a permanent audit sink and ZITADEL writer are configured
- 60-second platform-role freshness with process-local concurrent refresh
  suppression and privilege-clearing failure behavior

Back-channel logout and automated signing-key rotation remain operational
follow-ups. Explicit logout revokes both platform and ZITADEL sessions.

## Local development

```bash
cp .env.example .env
set -a && . ./.env && set +a
make run
```

When `IDENTITY_SIGNING_KEY_FILE` is empty outside production, an ephemeral RSA
key is generated. Production requires a key file, Redis, and a gateway token of
at least 32 characters. `ALLOWED_RETURN_ORIGINS` is the comma-separated
allowlist of first-party origins that may receive the browser after login.
`OIDC_PROVIDER_IDS` maps public provider names used by the login UI to ZITADEL
identity provider IDs, for example `github=383564589272399875,google=383566836731478019`. The mapping is
required for federated starts and is used to select the provider directly in
ZITADEL Login V2.

NAS deployments load this non-secret mapping from the versioned
`deploy/oidc-providers.env` file. Keep OAuth client secrets in the untracked
`deploy/auth.env`/secret files; when migrating ZITADEL, update only the provider
IDs in `deploy/oidc-providers.env` and the corresponding provider registrations.

### Local full-stack identity fixture

`LOCAL_IDENTITY_FIXTURE=1` enables an explicit development-only implementation
of login, session refresh, the Points identity directory, and a fake IAM role
provider. It requires encrypted Redis sessions and an exact HTTP localhost
origin; configuration validation rejects it in production or on a non-local
origin. The fake provider is connected to the real encrypted Redis command
journal, so idempotent replay, conflicts, reconciliation, and controlled retry
exercise the production command boundary without calling ZITADEL.

Use the checked-in orchestration from the sibling Access Gateway repository:

```bash
cd ../access-gateway
make local-e2e
```

Fixture recovery and failure-injection endpoints are mounted only while the
fixture flag is active and still require the local IAM manager session. Normal
production startup keeps the IAM writer nil and fail-closed.

## Endpoints

| Method | Path | Authentication |
|---|---|---|
| `GET` | `/health/live` | Public |
| `GET` | `/health/ready` | Public |
| `GET` | `/.well-known/jwks.json` | Public |
| `POST` | `/v1/authorize` | `X-SG-Gateway-Token`; strict JSON decision protocol |
| `GET` | `/v1/forward-auth` | `X-SG-Gateway-Token`; compatibility adapter only |
| `GET` | `/api/auth/federated/start` | Gateway token; federated login only |
| `GET` | `/api/auth/providers/feishu/authorize` | Gateway token; ZITADEL-to-Feishu authorization adapter |
| `POST` | `/api/auth/providers/feishu/token` | Gateway token; ZITADEL-to-Feishu token adapter |
| `GET` | `/api/auth/providers/feishu/userinfo` | Gateway token; Feishu user-info normalization |
| `GET` | `/api/auth/register/provider` | Gateway token; starts Website-owned federated registration |
| `POST` | `/api/auth/login/context` | Gateway token + Origin |
| `POST` | `/api/auth/login/password` | Gateway token + Origin + CSRF |
| `GET` | `/api/auth/oidc/callback` | Gateway token + OIDC transaction |
| `POST` | `/api/auth/register/federated/context` | Gateway token + Origin + pending federated transaction |
| `POST` | `/api/auth/register/federated` | Gateway token + Origin + CSRF |
| `GET` | `/api/auth/session` | Gateway token + session cookie |
| `POST` | `/api/auth/logout` | Gateway token + Origin |
| `GET` | `/api/auth/portal/access` | Gateway token + session cookie |
| `POST` | `/api/auth/iam/product-role-assignments/search` | Gateway token + IAM manager session + Origin |
| `POST` | `/api/auth/iam/product-role-assignments/resolve` | Gateway token + IAM manager session + Origin |
| `PUT` | `/api/auth/iam/product-role-assignments/{userId}` | Gateway token + IAM manager session + Origin + idempotency key |
| `POST` | `/v1/identity/users/search` | `POINTS_IDENTITY_SERVICE_TOKEN`; server-side only |
| `POST` | `/v1/identity/users/resolve` | `POINTS_IDENTITY_SERVICE_TOKEN`; server-side only |

`POST /v1/authorize` is the canonical internal protocol for Access Gateway.
It accepts a bounded JSON `authorize.Request` with unknown fields rejected and
returns an `authorize.Response` for allow, deny, and login-redirect decisions.
The shared credential is accepted only in `X-SG-Gateway-Token`; bearer auth is
not part of this protocol.

The compatibility forward-auth endpoint consumes the standard `X-Forwarded-Method`,
`X-Forwarded-Uri`, `X-Forwarded-Host`, and `X-Forwarded-Proto` headers plus
gateway-owned product policy headers. On success it returns `X-SG-Identity`.

Points user selection is a two-step server-side contract. `search` accepts a
trimmed 3-64 character query and limit 1-10, and returns only ACTIVE users as
`{id, loginName, displayName, state}`. Before persisting a membership, the
Points backend calls `resolve` with `{userId}` to repeat an exact ACTIVE check.
The dedicated credential must remain in the Points server secret store and is
never sent to Points Web or a browser.

See [docs/architecture.md](docs/architecture.md) for trust boundaries and the
request flow, and [docs/integration.md](docs/integration.md) for the product
integration guide (assertion contract, shared endpoints, checklists).

## NAS deployment

`deploy/docker-compose.nas.yml` runs Redis and Auth Service on an internal
backend network and exposes Auth Service only through `shiguang-auth-edge`.
Version tags matching `v*` publish `ghcr.io/shiguang-lab/auth-service` through
GitHub Actions. Set `AUTH_SERVICE_IMAGE_TAG` in `deploy/auth.env` to the release
tag, then run `docker compose --env-file deploy/auth.env -f deploy/docker-compose.nas.yml pull`
and `docker compose --env-file deploy/auth.env -f deploy/docker-compose.nas.yml up -d`.
`deploy/bootstrap-zitadel.sh` creates the confidential OIDC application through
official ZITADEL APIs and writes its one-time secret only to the NAS private
`deploy/zitadel-oidc.env` file.

For an application created before the `/api/auth/*` route migration, replace
the registered redirect URI
`https://shiguanglab.com/_auth/oidc/callback` with
`https://shiguanglab.com/api/auth/oidc/callback` before deploying. Existing
applications are not recreated automatically because doing so would rotate the
client credentials.

### Feishu provider

Feishu is registered as an organization-level generic OAuth provider. Its App
Secret belongs only in the ignored `deploy/feishu-oauth.env` file; Auth Service
receives only the generated, non-secret `FEISHU_IDP_ID` and `FEISHU_APP_ID`
from `deploy/feishu-provider.env`. The App ID binds the compatibility adapter
to this Feishu application without exposing the App Secret to Auth Service.

Follow [docs/feishu-login.md](docs/feishu-login.md) to configure the Feishu
redirect URL, bootstrap or rotate the ZITADEL provider, restart the service,
and verify both first-time registration and returning-user login.
