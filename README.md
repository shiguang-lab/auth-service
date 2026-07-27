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

- Gateway-protected `GET /v1/forward-auth`
- Missing and duplicate shared-cookie rejection
- Memory session store for tests and development
- AES-256-GCM encrypted Redis sessions and login transactions
- RS256 `sg-identity+jwt` assertions through jwx
- Public JWKS, liveness, and Redis-backed readiness
- Direct ZITADEL Session API username/password authentication with no browser OIDC round trip
- ZITADEL IDP Intent callbacks for GitHub/Google; existing links sign in directly and new identities continue in Website's custom registration page
- Parent-domain opaque session creation, inspection, and logout
- Origin validation, CSRF protection, and Redis login rate limiting

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

## Endpoints

| Method | Path | Authentication |
|---|---|---|
| `GET` | `/health/live` | Public |
| `GET` | `/health/ready` | Public |
| `GET` | `/.well-known/jwks.json` | Public |
| `GET` | `/v1/forward-auth` | `X-SG-Gateway-Token` |
| `GET` | `/api/auth/federated/start` | Gateway token; federated login only |
| `GET` | `/api/auth/register/provider` | Gateway token; starts Website-owned federated registration |
| `POST` | `/api/auth/login/context` | Gateway token + Origin |
| `POST` | `/api/auth/login/password` | Gateway token + Origin + CSRF |
| `GET` | `/api/auth/oidc/callback` | Gateway token + OIDC transaction |
| `POST` | `/api/auth/register/federated/context` | Gateway token + Origin + pending federated transaction |
| `POST` | `/api/auth/register/federated` | Gateway token + Origin + CSRF |
| `GET` | `/api/auth/session` | Gateway token + session cookie |
| `POST` | `/api/auth/logout` | Gateway token + Origin |

The forward-auth endpoint consumes the standard `X-Forwarded-Method`,
`X-Forwarded-Uri`, `X-Forwarded-Host`, and `X-Forwarded-Proto` headers plus
gateway-owned product policy headers. On success it returns `X-SG-Identity`.

See [docs/architecture.md](docs/architecture.md) for trust boundaries and the
request flow, and [docs/integration.md](docs/integration.md) for the product
integration guide (assertion contract, shared endpoints, checklists).

## NAS deployment

`deploy/docker-compose.nas.yml` runs Redis and Auth Service on an internal
backend network and exposes Auth Service only through `shiguang-auth-edge`.
`deploy/bootstrap-zitadel.sh` creates the confidential OIDC application through
official ZITADEL APIs and writes its one-time secret only to the NAS private
`deploy/zitadel-oidc.env` file.

For an application created before the `/api/auth/*` route migration, replace
the registered redirect URI
`https://shiguanglab.com/_auth/oidc/callback` with
`https://shiguanglab.com/api/auth/oidc/callback` before deploying. Existing
applications are not recreated automatically because doing so would rotate the
client credentials.
