# Shiguang Auth Service

Central authentication decision service for Shiguang first-party web products.

The service receives authorization checks only from `access-gateway`, validates
the opaque parent-domain session, enforces coarse product entitlements, and
issues a short-lived RS256 identity assertion scoped to one product audience.

## Current scope

- Shared-token protected `POST /v1/authorize`
- Public-route and authenticated-route decisions
- Duplicate shared-cookie rejection
- Server-side session store interface
- In-memory session store for tests and local development only
- RS256 `sg-identity+jwt` assertions
- Public JWKS endpoint
- Liveness and readiness endpoints

OIDC Authorization Code + PKCE, ZITADEL Session API login steps, Redis/Valkey,
back-channel logout, CSRF, and session lifecycle endpoints are intentionally
the next implementation milestone. Protected requests fail closed until a
valid server-side session exists.

## Local development

Go 1.26 is required.

```bash
export GATEWAY_SHARED_TOKEN="$(openssl rand -hex 32)"
go run ./cmd/auth-service
```

When `IDENTITY_SIGNING_KEY_FILE` is empty in development, the service creates
an ephemeral RSA key. Production refuses to start without a key file and a
non-memory session backend. The service does not implicitly load `.env`;
deployment configuration must be injected by the process supervisor or
container runtime.

## Endpoints

| Method | Path | Authentication |
|---|---|---|
| `GET` | `/health/live` | Public |
| `GET` | `/health/ready` | Public |
| `GET` | `/.well-known/jwks.json` | Public |
| `POST` | `/v1/authorize` | Gateway shared Bearer token |

## Commands

```bash
make test
make build
```

The module path assumes the future GitHub repository will be
`github.com/shiguanglab/auth-service`.
