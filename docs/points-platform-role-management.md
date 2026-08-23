# Points Platform Role Management Contract

## Scope and role source

This contract manages only context-independent Points platform roles. It does
not manage application membership.

| Capability | Source | Meaning |
| --- | --- | --- |
| Base access | `platform:access` entitlement | May open the Points host after unified login |
| IAM manager | `opc:system-admin` platform role | Sole caller allowed to grant or revoke Points platform roles |
| Points administrator | `platform:points-admin` platform role | Global Points read/write operations |
| Points auditor | `platform:points-auditor` platform role | Global Points read-only operations |
| Application manager | Points Service ACTIVE `OWNER`/`ADMIN` membership | One application's credentials, ledger, audit, and supported settings |

`opc:system-admin` already exists in the platform IAM model, so no duplicate
`platform:iam-admin` role is introduced. Platform roles and application
membership are combined as a permission union, but are stored and managed in
different systems. IAM role management never writes an application membership.

## Same-origin browser API

The Points host routes the following protected prefix to Auth Service:

`/api/auth/iam/points-role-assignments/`

The gateway requires `platform:access`, forwards only the shared session cookie
and its internal gateway credential, and strips browser `Authorization`.
Auth Service refreshes the session's platform roles and requires
`opc:system-admin` on every request.

Every endpoint also requires an exact browser `Origin` from the dedicated
`IAM_ROLE_ADMIN_ORIGINS` allowlist. Production defaults to the Portal origin
`https://shiguanglab.com` and the Points administration origin
`https://point.shiguanglab.com`; the broader first-party return-origin list is
intentionally not reused, so a compromised sibling product cannot submit IAM
role changes with the shared parent-domain session cookie.

Endpoints:

- `POST .../search` with `{"query":"alice","limit":10}`. Query length is
  3-64 Unicode code points and limit is 1-10.
- `POST .../resolve` with `{"userId":"..."}` for an exact ACTIVE-user check.
- `PUT .../{userId}` with `{"roles":[...]}`. The roles array is the complete
  desired Points platform-role state and may contain only
  `platform:points-admin` and `platform:points-auditor`. A valid
  `Idempotency-Key` header (8-128 characters from `[A-Za-z0-9._:-]`) is
  required for a change.

The desired-state `PUT` is idempotent: the same target and normalized role set
returns `200` with `changed:false` and performs no second write. Empty roles
revoke both manageable roles. Unknown fields, extra JSON values, oversized
bodies, and non-allowlisted roles are rejected.

Stable errors include `iam_admin_forbidden`,
`iam_self_role_change_forbidden`, `iam_role_not_manageable`,
`iam_role_rate_limited`, `iam_role_directory_unavailable`,
`iam_role_change_unavailable`, `iam_role_reconcile_required`,
`idempotency_key_required`, `idempotency_conflict`, `request_in_progress`, and
`invalid_origin`.

## Durable command journal

The production-capable executor separates persistence from the provider:

1. Derive a stable, non-reversible `operationId` from actor subject and the
   caller's idempotency key; bind it to a target/desired-role fingerprint.
2. Persist an encrypted `PENDING` command with a short execution lease.
3. Call `ProviderRoleWriter.SetPointsRoles` with the complete desired state.
4. CAS the command to `SUCCEEDED`, `FAILED`, or `RECONCILE_REQUIRED`.

States:

| State | Meaning | Automated behavior |
| --- | --- | --- |
| `PENDING` | Persisted before provider call; lease may still be active | Do not retry until the lease expires |
| `SUCCEEDED` | Provider success and result persisted | Same operation/payload replays the stored result |
| `FAILED` | Provider definitively rejected before mutation | IAM manager may explicitly retry after correcting the cause |
| `RECONCILE_REQUIRED` | Provider outcome is unknown or result persistence was uncertain | Compare provider desired state, then use controlled retry |

The Redis journal uses encrypted command values, per-command TTL, WATCH/MULTI
CAS, status indexes, and a retry lease. Default TTL is 30 days
(`IAM_ROLE_COMMAND_TTL=720h`, permitted range 24h-2160h). It stores only actor
subject, target user ID, before/after allowlisted roles, request/operation IDs,
state, attempts, timestamps, and a bounded error code. It never stores browser
cookies, provider/service tokens, secrets, email, or unrelated profile fields.

Redis is appropriate for idempotency and crash recovery, but TTL means it is
not permanent audit retention. Before real IAM writes are enabled, successful
commands and provider outcomes should also be copied to an append-only
PostgreSQL audit store with an independently approved retention policy.
Denial audit remains a separate `AuditSink`; denied requests never create a
provider command.

### Internal operations contract (not mounted)

The service layer defines two IAM-manager-gated operations, but this release
does not expose them on the browser router:

- list `PENDING` and `RECONCILE_REQUIRED` commands, oldest first, maximum 100;
- retry one operation by `operationId` using CAS and a new short lease.

A future internal route may expose `GET /internal/v1/iam/points-role-commands`
and `POST /internal/v1/iam/points-role-commands/{operationId}/retry` only behind
an internal service credential plus a refreshed `opc:system-admin` principal.
It must never be added to the public Points browser gateway prefix without a
separate review.

## Session capability

`GET /api/auth/session` returns server-computed capability metadata without a
service token:

```json
{
  "iamCapabilities": {
    "pointsRoleAssignments": {
      "read": true,
      "write": true,
      "manageableRoles": [
        "platform:points-admin",
        "platform:points-auditor"
      ]
    }
  }
}
```

Only `opc:system-admin` receives `read:true` and `write:true`. The UI uses this
capability for discoverability; Auth Service authorization remains decisive.

## Threat model and controls

- A Points administrator, auditor, ordinary user, or application member alone
  receives `403`, including direct API calls that bypass hidden navigation.
- A caller cannot modify its own privileged roles. This prevents self-demotion
  from bypassing review and self-elevation through mixed-role requests.
- The API cannot create, revoke, or mutate `opc:system-admin`. Consequently it
  cannot remove the last IAM manager. Any future API that manages IAM-manager
  roles must add an explicit last-active-manager invariant at the writer.
- Read and write operations have separate per-actor rate limits. Provider
  errors, malformed responses, missing directory/executor configuration, and
  command-journal failures fail closed.
- Search returns only user ID, login name, display name, ACTIVE state, and the
  two manageable roles. Tokens and unrelated IAM roles are never returned or
  logged.
- Successful changes and denied write attempts carry actor, target, before and
  after role sets, reason, request ID, and timestamp in the audit contract.
- The no-secret in-memory implementation exists only in the Points Web local
  fixture. Production builds exclude fixture selectors and headers.

## Production writer gate

This release defines `Directory` and `ChangeExecutor` interfaces but deliberately
does not implement or configure a ZITADEL executor. `cmd/auth-service` mounts a
fail-closed service: an authorized manager can discover that the directory or
executor is unavailable, but no real role mutation occurs.

Before enabling a real executor, a separate review must prove fixed organization
and project targeting, preservation of unrelated roles, ACTIVE-user checks,
redirect-free authenticated transport, and a durable idempotent command
journal. The executor must persist actor, target, before/after roles, request ID,
and a pending state before calling the provider, then record success/failure so
an interrupted command can be reconciled without being reported as an
unaudited success. Session-role refresh behavior and last-manager protection
also require review. This needs deployment configuration and real IAM
authorization outside this local phase.

## Operations enablement checklist

1. Approve and provision a dedicated Redis namespace, 32-byte encryption key,
   30-day TTL, memory/eviction policy, persistence mode, backup, and alerts.
2. Add a provider writer only after fixed organization/project targeting,
   desired-state idempotency, unrelated-role preservation, timeout behavior,
   and no-redirect authenticated transport are proven.
3. Keep the production executor nil until both Redis journal and permanent
   audit sink readiness checks pass; startup must fail closed for partial
   configuration.
4. Add metrics for state counts, oldest PENDING age, reconcile backlog,
   provider latency/errors, CAS conflicts, and result-persistence failures.
5. Define the operator runbook for expired leases, provider comparison,
   controlled retry, duplicate-key conflicts, and emergency writer disable.
6. Run unit tests plus Redis integration tests, then a no-secret provider fake
   smoke before requesting any real ZITADEL authorization.
