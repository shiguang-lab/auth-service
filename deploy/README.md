# Auth Service NAS release

The Website Portal depends on Auth Service routes that are not part of the
static Website artifact. Releasing the Website without promoting a compatible
Auth Service candidate leaves `/portal` visible while its access APIs return
404.

## Candidate promotion

1. Build the candidate from the reviewed Auth Service commit and assign a
   unique image tag or immutable digest. Do not use `latest`.
2. Set `AUTH_SERVICE_IMAGE` in the private deployment environment used by
   `deploy/docker-compose.nas.yml`.
3. Run `docker compose config` and confirm the resolved `auth-service.image`
   matches the reviewed candidate.
4. Recreate only `auth-service`; do not recreate Redis, ZITADEL, Gateway, or
   unrelated Website services.
5. Confirm `/health/live` and `/health/ready` before public smoke testing.

The Portal release requires a candidate containing commit `2abedc0` or a
descendant. The deployed environment must retain the existing Gateway token,
Redis, ZITADEL, signing-key, Origin, and session-cookie configuration.

## Public release gate

Run the anonymous smoke against the same public origin used by the Website:

```bash
AUTH_PUBLIC_ORIGIN=https://shiguanglab.com make smoke-portal
```

Both `/api/auth/session` and `/api/auth/portal/access` must return JSON `401`
without a session. A `404` means the Portal-compatible Auth Service or its
Gateway route is not deployed. The smoke does not log in, mutate IAM roles, or
send credentials.

After the anonymous gate passes, separately validate an ordinary user and an
IAM administrator through the browser. Production IAM writes remain
fail-closed until the permanent audit sink and approved ZITADEL writer are
configured.

## Rollback

Keep the previous Auth Service image reference until the observation window
ends. On regression, restore that exact image reference and recreate only
`auth-service`; do not roll back Redis data or rotate session/signing secrets.
