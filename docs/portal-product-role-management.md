# Portal product role management

The Website Portal is the browser entry point for product access. Auth Service
owns the product-role directory contract; products continue to own tenant,
application, task, asset, ledger, and other resource-level permissions.

## Managed roles

The browser API may assign only these roles:

- Huiguang: `huiguang:user`, `huiguang:gray-creator`, `huiguang:ops-admin`
- Yingguang: `yingguang:user`, `yingguang:ops-admin`
- Lingguang: `lingguang:consumer`, `lingguang:developer`,
  `lingguang:reviewer`, `lingguang:platform-admin`
- Points: `platform:points-auditor`, `platform:points-admin`

It must never assign `opc:system-admin`, `platform:admin`, organization roles,
or product-internal memberships. The legacy Points API remains scoped to the two
Points roles even when the target also has roles for other products.

## Browser routes

- `GET /api/auth/portal/access` returns the signed-in user's four product access
  states from the current platform-role snapshot. Points personal access is
  always active for an authenticated platform user.
- `POST /api/auth/iam/product-role-assignments/search` searches the bounded IAM
  directory and returns ACTIVE users only.
- `POST /api/auth/iam/product-role-assignments/resolve` resolves one exact user.
- `PUT /api/auth/iam/product-role-assignments/{userId}` submits the complete
  desired set of managed product roles.

The mutation path requires an `opc:system-admin` session, an allowlisted Origin,
an idempotency key, a non-self target, an ACTIVE target, and an allowlisted role
set. Its durable command records the managed scope as well as desired roles, so
retries cannot erase unrelated platform roles.

## Release gate

Local identity fixtures connect the API to the encrypted Redis command journal
and a scope-preserving fake provider. Production exposes Portal access and the
read-only ZITADEL directory, but role mutation deliberately returns
`iam_role_change_unavailable` until all of the following are configured:

1. a ZITADEL writer fixed to the platform organization and project;
2. preservation of every role outside the command's managed scope;
3. a permanent audit sink and reconciliation operations;
4. staging tests for idempotent replay, timeout ambiguity, revocation freshness,
   and cross-product role preservation.

No browser receives a PAT, ZITADEL token, machine credential, or product secret.
