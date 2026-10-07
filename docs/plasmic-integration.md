# Plasmic unified identity

The product uses `studio.plasmic.shiguanglab.com` and `canvas.plasmic.shiguanglab.com`.
Add both to `ALLOWED_RETURN_ORIGINS` and grant `plasmic:access` through IAM policy.
The gateway authorizes the product with audience `plasmic-api`; Studio validates
RS256 `sg-identity+jwt` assertions and references users by `sub` in business tables.

Register the `plasmicapp` public native client with redirect URI
`http://127.0.0.1/callback`, scope `web:session`, audience `plasmicapp`, webAppUrl
`https://studio.plasmic.shiguanglab.com/`, and required entitlement `plasmic:access`.
Add the registration to `OAUTH_CLIENTS_JSON` without removing existing clients.
The native authorization-code flow uses PKCE S256 and consumes an IAM web-session
ticket in Electron. No product password or refresh token store is required.

The private identity API uses the service `IDENTITY_API_TOKEN` bearer credential:

- POST `/v1/identity/users/batch-get`: `{ids: string[]}`, max 200; returns canonical
  `id`, `loginName`, `displayName`, `email`, `emailVerified` and `state`.
- POST `/v1/identity/users/by-email`: `{email: string}`; returns `{user: {id}}` only for
  an exact verified active primary email, otherwise `{user: null}`. This resolves
  business invitations and never performs product sign-in.
- POST `/v1/identity/users/query`: `{query: string, limit?: number}`; bounded active
  user search for product administration. It uses the existing directory search
  implementation and validation/rate limits. Points service credentials do not
  authorize these generic endpoints.

Studio session/logout routes are exact gateway routes to auth-service with the
shared cookie and gateway credential forwarded. Browser writes retain IAM origin
validation; product APIs check the Studio/canvas origin independently.
