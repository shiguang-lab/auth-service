#!/bin/sh
# Bootstrap the organization platform in ZITADEL:
#   1. Grant the login-client machine user IAM_OWNER so the Auth Service can
#      manage organizations, project grants and authorizations at runtime.
#   2. Ensure the platform project roles org:admin / org:member / org:viewer.
#   3. Verify the runtime PAT can search organizations and authorizations.
#
# Idempotent: existing memberships and roles are tolerated.
set -eu

ZITADEL_ENV_FILE="${ZITADEL_ENV_FILE:-/volume1/docker/zitadel/.env}"
OIDC_ENV_FILE="${OIDC_ENV_FILE:-/volume1/docker/shiguang-auth/source/deploy/zitadel-oidc.env}"
API_URL="${ZITADEL_API_URL:-http://100.87.115.78:8080}"
PUBLIC_HOST="${ZITADEL_PUBLIC_HOST:-sso.shiguanglab.com}"
ADMIN_LOGIN_NAME="${ZITADEL_ADMIN_LOGIN_NAME:-admin@zitadel.local}"
LOGIN_PAT_FILE="${ZITADEL_LOGIN_PAT_FILE:-/volume1/docker/zitadel/data/bootstrap/login-client.pat}"

for file in "$ZITADEL_ENV_FILE" "$OIDC_ENV_FILE" "$LOGIN_PAT_FILE"; do
  if [ ! -r "$file" ]; then
    echo "Cannot read $file" >&2
    exit 1
  fi
done

set -a
. "$ZITADEL_ENV_FILE"
set +a
: "${ZITADEL_ADMIN_PASSWORD:?ZITADEL_ADMIN_PASSWORD is required}"
project_id="$(grep '^ZITADEL_PROJECT_ID=' "$OIDC_ENV_FILE" | cut -d= -f2 | tr -d '\r\n')"
: "${project_id:?ZITADEL_PROJECT_ID missing in $OIDC_ENV_FILE}"
login_pat="$(tr -d '\r\n' < "$LOGIN_PAT_FILE")"

workdir="$(mktemp -d)"
chmod 700 "$workdir"
trap 'rm -rf "$workdir"' EXIT

# api_call METHOD PATH TOKEN BODY_FILE OUTPUT_FILE [ORG_ID]
# Prints the HTTP status; never exits on non-2xx (callers decide).
api_call() {
  method="$1"; path="$2"; token="$3"; body_file="$4"; output_file="$5"; org_id="${6:-}"
  set -- -sS -o "$output_file" -w '%{http_code}' -X "$method" "$API_URL$path" \
    -H "Host: $PUBLIC_HOST" -H "X-Forwarded-Proto: https" \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json"
  [ -n "$org_id" ] && set -- "$@" -H "x-zitadel-orgid: $org_id"
  [ -n "$body_file" ] && set -- "$@" --data-binary "@$body_file"
  curl "$@"
}

require_2xx() {
  status="$1"; context="$2"; output_file="$3"
  case "$status" in
    2??) ;;
    *)
      echo "$context failed with HTTP $status" >&2
      head -c 400 "$output_file" >&2 || true
      echo >&2
      exit 1
      ;;
  esac
}

# ── 1. Admin session ─────────────────────────────────────────────────────────
jq -n --arg login "$ADMIN_LOGIN_NAME" --arg password "$ZITADEL_ADMIN_PASSWORD" \
  '{checks:{user:{loginName:$login},password:{password:$password}}}' \
  > "$workdir/admin-session-request.json"
status="$(api_call POST /v2/sessions "$login_pat" "$workdir/admin-session-request.json" "$workdir/admin-session.json")"
require_2xx "$status" "create admin session" "$workdir/admin-session.json"
admin_session_id="$(jq -er '.sessionId' "$workdir/admin-session.json")"
admin_token="$(jq -er '.sessionToken' "$workdir/admin-session.json")"

status="$(api_call GET "/v2/sessions/$admin_session_id" "$admin_token" "" "$workdir/admin-session-details.json")"
require_2xx "$status" "read admin session" "$workdir/admin-session-details.json"
platform_org_id="$(jq -er '.session.factors.user.organizationId' "$workdir/admin-session-details.json")"

# ── 2. Resolve the login-client machine user and grant IAM_OWNER ────────────
status="$(api_call GET /auth/v1/users/me "$login_pat" "" "$workdir/login-client-me.json")"
require_2xx "$status" "resolve login-client user" "$workdir/login-client-me.json"
login_client_user_id="$(jq -er '.user.id' "$workdir/login-client-me.json")"

jq -n --arg userId "$login_client_user_id" '{userId:$userId,roles:["IAM_OWNER"]}' \
  > "$workdir/iam-member-request.json"
status="$(api_call POST /admin/v1/members "$admin_token" "$workdir/iam-member-request.json" "$workdir/iam-member.json")"
case "$status" in
  2??) echo "Granted IAM_OWNER to login-client ($login_client_user_id)." ;;
  *)
    # An existing membership (for example IAM_LOGIN_CLIENT) makes the add
    # conflict; merge IAM_OWNER into the current role set instead.
    printf '{}' > "$workdir/member-search-request.json"
    search_status="$(api_call POST /admin/v1/members/_search "$admin_token" "$workdir/member-search-request.json" "$workdir/members.json")"
    require_2xx "$search_status" "search instance members" "$workdir/members.json"
    merged_roles="$(jq -c --arg userId "$login_client_user_id" \
      '[.result[]? | select(.userId == $userId) | .roles[]?] + ["IAM_OWNER"] | unique' \
      "$workdir/members.json")"
    if jq -e --arg userId "$login_client_user_id" \
      '.result[]? | select(.userId == $userId) | .roles | index("IAM_OWNER")' \
      "$workdir/members.json" > /dev/null; then
      echo "login-client already holds IAM_OWNER."
    else
      jq -n --argjson roles "$merged_roles" '{roles:$roles}' > "$workdir/member-update-request.json"
      update_status="$(api_call PUT "/admin/v1/members/$login_client_user_id" "$admin_token" "$workdir/member-update-request.json" "$workdir/member-update.json")"
      require_2xx "$update_status" "merge IAM_OWNER into login-client roles" "$workdir/member-update.json"
      echo "Merged IAM_OWNER into login-client roles ($merged_roles)."
    fi
    ;;
esac

# ── 3. Ensure the platform project roles ─────────────────────────────────────
for role in "org:admin|Organization Admin" "org:member|Organization Member" "org:viewer|Organization Viewer" "opc:system-admin|OPC 系统管理员"; do
  key="${role%%|*}"; display="${role#*|}"
  jq -n --arg roleKey "$key" --arg displayName "$display" \
    '{roleKey:$roleKey,displayName:$displayName}' > "$workdir/role-request.json"
  status="$(api_call POST "/management/v1/projects/$project_id/roles" "$admin_token" "$workdir/role-request.json" "$workdir/role.json" "$platform_org_id")"
  case "$status" in
    2??) echo "Created project role $key." ;;
    409) echo "Project role $key already exists." ;;
    400)
      if grep -qi "already\|exist" "$workdir/role.json"; then
        echo "Project role $key already exists."
      else
        require_2xx "$status" "create project role $key" "$workdir/role.json"
      fi
      ;;
    *) require_2xx "$status" "create project role $key" "$workdir/role.json" ;;
  esac
done

# ── 3b. Grant the platform administrator role ───────────────────────────────
# PLATFORM_ADMIN_LOGIN_NAME (default yanxianliang) receives opc:system-admin
# on the platform project's own organization; the role therefore reaches every
# assertion independent of the active business-organization context.
PLATFORM_ADMIN_LOGIN_NAME="${PLATFORM_ADMIN_LOGIN_NAME:-yanxianliang}"
jq -n --arg loginName "$PLATFORM_ADMIN_LOGIN_NAME" \
  '{queries:[{loginNameQuery:{loginName:$loginName,method:"TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE"}}]}' \
  > "$workdir/admin-user-search.json"
status="$(api_call POST /v2/users "$admin_token" "$workdir/admin-user-search.json" "$workdir/admin-user.json")"
require_2xx "$status" "resolve platform admin user" "$workdir/admin-user.json"
platform_admin_id="$(jq -er '.result[0].userId' "$workdir/admin-user.json")"

jq -n --arg orgId "$platform_org_id" --arg projectId "$project_id" --arg userId "$platform_admin_id" \
  '{filters:[{organizationId:{id:$orgId}},{projectId:{id:$projectId}},{userId:{id:$userId}}]}' \
  > "$workdir/authz-lookup.json"
status="$(api_call POST /v2beta/authorizations/search "$admin_token" "$workdir/authz-lookup.json" "$workdir/authz-existing.json")"
require_2xx "$status" "search platform authorizations" "$workdir/authz-existing.json"
existing_authz_id="$(jq -r '.authorizations[0].id // empty' "$workdir/authz-existing.json")"
if [ -z "$existing_authz_id" ]; then
  jq -n --arg userId "$platform_admin_id" --arg projectId "$project_id" --arg orgId "$platform_org_id" \
    '{userId:$userId,projectId:$projectId,organizationId:$orgId,roleKeys:["opc:system-admin"]}' \
    > "$workdir/authz-create.json"
  status="$(api_call POST /v2beta/authorizations "$admin_token" "$workdir/authz-create.json" "$workdir/authz-created.json")"
  require_2xx "$status" "grant opc:system-admin" "$workdir/authz-created.json"
  echo "Granted opc:system-admin to $PLATFORM_ADMIN_LOGIN_NAME ($platform_admin_id)."
else
  merged_role_keys="$(jq -c '(.authorizations[0].roles // []) + ["opc:system-admin"] | unique' "$workdir/authz-existing.json")"
  if jq -e '.authorizations[0].roles | index("opc:system-admin")' "$workdir/authz-existing.json" > /dev/null; then
    echo "$PLATFORM_ADMIN_LOGIN_NAME already holds opc:system-admin."
  else
    jq -n --argjson roleKeys "$merged_role_keys" '{roleKeys:$roleKeys}' > "$workdir/authz-update.json"
    status="$(api_call PATCH "/v2beta/authorizations/$existing_authz_id" "$admin_token" "$workdir/authz-update.json" "$workdir/authz-updated.json")"
    require_2xx "$status" "merge opc:system-admin into authorization" "$workdir/authz-updated.json"
    echo "Merged opc:system-admin into the existing platform authorization."
  fi
fi

# ── 4. Verify the runtime PAT ────────────────────────────────────────────────
printf '{"queries":[]}' > "$workdir/org-search.json"
status="$(api_call POST /v2/organizations/_search "$login_pat" "$workdir/org-search.json" "$workdir/orgs.json")"
require_2xx "$status" "verify organization search with runtime PAT" "$workdir/orgs.json"
printf '{}' > "$workdir/authz-search.json"
status="$(api_call POST /v2beta/authorizations/search "$login_pat" "$workdir/authz-search.json" "$workdir/authz.json")"
require_2xx "$status" "verify authorization search with runtime PAT" "$workdir/authz.json"

api_call DELETE "/v2/sessions/$admin_session_id" "$admin_token" "" "$workdir/delete-session.json" > /dev/null
echo "Organization platform bootstrap complete (project $project_id)."
