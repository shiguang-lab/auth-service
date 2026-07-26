#!/bin/sh
set -eu

ZITADEL_ENV_FILE="${ZITADEL_ENV_FILE:-/volume1/docker/zitadel/.env}"
OUTPUT_FILE="${OUTPUT_FILE:-/volume1/docker/zitadel/data/bootstrap/registration-client.pat}"
API_URL="${ZITADEL_API_URL:-http://100.87.115.78:8080}"
PUBLIC_HOST="${ZITADEL_PUBLIC_HOST:-sso.shiguanglab.com}"
ADMIN_LOGIN_NAME="${ZITADEL_ADMIN_LOGIN_NAME:-admin@zitadel.local}"
LOGIN_PAT_FILE="${ZITADEL_LOGIN_PAT_FILE:-/volume1/docker/zitadel/data/bootstrap/login-client.pat}"

if [ -s "$OUTPUT_FILE" ]; then
  echo "ZITADEL registration client is already bootstrapped."
  exit 0
fi
if [ ! -r "$ZITADEL_ENV_FILE" ] || [ ! -r "$LOGIN_PAT_FILE" ]; then
  echo "ZITADEL bootstrap inputs are not readable." >&2
  exit 1
fi

set -a
. "$ZITADEL_ENV_FILE"
set +a
: "${ZITADEL_ADMIN_PASSWORD:?ZITADEL_ADMIN_PASSWORD is required}"
login_pat="$(tr -d '\r\n' < "$LOGIN_PAT_FILE")"

workdir="$(mktemp -d)"
chmod 700 "$workdir"
trap 'rm -rf "$workdir"' EXIT

api_request() {
  method="$1"
  path="$2"
  token="$3"
  body_file="$4"
  output_file="$5"
  org_id="${6:-}"

  set -- -sS -o "$output_file" -w '%{http_code}' -X "$method" "$API_URL$path" \
    -H "Host: $PUBLIC_HOST" \
    -H "X-Forwarded-Proto: https" \
    -H "Accept: application/json" \
    -H "Authorization: Bearer $token"
  if [ -n "$org_id" ]; then
    set -- "$@" -H "X-Zitadel-Orgid: $org_id"
  fi
  if [ -n "$body_file" ]; then
    set -- "$@" -H "Content-Type: application/json" --data-binary "@$body_file"
  fi
  status="$(curl "$@")"
  case "$status" in
    2??) ;;
    *)
      echo "ZITADEL API request $path failed with HTTP $status" >&2
      exit 1
      ;;
  esac
}

jq -n \
  --arg login "$ADMIN_LOGIN_NAME" \
  --arg password "$ZITADEL_ADMIN_PASSWORD" \
  '{checks:{user:{loginName:$login},password:{password:$password}}}' \
  > "$workdir/admin-session-request.json"
api_request POST /v2/sessions "$login_pat" "$workdir/admin-session-request.json" "$workdir/admin-session.json"

admin_session_id="$(jq -er '.sessionId' "$workdir/admin-session.json")"
admin_session_token="$(jq -er '.sessionToken' "$workdir/admin-session.json")"
api_request GET "/v2/sessions/$admin_session_id" "$admin_session_token" "" "$workdir/admin-session-details.json"
organization_id="$(jq -er '.session.factors.user.organizationId' "$workdir/admin-session-details.json")"

jq -n \
  --arg organizationId "$organization_id" \
  '{
    organizationId:$organizationId,
    username:"registration-client",
    machine:{
      name:"Shiguang Registration Service",
      description:"Creates self-service Shiguang accounts",
      accessTokenType:"ACCESS_TOKEN_TYPE_BEARER"
    }
  }' > "$workdir/user-request.json"
api_request POST /v2/users/new "$admin_session_token" "$workdir/user-request.json" "$workdir/user.json"
user_id="$(jq -er '.id' "$workdir/user.json")"

jq -n \
  --arg userId "$user_id" \
  '{userId:$userId,roles:["ORG_USER_MANAGER"]}' \
  > "$workdir/member-request.json"
api_request POST /management/v1/orgs/me/members "$admin_session_token" "$workdir/member-request.json" "$workdir/member.json" "$organization_id"

jq -n \
  '{expirationDate:"2036-01-01T00:00:00Z"}' \
  > "$workdir/pat-request.json"
api_request POST "/v2/users/$user_id/pats" "$admin_session_token" "$workdir/pat-request.json" "$workdir/pat.json"

umask 077
jq -er '.token' "$workdir/pat.json" > "$OUTPUT_FILE"
api_request DELETE "/v2/sessions/$admin_session_id" "$admin_session_token" "" "$workdir/delete-session.json"
unset admin_session_token login_pat ZITADEL_ADMIN_PASSWORD

echo "Created the ZITADEL registration client for organization $organization_id."
