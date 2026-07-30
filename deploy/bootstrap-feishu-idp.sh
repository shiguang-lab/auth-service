#!/bin/sh
# Create or update the Feishu generic OAuth provider in ZITADEL, activate it
# for the platform organization, and publish its non-secret provider ID for
# Auth Service. The App ID is public configuration; the Feishu App Secret
# remains in feishu-oauth.env only.
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ZITADEL_ENV_FILE="${ZITADEL_ENV_FILE:-/volume1/docker/zitadel/.env}"
FEISHU_ENV_FILE="${FEISHU_ENV_FILE:-$script_dir/feishu-oauth.env}"
OUTPUT_FILE="${OUTPUT_FILE:-$script_dir/feishu-provider.env}"
API_URL="${ZITADEL_API_URL:-http://100.87.115.78:8080}"
PUBLIC_HOST="${ZITADEL_PUBLIC_HOST:-sso.shiguanglab.com}"
ADMIN_LOGIN_NAME="${ZITADEL_ADMIN_LOGIN_NAME:-admin@zitadel.local}"
LOGIN_PAT_FILE="${ZITADEL_LOGIN_PAT_FILE:-/volume1/docker/zitadel/data/bootstrap/login-client.pat}"
SHIGUANG_PUBLIC_ORIGIN="${SHIGUANG_PUBLIC_ORIGIN:-https://shiguanglab.com}"

for file in "$ZITADEL_ENV_FILE" "$FEISHU_ENV_FILE" "$LOGIN_PAT_FILE"; do
  if [ ! -r "$file" ]; then
    echo "Cannot read $file" >&2
    exit 1
  fi
done

set -a
. "$ZITADEL_ENV_FILE"
. "$FEISHU_ENV_FILE"
set +a
: "${ZITADEL_ADMIN_PASSWORD:?ZITADEL_ADMIN_PASSWORD is required}"
: "${FEISHU_APP_ID:?FEISHU_APP_ID is required}"
: "${FEISHU_APP_SECRET:?FEISHU_APP_SECRET is required}"
login_pat="$(tr -d '\r\n' < "$LOGIN_PAT_FILE")"

existing_id=""
if [ -r "$OUTPUT_FILE" ]; then
  existing_id="$(sed -n 's/^FEISHU_IDP_ID=//p' "$OUTPUT_FILE" | tail -n 1 | tr -d '\r\n')"
fi
if [ -n "$existing_id" ] && [ "${FORCE_BOOTSTRAP:-0}" != "1" ]; then
  echo "Feishu identity provider is already bootstrapped as $existing_id."
  exit 0
fi

workdir="$(mktemp -d)"
chmod 700 "$workdir"
admin_session_id=""
admin_token=""

cleanup() {
  if [ -n "$admin_session_id" ] && [ -n "$admin_token" ]; then
    curl -sS -o /dev/null -X DELETE "$API_URL/v2/sessions/$admin_session_id" \
      -H "Host: $PUBLIC_HOST" \
      -H "X-Forwarded-Proto: https" \
      -H "Authorization: Bearer $admin_token" || true
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

# api_call METHOD PATH TOKEN BODY_FILE OUTPUT_FILE [ORG_ID]
api_call() {
  method="$1"; path="$2"; token="$3"; body_file="$4"; output_file="$5"; org_id="${6:-}"
  set -- -sS -o "$output_file" -w '%{http_code}' -X "$method" "$API_URL$path" \
    -H "Host: $PUBLIC_HOST" \
    -H "X-Forwarded-Proto: https" \
    -H "Accept: application/json" \
    -H "Authorization: Bearer $token"
  [ -n "$org_id" ] && set -- "$@" -H "X-Zitadel-Orgid: $org_id"
  [ -n "$body_file" ] && set -- "$@" -H "Content-Type: application/json" --data-binary "@$body_file"
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

jq -n --arg login "$ADMIN_LOGIN_NAME" --arg password "$ZITADEL_ADMIN_PASSWORD" \
  '{checks:{user:{loginName:$login},password:{password:$password}}}' \
  > "$workdir/admin-session-request.json"
status="$(api_call POST /v2/sessions "$login_pat" "$workdir/admin-session-request.json" "$workdir/admin-session.json")"
require_2xx "$status" "create admin session" "$workdir/admin-session.json"
admin_session_id="$(jq -er '.sessionId' "$workdir/admin-session.json")"
admin_token="$(jq -er '.sessionToken' "$workdir/admin-session.json")"

status="$(api_call GET "/v2/sessions/$admin_session_id" "$admin_token" "" "$workdir/admin-session-details.json")"
require_2xx "$status" "read admin session" "$workdir/admin-session-details.json"
organization_id="$(jq -er '.session.factors.user.organizationId' "$workdir/admin-session-details.json")"

jq -n --arg origin "${SHIGUANG_PUBLIC_ORIGIN%/}" '
  {
    name:"Feishu",
    clientId:env.FEISHU_APP_ID,
    clientSecret:env.FEISHU_APP_SECRET,
    authorizationEndpoint:($origin + "/api/auth/providers/feishu/authorize"),
    tokenEndpoint:($origin + "/api/auth/providers/feishu/token"),
    userEndpoint:($origin + "/api/auth/providers/feishu/userinfo"),
    scopes:[],
    idAttribute:"sub",
    providerOptions:{
      isLinkingAllowed:true,
      isCreationAllowed:true,
      isAutoCreation:false,
      isAutoUpdate:false
    },
    usePkce:false
  }' > "$workdir/provider-request.json"

if [ -n "$existing_id" ]; then
  status="$(api_call PUT "/management/v1/idps/oauth/$existing_id" "$admin_token" "$workdir/provider-request.json" "$workdir/provider.json" "$organization_id")"
  require_2xx "$status" "update Feishu identity provider" "$workdir/provider.json"
  provider_id="$existing_id"
else
  status="$(api_call POST /management/v1/idps/oauth "$admin_token" "$workdir/provider-request.json" "$workdir/provider.json" "$organization_id")"
  require_2xx "$status" "create Feishu identity provider" "$workdir/provider.json"
  provider_id="$(jq -er '.id' "$workdir/provider.json")"
fi

jq -n --arg idpId "$provider_id" '{idpId:$idpId,ownerType:"IDP_OWNER_TYPE_ORG"}' \
  > "$workdir/activate-request.json"
status="$(api_call POST /management/v1/policies/login/idps "$admin_token" "$workdir/activate-request.json" "$workdir/activate.json" "$organization_id")"
case "$status" in
  2??|409) ;;
  400)
    if ! grep -qi 'already\|exist' "$workdir/activate.json"; then
      require_2xx "$status" "activate Feishu identity provider" "$workdir/activate.json"
    fi
    ;;
  *) require_2xx "$status" "activate Feishu identity provider" "$workdir/activate.json" ;;
esac

umask 077
{
  echo "# Generated by bootstrap-feishu-idp.sh. This ID is not a credential."
  printf 'FEISHU_IDP_ID=%s\n' "$provider_id"
  printf 'FEISHU_APP_ID=%s\n' "$FEISHU_APP_ID"
} > "$OUTPUT_FILE"

unset FEISHU_APP_SECRET ZITADEL_ADMIN_PASSWORD login_pat
echo "Feishu identity provider $provider_id is active for organization $organization_id."
echo "Restart auth-service after confirming the Feishu redirect URL: https://$PUBLIC_HOST/idps/callback"
