#!/bin/sh
set -eu

ZITADEL_ENV_FILE="${ZITADEL_ENV_FILE:-/volume1/docker/zitadel/.env}"
OUTPUT_FILE="${OUTPUT_FILE:-/volume1/docker/shiguang-auth/source/deploy/zitadel-oidc.env}"
API_URL="${ZITADEL_API_URL:-http://100.87.115.78:8080}"
PUBLIC_HOST="${ZITADEL_PUBLIC_HOST:-sso.shiguanglab.com}"
ADMIN_LOGIN_NAME="${ZITADEL_ADMIN_LOGIN_NAME:-admin@zitadel.local}"
LOGIN_PAT_FILE="${ZITADEL_LOGIN_PAT_FILE:-/volume1/docker/zitadel/data/bootstrap/login-client.pat}"

if [ -s "$OUTPUT_FILE" ] && [ "${FORCE_BOOTSTRAP:-0}" != "1" ]; then
  echo "ZITADEL OIDC application is already bootstrapped."
  exit 0
fi
if [ ! -r "$ZITADEL_ENV_FILE" ]; then
  echo "Cannot read $ZITADEL_ENV_FILE" >&2
  exit 1
fi
if [ ! -r "$LOGIN_PAT_FILE" ]; then
  echo "Cannot read $LOGIN_PAT_FILE" >&2
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

  if [ -n "$body_file" ]; then
    if [ -n "$token" ]; then
      status="$(curl -sS -o "$output_file" -w '%{http_code}' \
        -X "$method" "$API_URL$path" \
        -H "Host: $PUBLIC_HOST" \
        -H "X-Forwarded-Proto: https" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $token" \
        --data-binary "@$body_file")"
    else
      status="$(curl -sS -o "$output_file" -w '%{http_code}' \
        -X "$method" "$API_URL$path" \
        -H "Host: $PUBLIC_HOST" \
        -H "X-Forwarded-Proto: https" \
        -H "Content-Type: application/json" \
        --data-binary "@$body_file")"
    fi
  else
    status="$(curl -sS -o "$output_file" -w '%{http_code}' \
      -X "$method" "$API_URL$path" \
      -H "Host: $PUBLIC_HOST" \
      -H "X-Forwarded-Proto: https" \
      -H "Authorization: Bearer $token")"
  fi
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
organization_id="$(jq -er '.details.resourceOwner' "$workdir/admin-session.json")"
api_request GET "/v2/sessions/$admin_session_id" "$admin_session_token" "" "$workdir/admin-session-details.json"
organization_id="$(jq -er '.session.factors.user.organizationId' "$workdir/admin-session-details.json")"

jq -n \
  --arg organizationId "$organization_id" \
  '{organizationId:$organizationId,name:"Shiguang Platform",projectRoleAssertion:true}' \
  > "$workdir/project-request.json"
api_request POST /zitadel.project.v2.ProjectService/CreateProject "$admin_session_token" "$workdir/project-request.json" "$workdir/project.json"
project_id="$(jq -er '.projectId' "$workdir/project.json")"

jq -n \
  --arg projectId "$project_id" \
  '{
    projectId:$projectId,
    name:"Unified Web Session",
    oidcConfiguration:{
      redirectUris:["https://shiguanglab.com/api/auth/oidc/callback"],
      responseTypes:["OIDC_RESPONSE_TYPE_CODE"],
      grantTypes:["OIDC_GRANT_TYPE_AUTHORIZATION_CODE","OIDC_GRANT_TYPE_REFRESH_TOKEN"],
      applicationType:"OIDC_APPLICATION_TYPE_WEB",
      authMethodType:"OIDC_AUTH_METHOD_TYPE_BASIC",
      postLogoutRedirectUris:["https://shiguanglab.com/"],
      version:"OIDC_VERSION_1_0",
      developmentMode:false,
      accessTokenType:"OIDC_TOKEN_TYPE_BEARER",
      idTokenUserinfoAssertion:true,
      loginVersion:{loginV2:{baseUri:"https://shiguanglab.com"}}
    }
  }' > "$workdir/application-request.json"
api_request POST /zitadel.application.v2.ApplicationService/CreateApplication "$admin_session_token" "$workdir/application-request.json" "$workdir/application.json"

client_id="$(jq -er '.oidcConfiguration.clientId' "$workdir/application.json")"
client_secret="$(jq -er '.oidcConfiguration.clientSecret' "$workdir/application.json")"
umask 077
{
  printf 'OIDC_CLIENT_ID=%s\n' "$client_id"
  printf 'OIDC_CLIENT_SECRET=%s\n' "$client_secret"
  printf 'ZITADEL_PROJECT_ID=%s\n' "$project_id"
  printf 'ZITADEL_APPLICATION_ID=%s\n' "$(jq -er '.applicationId' "$workdir/application.json")"
} > "$OUTPUT_FILE"

api_request DELETE "/v2/sessions/$admin_session_id" "$admin_session_token" "" "$workdir/delete-session.json"
echo "Created the Shiguang Platform OIDC application."
