#!/bin/sh

set -eu

origin=${AUTH_PUBLIC_ORIGIN:-https://shiguanglab.com}
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/shiguang-auth-portal-smoke.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

check_unauthenticated_json() {
  name=$1
  path=$2
  expected_body=$3
  headers="$work_dir/$name.headers"
  body="$work_dir/$name.body"

  status=$(curl --silent --show-error \
    --connect-timeout "${AUTH_SMOKE_CONNECT_TIMEOUT:-5}" \
    --max-time "${AUTH_SMOKE_MAX_TIME:-15}" \
    --dump-header "$headers" \
    --output "$body" \
    --write-out '%{http_code}' \
    "$origin$path")

  if [ "$status" != "401" ]; then
    printf '%s\n' "[auth-portal-smoke] $path returned HTTP $status; expected 401" >&2
    exit 1
  fi
  if ! grep -Eiq '^content-type:[[:space:]]*application/json' "$headers"; then
    printf '%s\n' "[auth-portal-smoke] $path did not return JSON" >&2
    exit 1
  fi
  if ! grep -Fq "$expected_body" "$body"; then
    printf '%s\n' "[auth-portal-smoke] $path returned an unexpected response contract" >&2
    exit 1
  fi

  printf '%s\n' "[auth-portal-smoke] $path: 401 JSON contract pass"
}

check_unauthenticated_json session /api/auth/session '"authenticated":false'
check_unauthenticated_json portal /api/auth/portal/access '"error":"unauthorized"'

printf '%s\n' '[auth-portal-smoke] production Portal API routes pass'
