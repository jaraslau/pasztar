#!/bin/sh
set -eu

rotate=false
if [ "${1:-}" = "--rotate" ]; then
  rotate=true
  shift
fi

host="${1:-localhost:8080}"
env_file=".env"

if [ ! -f "$env_file" ]; then
  cp .env.example "$env_file"
fi

get_env() {
  awk -F= -v key="$1" '$1 == key { print substr($0, length(key) + 2); exit }' "$env_file"
}

set_env() {
  key="$1"
  value="$2"
  tmp="${env_file}.tmp"
  awk -F= -v key="$key" -v value="$value" '
    $1 == key { print key "=" value; found = 1; next }
    { print }
    END { if (!found) print key "=" value }
  ' "$env_file" > "$tmp"
  mv "$tmp" "$env_file"
}

token="$(get_env BOOTSTRAP_TOKEN || true)"
if [ -z "$token" ] || [ "$rotate" = true ]; then
  token="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
  set_env BOOTSTRAP_TOKEN "$token"
fi
set_env TRUSTED_IDENTITIES true
turn_secret="$(get_env TURN_SHARED_SECRET || true)"
if [ -z "$turn_secret" ] || [ "$turn_secret" = "change-me" ]; then
  set_env TURN_SHARED_SECRET "$(openssl rand -hex 32)"
fi

case "$host" in
  http://*|https://*) url_base="$host" ;;
  localhost*|127.0.0.1*) url_base="http://$host" ;;
  *) url_base="https://$host" ;;
esac

printf 'Bootstrap token written to %s\n' "$env_file"
printf 'Setup URL: %s/setup.html#bootstrap=%s\n' "$url_base" "$token"
