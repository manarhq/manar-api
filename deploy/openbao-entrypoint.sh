#!/bin/sh
# Local-dev OpenBao with persistent file storage (see deploy/docker-compose.yml).
#
# Every container start: start the server, initialize it once (1 key share),
# unseal it, and make sure the well-known dev token exists. Idempotent.
#
# The unseal key and the initial root token are written to /manar/keys, a bind
# mount of ~/.manar-openbao on the host (outside every git repo, 0700/0600,
# owned by the host user). Nothing secret is printed. The apps keep using
# BAO_TOKEN (manar-dev-root-token), created here as an orphan root-policy token,
# exactly the token -dev mode used to hand out, so no .env changes.
set -eu

KEYS=/manar/keys
APP_TOKEN=$BAO_TOKEN

cat > /openbao/config/manar.hcl <<'EOF'
storage "file" {
  path = "/openbao/file"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
EOF
chown -R openbao:openbao /openbao/config /openbao/file

su-exec openbao bao server -config=/openbao/config/manar.hcl &
server=$!
trap 'kill -TERM "$server" 2>/dev/null' TERM INT

# `bao status`: 0 unsealed, 2 sealed, 1 not reachable yet.
status() { rc=0; bao status >/dev/null 2>&1 || rc=$?; echo "$rc"; }
while [ "$(status)" = 1 ]; do sleep 0.5; done

chmod 700 "$KEYS"
owner=$(stat -c %u:%g "$KEYS")

if bao status 2>/dev/null | grep -Eq '^Initialized +false'; then
  echo "openbao-entrypoint: first start, initializing (keys go to the host's ~/.manar-openbao)"
  umask 077
  out=$(bao operator init -key-shares=1 -key-threshold=1)
  # No trailing newline: `key=@file` below sends the file content verbatim.
  printf '%s\n' "$out" | awk '/^Unseal Key 1:/ {printf "%s", $NF}' > "$KEYS/unseal-key"
  printf '%s\n' "$out" | awk '/^Initial Root Token:/ {printf "%s", $NF}' > "$KEYS/root-token"
  out=
  chown "$owner" "$KEYS/unseal-key" "$KEYS/root-token"
  chmod 600 "$KEYS/unseal-key" "$KEYS/root-token"
fi

if [ "$(status)" = 2 ]; then
  if [ ! -s "$KEYS/unseal-key" ]; then
    echo "openbao-entrypoint: storage is initialized but $KEYS/unseal-key is missing." >&2
    echo "  To start over (wipes OpenBao): docker compose -f deploy/docker-compose.yml rm -sf openbao && docker volume rm deploy_manar-openbao-data" >&2
    kill -TERM "$server"
    exit 1
  fi
  bao write sys/unseal key=@"$KEYS/unseal-key" >/dev/null
fi

ROOT=$(cat "$KEYS/root-token")
if ! bao token lookup >/dev/null 2>&1; then
  BAO_TOKEN=$ROOT bao token create -id="$APP_TOKEN" -policy=root -orphan >/dev/null
fi
# -dev mode mounted kv-v2 at secret/ by itself; keep that so nothing else changes.
if ! bao secrets list 2>/dev/null | grep -q '^secret/'; then
  bao secrets enable -path=secret kv-v2 >/dev/null
fi
ROOT=
echo "openbao-entrypoint: unsealed and ready"

wait "$server"
