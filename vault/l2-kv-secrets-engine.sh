#!/usr/bin/env bash
# =============================================================================
# l2 - Vault KV v2: write, read, patch, version, soft-delete, undelete, destroy, metadata
#
#   export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root-token
#   ./l2-kv-secrets-engine.sh
#
# KV v2 keeps versions of every secret: `put` replaces all fields (new version), `patch` changes some fields (new
# version), `delete` is a soft delete you can undo, `destroy` wipes a version for good.
# Re-runnable: it starts by removing its own demo secrets. Needs: vault, jq, openssl; a dev server from l1.
# =============================================================================
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

MOUNT="kv-apps"           # the dev server already has `secret/`; this adds a second mount
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

require vault "https://developer.hashicorp.com/vault/downloads"; require jq; require openssl
wait_for_vault

log "Step 1: enable KV v2 at ${MOUNT}/ and set defaults"
ensure_mount "${MOUNT}" kv -version=2
run vault write "${MOUNT}/config" max_versions=10 delete_version_after=720h
vault secrets list -detailed | grep -E "^(Path|${MOUNT}/)" | sed 's/^/    /'

# start from a clean slate so the version numbers below are always 1, 2, 3
if vault kv metadata get "${MOUNT}/myapp/database" >/dev/null 2>&1; then
  vault kv metadata delete "${MOUNT}/myapp/database"
fi

log "Step 2: write secrets (version 1)"
run vault kv put "${MOUNT}/myapp/database" host=postgres.internal port=5432 username=myapp_user \
  password=initial-demo-password dbname=myapp
run vault kv put "${MOUNT}/myapp/api-keys" payment_key=example-payment-key-not-real mail_key=example-mail-key-not-real
# a file as the value: `key=@path` reads the file's contents
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=myapp.example.internal" \
  -keyout "${WORK}/tls.key" -out "${WORK}/tls.crt" 2>/dev/null
run vault kv put "${MOUNT}/myapp/tls" cert=@"${WORK}/tls.crt" key=@"${WORK}/tls.key"
assert_eq "tls cert round-trips through @file" "$(vault kv get -field=cert "${MOUNT}/myapp/tls")" "$(cat "${WORK}/tls.crt")"

log "Step 3: read"
run vault kv get "${MOUNT}/myapp/database"
run vault kv get -format=json "${MOUNT}/myapp/database" | jq '.data.data'
assert_eq "username" "$(vault kv get -field=username "${MOUNT}/myapp/database")" "myapp_user"

log "Step 4: patch (version 2) then put (version 3)"
run vault kv patch "${MOUNT}/myapp/database" password=rotated-demo-password-v2
assert_eq "patch kept the other fields" "$(vault kv get -field=host "${MOUNT}/myapp/database")" "postgres.internal"
run vault kv put "${MOUNT}/myapp/database" host=postgres.internal port=5432 username=myapp_user \
  password=rotated-demo-password-v3 dbname=myapp
assert_eq "current version" "$(vault kv metadata get -format=json "${MOUNT}/myapp/database" | jq -r '.data.current_version')" "3"

log "Step 5: versions"
run vault kv metadata get "${MOUNT}/myapp/database"
assert_eq "version 1 still readable" "$(vault kv get -version=1 -field=password "${MOUNT}/myapp/database")" "initial-demo-password"

log "Step 6: list"
run vault kv list "${MOUNT}/myapp"
run vault kv list "${MOUNT}/"

log "Step 7: soft delete version 1, then undelete"
run vault kv delete -versions=1 "${MOUNT}/myapp/database"
deleted="$(vault kv metadata get -format=json "${MOUNT}/myapp/database" | jq -r '.data.versions["1"].deletion_time')"
[[ -n "${deleted}" ]] || die "version 1 was not marked deleted"
run vault kv undelete -versions=1 "${MOUNT}/myapp/database"
assert_eq "version 1 is back" "$(vault kv get -version=1 -field=username "${MOUNT}/myapp/database")" "myapp_user"

log "Step 8: destroy version 1 (irreversible)"
run vault kv destroy -versions=1 "${MOUNT}/myapp/database"
assert_eq "version 1 destroyed" "$(vault kv metadata get -format=json "${MOUNT}/myapp/database" | jq -r '.data.versions["1"].destroyed')" "true"

log "Step 9: per-path metadata"
run vault kv metadata put -max-versions=5 -delete-version-after=24h \
  -custom-metadata=owner=platform-team -custom-metadata=environment=production "${MOUNT}/myapp/database"
assert_eq "custom metadata" "$(vault kv metadata get -format=json "${MOUNT}/myapp/database" | jq -r '.data.custom_metadata.owner')" "platform-team"

log "Step 10: remove every version and the metadata of the demo secrets"
for path in database api-keys tls; do
  run vault kv metadata delete "${MOUNT}/myapp/${path}"
done

log "KV v2 demo complete. UI: ${VAULT_ADDR}/ui/vault/secrets/${MOUNT}/list"
