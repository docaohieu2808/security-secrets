#!/usr/bin/env bash
# =============================================================================
# l2-kv-secrets-engine.sh — Vault: KV v2 secrets engine CRUD operations
#
# Demonstrates full lifecycle of KV (Key-Value) v2 secrets engine:
#   - Enable the engine at a custom mount path
#   - Write, read, update, list, and delete secrets
#   - Access specific versions, compare diffs between versions
#   - Permanently destroy versions and metadata
#   - Configure max versions and delete-version-after TTL
#
# Usage:
#   export VAULT_ADDR=http://127.0.0.1:8200
#   export VAULT_TOKEN=dev-root-token
#   ./l2-kv-secrets-engine.sh
#
# Prerequisites:
#   - vault CLI installed: https://developer.hashicorp.com/vault/downloads
#   - Vault server running (see l1-dev-server-docker-compose.yml)
# =============================================================================
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"
MOUNT_PATH="secret"           # KV engine mount path (dev server pre-mounts this)
ALT_MOUNT="kv-apps"           # Custom mount path example

export VAULT_ADDR VAULT_TOKEN

log()  { echo; echo "==> $*"; }
cmd()  { echo "    \$ $*"; eval "$@"; }

# =============================================================================
# 1. Enable KV v2 engine at a custom path
# =============================================================================
log "Step 1: Enable KV v2 secrets engine at path '${ALT_MOUNT}/'"
# Dev server already has 'secret/' mounted — we create an additional mount
cmd "vault secrets enable -path=${ALT_MOUNT} -version=2 kv" || \
    echo "    (already enabled — continuing)"

# Configure max versions to retain per secret path
cmd "vault write ${ALT_MOUNT}/config max_versions=10 delete_version_after=720h"

# List all enabled secrets engines
log "Enabled secrets engines:"
cmd "vault secrets list -detailed"

# =============================================================================
# 2. Write secrets — KV v2 uses 'vault kv put' not 'vault write'
# =============================================================================
log "Step 2: Write secrets (creates version 1)"

# Write a database credential set
cmd "vault kv put ${ALT_MOUNT}/myapp/database \
    host=postgres.internal \
    port=5432 \
    username=myapp_user \
    password=super-secret-db-pass \
    dbname=myapp_production"

# Write API credentials
cmd "vault kv put ${ALT_MOUNT}/myapp/api-keys \
    stripe_secret=sk_live_xxxxxxxxxxxx \
    stripe_publishable=pk_live_xxxxxxxxxxxx \
    sendgrid_api_key=SG.xxxxxxxxxx"

# Write with JSON input (useful for complex values)
cmd "vault kv put ${ALT_MOUNT}/myapp/tls \
    cert=@/dev/null \
    key=@/dev/null" || true   # placeholder — replace /dev/null with real paths

# =============================================================================
# 3. Read secrets
# =============================================================================
log "Step 3: Read secrets"

# Read latest version
cmd "vault kv get ${ALT_MOUNT}/myapp/database"

# Read as JSON (useful in scripts)
cmd "vault kv get -format=json ${ALT_MOUNT}/myapp/database | jq '.data.data'"

# Read a specific field only
cmd "vault kv get -field=username ${ALT_MOUNT}/myapp/database"

# =============================================================================
# 4. Update secrets — creates a new version, old version retained
# =============================================================================
log "Step 4: Update secrets (creates version 2)"

# patch: only updates specified fields, leaves others unchanged (KV v2 only)
cmd "vault kv patch ${ALT_MOUNT}/myapp/database \
    password=new-rotated-password-v2"

# put: replaces ALL fields (version 3 if used after patch above)
cmd "vault kv put ${ALT_MOUNT}/myapp/database \
    host=postgres.internal \
    port=5432 \
    username=myapp_user \
    password=new-rotated-password-v3 \
    dbname=myapp_production"

# =============================================================================
# 5. Version management
# =============================================================================
log "Step 5: Version management"

# Show metadata — lists all versions with creation time and deletion status
cmd "vault kv metadata get ${ALT_MOUNT}/myapp/database"

# Read a specific version (version 1 — the original)
cmd "vault kv get -version=1 ${ALT_MOUNT}/myapp/database"

# =============================================================================
# 6. List secrets
# =============================================================================
log "Step 6: List secrets at path"
cmd "vault kv list ${ALT_MOUNT}/myapp"
cmd "vault kv list ${ALT_MOUNT}/"

# =============================================================================
# 7. Soft-delete and undelete specific versions
# =============================================================================
log "Step 7: Soft-delete version 1 (recoverable)"

# Soft delete marks version as deleted but data is retained and recoverable
cmd "vault kv delete -versions=1 ${ALT_MOUNT}/myapp/database"

# Verify version 1 is now marked deleted in metadata
cmd "vault kv metadata get ${ALT_MOUNT}/myapp/database"

# Undelete (restore) version 1
cmd "vault kv undelete -versions=1 ${ALT_MOUNT}/myapp/database"
log "Restored version 1:"
cmd "vault kv get -version=1 ${ALT_MOUNT}/myapp/database"

# =============================================================================
# 8. Permanently destroy a version (irrecoverable)
# =============================================================================
log "Step 8: Permanently destroy version 1 (irrecoverable — data wiped)"
cmd "vault kv destroy -versions=1 ${ALT_MOUNT}/myapp/database"
cmd "vault kv metadata get ${ALT_MOUNT}/myapp/database"

# =============================================================================
# 9. Update metadata config for a specific secret path
# =============================================================================
log "Step 9: Configure per-path metadata"
cmd "vault kv metadata put \
    -max-versions=5 \
    -delete-version-after=24h \
    -custom-metadata=owner=platform-team \
    -custom-metadata=environment=production \
    ${ALT_MOUNT}/myapp/database"

# =============================================================================
# 10. Delete all versions and metadata (full cleanup)
# =============================================================================
log "Step 10: Delete all versions + metadata for a path (full wipe)"
cmd "vault kv metadata delete ${ALT_MOUNT}/myapp/api-keys"

log "KV v2 CRUD demo complete."
log "Vault UI: ${VAULT_ADDR}/ui/vault/secrets/${ALT_MOUNT}/list"
