#!/usr/bin/env bash
# =============================================================================
# l3-dynamic-secrets-database.sh — Vault: Dynamic database credentials engine
#
# Dynamic secrets are generated on-demand and automatically expire (TTL-based).
# Each consumer gets unique credentials — no shared passwords, full audit trail.
#
# Supported databases: PostgreSQL, MySQL, MongoDB, MSSQL, Cassandra, Redis, etc.
#
# Flow:
#   1. Enable database secrets engine
#   2. Configure connection to target database (root credentials stored in Vault)
#   3. Define roles with SQL templates for credential creation
#   4. Applications request credentials at runtime — Vault creates DB users
#   5. When lease expires, Vault revokes the credentials automatically
#
# Usage:
#   export VAULT_ADDR=http://127.0.0.1:8200
#   export VAULT_TOKEN=dev-root-token
#   export DB_HOST=postgres.internal
#   export DB_ROOT_PASSWORD=root-password
#   ./l3-dynamic-secrets-database.sh
#
# Prerequisites:
#   - vault CLI, psql CLI
#   - PostgreSQL reachable from Vault server
#   - Vault database secrets engine plugin (bundled in Vault binary)
# =============================================================================
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-myapp}"
DB_ROOT_USER="${DB_ROOT_USER:-postgres}"
DB_ROOT_PASSWORD="${DB_ROOT_PASSWORD:-postgres}"
MOUNT_PATH="database"

export VAULT_ADDR VAULT_TOKEN

log()  { echo; echo "==> $*"; }
cmd()  { echo "    \$ $*"; eval "$@"; }

# =============================================================================
# 1. Enable the database secrets engine
# =============================================================================
log "Step 1: Enable database secrets engine at path '${MOUNT_PATH}/'"
vault secrets enable -path=${MOUNT_PATH} database 2>/dev/null || \
    echo "    (already enabled — continuing)"

# =============================================================================
# 2. Configure PostgreSQL connection
# Vault stores the root credentials and uses them to create/revoke dynamic users
# =============================================================================
log "Step 2: Configure PostgreSQL database connection"

cmd "vault write ${MOUNT_PATH}/config/myapp-postgres \
    plugin_name=postgresql-database-plugin \
    allowed_roles='myapp-readonly,myapp-readwrite,myapp-admin' \
    connection_url='postgresql://{{username}}:{{password}}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable' \
    username='${DB_ROOT_USER}' \
    password='${DB_ROOT_PASSWORD}' \
    password_authentication=scram-sha-256"

# Rotate the root credentials immediately — Vault generates a new password
# that only Vault knows. This prevents humans from using root DB creds directly.
log "Rotating root credentials (Vault takes ownership of root password):"
cmd "vault write -force ${MOUNT_PATH}/rotate-root/myapp-postgres"

# =============================================================================
# 3. Create roles — each role defines SQL for user creation and TTLs
# =============================================================================
log "Step 3: Create database roles"

# Role: read-only (for app replicas, reporting services)
# TTL: 1 hour default, max 24 hours
cmd "vault write ${MOUNT_PATH}/roles/myapp-readonly \
    db_name=myapp-postgres \
    default_ttl=1h \
    max_ttl=24h \
    creation_statements=\"
        CREATE ROLE \\\"{{name}}\\\" WITH
            LOGIN
            PASSWORD '{{password}}'
            VALID UNTIL '{{expiration}}';
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO \\\"{{name}}\\\";
        GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO \\\"{{name}}\\\";
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
            GRANT SELECT ON TABLES TO \\\"{{name}}\\\";
    \" \
    revocation_statements=\"
        REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \\\"{{name}}\\\";
        REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM \\\"{{name}}\\\";
        REVOKE USAGE ON SCHEMA public FROM \\\"{{name}}\\\";
        DROP ROLE IF EXISTS \\\"{{name}}\\\";
    \""

# Role: read-write (for application backends)
cmd "vault write ${MOUNT_PATH}/roles/myapp-readwrite \
    db_name=myapp-postgres \
    default_ttl=2h \
    max_ttl=12h \
    creation_statements=\"
        CREATE ROLE \\\"{{name}}\\\" WITH
            LOGIN
            PASSWORD '{{password}}'
            VALID UNTIL '{{expiration}}';
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \\\"{{name}}\\\";
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO \\\"{{name}}\\\";
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
            GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO \\\"{{name}}\\\";
    \" \
    revocation_statements=\"
        REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \\\"{{name}}\\\";
        REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM \\\"{{name}}\\\";
        DROP ROLE IF EXISTS \\\"{{name}}\\\";
    \""

# Role: admin (for migrations, schema changes — short TTL)
cmd "vault write ${MOUNT_PATH}/roles/myapp-admin \
    db_name=myapp-postgres \
    default_ttl=30m \
    max_ttl=1h \
    creation_statements=\"
        CREATE ROLE \\\"{{name}}\\\" WITH
            LOGIN
            PASSWORD '{{password}}'
            VALID UNTIL '{{expiration}}';
        GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO \\\"{{name}}\\\";
        GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \\\"{{name}}\\\";
        GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO \\\"{{name}}\\\";
        ALTER USER \\\"{{name}}\\\" CREATEDB;
    \" \
    revocation_statements=\"
        REVOKE ALL PRIVILEGES ON DATABASE ${DB_NAME} FROM \\\"{{name}}\\\";
        REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \\\"{{name}}\\\";
        DROP ROLE IF EXISTS \\\"{{name}}\\\";
    \""

log "Configured roles:"
cmd "vault list ${MOUNT_PATH}/roles"

# =============================================================================
# 4. Generate dynamic credentials
# =============================================================================
log "Step 4: Generate dynamic credentials for 'myapp-readonly' role"
cmd "vault read ${MOUNT_PATH}/creds/myapp-readonly"

log "Generate credentials for 'myapp-readwrite' role:"
CREDS=$(vault read -format=json ${MOUNT_PATH}/creds/myapp-readwrite)
echo "    Credentials JSON:"
echo "${CREDS}" | jq '{username: .data.username, password: .data.password, lease_id: .lease_id, lease_duration: .lease_duration}'

# Extract for use in a script
DB_USER=$(echo "${CREDS}" | jq -r '.data.username')
DB_PASS=$(echo "${CREDS}" | jq -r '.data.password')
LEASE_ID=$(echo "${CREDS}" | jq -r '.lease_id')

log "Dynamic user created: ${DB_USER} (lease: ${LEASE_ID})"

# =============================================================================
# 5. Renew lease before expiry
# =============================================================================
log "Step 5: Renew lease (extend TTL before it expires)"
cmd "vault lease renew -increment=2h ${LEASE_ID}" || \
    echo "    (lease renewal demo — lease may already be expired in test env)"

# =============================================================================
# 6. Revoke lease immediately (e.g., on app shutdown or security incident)
# =============================================================================
log "Step 6: Revoke lease immediately (drops DB user)"
cmd "vault lease revoke ${LEASE_ID}" || \
    echo "    (lease revoke demo — lease may already be expired)"

# Revoke ALL leases for a prefix (e.g., emergency revocation of all app creds)
log "Emergency: Revoke ALL credentials for myapp-readwrite role:"
cmd "vault lease revoke -prefix ${MOUNT_PATH}/creds/myapp-readwrite" || true

# =============================================================================
# 7. Vault policies for dynamic DB access (least-privilege)
# =============================================================================
log "Step 7: Create Vault policy for application to read DB creds"

vault policy write myapp-db-policy - <<'EOF'
# Allow myapp service account to read dynamic DB credentials (readonly role only)
path "database/creds/myapp-readonly" {
  capabilities = ["read"]
}

# Allow renewing its own leases
path "sys/leases/renew" {
  capabilities = ["update"]
}

# Allow revoking its own leases
path "sys/leases/revoke" {
  capabilities = ["update"]
}
EOF

echo "    Policy 'myapp-db-policy' created."
cmd "vault policy read myapp-db-policy"

log "Dynamic secrets database demo complete."
log "Vault UI: ${VAULT_ADDR}/ui/vault/secrets/${MOUNT_PATH}/list"
