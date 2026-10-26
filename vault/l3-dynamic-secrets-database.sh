#!/usr/bin/env bash
# =============================================================================
# l3 - Vault database secrets engine: short-lived, per-consumer PostgreSQL credentials
#
# Vault holds one privileged DB account and mints a NEW database user for every request, with a TTL. A leaked
# credential expires on its own, and the audit log says which lease created which user.
#
#   1. enable the engine, 2. give it a connection (and let it rotate the root password),
#   3. define roles = SQL templates, 4. apps read creds/<role>, 5. renew / revoke leases, 6. least-privilege policy.
#
#   docker compose -f l1-dev-server-docker-compose.yml --profile db up -d --wait     # Vault + PostgreSQL
#   DB_HOST=postgres DB_ROOT_PASSWORD=postgres DB_CHECK_HOST=127.0.0.1 DB_CHECK_PORT=15432 \
#     ROTATE_ROOT=true ./l3-dynamic-secrets-database.sh
#
# DB_HOST/DB_PORT are as seen from the Vault server (inside compose: the service name `postgres`).
# DB_CHECK_HOST/DB_CHECK_PORT are as seen from this shell, used only for the psql login check.
#
# ROTATE_ROOT=true (default false) makes Vault change the root password so that only Vault knows it. That is the
# point of the lesson, but it also means the password you exported no longer works, so a second run against the
# same database needs the new one (or a fresh container).
# Needs: vault, jq, a PostgreSQL the Vault server can reach (the `db` compose profile). psql is optional:
# if present the script proves the minted credentials really log in and that revocation removes them.
# =============================================================================
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DB_HOST="${DB_HOST:-postgres}"
DB_PORT="${DB_PORT:-5432}"
DB_CHECK_HOST="${DB_CHECK_HOST:-127.0.0.1}"
DB_CHECK_PORT="${DB_CHECK_PORT:-15432}"
DB_NAME="${DB_NAME:-myapp}"
DB_ROOT_USER="${DB_ROOT_USER:-postgres}"
: "${DB_ROOT_PASSWORD:?set DB_ROOT_PASSWORD (the PostgreSQL root/admin password)}"
ROTATE_ROOT="${ROTATE_ROOT:-false}"
DB_SSLMODE="${DB_SSLMODE:-disable}"        # dev only; use verify-full against a real server
MOUNT="database"
CONN="myapp-postgres"

require vault; require jq
wait_for_vault

log "Step 1: enable the database secrets engine at ${MOUNT}/"
ensure_mount "${MOUNT}" database

log "Step 2: connection ${CONN}"
run_secret "vault write ${MOUNT}/config/${CONN} plugin_name=postgresql-database-plugin ... username=${DB_ROOT_USER} password=***" \
  vault write "${MOUNT}/config/${CONN}" \
    plugin_name=postgresql-database-plugin \
    allowed_roles='myapp-readonly,myapp-readwrite,myapp-admin' \
    connection_url="postgresql://{{username}}:{{password}}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=${DB_SSLMODE}" \
    username="${DB_ROOT_USER}" password="${DB_ROOT_PASSWORD}" \
    password_authentication=scram-sha-256

if [[ "${ROTATE_ROOT}" == "true" ]]; then
  log "Rotating the root credentials: from now on only Vault knows the ${DB_ROOT_USER} password"
  run vault write -force "${MOUNT}/rotate-root/${CONN}"
else
  info "ROTATE_ROOT=false: Vault still uses the password you gave it. Set ROTATE_ROOT=true to hand ownership to Vault."
fi

# Role revocation. `DROP OWNED BY` removes the role's grants AND its default privileges; a bare DROP ROLE fails
# with "role cannot be dropped because some objects depend on it" as soon as ALTER DEFAULT PRIVILEGES was used.
# Open sessions are terminated first so the drop is not blocked.
REVOKE_SQL='SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '"'"'{{name}}'"'"';
DROP OWNED BY "{{name}}";
DROP ROLE IF EXISTS "{{name}}";'

CREATE_RO='CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '"'"'{{password}}'"'"' VALID UNTIL '"'"'{{expiration}}'"'"';
GRANT CONNECT ON DATABASE '"${DB_NAME}"' TO "{{name}}";
GRANT USAGE ON SCHEMA public TO "{{name}}";
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO "{{name}}";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "{{name}}";'

CREATE_RW='CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '"'"'{{password}}'"'"' VALID UNTIL '"'"'{{expiration}}'"'"';
GRANT CONNECT ON DATABASE '"${DB_NAME}"' TO "{{name}}";
GRANT USAGE ON SCHEMA public TO "{{name}}";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{{name}}";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{{name}}";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "{{name}}";'

CREATE_ADMIN='CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '"'"'{{password}}'"'"' VALID UNTIL '"'"'{{expiration}}'"'"' CREATEDB;
GRANT ALL PRIVILEGES ON DATABASE '"${DB_NAME}"' TO "{{name}}";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "{{name}}";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "{{name}}";'

log "Step 3: roles (the SQL templates Vault runs)"
run vault write "${MOUNT}/roles/myapp-readonly" db_name="${CONN}" default_ttl=1h max_ttl=24h \
  creation_statements="${CREATE_RO}" revocation_statements="${REVOKE_SQL}"
run vault write "${MOUNT}/roles/myapp-readwrite" db_name="${CONN}" default_ttl=2h max_ttl=12h \
  creation_statements="${CREATE_RW}" revocation_statements="${REVOKE_SQL}"
run vault write "${MOUNT}/roles/myapp-admin" db_name="${CONN}" default_ttl=30m max_ttl=1h \
  creation_statements="${CREATE_ADMIN}" revocation_statements="${REVOKE_SQL}"
run vault list "${MOUNT}/roles"

log "Step 4: ask for credentials"
CREDS="$(vault read -format=json "${MOUNT}/creds/myapp-readwrite")"
DB_USER="$(jq -r '.data.username' <<<"${CREDS}")"
DB_PASS="$(jq -r '.data.password' <<<"${CREDS}")"
LEASE_ID="$(jq -r '.lease_id' <<<"${CREDS}")"
jq '{username: .data.username, lease_id: .lease_id, lease_duration: .lease_duration}' <<<"${CREDS}"   # password deliberately not printed
info "dynamic user created: ${DB_USER}"

have_psql=false
if command -v psql >/dev/null; then have_psql=true; fi
db_login() { PGPASSWORD="$1" psql "host=${DB_CHECK_HOST} port=${DB_CHECK_PORT} dbname=${DB_NAME} user=$2 sslmode=${DB_SSLMODE}" -tAc 'select current_user' 2>/dev/null; }
if [[ "${have_psql}" == "true" ]]; then
  assert_eq "the minted credentials log in as the new user" "$(db_login "${DB_PASS}" "${DB_USER}")" "${DB_USER}"
else
  info "psql not installed: skipping the login check"
fi

log "Step 5: renew the lease"
run vault lease renew -increment=2h "${LEASE_ID}"

log "Step 6: revoke the lease: Vault drops the database user"
run vault lease revoke "${LEASE_ID}"
if [[ "${have_psql}" == "true" ]]; then
  # revocation is queued and runs asynchronously, so give it a few seconds
  revoked=false
  for _ in $(seq 1 15); do
    if ! db_login "${DB_PASS}" "${DB_USER}" >/dev/null; then revoked=true; break; fi
    sleep 1
  done
  [[ "${revoked}" == "true" ]] || die "revoked user ${DB_USER} can still log in after 15s"
  info "ok: the revoked user can no longer log in"
fi

log "Emergency stop: revoke every lease under a role"
run vault read "${MOUNT}/creds/myapp-readonly" >/dev/null
run vault lease revoke -prefix "${MOUNT}/creds/myapp-readonly"

log "Step 7: least-privilege policy for the application"
vault policy write myapp-db-policy - <<'POLICY'
# read dynamic credentials of the read-only role, nothing else
path "database/creds/myapp-readonly" {
  capabilities = ["read"]
}
# manage its own leases (renew / revoke by lease id)
path "sys/leases/renew" {
  capabilities = ["update"]
}
path "sys/leases/revoke" {
  capabilities = ["update"]
}
POLICY
run vault policy read myapp-db-policy

log "Dynamic secrets demo complete. UI: ${VAULT_ADDR}/ui/vault/secrets/${MOUNT}/list"
