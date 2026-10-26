#!/usr/bin/env bash
# =============================================================================
# l1 - SonarQube first-run bootstrap
#
# A new SonarQube accepts admin/admin. This script waits until the server is UP, replaces that password,
# and prints ONE analysis token to stdout (everything else goes to stderr), so it can be captured:
#
#   export SONAR_ADMIN_PASSWORD='choose-a-long-one'
#   SONAR_TOKEN="$(./l1-bootstrap.sh)"
#
# Env: SONAR_HOST_URL (default http://localhost:9000), SONAR_ADMIN_PASSWORD (required),
#      SONAR_TOKEN_NAME (default lab-ci), SONAR_TOKEN_TYPE (default GLOBAL_ANALYSIS_TOKEN)
# Idempotent: if the password was already changed it uses the new one; a token with the same name is
# revoked first, because SonarQube refuses duplicate names.
# =============================================================================
set -euo pipefail

SONAR_HOST_URL="${SONAR_HOST_URL:-http://localhost:9000}"
TOKEN_NAME="${SONAR_TOKEN_NAME:-lab-ci}"
TOKEN_TYPE="${SONAR_TOKEN_TYPE:-GLOBAL_ANALYSIS_TOKEN}"
: "${SONAR_ADMIN_PASSWORD:?set SONAR_ADMIN_PASSWORD}"

log() { printf '[bootstrap] %s\n' "$*" >&2; }

log "waiting for ${SONAR_HOST_URL} ..."
for _ in $(seq 1 60); do
  if curl -sf "${SONAR_HOST_URL}/api/system/status" | grep -q '"status":"UP"'; then break; fi
  sleep 5
done
curl -sf "${SONAR_HOST_URL}/api/system/status" | grep -q '"status":"UP"' || { log "server never reached UP"; exit 1; }

# Current API: login + password + previousPassword. Returns 204 on success, 400/401 if already changed.
code="$(curl -s -o /dev/null -w '%{http_code}' -u "admin:admin" -X POST "${SONAR_HOST_URL}/api/users/change_password" \
  --data-urlencode "login=admin" --data-urlencode "previousPassword=admin" --data-urlencode "password=${SONAR_ADMIN_PASSWORD}")"
case "${code}" in
  204) log "default admin password replaced" ;;
  400|401) log "default password already changed (HTTP ${code}); using SONAR_ADMIN_PASSWORD" ;;
  *) log "change_password returned HTTP ${code}"; exit 1 ;;
esac

# Revoke a leftover token of the same name (ignore 'not found'), then mint a new one.
curl -s -o /dev/null -u "admin:${SONAR_ADMIN_PASSWORD}" -X POST "${SONAR_HOST_URL}/api/user_tokens/revoke" \
  --data-urlencode "name=${TOKEN_NAME}"
response="$(curl -sf -u "admin:${SONAR_ADMIN_PASSWORD}" -X POST "${SONAR_HOST_URL}/api/user_tokens/generate" \
  --data-urlencode "name=${TOKEN_NAME}" --data-urlencode "type=${TOKEN_TYPE}")"
token="$(printf '%s' "${response}" | jq -r '.token')"
[[ -n "${token}" && "${token}" != null ]] || { log "no token in response"; exit 1; }
log "token '${TOKEN_NAME}' created"
printf '%s\n' "${token}"
