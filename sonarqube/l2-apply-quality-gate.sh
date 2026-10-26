#!/usr/bin/env bash
# =============================================================================
# l2 - SonarQube: create the quality gate described in l2-quality-gate-config.json
#
#   SONAR_TOKEN=<admin token> ./l2-apply-quality-gate.sh [config.json]
#
# Uses the current web API parameters: create (name), create_condition (gateName, metric, op, error),
# set_as_default (name). Re-running replaces the gate with the same name, so the file stays the source
# of truth.
# Env: SONAR_HOST_URL (default http://localhost:9000), SONAR_TOKEN (required)
# =============================================================================
set -euo pipefail

SONAR_HOST_URL="${SONAR_HOST_URL:-http://localhost:9000}"
: "${SONAR_TOKEN:?set SONAR_TOKEN to an admin token (see l1-bootstrap.sh)}"
CONFIG="${1:-$(dirname "$0")/l2-quality-gate-config.json}"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
[[ -f "${CONFIG}" ]] || { echo "no such file: ${CONFIG}" >&2; exit 1; }

api() { # <endpoint> <curl --data-urlencode args...> ; fails on any HTTP error and shows the server's explanation
  local endpoint="$1" body code; shift
  body="$(mktemp)"
  code="$(curl -sS -o "${body}" -w '%{http_code}' -u "${SONAR_TOKEN}:" -X POST "${SONAR_HOST_URL}/api/${endpoint}" "$@")"
  if [[ "${code}" != 2* ]]; then
    printf 'HTTP %s from %s: %s\n' "${code}" "${endpoint}" "$(cat "${body}")" >&2
    rm -f "${body}"
    return 1
  fi
  cat "${body}"
  rm -f "${body}"
}

name="$(jq -r '.qualityGate.name' "${CONFIG}")"
make_default="$(jq -r '.qualityGate.isDefault' "${CONFIG}")"

# Drop a previous gate of the same name. Sonar refuses to destroy the default gate, so make the built-in
# one default first (only matters on re-runs).
if curl -sf -u "${SONAR_TOKEN}:" "${SONAR_HOST_URL}/api/qualitygates/list" | jq -e --arg n "${name}" '.qualitygates[] | select(.name == $n)' >/dev/null; then
  builtin="$(curl -sf -u "${SONAR_TOKEN}:" "${SONAR_HOST_URL}/api/qualitygates/list" | jq -r '.qualitygates[] | select(.isBuiltIn) | .name' | head -1)"
  api qualitygates/set_as_default --data-urlencode "name=${builtin}" >/dev/null
  api qualitygates/destroy --data-urlencode "name=${name}" >/dev/null
  echo "removed existing gate '${name}'"
fi

api qualitygates/create --data-urlencode "name=${name}" >/dev/null
echo "created gate '${name}'"

# A new gate is not necessarily empty (current versions start it with the recommended conditions), and a second
# condition on the same metric is refused, so clear whatever came with it: the JSON file is the whole truth.
while read -r condition_id; do
  [[ -n "${condition_id}" ]] || continue
  api qualitygates/delete_condition --data-urlencode "id=${condition_id}" >/dev/null
  echo "  removed pre-existing condition ${condition_id}"
done < <(curl -sf -u "${SONAR_TOKEN}:" "${SONAR_HOST_URL}/api/qualitygates/show?name=$(jq -rn --arg n "${name}" '$n|@uri')" | jq -r '.conditions[]?.id')

while IFS=$'\t' read -r metric op error; do
  api qualitygates/create_condition --data-urlencode "gateName=${name}" \
    --data-urlencode "metric=${metric}" --data-urlencode "op=${op}" --data-urlencode "error=${error}" >/dev/null
  echo "  condition: ${metric} ${op} ${error}"
done < <(jq -r '.qualityGate.conditions[] | [.metric, .op, .error] | @tsv' "${CONFIG}")

if [[ "${make_default}" == "true" ]]; then
  api qualitygates/set_as_default --data-urlencode "name=${name}" >/dev/null
  echo "'${name}' is now the default gate"
fi
