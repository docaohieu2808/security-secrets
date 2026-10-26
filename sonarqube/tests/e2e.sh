#!/usr/bin/env bash
# SonarQube labs end to end, as CI does it. The stack from l1 must be up and healthy:
#   docker compose -f sonarqube/l1-docker-compose-sonarqube.yml up -d --wait
#   SONAR_ADMIN_PASSWORD='Choose-A-Long-0ne!' sonarqube/tests/e2e.sh   # >= 12 chars: upper, lower, digit, special
# Proves: bootstrap (password change + token), quality gate import with the current API parameters, a clean project
# passes the gate, a project with deliberate problems FAILS it and the script's exit code says so.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SONAR_ADMIN_PASSWORD:?set SONAR_ADMIN_PASSWORD}"
export SONAR_HOST_URL="${SONAR_HOST_URL:-http://localhost:9000}"
fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS %s\n' "$*"; }

SONAR_TOKEN="$(SONAR_TOKEN_TYPE=USER_TOKEN SONAR_TOKEN_NAME=lab-e2e "${HERE}/l1-bootstrap.sh")"
export SONAR_TOKEN
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then echo "::add-mask::${SONAR_TOKEN}"; fi
pass "bootstrap: admin password changed and a token minted"

"${HERE}/l2-apply-quality-gate.sh"
default_gate="$(curl -sf -u "${SONAR_TOKEN}:" "${SONAR_HOST_URL}/api/qualitygates/list" | jq -r '.qualitygates[] | select(.isDefault) | .name')"
[[ "${default_gate}" == "Production Security Gate" ]] || fail "default gate is '${default_gate}'"
conditions="$(curl -sf -u "${SONAR_TOKEN}:" "${SONAR_HOST_URL}/api/qualitygates/show?name=Production+Security+Gate" | jq '.conditions | length')"
[[ "${conditions}" == "9" ]] || fail "gate has ${conditions} conditions, expected 9"
pass "quality gate imported: 9 conditions, set as default"

# A gate on NEW code needs a baseline: the first analysis of a project has none and passes trivially (its project
# status has no conditions at all). So each project is scanned twice, version 1.0 = baseline, 1.1 = the change.
scan() { # <project-key> <name> <version> <dir-with-src> [coverage-file]
  ( cd "$4" && SONAR_PROJECT_VERSION="$3" COVERAGE_REPORT="${5:-}" "${HERE}/l3-scanner-ci-integration.sh" "$1" "$2" src )
}
status_of() { curl -sf -u "${SONAR_TOKEN}:" "${SONAR_HOST_URL}/api/qualitygates/project_status?projectKey=$1"; }

echo "== baseline scans (version 1.0): nothing to judge yet =="
for key in clean-app bad-app; do
  scan "${key}" "${key}" 1.0 "${HERE}/fixtures/baseline" coverage.xml
done
pass "both projects have a 1.0 baseline"

echo "== clean change (version 1.1) must pass, with the gate actually evaluating conditions =="
scan clean-app clean-app 1.1 "${HERE}/fixtures/clean-change" coverage.xml
status="$(status_of clean-app)"
[[ "$(jq -r '.projectStatus.status' <<<"${status}")" == "OK" ]] || fail "clean-app gate: $(jq -c '.projectStatus' <<<"${status}")"
[[ "$(jq '.projectStatus.conditions | length' <<<"${status}")" -ge 1 ]] || fail "clean-app: the gate evaluated no conditions"
pass "clean-app 1.1: scanner exited 0, gate OK with $(jq '.projectStatus.conditions | length' <<<"${status}") conditions evaluated"

echo "== change with deliberate problems (version 1.1) must fail =="
rc=0
scan bad-app bad-app 1.1 "${HERE}/fixtures/bad-change" || rc=$?
status="$(status_of bad-app)"
printf '   gate: %s\n' "$(jq -c '.projectStatus' <<<"${status}")"
[[ ${rc} -ne 0 ]] || fail "bad-app passed the gate"
[[ "$(jq -r '.projectStatus.status' <<<"${status}")" == "ERROR" ]] || fail "bad-app gate is not ERROR"
pass "bad-app 1.1: scanner exited ${rc}, gate ERROR"
jq -r '.projectStatus.conditions[] | select(.status=="ERROR") | "     failed condition: \(.metricKey)"' <<<"${status}"
