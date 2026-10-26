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

echo "== clean project must pass =="
( cd "${HERE}/fixtures/clean" && COVERAGE_REPORT=coverage.xml "${HERE}/l3-scanner-ci-integration.sh" clean-app "Clean App" src )
status="$(curl -sf -u "${SONAR_TOKEN}:" "${SONAR_HOST_URL}/api/qualitygates/project_status?projectKey=clean-app" | jq -r '.projectStatus.status')"
[[ "${status}" == "OK" ]] || fail "clean-app gate is ${status}"
pass "clean-app: scanner exited 0, gate OK"

echo "== project with deliberate problems must fail =="
rc=0
( cd "${HERE}/fixtures/bad" && "${HERE}/l3-scanner-ci-integration.sh" bad-app "Bad App" src ) || rc=$?
[[ ${rc} -ne 0 ]] || fail "bad-app passed the gate"
status="$(curl -sf -u "${SONAR_TOKEN}:" "${SONAR_HOST_URL}/api/qualitygates/project_status?projectKey=bad-app" | jq -r '.projectStatus.status')"
[[ "${status}" == "ERROR" ]] || fail "bad-app gate is ${status}, expected ERROR"
pass "bad-app: scanner exited ${rc}, gate ERROR"
curl -sf -u "${SONAR_TOKEN}:" "${SONAR_HOST_URL}/api/qualitygates/project_status?projectKey=bad-app" \
  | jq -r '.projectStatus.conditions[] | select(.status=="ERROR") | "     failed condition: \(.metricKey)"'
