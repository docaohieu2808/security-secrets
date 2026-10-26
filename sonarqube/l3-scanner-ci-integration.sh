#!/usr/bin/env bash
# =============================================================================
# l3 - SonarQube: run the scanner from CI and fail the build when the quality gate fails
#
#   export SONAR_HOST_URL=http://localhost:9000
#   export SONAR_TOKEN=<analysis token>             # from l1-bootstrap.sh; read by the scanner from the env
#   ./l3-scanner-ci-integration.sh [project-key] [project-name] [src-dir]
#
#   ./l3-scanner-ci-integration.sh my-app "My Application" src      # names with spaces are fine
#
# The scanner runs with sonar.qualitygate.wait=true: it blocks until the server has evaluated the gate and
# exits non-zero when the gate is red, so this script just propagates that exit code (after printing which
# conditions failed). It exits 0 only when the gate is green.
#
# Env (all optional except the first two):
#   SONAR_HOST_URL, SONAR_TOKEN
#   SONAR_PROJECT_KEY, SONAR_PROJECT_NAME, SONAR_SOURCES   defaults for the three arguments
#   SONAR_PROJECT_VERSION   sets sonar.projectVersion. The default "new code" definition is "since the previous
#                     version", so a gate on new code only has something to judge from the SECOND analysis with a
#                     different version on (the first analysis of a project has no baseline and passes trivially).
#   COVERAGE_REPORT   path to a coverage report (relative to the repo root)
#   COVERAGE_FORMAT   generic (default for .xml) | jacoco | python | lcov (default for .info/.lcov)
#   SCANNER_DOCKER_NETWORK   docker network for the containerised scanner (default host, so localhost works)
#   BRANCH_NAME, PR_KEY, PR_BRANCH, PR_BASE   branch / pull-request analysis. These parameters are ignored
#                     or rejected by the Community Build; they need a paid edition. Off unless you set them.
# The sources path must be relative to where you run this (the repo root is mounted into the container).
# =============================================================================
set -euo pipefail

SONAR_HOST_URL="${SONAR_HOST_URL:-http://localhost:9000}"
SONAR_TOKEN="${SONAR_TOKEN:-}"
SONAR_PROJECT_KEY="${1:-${SONAR_PROJECT_KEY:-$(basename "$(git rev-parse --show-toplevel 2>/dev/null || pwd)")}}"
SONAR_PROJECT_NAME="${2:-${SONAR_PROJECT_NAME:-${SONAR_PROJECT_KEY}}}"
SRC_DIR="${3:-${SONAR_SOURCES:-src}}"
COVERAGE_REPORT="${COVERAGE_REPORT:-}"
QG_TIMEOUT="${QG_TIMEOUT:-300}"
SCANNER_IMAGE="sonarsource/sonar-scanner-cli:12.3.0.4285_8.1.0"

# Logs go to stderr so nothing a function prints can end up inside an argument list.
log()  { printf '[INFO]  %s %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
warn() { printf '[WARN]  %s %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
die()  { printf '[ERROR] %s %s\n' "$(date '+%H:%M:%S')" "$*" >&2; exit 1; }

SCANNER_CMD=()    # how to invoke the scanner
SCANNER_ARGS=()   # -D properties, one array element each, so spaces survive

choose_scanner() {
  command -v curl >/dev/null || die "curl is required"
  command -v jq >/dev/null || die "jq is required"
  [[ -n "${SONAR_TOKEN}" ]] || die "SONAR_TOKEN must be set (see l1-bootstrap.sh)"
  if command -v sonar-scanner >/dev/null; then
    SCANNER_CMD=(sonar-scanner)
  elif command -v docker >/dev/null; then
    log "sonar-scanner not installed, using ${SCANNER_IMAGE}"
    # -e NAME (no value) forwards the variable without putting the secret in the command line.
    # The image keeps the scanner work directory in /tmp/.scannerwork, which belongs to root; running as the caller's
    # uid (so files in the mounted repo stay yours) needs it inside the project and a writable user home instead.
    SCANNER_CMD=(docker run --rm --network "${SCANNER_DOCKER_NETWORK:-host}"
      -u "$(id -u):$(id -g)" -e SCANNER_WORKDIR_PATH=/usr/src/.scannerwork -e SONAR_USER_HOME=/tmp/.sonar
      -e SONAR_HOST_URL -e SONAR_TOKEN
      -v "$(pwd):/usr/src" "${SCANNER_IMAGE}")
  else
    die "need sonar-scanner or docker"
  fi
}

wait_for_sonarqube() {
  log "waiting for SonarQube at ${SONAR_HOST_URL}"
  local attempt
  for attempt in $(seq 1 30); do
    if curl -sf "${SONAR_HOST_URL}/api/system/status" | grep -q '"status":"UP"'; then
      log "SonarQube is up"
      return 0
    fi
    log "  attempt ${attempt}/30, retrying in 10s"
    sleep 10
  done
  die "SonarQube not ready after 30 attempts"
}

build_scanner_args() {
  export SONAR_HOST_URL SONAR_TOKEN
  SCANNER_ARGS=(
    "-Dsonar.projectKey=${SONAR_PROJECT_KEY}"
    "-Dsonar.projectName=${SONAR_PROJECT_NAME}"
    "-Dsonar.sources=${SRC_DIR}"
    "-Dsonar.qualitygate.wait=true"
    "-Dsonar.qualitygate.timeout=${QG_TIMEOUT}"
    "-Dsonar.scm.disabled=true"
  )
  if [[ -n "${SONAR_PROJECT_VERSION:-}" ]]; then
    SCANNER_ARGS+=("-Dsonar.projectVersion=${SONAR_PROJECT_VERSION}")
  fi

  if [[ -n "${PR_KEY:-}" ]]; then
    SCANNER_ARGS+=(
      "-Dsonar.pullrequest.key=${PR_KEY}"
      "-Dsonar.pullrequest.branch=${PR_BRANCH:-${BRANCH_NAME:-}}"
      "-Dsonar.pullrequest.base=${PR_BASE:-main}"
    )
  elif [[ -n "${BRANCH_NAME:-}" ]]; then
    SCANNER_ARGS+=("-Dsonar.branch.name=${BRANCH_NAME}")
  fi

  if [[ -n "${COVERAGE_REPORT}" ]]; then
    [[ -f "${COVERAGE_REPORT}" ]] || die "COVERAGE_REPORT not found: ${COVERAGE_REPORT}"
    local format="${COVERAGE_FORMAT:-}"
    if [[ -z "${format}" ]]; then
      case "${COVERAGE_REPORT}" in
        *.lcov|*.info) format=lcov ;;
        *) format=generic ;;
      esac
    fi
    case "${format}" in
      generic) SCANNER_ARGS+=("-Dsonar.coverageReportPaths=${COVERAGE_REPORT}") ;;
      jacoco)  SCANNER_ARGS+=("-Dsonar.coverage.jacoco.xmlReportPaths=${COVERAGE_REPORT}") ;;
      python)  SCANNER_ARGS+=("-Dsonar.python.coverage.reportPaths=${COVERAGE_REPORT}") ;;
      lcov)    SCANNER_ARGS+=("-Dsonar.javascript.lcov.reportPaths=${COVERAGE_REPORT}") ;;
      *) die "unknown COVERAGE_FORMAT: ${format}" ;;
    esac
    log "coverage: ${COVERAGE_REPORT} (${format})"
  fi
}

# Best effort: list the red conditions. An analysis token may not be allowed to read project status.
print_failed_conditions() {
  local status
  if ! status="$(curl -sf -u "${SONAR_TOKEN}:" "${SONAR_HOST_URL}/api/qualitygates/project_status?projectKey=${SONAR_PROJECT_KEY}")"; then
    warn "could not read project status (the token may be analysis-only); see ${SONAR_HOST_URL}/dashboard?id=${SONAR_PROJECT_KEY}"
    return 0
  fi
  warn "quality gate: $(jq -r '.projectStatus.status' <<<"${status}")"
  jq -r '.projectStatus.conditions[] | select(.status == "ERROR")
         | "  failed: \(.metricKey) \(.comparator) \(.errorThreshold) (actual \(.actualValue // "n/a"))"' <<<"${status}" >&2
}

main() {
  choose_scanner
  printf '%s\n' "SonarQube CI scan: ${SONAR_PROJECT_KEY} (sources: ${SRC_DIR}) -> ${SONAR_HOST_URL}" >&2
  wait_for_sonarqube
  build_scanner_args

  # set -e would abort on a non-zero scanner exit before we could report anything, so capture the code.
  local scan_rc=0
  "${SCANNER_CMD[@]}" "${SCANNER_ARGS[@]}" || scan_rc=$?

  if [[ ${scan_rc} -ne 0 ]]; then
    print_failed_conditions
    die "sonar-scanner exited with ${scan_rc}; the build must not pass. Issues: ${SONAR_HOST_URL}/project/issues?id=${SONAR_PROJECT_KEY}&resolved=false"
  fi
  log "analysis finished and the quality gate is green"
}

main "$@"
