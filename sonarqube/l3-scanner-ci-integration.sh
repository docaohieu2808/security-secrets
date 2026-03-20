#!/usr/bin/env bash
# =============================================================================
# l3-scanner-ci-integration.sh — SonarQube: CI pipeline scanner integration
#
# Runs sonar-scanner against the current project and waits for Quality Gate result.
# Designed to run in Jenkins, GitHub Actions, GitLab CI, or any CI system.
#
# Usage:
#   export SONAR_HOST_URL=http://sonarqube:9000
#   export SONAR_TOKEN=sqp_xxxxxxxxxxxx
#   ./l3-scanner-ci-integration.sh [project-key] [project-name] [src-dir]
#
# Examples:
#   ./l3-scanner-ci-integration.sh my-app "My Application" ./src
#   ./l3-scanner-ci-integration.sh                          # uses defaults from env
#
# Environment variables:
#   SONAR_HOST_URL   — SonarQube server URL (required)
#   SONAR_TOKEN      — Authentication token (required, generate in SonarQube UI)
#   SONAR_PROJECT_KEY   — Project key (default: derived from git remote)
#   SONAR_PROJECT_NAME  — Display name (default: same as key)
#   COVERAGE_REPORT  — Path to coverage XML report (lcov, cobertura, jacoco)
#   BRANCH_NAME      — Current branch (auto-detected from git)
#   PR_KEY           — Pull request number (for PR decoration)
#   PR_BRANCH        — PR source branch
#   PR_BASE          — PR target branch
# =============================================================================
set -euo pipefail

# --- Configuration -----------------------------------------------------------
SONAR_HOST_URL="${SONAR_HOST_URL:-http://localhost:9000}"
SONAR_TOKEN="${SONAR_TOKEN:-}"
SONAR_PROJECT_KEY="${1:-${SONAR_PROJECT_KEY:-$(basename "$(git rev-parse --show-toplevel 2>/dev/null || echo my-project)")}}"
SONAR_PROJECT_NAME="${2:-${SONAR_PROJECT_NAME:-${SONAR_PROJECT_KEY}}}"
SRC_DIR="${3:-${SONAR_SOURCES:-./src}}"
COVERAGE_REPORT="${COVERAGE_REPORT:-}"
BRANCH_NAME="${BRANCH_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)}"

# Quality Gate timeout in seconds
QG_TIMEOUT=300

# --- Helpers -----------------------------------------------------------------
log()  { echo "[INFO]  $(date '+%H:%M:%S') $*"; }
warn() { echo "[WARN]  $(date '+%H:%M:%S') $*" >&2; }
die()  { echo "[ERROR] $(date '+%H:%M:%S') $*" >&2; exit 1; }

check_dependencies() {
    if ! command -v sonar-scanner &>/dev/null; then
        log "sonar-scanner not found — attempting to use Docker..."
        if command -v docker &>/dev/null; then
            # Use sonar-scanner via Docker if not installed locally
            SONAR_SCANNER_CMD="docker run --rm \
                -e SONAR_HOST_URL \
                -e SONAR_TOKEN \
                -v \"$(pwd):/usr/src\" \
                sonarsource/sonar-scanner-cli:latest"
            log "Using Docker-based sonar-scanner"
        else
            die "sonar-scanner not found and Docker unavailable. Install: https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/"
        fi
    else
        SONAR_SCANNER_CMD="sonar-scanner"
    fi

    command -v curl &>/dev/null || die "curl is required"
    [[ -n "${SONAR_TOKEN}" ]] || die "SONAR_TOKEN must be set (generate at ${SONAR_HOST_URL}/account/security)"
}

wait_for_sonarqube() {
    log "Waiting for SonarQube to be ready at ${SONAR_HOST_URL}..."
    local attempts=0
    local max_attempts=30
    until curl -sf "${SONAR_HOST_URL}/api/system/status" | grep -q '"status":"UP"'; do
        attempts=$((attempts + 1))
        [[ $attempts -ge $max_attempts ]] && die "SonarQube not ready after ${max_attempts} attempts"
        log "  Attempt ${attempts}/${max_attempts} — waiting 10s..."
        sleep 10
    done
    log "SonarQube is ready."
}

build_scanner_args() {
    local args=(
        "-Dsonar.projectKey=${SONAR_PROJECT_KEY}"
        "-Dsonar.projectName=${SONAR_PROJECT_NAME}"
        "-Dsonar.sources=${SRC_DIR}"
        "-Dsonar.host.url=${SONAR_HOST_URL}"
        "-Dsonar.token=${SONAR_TOKEN}"
        "-Dsonar.qualitygate.wait=true"
        "-Dsonar.qualitygate.timeout=${QG_TIMEOUT}"
        "-Dsonar.scm.provider=git"
    )

    # Branch analysis (requires Developer Edition or Community Branch Plugin)
    if [[ "${BRANCH_NAME}" != "HEAD" ]]; then
        args+=("-Dsonar.branch.name=${BRANCH_NAME}")
    fi

    # Pull Request decoration
    if [[ -n "${PR_KEY:-}" ]]; then
        args+=(
            "-Dsonar.pullrequest.key=${PR_KEY}"
            "-Dsonar.pullrequest.branch=${PR_BRANCH:-${BRANCH_NAME}}"
            "-Dsonar.pullrequest.base=${PR_BASE:-main}"
        )
        # Remove branch arg when doing PR analysis
        args=("${args[@]//-Dsonar.branch.name*/}")
    fi

    # Coverage report (auto-detect format by file extension)
    if [[ -n "${COVERAGE_REPORT}" && -f "${COVERAGE_REPORT}" ]]; then
        case "${COVERAGE_REPORT}" in
            *.xml)
                args+=("-Dsonar.coverage.jacoco.xmlReportPaths=${COVERAGE_REPORT}")
                args+=("-Dsonar.python.coverage.reportPaths=${COVERAGE_REPORT}")
                ;;
            *.lcov|*.info)
                args+=("-Dsonar.javascript.lcov.reportPaths=${COVERAGE_REPORT}")
                ;;
        esac
        log "Coverage report: ${COVERAGE_REPORT}"
    fi

    echo "${args[@]}"
}

check_quality_gate() {
    log "Checking Quality Gate result..."
    local status
    # Poll the analysis task result
    local ce_task_url
    ce_task_url=$(grep "ceTaskUrl" .scannerwork/report-task.txt 2>/dev/null | cut -d= -f2- || echo "")

    if [[ -z "${ce_task_url}" ]]; then
        warn "Could not find CE task URL — Quality Gate result may have been checked inline by scanner"
        return 0
    fi

    local attempts=0
    local max_attempts=30
    while true; do
        local task_response
        task_response=$(curl -sf -u "${SONAR_TOKEN}:" "${ce_task_url}")
        local task_status
        task_status=$(echo "${task_response}" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

        case "${task_status}" in
            SUCCESS)
                break
                ;;
            FAILED|CANCELLED)
                die "Analysis task ${task_status}. Check ${SONAR_HOST_URL}/project/background_tasks?id=${SONAR_PROJECT_KEY}"
                ;;
            *)
                attempts=$((attempts + 1))
                [[ $attempts -ge $max_attempts ]] && die "Timed out waiting for analysis task"
                log "  Task status: ${task_status} — waiting 10s..."
                sleep 10
                ;;
        esac
    done

    # Get Quality Gate status from analysis ID
    local analysis_id
    analysis_id=$(echo "${task_response}" | grep -o '"analysisId":"[^"]*"' | cut -d'"' -f4)
    local qg_response
    qg_response=$(curl -sf -u "${SONAR_TOKEN}:" \
        "${SONAR_HOST_URL}/api/qualitygates/project_status?analysisId=${analysis_id}")

    local qg_status
    qg_status=$(echo "${qg_response}" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

    log "Quality Gate status: ${qg_status}"
    log "Dashboard: ${SONAR_HOST_URL}/dashboard?id=${SONAR_PROJECT_KEY}"

    if [[ "${qg_status}" != "OK" && "${qg_status}" != "NONE" ]]; then
        warn "Quality Gate FAILED — build should be blocked in CI"
        # Print failing conditions
        echo "${qg_response}" | grep -o '"metricKey":"[^"]*","comparator":"[^"]*","errorThreshold":"[^"]*","actualValue":"[^"]*","status":"ERROR"' \
            | while IFS= read -r condition; do
                warn "  FAILED condition: ${condition}"
              done
        return 1
    fi

    log "Quality Gate PASSED"
    return 0
}

print_banner() {
    echo "=============================================="
    echo " SonarQube CI Scanner"
    echo "=============================================="
    echo " Server   : ${SONAR_HOST_URL}"
    echo " Project  : ${SONAR_PROJECT_KEY}"
    echo " Branch   : ${BRANCH_NAME}"
    echo " Sources  : ${SRC_DIR}"
    echo "=============================================="
}

# --- Main --------------------------------------------------------------------
main() {
    check_dependencies
    print_banner
    wait_for_sonarqube

    log "Building scanner arguments..."
    # shellcheck disable=SC2207
    SCANNER_ARGS=($(build_scanner_args))

    log "Running sonar-scanner..."
    # shellcheck disable=SC2086
    ${SONAR_SCANNER_CMD} "${SCANNER_ARGS[@]}"

    local scan_exit=$?
    if [[ $scan_exit -ne 0 ]]; then
        die "sonar-scanner exited with code ${scan_exit}"
    fi

    check_quality_gate
    local qg_exit=$?

    if [[ $qg_exit -ne 0 ]]; then
        die "Quality Gate failed — blocking CI build. Fix issues at: ${SONAR_HOST_URL}/project/issues?id=${SONAR_PROJECT_KEY}&resolved=false"
    fi

    log "SonarQube analysis complete — Quality Gate passed."
}

main "$@"
