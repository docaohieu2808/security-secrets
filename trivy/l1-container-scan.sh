#!/usr/bin/env bash
# =============================================================================
# l1-container-scan.sh — Trivy Level 1: Scan Docker images for vulnerabilities
#
# Usage:
#   ./l1-container-scan.sh <image:tag> [severity] [output-format]
#
# Examples:
#   ./l1-container-scan.sh nginx:latest
#   ./l1-container-scan.sh myapp:1.0.0 HIGH,CRITICAL json
#   ./l1-container-scan.sh alpine:3.18 CRITICAL table
#
# Prerequisites:
#   - trivy installed (https://aquasecurity.github.io/trivy)
#     Install: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
#   - Docker running (for pulling images)
# =============================================================================
set -euo pipefail

# --- Configuration -----------------------------------------------------------
IMAGE="${1:-nginx:latest}"
SEVERITY="${2:-HIGH,CRITICAL}"        # UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL
OUTPUT_FORMAT="${3:-table}"           # table, json, sarif, cyclonedx, template
REPORT_DIR="./trivy-reports"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="${REPORT_DIR}/container-scan-${TIMESTAMP}.${OUTPUT_FORMAT}"

# Exit codes
EXIT_CODE_ON_VULN=1   # Set to 0 to never fail on findings (useful in dev)

# --- Helpers -----------------------------------------------------------------
log()  { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

check_dependencies() {
    command -v trivy &>/dev/null || die "trivy not found. Install: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
    command -v docker &>/dev/null || warn "docker not found — image must be pullable from registry cache"
}

print_banner() {
    echo "=============================================="
    echo " Trivy Container Image Vulnerability Scanner"
    echo "=============================================="
    echo " Image    : ${IMAGE}"
    echo " Severity : ${SEVERITY}"
    echo " Format   : ${OUTPUT_FORMAT}"
    echo " Report   : ${REPORT_FILE}"
    echo "=============================================="
}

# --- Main --------------------------------------------------------------------
main() {
    check_dependencies
    print_banner

    mkdir -p "${REPORT_DIR}"

    log "Updating Trivy vulnerability database..."
    trivy image --download-db-only --quiet

    log "Scanning image: ${IMAGE}"

    # Full vulnerability scan of the container image
    # --scanners: vuln = CVE scan, secret = embedded secrets, misconfig = Dockerfile issues
    # --ignore-unfixed: skip vulns with no patch yet (reduce noise)
    # --exit-code: return non-zero if vulns found at given severity
    trivy image \
        --severity "${SEVERITY}" \
        --scanners vuln,secret,misconfig \
        --format "${OUTPUT_FORMAT}" \
        --output "${REPORT_FILE}" \
        --exit-code "${EXIT_CODE_ON_VULN}" \
        --ignore-unfixed \
        --timeout 10m \
        "${IMAGE}"

    local exit_status=$?

    if [[ $exit_status -eq 0 ]]; then
        log "Scan complete — no ${SEVERITY} vulnerabilities found."
    else
        warn "Scan complete — vulnerabilities found! Review: ${REPORT_FILE}"
    fi

    # Also print summary to stdout regardless of format
    if [[ "${OUTPUT_FORMAT}" != "table" ]]; then
        log "Printing table summary to stdout..."
        trivy image \
            --severity "${SEVERITY}" \
            --scanners vuln,secret \
            --format table \
            --ignore-unfixed \
            --quiet \
            "${IMAGE}" || true
    fi

    log "Full report saved to: ${REPORT_FILE}"
    return $exit_status
}

main "$@"
