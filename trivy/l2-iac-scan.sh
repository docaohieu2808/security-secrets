#!/usr/bin/env bash
# =============================================================================
# l2-iac-scan.sh — Trivy Level 2: Scan Terraform and Kubernetes IaC configs
#
# Usage:
#   ./l2-iac-scan.sh [path-to-iac-dir] [severity] [output-format]
#
# Examples:
#   ./l2-iac-scan.sh ./terraform HIGH table
#   ./l2-iac-scan.sh ./k8s-manifests CRITICAL json
#   ./l2-iac-scan.sh .  HIGH,CRITICAL sarif
#
# What it scans:
#   - Terraform (.tf) files: misconfigured resources, insecure defaults
#   - Kubernetes YAML manifests: pod security, RBAC, network policies
#   - Helm charts: chart misconfigurations
#   - Dockerfile: insecure instructions
#
# Prerequisites:
#   - trivy >= 0.38.0 (supports --scanners misconfig)
# =============================================================================
set -euo pipefail

# --- Configuration -----------------------------------------------------------
SCAN_PATH="${1:-.}"
SEVERITY="${2:-HIGH,CRITICAL}"
OUTPUT_FORMAT="${3:-table}"
REPORT_DIR="./trivy-reports"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="${REPORT_DIR}/iac-scan-${TIMESTAMP}.${OUTPUT_FORMAT}"

# --- Helpers -----------------------------------------------------------------
log()  { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

check_dependencies() {
    command -v trivy &>/dev/null || die "trivy not found. Install via: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
}

print_banner() {
    echo "=============================================="
    echo " Trivy IaC / Misconfiguration Scanner"
    echo "=============================================="
    echo " Path     : ${SCAN_PATH}"
    echo " Severity : ${SEVERITY}"
    echo " Format   : ${OUTPUT_FORMAT}"
    echo " Report   : ${REPORT_FILE}"
    echo "=============================================="
}

scan_terraform() {
    local tf_dirs
    tf_dirs=$(find "${SCAN_PATH}" -name "*.tf" -exec dirname {} \; | sort -u)

    if [[ -z "${tf_dirs}" ]]; then
        log "No Terraform files found in ${SCAN_PATH}"
        return 0
    fi

    log "Found Terraform configs — scanning for misconfigurations..."
    # --tf-exclude-downloaded-modules: skip .terraform/ module cache
    trivy config \
        --severity "${SEVERITY}" \
        --format "${OUTPUT_FORMAT}" \
        --output "${REPORT_DIR}/iac-terraform-${TIMESTAMP}.${OUTPUT_FORMAT}" \
        --tf-exclude-downloaded-modules \
        --exit-code 1 \
        "${SCAN_PATH}" || warn "Terraform misconfigurations found — review report"
}

scan_kubernetes() {
    local k8s_files
    k8s_files=$(find "${SCAN_PATH}" -name "*.yaml" -o -name "*.yml" 2>/dev/null | head -1)

    if [[ -z "${k8s_files}" ]]; then
        log "No Kubernetes YAML files found in ${SCAN_PATH}"
        return 0
    fi

    log "Found Kubernetes manifests — scanning for misconfigurations..."
    # Checks: privileged containers, missing resource limits, hostPath mounts,
    #         insecure capabilities, missing network policies, etc.
    trivy config \
        --severity "${SEVERITY}" \
        --format "${OUTPUT_FORMAT}" \
        --output "${REPORT_DIR}/iac-k8s-${TIMESTAMP}.${OUTPUT_FORMAT}" \
        --exit-code 1 \
        "${SCAN_PATH}" || warn "Kubernetes misconfigurations found — review report"
}

# --- Main --------------------------------------------------------------------
main() {
    check_dependencies
    print_banner

    mkdir -p "${REPORT_DIR}"

    [[ -d "${SCAN_PATH}" ]] || die "Scan path does not exist: ${SCAN_PATH}"

    log "Running combined IaC misconfiguration scan on: ${SCAN_PATH}"

    # Single comprehensive scan covering all IaC types in the path
    # --scanners misconfig: focus on misconfiguration checks (not CVEs)
    # --include-non-failures: show passed checks too for audit trail
    trivy config \
        --severity "${SEVERITY}" \
        --scanners misconfig \
        --format "${OUTPUT_FORMAT}" \
        --output "${REPORT_FILE}" \
        --exit-code 1 \
        --tf-exclude-downloaded-modules \
        "${SCAN_PATH}"

    local exit_status=$?

    if [[ $exit_status -eq 0 ]]; then
        log "IaC scan complete — no ${SEVERITY} misconfigurations found."
    else
        warn "IaC scan complete — misconfigurations found! Review: ${REPORT_FILE}"
    fi

    log "Full report saved to: ${REPORT_FILE}"
    return $exit_status
}

main "$@"
