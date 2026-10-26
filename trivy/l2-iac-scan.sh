#!/usr/bin/env bash
# =============================================================================
# l2 - Trivy: scan infrastructure-as-code (Terraform, Kubernetes, Helm, Dockerfile, CloudFormation)
#
#   ./l2-iac-scan.sh [path] [severity] [format]
#   ./l2-iac-scan.sh ./terraform HIGH,CRITICAL
#   ./l2-iac-scan.sh ./k8s CRITICAL sarif
#
# One `trivy config` run covers every IaC type it finds under the path.
# Exit status: 0 = clean, 1 = misconfigurations at/above SEVERITY, other = scan failed.
# Add your own checks with:  CUSTOM_CHECKS=./l-max-custom-checks ./l2-iac-scan.sh k8s/
# Silence one reviewed finding with a .trivyignore.yaml entry (id + expiry date) instead of lowering SEVERITY.
# =============================================================================
set -euo pipefail

SCAN_PATH="${1:-.}"
SEVERITY="${2:-HIGH,CRITICAL}"
FORMAT="${3:-table}"
CUSTOM_CHECKS="${CUSTOM_CHECKS:-}"
REPORT_DIR="${REPORT_DIR:-./trivy-reports}"
REPORT_FILE="${REPORT_DIR}/iac-scan-$(date +%Y%m%d-%H%M%S).${FORMAT}"

log()  { printf '[INFO]  %s\n' "$*"; }
warn() { printf '[WARN]  %s\n' "$*" >&2; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

command -v trivy >/dev/null || die "trivy not found; run ./install-trivy.sh"
[[ -d "${SCAN_PATH}" ]] || die "scan path does not exist: ${SCAN_PATH}"
mkdir -p "${REPORT_DIR}"

args=(config --severity "${SEVERITY}" --format "${FORMAT}" --output "${REPORT_FILE}" --exit-code 1 --tf-exclude-downloaded-modules)
if [[ -n "${CUSTOM_CHECKS}" ]]; then
  # --config-check replaces the deprecated --policy; --check-namespaces says which Rego packages to evaluate
  args+=(--config-check "${CUSTOM_CHECKS}" --check-namespaces user)
fi

log "scanning ${SCAN_PATH} (severity ${SEVERITY})${CUSTOM_CHECKS:+ with custom checks from ${CUSTOM_CHECKS}}"

rc=0
trivy "${args[@]}" "${SCAN_PATH}" || rc=$?

case "${rc}" in
  0) log "no ${SEVERITY} misconfigurations" ;;
  1) warn "misconfigurations found" ;;
  *) die "trivy failed with exit ${rc}" ;;
esac
[[ "${FORMAT}" == "table" ]] && cat "${REPORT_FILE}"
log "report: ${REPORT_FILE}"
exit "${rc}"
