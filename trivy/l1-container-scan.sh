#!/usr/bin/env bash
# =============================================================================
# l1 - Trivy: scan a container image for vulnerabilities, secrets and image misconfiguration
#
#   ./l1-container-scan.sh <image:tag> [severity] [format]
#   ./l1-container-scan.sh python:3.12-alpine
#   ./l1-container-scan.sh myapp:1.4.0 HIGH,CRITICAL json
#
# Exit status: 0 = nothing at/above SEVERITY, 1 = findings (the CI gate), anything else = the scan itself failed.
# The scan runs once and writes a JSON report; a table is rendered from that report with `trivy convert`, so the
# numbers on screen and in the file always agree.
#
# Install a pinned trivy first: ./install-trivy.sh   (never pipe a script from a moving branch into sh)
# Env: IGNORE_UNFIXED=true|false (default true: hide vulnerabilities that have no fixed version yet)
#      REPORT_DIR (default ./trivy-reports)
# =============================================================================
set -euo pipefail

IMAGE="${1:?usage: $0 <image:tag> [severity] [format]}"
SEVERITY="${2:-HIGH,CRITICAL}"           # UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL
FORMAT="${3:-json}"                      # json, sarif, cyclonedx, ... (anything `trivy image --format` accepts)
IGNORE_UNFIXED="${IGNORE_UNFIXED:-true}"
REPORT_DIR="${REPORT_DIR:-./trivy-reports}"
REPORT_FILE="${REPORT_DIR}/container-scan-$(date +%Y%m%d-%H%M%S).${FORMAT}"

log()  { printf '[INFO]  %s\n' "$*"; }
warn() { printf '[WARN]  %s\n' "$*" >&2; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

command -v trivy >/dev/null || die "trivy not found; run ./install-trivy.sh"
mkdir -p "${REPORT_DIR}"

args=(image --severity "${SEVERITY}" --scanners "vuln,secret,misconfig" --format "${FORMAT}" --output "${REPORT_FILE}"
      --exit-code 1 --timeout 10m)
[[ "${IGNORE_UNFIXED}" == "true" ]] && args+=(--ignore-unfixed)

log "scanning ${IMAGE} (severity ${SEVERITY}, unfixed ignored: ${IGNORE_UNFIXED})"

# `set -e` would end the script at the first non-zero exit, which is exactly the "findings" case we want to
# report on. Capture the code instead.
rc=0
trivy "${args[@]}" "${IMAGE}" || rc=$?

case "${rc}" in
  0) log "no ${SEVERITY} findings" ;;
  1) warn "${SEVERITY} findings in ${IMAGE}" ;;
  *) die "trivy failed with exit ${rc}" ;;
esac

if [[ "${FORMAT}" == "json" ]]; then
  trivy convert --format table --severity "${SEVERITY}" "${REPORT_FILE}"
fi
log "report: ${REPORT_FILE}"
exit "${rc}"
