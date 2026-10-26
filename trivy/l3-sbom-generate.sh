#!/usr/bin/env bash
# =============================================================================
# l3 - Trivy: generate an SBOM (software bill of materials) and check it for known vulnerabilities
#
#   ./l3-sbom-generate.sh <image:tag | directory> [format] [output-dir]
#   ./l3-sbom-generate.sh myapp:2.0.0 cyclonedx ./sbom
#   ./l3-sbom-generate.sh ./app spdx-json ./sbom
#
# Formats and the file they produce:
#   cyclonedx  -> *.cdx.json   CycloneDX is JSON in Trivy (there is no XML output)
#   spdx-json  -> *.spdx.json
#   spdx       -> *.spdx       tag-value
# The SBOM is then scanned with `trivy sbom`: you can scan what you shipped later, without the image.
# Env: SBOM_EXIT_CODE (default 0 = report only; set 1 to fail on HIGH/CRITICAL findings in the SBOM)
# =============================================================================
set -euo pipefail

TARGET="${1:?usage: $0 <image:tag|directory> [format] [output-dir]}"
FORMAT="${2:-cyclonedx}"
OUTPUT_DIR="${3:-./sbom-output}"
SBOM_EXIT_CODE="${SBOM_EXIT_CODE:-0}"

case "${FORMAT}" in
  cyclonedx) EXT="cdx.json" ;;
  spdx-json) EXT="spdx.json" ;;
  spdx) EXT="spdx" ;;
  *) printf '[ERROR] unsupported format %s (cyclonedx, spdx-json, spdx)\n' "${FORMAT}" >&2; exit 1 ;;
esac

log() { printf '[INFO]  %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

command -v trivy >/dev/null || die "trivy not found; run ./install-trivy.sh"
mkdir -p "${OUTPUT_DIR}"
slug="$(printf '%s' "${TARGET}" | tr '/: ' '---' | tr -s '-')"
SBOM_FILE="${OUTPUT_DIR}/sbom-${slug}.${EXT}"

if [[ -e "${TARGET}" ]]; then
  log "generating ${FORMAT} SBOM for directory ${TARGET}"
  trivy fs --format "${FORMAT}" --output "${SBOM_FILE}" "${TARGET}"
else
  log "generating ${FORMAT} SBOM for image ${TARGET}"
  trivy image --format "${FORMAT}" --output "${SBOM_FILE}" "${TARGET}"
fi
log "wrote ${SBOM_FILE} ($(du -h "${SBOM_FILE}" | cut -f1))"

if [[ "${EXT}" == "cdx.json" || "${EXT}" == "spdx.json" ]]; then
  if command -v jq >/dev/null; then
    key=$([[ "${EXT}" == "cdx.json" ]] && echo '.components' || echo '.packages')
    log "components catalogued: $(jq "${key} | length" "${SBOM_FILE}")"
  fi
fi

log "scanning the SBOM for HIGH/CRITICAL vulnerabilities"
rc=0
trivy sbom --severity HIGH,CRITICAL --exit-code "${SBOM_EXIT_CODE}" "${SBOM_FILE}" || rc=$?
exit "${rc}"
