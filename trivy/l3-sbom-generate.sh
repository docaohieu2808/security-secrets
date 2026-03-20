#!/usr/bin/env bash
# =============================================================================
# l3-sbom-generate.sh — Trivy Level 3: Generate Software Bill of Materials (SBOM)
#
# Generates SBOM in CycloneDX or SPDX format for container images or filesystems.
# SBOM documents all components, libraries, and dependencies in a software artifact.
#
# Usage:
#   ./l3-sbom-generate.sh <image:tag|fs-path> [sbom-format] [output-dir]
#
# Examples:
#   ./l3-sbom-generate.sh nginx:latest cyclonedx ./sbom-output
#   ./l3-sbom-generate.sh myapp:2.0.0 spdx-json ./sbom-output
#   ./l3-sbom-generate.sh /path/to/app cyclonedx ./sbom-output
#
# SBOM Formats:
#   cyclonedx     — CycloneDX XML (default, widely supported)
#   cyclonedx-json — CycloneDX JSON
#   spdx          — SPDX tag-value format
#   spdx-json     — SPDX JSON (preferred for tooling integration)
#
# Prerequisites:
#   - trivy >= 0.38.0
# =============================================================================
set -euo pipefail

# --- Configuration -----------------------------------------------------------
TARGET="${1:-nginx:latest}"
SBOM_FORMAT="${2:-cyclonedx}"       # cyclonedx, cyclonedx-json, spdx, spdx-json
OUTPUT_DIR="${3:-./sbom-output}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Determine file extension from format
case "${SBOM_FORMAT}" in
    cyclonedx)      EXT="xml" ;;
    cyclonedx-json) EXT="json" ;;
    spdx)           EXT="spdx" ;;
    spdx-json)      EXT="spdx.json" ;;
    *)              EXT="json" ;;
esac

# Sanitize target name for use in filename (replace / and : with -)
TARGET_SLUG=$(echo "${TARGET}" | tr '/: ' '---')
SBOM_FILE="${OUTPUT_DIR}/sbom-${TARGET_SLUG}-${TIMESTAMP}.${EXT}"

# --- Helpers -----------------------------------------------------------------
log()  { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

check_dependencies() {
    command -v trivy &>/dev/null || die "trivy not found. Install: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
}

print_banner() {
    echo "=============================================="
    echo " Trivy SBOM Generator"
    echo "=============================================="
    echo " Target   : ${TARGET}"
    echo " Format   : ${SBOM_FORMAT}"
    echo " Output   : ${SBOM_FILE}"
    echo "=============================================="
}

detect_target_type() {
    # Determine if target is a container image or filesystem path
    if [[ -d "${TARGET}" ]] || [[ -f "${TARGET}" ]]; then
        echo "fs"
    else
        echo "image"
    fi
}

generate_sbom_for_image() {
    log "Generating SBOM for container image: ${TARGET}"
    # --format cyclonedx/spdx-json: standard SBOM output format
    # --scanners: empty string = skip vuln scan, only collect component inventory
    trivy image \
        --format "${SBOM_FORMAT}" \
        --output "${SBOM_FILE}" \
        --quiet \
        "${TARGET}"
}

generate_sbom_for_filesystem() {
    log "Generating SBOM for filesystem path: ${TARGET}"
    trivy fs \
        --format "${SBOM_FORMAT}" \
        --output "${SBOM_FILE}" \
        --quiet \
        "${TARGET}"
}

print_sbom_summary() {
    log "SBOM Summary:"
    if command -v jq &>/dev/null && [[ "${EXT}" == "json" ]]; then
        local component_count
        component_count=$(jq '.components | length' "${SBOM_FILE}" 2>/dev/null || echo "unknown")
        log "  Components catalogued: ${component_count}"
    fi
    log "  File: ${SBOM_FILE}"
    log "  Size: $(du -sh "${SBOM_FILE}" | cut -f1)"
}

# --- Main --------------------------------------------------------------------
main() {
    check_dependencies
    print_banner

    mkdir -p "${OUTPUT_DIR}"

    local target_type
    target_type=$(detect_target_type)

    if [[ "${target_type}" == "fs" ]]; then
        generate_sbom_for_filesystem
    else
        log "Updating Trivy vulnerability database..."
        trivy image --download-db-only --quiet
        generate_sbom_for_image
    fi

    log "SBOM generated successfully."
    print_sbom_summary

    # Optional: also scan the generated SBOM for known vulnerabilities
    log "Scanning SBOM for known vulnerabilities..."
    trivy sbom \
        --severity HIGH,CRITICAL \
        --format table \
        --exit-code 0 \
        "${SBOM_FILE}" || true

    log "Done. SBOM saved to: ${SBOM_FILE}"
}

main "$@"
