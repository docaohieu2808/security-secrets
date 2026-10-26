#!/usr/bin/env bash
# Install pinned CLI tools for CI (and for you), each verified against the checksum file published with the release.
#
#   scripts/install-tools.sh opa conftest kubeconform gator kyverno sops kubeseal   # into ${BIN_DIR:-$HOME/.local/bin}
#
# Versions live here and nowhere else; Dependabot cannot see them, so the weekly CI run is what notices a release
# that breaks the labs, and bumping a version is a one-line change plus the matching test run.
set -euo pipefail

OPA_VERSION=1.21.4
CONFTEST_VERSION=0.71.1
KUBECONFORM_VERSION=0.8.0
GATOR_VERSION=3.23.1
KYVERNO_CLI_VERSION=1.19.2
SOPS_VERSION=3.13.3
KUBESEAL_VERSION=0.40.0

BIN_DIR="${BIN_DIR:-${HOME}/.local/bin}"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
mkdir -p "${BIN_DIR}"

die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

# download <url> <checksum-url> <asset-name> -> ${TMP}/<asset-name>, verified
download() {
  local url="$1" sums_url="$2" asset="$3" expected actual
  curl -fsSL -o "${TMP}/${asset}" "${url}"
  curl -fsSL -o "${TMP}/${asset}.sums" "${sums_url}"
  expected="$(grep -F "${asset}" "${TMP}/${asset}.sums" | head -1 | cut -d' ' -f1)"
  [[ -n "${expected}" ]] || die "no checksum for ${asset} in ${sums_url}"
  actual="$(sha256sum "${TMP}/${asset}" | cut -d' ' -f1)"
  [[ "${actual}" == "${expected}" ]] || die "checksum mismatch for ${asset}"
  echo "verified ${asset}"
}

install_tool() {
  case "$1" in
    opa)
      local base="https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}"
      download "${base}/opa_linux_amd64_static" "${base}/opa_linux_amd64_static.sha256" opa_linux_amd64_static
      install -m 0755 "${TMP}/opa_linux_amd64_static" "${BIN_DIR}/opa" ;;
    conftest)
      local base="https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}" asset="conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz"
      download "${base}/${asset}" "${base}/checksums.txt" "${asset}"
      tar -xzf "${TMP}/${asset}" -C "${TMP}" conftest && install -m 0755 "${TMP}/conftest" "${BIN_DIR}/conftest" ;;
    kubeconform)
      local base="https://github.com/yannh/kubeconform/releases/download/v${KUBECONFORM_VERSION}" asset="kubeconform-linux-amd64.tar.gz"
      download "${base}/${asset}" "${base}/CHECKSUMS" "${asset}"
      tar -xzf "${TMP}/${asset}" -C "${TMP}" kubeconform && install -m 0755 "${TMP}/kubeconform" "${BIN_DIR}/kubeconform" ;;
    gator)
      local base="https://github.com/open-policy-agent/gatekeeper/releases/download/v${GATOR_VERSION}" asset="gator-v${GATOR_VERSION}-linux-amd64.tar.gz"
      download "${base}/${asset}" "${base}/sha256sums.txt" "${asset}"
      tar -xzf "${TMP}/${asset}" -C "${TMP}" gator && install -m 0755 "${TMP}/gator" "${BIN_DIR}/gator" ;;
    kyverno)
      local base="https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_CLI_VERSION}" asset="kyverno-cli_v${KYVERNO_CLI_VERSION}_linux_x86_64.tar.gz"
      download "${base}/${asset}" "${base}/checksums.txt" "${asset}"
      tar -xzf "${TMP}/${asset}" -C "${TMP}" kyverno && install -m 0755 "${TMP}/kyverno" "${BIN_DIR}/kyverno" ;;
    sops)
      local base="https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}" asset="sops-v${SOPS_VERSION}.linux.amd64"
      download "${base}/${asset}" "${base}/sops-v${SOPS_VERSION}.checksums.txt" "${asset}"
      install -m 0755 "${TMP}/${asset}" "${BIN_DIR}/sops" ;;
    kubeseal)
      local base="https://github.com/bitnami/sealed-secrets/releases/download/v${KUBESEAL_VERSION}" asset="kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz"
      download "${base}/${asset}" "${base}/sealed-secrets_${KUBESEAL_VERSION}_checksums.txt" "${asset}"
      tar -xzf "${TMP}/${asset}" -C "${TMP}" kubeseal && install -m 0755 "${TMP}/kubeseal" "${BIN_DIR}/kubeseal" ;;
    *) die "unknown tool '$1'" ;;
  esac
}

[[ $# -gt 0 ]] || die "usage: $0 <tool>... (opa conftest kubeconform gator kyverno sops kubeseal)"
for tool in "$@"; do install_tool "${tool}"; done
if [[ -n "${GITHUB_PATH:-}" ]]; then echo "${BIN_DIR}" >> "${GITHUB_PATH}"; fi
