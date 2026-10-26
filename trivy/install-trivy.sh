#!/usr/bin/env bash
# =============================================================================
# Install a pinned Trivy release and refuse anything whose checksum does not match.
#
# Why not `curl .../trivy/main/contrib/install.sh | sh`? That runs whatever is on the main branch, unpinned and
# unverified - exactly the shape of the March 2026 supply-chain incident (trivy 0.69.4, trivy-action < 0.35.0 and
# setup-trivy < 0.2.6 were briefly compromised; GHSA-69fq-xp46-6x23). Here the version AND the sha256 of each
# tarball are written in this file, so a tampered release asset fails the install even if the release page and its
# checksums.txt were both replaced.
#
#   ./install-trivy.sh [install-dir]        # default ~/.local/bin ; needs curl, tar, sha256sum (or shasum)
# Updating: change TRIVY_VERSION and the four digests together
#   (gh release download vX -R aquasecurity/trivy -p '*checksums.txt'), review the diff, commit.
# Optional extra check: if `cosign` is installed the release's sigstore bundle is verified too.
# =============================================================================
set -euo pipefail

TRIVY_VERSION="0.76.1"
INSTALL_DIR="${1:-${HOME}/.local/bin}"

declare -A SHA256=(
  [Linux-64bit]="c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0"
  [Linux-ARM64]="e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f"
  [macOS-64bit]="7aa762eacd582052d053b62dcf972a1ab058abe39a57ccae234ed8894945b6b7"
  [macOS-ARM64]="11a9b6cd2752011b54f01ea4bd0dbfa9f0c41dc6538d5a3f9d23955f471bf4e5"
)

die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=Linux-64bit ;;
  Linux-aarch64|Linux-arm64) platform=Linux-ARM64 ;;
  Darwin-x86_64) platform=macOS-64bit ;;
  Darwin-arm64) platform=macOS-ARM64 ;;
  *) die "unsupported platform $(uname -s)-$(uname -m)" ;;
esac

sha256_of() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
file="trivy_${TRIVY_VERSION}_${platform}.tar.gz"
base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"

curl -fsSL -o "${tmp}/${file}" "${base}/${file}"
actual="$(sha256_of "${tmp}/${file}")"
[[ "${actual}" == "${SHA256[${platform}]}" ]] || die "checksum mismatch for ${file}: got ${actual}, expected ${SHA256[${platform}]}"
echo "sha256 ok for ${file}"

if command -v cosign >/dev/null; then
  curl -fsSL -o "${tmp}/${file}.sigstore.json" "${base}/${file}.sigstore.json"
  cosign verify-blob --bundle "${tmp}/${file}.sigstore.json" \
    --certificate-identity-regexp '^https://github.com/aquasecurity/trivy/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "${tmp}/${file}"
fi

mkdir -p "${INSTALL_DIR}"
tar -xzf "${tmp}/${file}" -C "${tmp}" trivy
install -m 0755 "${tmp}/trivy" "${INSTALL_DIR}/trivy"
"${INSTALL_DIR}/trivy" --version | head -1
case ":${PATH}:" in *":${INSTALL_DIR}:"*) ;; *) echo "note: add ${INSTALL_DIR} to PATH" ;; esac
