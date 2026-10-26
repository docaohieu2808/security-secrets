#!/usr/bin/env bash
# End-to-end check of the SOPS labs with throwaway age keys in a temp directory (nothing touches ~/.config).
# Needs: age, sops, openssl.   sops/tests/e2e.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
export SOPS_AGE_KEY_FILE="${TMP}/l1-key.txt"
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }

echo "== l1: age key, .sops.yaml, encrypt, decrypt =="
WORKDIR="${TMP}/l1" "${HERE}/l1-encrypt-yaml-with-age.sh" >/dev/null
enc="${TMP}/l1/example-secret.enc.yaml"
grep -q 'name: myapp-secrets' "${enc}" && pass "metadata stays readable (encrypted_regex)"
if grep -qE 'example-api-key-not-real' "${enc}"; then fail "plaintext found in the encrypted file"; fi
pass "no plaintext in the encrypted file"
other_key="${TMP}/other.txt"; age-keygen -o "${other_key}" 2>/dev/null
if SOPS_AGE_KEY_FILE="${other_key}" sops decrypt "${enc}" >/dev/null 2>&1; then fail "a stranger's key decrypted the file"; fi
pass "a different age key cannot decrypt"

echo "== l-max: per-environment keys, rules, rotation =="
export WORKDIR="${TMP}/gitops" KEYS_DIR="${TMP}/keys"
lmax="${HERE}/l-max-sops-gitops-workflow.sh"
"${lmax}" init >/dev/null
for env in dev staging prod shared; do
  mkdir -p "${WORKDIR}/k8s/secrets/${env}"
  cat > "${WORKDIR}/k8s/secrets/${env}/app.yaml" <<YAML
apiVersion: v1
kind: Secret
metadata: {name: app-${env}, namespace: shop}
stringData: {token: demo-${env}-token}
YAML
  "${lmax}" encrypt "${WORKDIR}/k8s/secrets/${env}/app.yaml" >/dev/null
done
for env in dev staging prod shared; do
  got="$("${lmax}" decrypt "${WORKDIR}/k8s/secrets/${env}/app.enc.yaml" | grep token | awk '{print $2}')"
  [[ "${got}" == "demo-${env}-token" ]] || fail "${env}: decrypted '${got}'"
  pass "${env} round trip (path_regex matched the plaintext input name)"
done
if SOPS_AGE_KEY_FILE="${KEYS_DIR}/dev.txt" sops decrypt "${WORKDIR}/k8s/secrets/prod/app.enc.yaml" >/dev/null 2>&1; then fail "dev key decrypted prod"; fi
pass "dev key cannot decrypt prod"
for env in staging prod; do
  SOPS_AGE_KEY_FILE="${KEYS_DIR}/${env}.txt" sops decrypt "${WORKDIR}/k8s/secrets/shared/app.enc.yaml" >/dev/null || fail "${env} key cannot read shared"
done
pass "shared secrets open with any environment key"

before_mac="$(grep 'mac:' "${WORKDIR}/k8s/secrets/dev/app.enc.yaml")"
"${lmax}" rotate-keys >/dev/null
after_mac="$(grep 'mac:' "${WORKDIR}/k8s/secrets/dev/app.enc.yaml")"
[[ "${before_mac}" != "${after_mac}" ]] || fail "rotate-keys did not change the data key / MAC"
[[ "$("${lmax}" decrypt "${WORKDIR}/k8s/secrets/dev/app.enc.yaml" | grep -c demo-dev-token)" == 1 ]] || fail "dev secret unreadable after rotation"
pass "rotate-keys re-keyed the files and they still decrypt"
audit_out="$("${lmax}" audit)"
grep -q ROTATE <<<"${audit_out}" || fail "audit log has no ROTATE entry"
pass "audit log recorded the rotation"
flux_out="$("${lmax}" flux-setup)"
grep -q 'provider: sops' <<<"${flux_out}" || fail "flux-setup output lacks the decryption block"
pass "flux-setup prints a Kustomization with decryption"
