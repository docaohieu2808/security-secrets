#!/usr/bin/env bash
# =============================================================================
# l5 - Vault Transit: encryption, signing and HMAC as a service (keys never leave Vault)
#
# The application sends data to Vault, stores only the ciphertext, and asks Vault to decrypt when it needs the
# plaintext. Rotating a key does not force a mass re-encryption: old versions still decrypt, and `rewrap` upgrades a
# ciphertext without the plaintext ever reaching the caller.
#
#   export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root-token
#   ./l5-transit-encryption.sh
# Re-runnable: the demo keys are deleted and recreated first (deletion_allowed=true is a lab choice; real keys
# keep the default false so nobody can destroy the data they protect).
# Needs: vault, jq, base64; a dev server from l1.
# =============================================================================
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

MOUNT="transit"
b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

require vault; require jq; require base64
wait_for_vault

log "Step 1: enable Transit at ${MOUNT}/"
ensure_mount "${MOUNT}" transit

reset_key() { # <name> <create args...>
  local name="$1"; shift
  if vault read "${MOUNT}/keys/${name}" >/dev/null 2>&1; then
    vault write "${MOUNT}/keys/${name}/config" deletion_allowed=true >/dev/null
    vault delete "${MOUNT}/keys/${name}" >/dev/null
  fi
  vault write -f "${MOUNT}/keys/${name}" "$@" >/dev/null
  vault write "${MOUNT}/keys/${name}/config" deletion_allowed=true >/dev/null   # a config setting, not a create parameter
  info "created key ${name} ($*)"
}

log "Step 2: named keys, one per purpose"
reset_key user-pii type=aes256-gcm96 exportable=false allow_plaintext_backup=false
# convergent + derived: the same plaintext AND context always give the same ciphertext, which allows equality search
# on encrypted columns at the cost of leaking which rows are equal
reset_key db-field-encryption type=aes256-gcm96 derived=true convergent_encryption=true
reset_key payload-signing type=ed25519
run vault list "${MOUNT}/keys"
run vault read "${MOUNT}/keys/user-pii"

log "Step 3: encrypt (Transit takes base64)"
PLAINTEXT="Hello, this is sensitive PII: SSN 123-45-6789"
ENCRYPT_RESPONSE="$(vault write -format=json "${MOUNT}/encrypt/user-pii" plaintext="$(b64 "${PLAINTEXT}")")"
CIPHERTEXT="$(jq -r '.data.ciphertext' <<<"${ENCRYPT_RESPONSE}")"
info "ciphertext (safe to store in a database): ${CIPHERTEXT}"
assert_eq "key version used" "$(jq -r '.data.key_version' <<<"${ENCRYPT_RESPONSE}")" "1"
log "Batch: several values in one request (the CLI sends k=v pairs as strings, so a JSON array needs a whole-body file)"
batch="$(mktemp)"
trap 'rm -f "${batch}"' EXIT
jq -nc --arg a "$(b64 'email@example.com')" --arg b "$(b64 'phone: 555-0100')" '{batch_input: [{plaintext: $a}, {plaintext: $b}]}' > "${batch}"
assert_eq "batch results" "$(vault write -format=json "${MOUNT}/encrypt/user-pii" @"${batch}" | jq -r '.data.batch_results | length')" "2"

log "Step 4: decrypt"
DECRYPTED="$(vault write -format=json "${MOUNT}/decrypt/user-pii" ciphertext="${CIPHERTEXT}" | jq -r '.data.plaintext' | base64 -d)"
assert_eq "decrypts to the original" "${DECRYPTED}" "${PLAINTEXT}"

log "Step 4b: convergent key - same input + context, same ciphertext"
ctx="$(b64 'tenant-42')"
c1="$(vault write -format=json "${MOUNT}/encrypt/db-field-encryption" plaintext="$(b64 'a@example.com')" context="${ctx}" | jq -r '.data.ciphertext')"
c2="$(vault write -format=json "${MOUNT}/encrypt/db-field-encryption" plaintext="$(b64 'a@example.com')" context="${ctx}" | jq -r '.data.ciphertext')"
assert_eq "deterministic ciphertext" "${c1}" "${c2}"
c3="$(vault write -format=json "${MOUNT}/encrypt/user-pii" plaintext="$(b64 'a@example.com')" | jq -r '.data.ciphertext')"
c4="$(vault write -format=json "${MOUNT}/encrypt/user-pii" plaintext="$(b64 'a@example.com')" | jq -r '.data.ciphertext')"
[[ "${c3}" != "${c4}" ]] || die "non-convergent key produced identical ciphertexts"
info "ok: a normal key gives a different ciphertext every time"

log "Step 5: sign and verify (Ed25519; the hash algorithm is not used for this key type)"
PAYLOAD='{"user_id":42,"action":"transfer","amount":1000}'
SIGNATURE="$(vault write -format=json "${MOUNT}/sign/payload-signing" input="$(b64 "${PAYLOAD}")" | jq -r '.data.signature')"
info "signature: ${SIGNATURE}"
assert_eq "valid signature verifies" "$(vault write -format=json "${MOUNT}/verify/payload-signing" input="$(b64 "${PAYLOAD}")" signature="${SIGNATURE}" | jq -r '.data.valid')" "true"
TAMPERED='{"user_id":42,"action":"transfer","amount":9999}'
assert_eq "tampered payload is rejected" "$(vault write -format=json "${MOUNT}/verify/payload-signing" input="$(b64 "${TAMPERED}")" signature="${SIGNATURE}" | jq -r '.data.valid')" "false"

log "Step 6: HMAC (any key can produce one; here the AES key user-pii)"
HMAC="$(vault write -format=json "${MOUNT}/hmac/user-pii" input="$(b64 "${PAYLOAD}")" algorithm=sha2-256 | jq -r '.data.hmac')"
info "hmac: ${HMAC}"
assert_eq "hmac verifies" "$(vault write -format=json "${MOUNT}/verify/user-pii" input="$(b64 "${PAYLOAD}")" hmac="${HMAC}" algorithm=sha2-256 | jq -r '.data.valid')" "true"

log "Step 7: rotate the key (version 2); version 1 ciphertext keeps working"
run vault write -f "${MOUNT}/keys/user-pii/rotate"
assert_eq "latest version" "$(vault read -format=json "${MOUNT}/keys/user-pii" | jq -r '.data.latest_version')" "2"
NEW_RESPONSE="$(vault write -format=json "${MOUNT}/encrypt/user-pii" plaintext="$(b64 "${PLAINTEXT}")")"
assert_eq "new encryptions use version 2" "$(jq -r '.data.key_version' <<<"${NEW_RESPONSE}")" "2"
assert_eq "old ciphertext still decrypts" "$(vault write -format=json "${MOUNT}/decrypt/user-pii" ciphertext="${CIPHERTEXT}" | jq -r '.data.plaintext' | base64 -d)" "${PLAINTEXT}"

log "Step 8: rewrap - upgrade the old ciphertext to version 2 without exposing the plaintext"
REWRAPPED="$(vault write -format=json "${MOUNT}/rewrap/user-pii" ciphertext="${CIPHERTEXT}" | jq -r '.data.ciphertext')"
info "before: ${CIPHERTEXT}"
info "after:  ${REWRAPPED}"
[[ "${REWRAPPED}" == vault:v2:* ]] || die "rewrapped ciphertext is not version 2"

log "Step 9: retire version 1"
run vault write "${MOUNT}/keys/user-pii/config" min_decryption_version=2
if vault write "${MOUNT}/decrypt/user-pii" ciphertext="${CIPHERTEXT}" >/dev/null 2>&1; then
  die "a version 1 ciphertext still decrypts after min_decryption_version=2"
fi
info "ok: the version 1 ciphertext is rejected now (rewrap everything BEFORE raising min_decryption_version)"
assert_eq "the rewrapped ciphertext still works" "$(vault write -format=json "${MOUNT}/decrypt/user-pii" ciphertext="${REWRAPPED}" | jq -r '.data.plaintext' | base64 -d)" "${PLAINTEXT}"

log "Step 10: least-privilege policy for an application"
vault policy write app-transit-policy - <<'POLICY'
# encrypt, decrypt and HMAC with the user-pii key only; no key metadata, rotation or other keys
path "transit/encrypt/user-pii" {
  capabilities = ["update"]
}
path "transit/decrypt/user-pii" {
  capabilities = ["update"]
}
path "transit/hmac/user-pii" {
  capabilities = ["update"]
}
POLICY

log "Transit demo complete. UI: ${VAULT_ADDR}/ui/vault/secrets/${MOUNT}/list"
