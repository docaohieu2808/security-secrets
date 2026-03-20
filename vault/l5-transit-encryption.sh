#!/usr/bin/env bash
# =============================================================================
# l5-transit-encryption.sh — Vault: Transit engine encrypt/decrypt as a service
#
# Transit engine provides cryptographic operations WITHOUT storing the plaintext.
# Applications encrypt/decrypt data through Vault API — keys never leave Vault.
#
# Use cases:
#   - Encrypt PII/PAN data before storing in database
#   - Sign and verify application payloads (JWT-like)
#   - Generate HMACs for tamper detection
#   - Key rotation without re-encrypting all data (convergent encryption)
#   - Rewrap ciphertexts after key rotation
#
# Usage:
#   export VAULT_ADDR=http://127.0.0.1:8200
#   export VAULT_TOKEN=dev-root-token
#   ./l5-transit-encryption.sh
#
# Prerequisites:
#   - vault CLI, base64, jq
# =============================================================================
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"
MOUNT_PATH="transit"

export VAULT_ADDR VAULT_TOKEN

log()  { echo; echo "==> $*"; }
cmd()  { echo "    \$ $*"; eval "$@"; }

# =============================================================================
# 1. Enable Transit secrets engine
# =============================================================================
log "Step 1: Enable Transit secrets engine at '${MOUNT_PATH}/'"
vault secrets enable -path=${MOUNT_PATH} transit 2>/dev/null || \
    echo "    (already enabled — continuing)"

# =============================================================================
# 2. Create encryption keys for different use cases
# =============================================================================
log "Step 2: Create named encryption keys"

# Key for encrypting user PII (AES-256-GCM96 — default, fast, authenticated)
cmd "vault write -f ${MOUNT_PATH}/keys/user-pii \
    type=aes256-gcm96 \
    deletion_allowed=false \
    exportable=false \
    allow_plaintext_backup=false"

# Key for database field encryption (convergent = same plaintext → same ciphertext,
# useful for encrypted search/indexing but reduces security slightly)
cmd "vault write -f ${MOUNT_PATH}/keys/db-field-encryption \
    type=aes256-gcm96 \
    convergent_encryption=true \
    derived=true \
    deletion_allowed=false"

# Key for signing payloads (Ed25519 — fast EdDSA signatures)
cmd "vault write -f ${MOUNT_PATH}/keys/payload-signing \
    type=ed25519 \
    deletion_allowed=false"

# Key for HMAC operations (sha2-256 HMAC)
cmd "vault write -f ${MOUNT_PATH}/keys/hmac-auth \
    type=hmac \
    deletion_allowed=false" || \
    # HMAC key type may need different syntax depending on Vault version
    cmd "vault write -f ${MOUNT_PATH}/keys/hmac-auth type=aes256-gcm96"

log "All transit keys:"
cmd "vault list ${MOUNT_PATH}/keys"

# Key details
cmd "vault read ${MOUNT_PATH}/keys/user-pii"

# =============================================================================
# 3. Encrypt plaintext data
# =============================================================================
log "Step 3: Encrypt plaintext (Transit receives base64-encoded input)"

PLAINTEXT="Hello, this is sensitive PII: SSN 123-45-6789"
PLAINTEXT_B64=$(echo -n "${PLAINTEXT}" | base64)
echo "    Plaintext: ${PLAINTEXT}"
echo "    Base64:    ${PLAINTEXT_B64}"

# Encrypt using user-pii key
ENCRYPT_RESPONSE=$(vault write -format=json ${MOUNT_PATH}/encrypt/user-pii \
    plaintext="${PLAINTEXT_B64}")
CIPHERTEXT=$(echo "${ENCRYPT_RESPONSE}" | jq -r '.data.ciphertext')
KEY_VERSION=$(echo "${ENCRYPT_RESPONSE}" | jq -r '.data.key_version')

echo "    Ciphertext: ${CIPHERTEXT}"
echo "    Key version used: ${KEY_VERSION}"
echo "    (Store this ciphertext in your database — it is safe to store)"

# Encrypt batch of items (more efficient for bulk operations)
log "Batch encrypt multiple values:"
cmd "vault write ${MOUNT_PATH}/encrypt/user-pii \
    batch_input='[
        {\"plaintext\": \"$(echo -n 'email@example.com' | base64)\"},
        {\"plaintext\": \"$(echo -n 'phone: 555-0100' | base64)\"},
        {\"plaintext\": \"$(echo -n 'DOB: 1990-01-15' | base64)\"}
    ]'"

# =============================================================================
# 4. Decrypt ciphertext
# =============================================================================
log "Step 4: Decrypt ciphertext"
DECRYPT_RESPONSE=$(vault write -format=json ${MOUNT_PATH}/decrypt/user-pii \
    ciphertext="${CIPHERTEXT}")
DECRYPTED_B64=$(echo "${DECRYPT_RESPONSE}" | jq -r '.data.plaintext')
DECRYPTED=$(echo "${DECRYPTED_B64}" | base64 -d)

echo "    Decrypted base64: ${DECRYPTED_B64}"
echo "    Decrypted text:   ${DECRYPTED}"
[[ "${DECRYPTED}" == "${PLAINTEXT}" ]] && echo "    Verification: PASSED" || echo "    Verification: FAILED"

# =============================================================================
# 5. Sign and verify payloads
# =============================================================================
log "Step 5: Sign and verify a payload using Ed25519 key"

PAYLOAD='{"user_id":42,"action":"transfer","amount":1000,"ts":1700000000}'
PAYLOAD_B64=$(echo -n "${PAYLOAD}" | base64)

# Sign the payload
SIGN_RESPONSE=$(vault write -format=json ${MOUNT_PATH}/sign/payload-signing \
    input="${PAYLOAD_B64}" \
    hash_algorithm=sha2-256)
SIGNATURE=$(echo "${SIGN_RESPONSE}" | jq -r '.data.signature')
echo "    Payload:   ${PAYLOAD}"
echo "    Signature: ${SIGNATURE}"

# Verify the signature
VERIFY_RESPONSE=$(vault write -format=json ${MOUNT_PATH}/verify/payload-signing \
    input="${PAYLOAD_B64}" \
    signature="${SIGNATURE}" \
    hash_algorithm=sha2-256)
VALID=$(echo "${VERIFY_RESPONSE}" | jq -r '.data.valid')
echo "    Signature valid: ${VALID}"

# Verify tampered payload (should fail)
TAMPERED_B64=$(echo -n '{"user_id":42,"action":"transfer","amount":9999,"ts":1700000000}' | base64)
TAMPERED_VERIFY=$(vault write -format=json ${MOUNT_PATH}/verify/payload-signing \
    input="${TAMPERED_B64}" \
    signature="${SIGNATURE}" \
    hash_algorithm=sha2-256 2>/dev/null || echo '{"data":{"valid":false}}')
echo "    Tampered payload valid: $(echo "${TAMPERED_VERIFY}" | jq -r '.data.valid')"

# =============================================================================
# 6. HMAC generation for tamper detection
# =============================================================================
log "Step 6: Generate HMAC for data integrity verification"
HMAC_RESPONSE=$(vault write -format=json ${MOUNT_PATH}/hmac/user-pii \
    input="${PAYLOAD_B64}" \
    algorithm=sha2-256)
HMAC=$(echo "${HMAC_RESPONSE}" | jq -r '.data.hmac')
echo "    HMAC: ${HMAC}"

# Verify HMAC
cmd "vault write ${MOUNT_PATH}/verify/user-pii \
    input='${PAYLOAD_B64}' \
    hmac='${HMAC}' \
    algorithm=sha2-256"

# =============================================================================
# 7. Key rotation — new version created, old versions still decrypt
# =============================================================================
log "Step 7: Rotate encryption key (creates new key version)"
cmd "vault write -f ${MOUNT_PATH}/keys/user-pii/rotate"
cmd "vault read ${MOUNT_PATH}/keys/user-pii"

# New encryptions use the latest key version automatically
NEW_CIPHERTEXT=$(vault write -format=json ${MOUNT_PATH}/encrypt/user-pii \
    plaintext="${PLAINTEXT_B64}" | jq -r '.data.ciphertext')
echo "    New ciphertext (key v2): ${NEW_CIPHERTEXT}"

# Old ciphertext still decrypts (key v1 still available)
OLD_DECRYPTED=$(vault write -format=json ${MOUNT_PATH}/decrypt/user-pii \
    ciphertext="${CIPHERTEXT}" | jq -r '.data.plaintext' | base64 -d)
echo "    Old ciphertext still decrypts: ${OLD_DECRYPTED}"

# =============================================================================
# 8. Rewrap — re-encrypt old ciphertext with latest key version
# =============================================================================
log "Step 8: Rewrap old ciphertext to latest key version"
REWRAP_RESPONSE=$(vault write -format=json ${MOUNT_PATH}/rewrap/user-pii \
    ciphertext="${CIPHERTEXT}")
REWRAPPED=$(echo "${REWRAP_RESPONSE}" | jq -r '.data.ciphertext')
echo "    Original:  ${CIPHERTEXT}"
echo "    Rewrapped: ${REWRAPPED}"
echo "    (Rewrapped ciphertext uses latest key version — run rewrap job after each rotation)"

# =============================================================================
# 9. Set minimum decryption version (retire old key versions)
# =============================================================================
log "Step 9: Set minimum decryption version to retire key v1"
cmd "vault write ${MOUNT_PATH}/keys/user-pii/config \
    min_decryption_version=2 \
    min_encryption_version=2"
echo "    Key v1 ciphertext will now be rejected (must rewrap before retiring)"

# =============================================================================
# 10. Vault policy for application transit access (least-privilege)
# =============================================================================
log "Step 10: Create Vault policy for app transit encrypt/decrypt only"
vault policy write app-transit-policy - <<'EOF'
# Allow encrypting with user-pii key only
path "transit/encrypt/user-pii" {
  capabilities = ["update"]
}

# Allow decrypting with user-pii key only
path "transit/decrypt/user-pii" {
  capabilities = ["update"]
}

# Allow HMAC generation for integrity checks
path "transit/hmac/user-pii" {
  capabilities = ["update"]
}

# No access to key metadata, rotation, or other keys
EOF

log "Transit encryption demo complete."
log "Vault UI: ${VAULT_ADDR}/ui/vault/secrets/${MOUNT_PATH}/list"
