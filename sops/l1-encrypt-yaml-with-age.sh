#!/usr/bin/env bash
# =============================================================================
# l1-encrypt-yaml-with-age.sh — SOPS: Encrypt YAML secrets using age key
#
# SOPS (Secrets OPerationS) encrypts only the VALUES in YAML/JSON files,
# leaving keys in plaintext — diffs remain readable in Git.
#
# age is a simple, modern encryption tool (replaces GPG for most use cases).
#
# Workflow:
#   1. Generate age keypair (once per operator/CI system)
#   2. Configure SOPS to use the age public key via .sops.yaml
#   3. Encrypt secrets file with: sops --encrypt
#   4. Commit encrypted file to Git (safe)
#   5. Decrypt at deploy time with: sops --decrypt (requires private key)
#
# Usage:
#   ./l1-encrypt-yaml-with-age.sh
#
# Prerequisites:
#   - age:  apt install age  OR  brew install age
#   - sops: apt install sops OR  brew install sops OR
#           https://github.com/getsops/sops/releases
# =============================================================================
set -euo pipefail

AGE_KEY_FILE="${HOME}/.config/sops/age/keys.txt"
SOPS_CONFIG=".sops.yaml"
EXAMPLE_SECRET="example-secret.yaml"
ENCRYPTED_SECRET="example-secret.enc.yaml"

log()  { echo; echo "==> $*"; }
cmd()  { echo "    \$ $*"; eval "$@"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

check_dependencies() {
    command -v age      &>/dev/null || die "age not found.  Install: apt install age"
    command -v age-keygen &>/dev/null || die "age-keygen not found. Install: apt install age"
    command -v sops     &>/dev/null || die "sops not found. Install: https://github.com/getsops/sops/releases"
}

# =============================================================================
# 1. Generate age keypair
# =============================================================================
generate_age_key() {
    log "Step 1: Generate age keypair"

    if [[ -f "${AGE_KEY_FILE}" ]]; then
        echo "    age key already exists at ${AGE_KEY_FILE} — skipping generation"
        echo "    To regenerate: rm ${AGE_KEY_FILE} && age-keygen -o ${AGE_KEY_FILE}"
    else
        mkdir -p "$(dirname "${AGE_KEY_FILE}")"
        cmd "age-keygen -o ${AGE_KEY_FILE}"
        chmod 600 "${AGE_KEY_FILE}"
        echo "    Private key saved to: ${AGE_KEY_FILE}"
        echo "    IMPORTANT: Back this up securely. Loss = permanent data loss."
    fi

    # Extract public key for use in .sops.yaml
    AGE_PUBLIC_KEY=$(grep "^# public key:" "${AGE_KEY_FILE}" | awk '{print $NF}')
    echo "    Public key: ${AGE_PUBLIC_KEY}"
    export AGE_PUBLIC_KEY
}

# =============================================================================
# 2. Create .sops.yaml configuration
# =============================================================================
create_sops_config() {
    log "Step 2: Create .sops.yaml configuration"

    # .sops.yaml tells SOPS which key to use for each file pattern
    # Multiple recipients (age public keys) can decrypt — useful for teams
    cat > "${SOPS_CONFIG}" <<EOF
# .sops.yaml — SOPS encryption configuration
# Commit this file to Git (it only contains public keys)
#
# Rules are matched top-to-bottom; first match wins.
# path_regex applies to the file path being encrypted/decrypted.

creation_rules:
  # Kubernetes secrets — encrypt with age + optionally GCP/AWS KMS for CI
  - path_regex: .*secret.*\.ya?ml$
    age: >-
      ${AGE_PUBLIC_KEY}
    # Add team members' public keys here (comma-separated):
    # age: >-
    #   ${AGE_PUBLIC_KEY},
    #   age1xxxxxxxxxx_teammate1,
    #   age1xxxxxxxxxx_teammate2

  # Environment files
  - path_regex: \.env\..*
    age: ${AGE_PUBLIC_KEY}

  # All other YAML files in secrets/ directory
  - path_regex: secrets/.*\.ya?ml$
    age: ${AGE_PUBLIC_KEY}

  # Default fallback rule
  - path_regex: .*
    age: ${AGE_PUBLIC_KEY}
EOF

    echo "    Created ${SOPS_CONFIG}"
    cat "${SOPS_CONFIG}"
}

# =============================================================================
# 3. Create example plaintext secret (NEVER commit this)
# =============================================================================
create_example_secret() {
    log "Step 3: Create example plaintext secret file (do not commit this)"

    cat > "${EXAMPLE_SECRET}" <<'EOF'
# example-secret.yaml — PLAINTEXT (never commit this file)
apiVersion: v1
kind: Secret
metadata:
  name: myapp-secrets
  namespace: myapp
type: Opaque
stringData:
  database_url: "postgresql://user:${DB_PASSWORD}@postgres:5432/myapp"
  api_key: "sk_live_abcdef1234567890"
  jwt_secret: "my-super-secret-jwt-signing-key-32chars"
  redis_password: "${REDIS_PASSWORD}"
  smtp_password: "${SMTP_PASSWORD}"
EOF

    echo "    Created ${EXAMPLE_SECRET}"
    echo "    WARNING: Add '${EXAMPLE_SECRET}' to .gitignore before committing"
}

# =============================================================================
# 4. Encrypt the secret file
# =============================================================================
encrypt_secret() {
    log "Step 4: Encrypt secret file with SOPS + age"

    # SOPS_AGE_KEY_FILE tells SOPS where the private key is for encryption
    cmd "SOPS_AGE_KEY_FILE=${AGE_KEY_FILE} sops --encrypt ${EXAMPLE_SECRET} > ${ENCRYPTED_SECRET}"

    echo "    Encrypted file: ${ENCRYPTED_SECRET}"
    echo "    Safe to commit: YES"
    echo ""
    echo "    Encrypted content preview:"
    head -30 "${ENCRYPTED_SECRET}"
}

# =============================================================================
# 5. Decrypt the encrypted file
# =============================================================================
decrypt_secret() {
    log "Step 5: Decrypt secret file"

    cmd "SOPS_AGE_KEY_FILE=${AGE_KEY_FILE} sops --decrypt ${ENCRYPTED_SECRET}"

    echo ""
    echo "    Decrypt to file:"
    cmd "SOPS_AGE_KEY_FILE=${AGE_KEY_FILE} sops --decrypt ${ENCRYPTED_SECRET} > /tmp/decrypted-secret.yaml"
    echo "    Decrypted to /tmp/decrypted-secret.yaml (never write to project directory)"
}

# =============================================================================
# 6. Edit encrypted file in-place (SOPS decrypts, opens editor, re-encrypts)
# =============================================================================
show_edit_usage() {
    log "Step 6: Edit encrypted file in-place"
    echo "    To edit an encrypted file directly:"
    echo "    \$ SOPS_AGE_KEY_FILE=${AGE_KEY_FILE} sops ${ENCRYPTED_SECRET}"
    echo ""
    echo "    SOPS will:"
    echo "      1. Decrypt to a temp file"
    echo "      2. Open \$EDITOR"
    echo "      3. Re-encrypt on save"
    echo "      4. Only changed values appear in git diff"
}

# =============================================================================
# 7. Update .gitignore to protect plaintext files
# =============================================================================
update_gitignore() {
    log "Step 7: Update .gitignore"

    local gitignore="../.gitignore"
    if ! grep -q "example-secret.yaml" "${gitignore}" 2>/dev/null; then
        cat >> "${gitignore}" <<'EOF'

# SOPS: plaintext secrets (encrypted .enc.yaml files ARE safe to commit)
*-secret.yaml
*-secrets.yaml
*.secret.yaml
!*.enc.yaml
.sops-age-key.txt
EOF
        echo "    Updated ${gitignore}"
    else
        echo "    .gitignore already configured"
    fi
}

# =============================================================================
# 8. Use in CI/CD — decrypt with key from environment variable
# =============================================================================
show_ci_usage() {
    log "Step 8: CI/CD usage"
    echo ""
    echo "    In CI (GitHub Actions / Jenkins), store age private key as a secret:"
    echo ""
    echo "    GitHub Actions example:"
    cat <<'YAML'
    - name: Decrypt secrets
      env:
        SOPS_AGE_KEY: ${{ secrets.AGE_PRIVATE_KEY }}
      run: |
        echo "$SOPS_AGE_KEY" > /tmp/age-key.txt
        SOPS_AGE_KEY_FILE=/tmp/age-key.txt sops --decrypt k8s/secret.enc.yaml | kubectl apply -f -
        rm /tmp/age-key.txt
YAML
    echo ""
    echo "    Or use SOPS_AGE_KEY env var directly (no file needed):"
    echo "    \$ export SOPS_AGE_KEY=\$(cat ~/.config/sops/age/keys.txt | grep -v '^#')"
    echo "    \$ sops --decrypt ${ENCRYPTED_SECRET}"
}

# --- Main --------------------------------------------------------------------
main() {
    check_dependencies
    generate_age_key
    create_sops_config
    create_example_secret
    encrypt_secret
    decrypt_secret
    show_edit_usage
    update_gitignore
    show_ci_usage

    echo ""
    echo "=== SOPS + age setup complete ==="
    echo "    Private key: ${AGE_KEY_FILE}"
    echo "    Config:      ${SOPS_CONFIG}"
    echo "    Encrypted:   ${ENCRYPTED_SECRET} (commit this)"
    echo "    Plaintext:   ${EXAMPLE_SECRET} (DO NOT commit)"
}

main "$@"
