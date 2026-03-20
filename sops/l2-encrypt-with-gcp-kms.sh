#!/usr/bin/env bash
# =============================================================================
# l2-encrypt-with-gcp-kms.sh — SOPS: Encrypt secrets using GCP KMS key
#
# Uses Google Cloud KMS as the key provider instead of age.
# Advantages over age:
#   - No private key to manage — GCP IAM controls access
#   - Full audit trail in Cloud Audit Logs
#   - Key rotation handled by GCP
#   - Works with Workload Identity (no SA key files in CI)
#
# Usage:
#   export GCP_PROJECT=my-project
#   export GCP_KMS_KEYRING=my-keyring
#   export GCP_KMS_KEY=my-key
#   export GCP_LOCATION=global
#   ./l2-encrypt-with-gcp-kms.sh
#
# Prerequisites:
#   - sops: https://github.com/getsops/sops/releases
#   - gcloud CLI authenticated: gcloud auth application-default login
#   - KMS key created and IAM binding granted (roles/cloudkms.cryptoKeyEncrypterDecrypter)
# =============================================================================
set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-my-gcp-project}"
GCP_LOCATION="${GCP_LOCATION:-global}"
GCP_KEYRING="${GCP_KMS_KEYRING:-sops-keyring}"
GCP_KEY="${GCP_KMS_KEY:-sops-key}"
GCP_KMS_RESOURCE="projects/${GCP_PROJECT}/locations/${GCP_LOCATION}/keyRings/${GCP_KEYRING}/cryptoKeys/${GCP_KEY}"

SOPS_CONFIG=".sops.yaml"
EXAMPLE_SECRET="example-app-secret.yaml"
ENCRYPTED_SECRET="example-app-secret.enc.yaml"

log()  { echo; echo "==> $*"; }
cmd()  { echo "    \$ $*"; eval "$@"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

check_dependencies() {
    command -v sops   &>/dev/null || die "sops not found. Install: https://github.com/getsops/sops/releases"
    command -v gcloud &>/dev/null || die "gcloud not found. Install: https://cloud.google.com/sdk/docs/install"
}

# =============================================================================
# 1. Create GCP KMS key (if it doesn't exist)
# =============================================================================
setup_gcp_kms() {
    log "Step 1: Set up GCP KMS key"
    echo "    Project:  ${GCP_PROJECT}"
    echo "    Location: ${GCP_LOCATION}"
    echo "    Keyring:  ${GCP_KEYRING}"
    echo "    Key:      ${GCP_KEY}"
    echo "    Resource: ${GCP_KMS_RESOURCE}"

    # Enable KMS API
    cmd "gcloud services enable cloudkms.googleapis.com --project=${GCP_PROJECT}" || true

    # Create keyring (idempotent)
    cmd "gcloud kms keyrings create ${GCP_KEYRING} \
        --location=${GCP_LOCATION} \
        --project=${GCP_PROJECT}" 2>/dev/null || \
        echo "    Keyring already exists — continuing"

    # Create symmetric encryption key (idempotent)
    cmd "gcloud kms keys create ${GCP_KEY} \
        --keyring=${GCP_KEYRING} \
        --location=${GCP_LOCATION} \
        --project=${GCP_PROJECT} \
        --purpose=encryption \
        --rotation-period=90d \
        --next-rotation-time=$(date -d '+90 days' --iso-8601 2>/dev/null || date -v+90d +%Y-%m-%d)" 2>/dev/null || \
        echo "    Key already exists — continuing"

    # Grant current user encrypter/decrypter role
    CURRENT_USER=$(gcloud config get-value account 2>/dev/null || echo "unknown")
    echo "    Granting roles/cloudkms.cryptoKeyEncrypterDecrypter to ${CURRENT_USER}"
    cmd "gcloud kms keys add-iam-policy-binding ${GCP_KEY} \
        --keyring=${GCP_KEYRING} \
        --location=${GCP_LOCATION} \
        --project=${GCP_PROJECT} \
        --member=user:${CURRENT_USER} \
        --role=roles/cloudkms.cryptoKeyEncrypterDecrypter" || true
}

# =============================================================================
# 2. Create .sops.yaml for GCP KMS
# =============================================================================
create_sops_config() {
    log "Step 2: Create .sops.yaml for GCP KMS"

    cat > "${SOPS_CONFIG}" <<EOF
# .sops.yaml — SOPS with GCP KMS
# Commit this file (contains only public key references, not secrets)

creation_rules:
  # Kubernetes secret manifests — encrypt with GCP KMS
  - path_regex: .*secret.*\.ya?ml$
    gcp_kms: ${GCP_KMS_RESOURCE}

  # Multi-provider: use both GCP KMS and age for redundancy
  # Either key can decrypt — useful for break-glass access
  - path_regex: secrets/.*\.ya?ml$
    gcp_kms: ${GCP_KMS_RESOURCE}
    age: age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

  # Environment files
  - path_regex: \.env\.(prod|staging)$
    gcp_kms: ${GCP_KMS_RESOURCE}

  # Default fallback
  - path_regex: .*
    gcp_kms: ${GCP_KMS_RESOURCE}
EOF

    echo "    Created ${SOPS_CONFIG}"
}

# =============================================================================
# 3. Create example plaintext secret
# =============================================================================
create_example_secret() {
    log "Step 3: Create example plaintext secret"

    cat > "${EXAMPLE_SECRET}" <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: myapp-gcp-secrets
  namespace: myapp
type: Opaque
stringData:
  db_password: "${DB_PASSWORD}"
  gcs_bucket: "my-app-assets-bucket"
  bigquery_dataset: "analytics_prod"
  pubsub_topic: "projects/my-project/topics/events"
  oauth_client_secret: "oauth-client-secret-value"
EOF

    echo "    Created ${EXAMPLE_SECRET}"
}

# =============================================================================
# 4. Encrypt with GCP KMS
# =============================================================================
encrypt_with_gcp_kms() {
    log "Step 4: Encrypt with GCP KMS"

    # SOPS reads GCP credentials from Application Default Credentials (ADC)
    # In CI, use Workload Identity (GKE) or service account key (legacy)
    cmd "sops --encrypt \
        --gcp-kms ${GCP_KMS_RESOURCE} \
        ${EXAMPLE_SECRET} > ${ENCRYPTED_SECRET}"

    echo "    Encrypted: ${ENCRYPTED_SECRET}"
    echo "    Preview of encrypted file:"
    head -20 "${ENCRYPTED_SECRET}"
}

# =============================================================================
# 5. Decrypt
# =============================================================================
decrypt_with_gcp_kms() {
    log "Step 5: Decrypt with GCP KMS"
    cmd "sops --decrypt ${ENCRYPTED_SECRET}"
}

# =============================================================================
# 6. Grant CI/CD service account access to KMS key
# =============================================================================
setup_ci_access() {
    log "Step 6: Grant CI/CD service account KMS access"

    local CI_SA="ci-deployer@${GCP_PROJECT}.iam.gserviceaccount.com"
    echo "    CI service account: ${CI_SA}"
    echo "    Run this to grant access:"
    echo ""
    echo "    gcloud kms keys add-iam-policy-binding ${GCP_KEY} \\"
    echo "      --keyring=${GCP_KEYRING} \\"
    echo "      --location=${GCP_LOCATION} \\"
    echo "      --project=${GCP_PROJECT} \\"
    echo "      --member=serviceAccount:${CI_SA} \\"
    echo "      --role=roles/cloudkms.cryptoKeyEncrypterDecrypter"
    echo ""
    echo "    For GKE Workload Identity (no key files needed):"
    echo "    gcloud iam service-accounts add-iam-policy-binding ${CI_SA} \\"
    echo "      --role=roles/iam.workloadIdentityUser \\"
    echo "      --member=serviceAccount:${GCP_PROJECT}.svc.id.goog[ci-namespace/ci-sa]"
}

# =============================================================================
# 7. GitOps CI usage example
# =============================================================================
show_gitops_usage() {
    log "Step 7: GitOps usage in CI pipeline"
    echo ""
    cat <<'YAML'
# GitHub Actions example with GCP Workload Identity Federation
- name: Authenticate to GCP
  uses: google-github-actions/auth@v2
  with:
    workload_identity_provider: projects/123/locations/global/workloadIdentityPools/github/providers/github
    service_account: ci-deployer@my-project.iam.gserviceaccount.com

- name: Decrypt and apply secrets
  run: |
    sops --decrypt k8s/secrets/myapp.enc.yaml | kubectl apply -f -
YAML
}

# --- Main --------------------------------------------------------------------
main() {
    check_dependencies
    setup_gcp_kms
    create_sops_config
    create_example_secret
    encrypt_with_gcp_kms
    decrypt_with_gcp_kms
    setup_ci_access
    show_gitops_usage

    echo ""
    echo "=== SOPS + GCP KMS setup complete ==="
    echo "    KMS Key:   ${GCP_KMS_RESOURCE}"
    echo "    Config:    ${SOPS_CONFIG}"
    echo "    Encrypted: ${ENCRYPTED_SECRET} (commit this)"
    echo "    Plaintext: ${EXAMPLE_SECRET} (DO NOT commit)"
}

main "$@"
