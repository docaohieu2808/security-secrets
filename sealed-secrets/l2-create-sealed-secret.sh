#!/usr/bin/env bash
# =============================================================================
# l2-create-sealed-secret.sh — Sealed Secrets: Create SealedSecret from K8s Secret
#
# Workflow:
#   1. Create a plain K8s Secret manifest (never commit this)
#   2. Use kubeseal to encrypt it into a SealedSecret (safe to commit)
#   3. Apply SealedSecret to cluster via kubectl or GitOps
#   4. Controller decrypts and creates the native K8s Secret in-cluster
#
# Scopes:
#   strict       — bound to specific name + namespace (most secure, default)
#   namespace-wide — bound to namespace only (name can change)
#   cluster-wide — not bound to name or namespace (use sparingly)
#
# Usage:
#   ./l2-create-sealed-secret.sh
#
# Prerequisites:
#   - kubeseal CLI (see l1-install-controller.yaml for install instructions)
#   - kubectl configured with cluster access
#   - Sealed Secrets controller running in cluster
# =============================================================================
set -euo pipefail

NAMESPACE="${NAMESPACE:-myapp}"
OUTPUT_DIR="./sealed-output"

log()  { echo; echo "==> $*"; }
cmd()  { echo "    \$ $*"; eval "$@"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

check_dependencies() {
    command -v kubeseal &>/dev/null || die "kubeseal not found. See l1-install-controller.yaml for install instructions."
    command -v kubectl  &>/dev/null || die "kubectl not found."
}

mkdir -p "${OUTPUT_DIR}"

# =============================================================================
# 1. Fetch controller's public key (cache locally for offline sealing)
# =============================================================================
fetch_public_key() {
    log "Step 1: Fetch controller public key"

    local pub_key="${OUTPUT_DIR}/sealed-secrets-public-key.pem"

    if [[ -f "${pub_key}" ]]; then
        info "Using cached public key: ${pub_key}"
        info "To refresh: rm ${pub_key} && run this script again"
    else
        cmd "kubeseal --fetch-cert \
            --controller-name=sealed-secrets \
            --controller-namespace=kube-system \
            > ${pub_key}"
        echo "    Public key saved to: ${pub_key}"
    fi

    export SEALED_SECRETS_CERT="${OUTPUT_DIR}/sealed-secrets-public-key.pem"
}

info() { echo "    [INFO] $*"; }

# =============================================================================
# 2. Example: Seal a database credentials Secret (strict scope)
# =============================================================================
seal_database_credentials() {
    log "Step 2: Seal database credentials (strict scope)"

    local plaintext="${OUTPUT_DIR}/db-secret-plaintext.yaml"
    local sealed="${OUTPUT_DIR}/db-secret-sealed.yaml"

    # Create the plaintext secret manifest
    kubectl create secret generic myapp-db-credentials \
        --namespace="${NAMESPACE}" \
        --from-literal=username=myapp_user \
        --from-literal=password=${DB_PASSWORD} \
        --from-literal=host=postgres.internal \
        --from-literal=port=5432 \
        --dry-run=client \
        --output=yaml > "${plaintext}"

    echo "    Plaintext secret: ${plaintext} (DO NOT commit)"

    # Seal with strict scope (bound to name=myapp-db-credentials, ns=myapp)
    cmd "kubeseal \
        --cert=${SEALED_SECRETS_CERT} \
        --scope=strict \
        --format=yaml \
        < ${plaintext} > ${sealed}"

    echo "    SealedSecret: ${sealed} (SAFE to commit)"
    echo ""
    echo "    Preview:"
    head -20 "${sealed}"
}

# =============================================================================
# 3. Example: Seal TLS certificate Secret
# =============================================================================
seal_tls_secret() {
    log "Step 3: Seal TLS certificate Secret"

    local plaintext="${OUTPUT_DIR}/tls-secret-plaintext.yaml"
    local sealed="${OUTPUT_DIR}/tls-secret-sealed.yaml"

    # Create from certificate files (replace with real cert paths)
    # Using placeholder data for demo — replace /dev/stdin with real files
    kubectl create secret tls myapp-tls \
        --namespace="${NAMESPACE}" \
        --cert=<(echo "-----BEGIN CERTIFICATE-----\nPLACEHOLDER\n-----END CERTIFICATE-----") \
        --key=<(echo "-----BEGIN PRIVATE KEY-----\nPLACEHOLDER\n-----END PRIVATE KEY-----") \
        --dry-run=client \
        --output=yaml > "${plaintext}" 2>/dev/null || \
    kubectl create secret generic myapp-tls \
        --namespace="${NAMESPACE}" \
        --from-literal=tls.crt="CERT_PLACEHOLDER" \
        --from-literal=tls.key="KEY_PLACEHOLDER" \
        --dry-run=client \
        --output=yaml > "${plaintext}"

    cmd "kubeseal \
        --cert=${SEALED_SECRETS_CERT} \
        --scope=strict \
        --format=yaml \
        < ${plaintext} > ${sealed}"

    echo "    SealedSecret saved: ${sealed}"
}

# =============================================================================
# 4. Example: Seal with namespace-wide scope (reusable across secret names)
# =============================================================================
seal_namespace_wide() {
    log "Step 4: Seal with namespace-wide scope"

    local plaintext="${OUTPUT_DIR}/api-keys-plaintext.yaml"
    local sealed="${OUTPUT_DIR}/api-keys-sealed.yaml"

    kubectl create secret generic myapp-api-keys \
        --namespace="${NAMESPACE}" \
        --from-literal=stripe_key=sk_live_xxxxxxxxxxxx \
        --from-literal=sendgrid_key=SG.xxxxxxxxxx \
        --dry-run=client \
        --output=yaml > "${plaintext}"

    # namespace-wide: can be renamed without re-sealing
    # Useful for Helm charts that parametrize secret names
    cmd "kubeseal \
        --cert=${SEALED_SECRETS_CERT} \
        --scope=namespace-wide \
        --format=yaml \
        < ${plaintext} > ${sealed}"

    echo "    SealedSecret (namespace-wide): ${sealed}"
}

# =============================================================================
# 5. Apply SealedSecret to cluster
# =============================================================================
apply_sealed_secrets() {
    log "Step 5: Apply SealedSecrets to cluster"

    cmd "kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -"

    for sealed_file in "${OUTPUT_DIR}"/*-sealed.yaml; do
        info "Applying: ${sealed_file}"
        cmd "kubectl apply -f ${sealed_file}"
    done

    echo ""
    info "Waiting for controller to decrypt and create Secrets..."
    sleep 3

    cmd "kubectl get secrets -n ${NAMESPACE}"
    cmd "kubectl get sealedsecrets -n ${NAMESPACE}"
}

# =============================================================================
# 6. Verify decrypted Secret
# =============================================================================
verify_secret() {
    log "Step 6: Verify decrypted Secret exists in cluster"

    cmd "kubectl get secret myapp-db-credentials -n ${NAMESPACE} -o yaml" || \
        info "Secret not yet created — controller may still be processing"

    # Decode a value to verify
    local db_user
    db_user=$(kubectl get secret myapp-db-credentials \
        -n "${NAMESPACE}" \
        -o jsonpath='{.data.username}' 2>/dev/null | base64 -d || echo "not found")
    info "Decoded username: ${db_user}"
}

# =============================================================================
# 7. Key rotation — re-seal after controller key rotation
# =============================================================================
show_rotation_workflow() {
    log "Step 7: Key rotation workflow"

    echo "    After controller rotates its sealing key:"
    echo ""
    echo "    1. Fetch new public key:"
    echo "       kubeseal --fetch-cert --controller-namespace=kube-system > new-key.pem"
    echo ""
    echo "    2. Re-seal all SealedSecrets with new key:"
    echo "       for f in \$(find ./k8s -name '*-sealed.yaml'); do"
    echo "         # Decrypt from cluster, re-seal with new key"
    echo "         kubectl get secret \$(yq .spec.template.metadata.name \$f) \\"
    echo "           -n \$(yq .metadata.namespace \$f) -o yaml \\"
    echo "           | kubeseal --cert new-key.pem -o yaml > \$f"
    echo "       done"
    echo ""
    echo "    3. Commit and push updated SealedSecrets to Git"
    echo ""
    echo "    Note: Old sealing keys are retained by the controller,"
    echo "    so existing SealedSecrets continue to work until re-sealed."
}

# =============================================================================
# 8. Update .gitignore
# =============================================================================
update_gitignore() {
    log "Step 8: Ensure plaintext secrets are gitignored"

    local gitignore="../.gitignore"
    if ! grep -q "plaintext" "${gitignore}" 2>/dev/null; then
        cat >> "${gitignore}" <<'EOF'

# Sealed Secrets: plaintext manifests (sealed *-sealed.yaml ARE safe to commit)
*-plaintext.yaml
*-plain.yaml
*.plaintext.yaml
EOF
        info "Updated .gitignore"
    fi
}

# --- Main --------------------------------------------------------------------
main() {
    check_dependencies
    fetch_public_key
    seal_database_credentials
    seal_tls_secret
    seal_namespace_wide
    apply_sealed_secrets
    verify_secret
    show_rotation_workflow
    update_gitignore

    echo ""
    echo "=== Sealed Secrets demo complete ==="
    echo "    Output dir: ${OUTPUT_DIR}"
    echo "    Commit:     ${OUTPUT_DIR}/*-sealed.yaml"
    echo "    DO NOT commit: ${OUTPUT_DIR}/*-plaintext.yaml"
}

main "$@"
