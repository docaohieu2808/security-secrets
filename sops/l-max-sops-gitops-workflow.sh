#!/usr/bin/env bash
# =============================================================================
# l-max-sops-gitops-workflow.sh — SOPS L-Max: Full GitOps workflow with SOPS
#
# Demonstrates a complete GitOps secrets workflow:
#   - Multi-environment secret management (dev/staging/prod)
#   - Multiple key providers (age for local, GCP KMS for CI/prod)
#   - Flux CD / ArgoCD integration patterns
#   - Automated secret rotation via SOPS re-encryption
#   - Audit: who decrypted what, when
#   - Emergency break-glass decryption
#
# Usage:
#   ./l-max-sops-gitops-workflow.sh [command] [args]
#
# Commands:
#   init              — Initialize SOPS config for all environments
#   encrypt <file>    — Encrypt a secret file for target environment
#   decrypt <file>    — Decrypt a secret file
#   rotate-keys       — Re-encrypt all secrets with new keys
#   diff <file>       — Show plaintext diff between git versions
#   audit             — Show decryption audit log
#   flux-setup        — Configure Flux CD SOPS decryption
#   argo-setup        — Configure ArgoCD SOPS plugin
#
# Prerequisites:
#   - sops, age, git, kubectl, flux/argocd (optional)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_DIR="${SECRETS_DIR:-./k8s/secrets}"
AGE_KEY_FILE="${HOME}/.config/sops/age/keys.txt"
AUDIT_LOG="${SCRIPT_DIR}/.sops-audit.log"

log()     { echo; echo "==> $*"; }
info()    { echo "    [INFO] $*"; }
cmd()     { echo "    \$ $*"; eval "$@"; }
die()     { echo "[ERROR] $*" >&2; exit 1; }
require() { command -v "$1" &>/dev/null || die "$1 not found. $2"; }

# =============================================================================
# init: Create multi-environment .sops.yaml with multiple recipients
# =============================================================================
cmd_init() {
    log "Initializing SOPS GitOps configuration"

    require age    "Install: apt install age"
    require sops   "Install: https://github.com/getsops/sops/releases"

    # Generate age keys per environment if missing
    for env in dev staging prod; do
        local key_file="${HOME}/.config/sops/age/${env}.txt"
        if [[ ! -f "${key_file}" ]]; then
            info "Generating age key for environment: ${env}"
            mkdir -p "$(dirname "${key_file}")"
            age-keygen -o "${key_file}" 2>/dev/null
            chmod 600 "${key_file}"
        fi
        info "Key for ${env}: $(grep '# public key:' "${key_file}" | awk '{print $NF}')"
    done

    # Extract public keys
    DEV_KEY=$(grep '# public key:' "${HOME}/.config/sops/age/dev.txt" | awk '{print $NF}')
    STAGING_KEY=$(grep '# public key:' "${HOME}/.config/sops/age/staging.txt" | awk '{print $NF}')
    PROD_KEY=$(grep '# public key:' "${HOME}/.config/sops/age/prod.txt" | awk '{print $NF}')

    cat > .sops.yaml <<EOF
# .sops.yaml — Multi-environment SOPS configuration
# Commit this file. It contains only public key references.
#
# Key hierarchy:
#   dev     — age key only (local dev, no KMS cost)
#   staging — age key + GCP KMS (CI can decrypt, dev team can too)
#   prod    — GCP KMS only (only CI with Workload Identity can decrypt)

creation_rules:
  # ---- Development environment ----------------------------------------------
  - path_regex: .*/dev/.*\.enc\.ya?ml$
    age: ${DEV_KEY}

  # ---- Staging environment --------------------------------------------------
  - path_regex: .*/staging/.*\.enc\.ya?ml$
    age: ${STAGING_KEY}
    # Uncomment to also allow GCP KMS decryption in CI:
    # gcp_kms: projects/MY_PROJECT/locations/global/keyRings/sops/cryptoKeys/staging

  # ---- Production environment -----------------------------------------------
  # Prod requires GCP KMS — no individual has the decryption key
  - path_regex: .*/prod/.*\.enc\.ya?ml$
    # gcp_kms: projects/MY_PROJECT/locations/global/keyRings/sops/cryptoKeys/prod
    # Fallback age key for break-glass (stored in offline vault):
    age: ${PROD_KEY}

  # ---- Shared / cluster-wide secrets ----------------------------------------
  - path_regex: .*/shared/.*\.enc\.ya?ml$
    age: >-
      ${DEV_KEY},
      ${STAGING_KEY},
      ${PROD_KEY}

  # ---- Default fallback -----------------------------------------------------
  - path_regex: .*\.enc\.ya?ml$
    age: ${DEV_KEY}
EOF

    info "Created .sops.yaml with multi-environment keys"

    # Create directory structure
    mkdir -p "${SECRETS_DIR}"/{dev,staging,prod,shared}
    info "Created secrets directory: ${SECRETS_DIR}"

    # Create example plaintext secret templates
    for env in dev staging prod; do
        local template="${SECRETS_DIR}/${env}/.gitkeep"
        touch "${template}"
    done

    info "Initialization complete. Next: create secrets in ${SECRETS_DIR}/<env>/"
}

# =============================================================================
# encrypt: Encrypt a file for a specific environment
# =============================================================================
cmd_encrypt() {
    local file="${1:-}"
    [[ -n "${file}" ]] || die "Usage: $0 encrypt <plaintext-file.yaml>"
    [[ -f "${file}" ]] || die "File not found: ${file}"

    # Determine output filename (.yaml -> .enc.yaml)
    local encrypted="${file%.yaml}.enc.yaml"
    encrypted="${encrypted%.yml}.enc.yaml"

    log "Encrypting: ${file} -> ${encrypted}"

    # Select key based on path
    local sops_args=()
    if [[ "${file}" == *"/prod/"* ]]; then
        info "Using production keys"
    elif [[ "${file}" == *"/staging/"* ]]; then
        info "Using staging keys"
    else
        info "Using dev keys (SOPS_AGE_KEY_FILE=${AGE_KEY_FILE})"
        export SOPS_AGE_KEY_FILE="${AGE_KEY_FILE}"
    fi

    cmd "sops --encrypt \"${file}\" > \"${encrypted}\""
    info "Encrypted to: ${encrypted} (safe to commit)"

    # Audit log
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ENCRYPT ${file} -> ${encrypted} by $(whoami)@$(hostname)" \
        >> "${AUDIT_LOG}"
}

# =============================================================================
# decrypt: Decrypt a file (with audit logging)
# =============================================================================
cmd_decrypt() {
    local file="${1:-}"
    [[ -n "${file}" ]] || die "Usage: $0 decrypt <encrypted-file.enc.yaml>"
    [[ -f "${file}" ]] || die "File not found: ${file}"

    log "Decrypting: ${file}"

    export SOPS_AGE_KEY_FILE="${AGE_KEY_FILE}"

    # Audit log BEFORE decryption (so we log the attempt even if it fails)
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) DECRYPT ${file} by $(whoami)@$(hostname)" \
        >> "${AUDIT_LOG}"

    cmd "sops --decrypt \"${file}\""
}

# =============================================================================
# rotate-keys: Re-encrypt all secrets with new/updated keys
# Used after onboarding/offboarding team members or key rotation
# =============================================================================
cmd_rotate_keys() {
    log "Rotating keys: re-encrypting all secrets with current .sops.yaml"

    export SOPS_AGE_KEY_FILE="${AGE_KEY_FILE}"

    local count=0
    while IFS= read -r -d '' enc_file; do
        info "Re-encrypting: ${enc_file}"
        # sops updatekeys re-encrypts the file's data key with all current recipients
        sops updatekeys --yes "${enc_file}" || {
            echo "[WARN] Failed to rotate keys for: ${enc_file}" >&2
            continue
        }
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ROTATE ${enc_file} by $(whoami)@$(hostname)" \
            >> "${AUDIT_LOG}"
        count=$((count + 1))
    done < <(find "${SECRETS_DIR}" -name "*.enc.yaml" -print0 2>/dev/null)

    info "Rotated keys for ${count} encrypted files."
    info "Commit the updated encrypted files to Git."
}

# =============================================================================
# diff: Show human-readable diff of encrypted file changes in git
# =============================================================================
cmd_diff() {
    local file="${1:-}"
    [[ -n "${file}" ]] || die "Usage: $0 diff <encrypted-file.enc.yaml>"

    log "Showing plaintext diff for: ${file}"

    export SOPS_AGE_KEY_FILE="${AGE_KEY_FILE}"

    # Configure git to use sops as textconv driver for .enc.yaml files
    # Add to .gitattributes: *.enc.yaml diff=sopsdiffer
    # Add to .git/config: [diff "sopsdiffer"] textconv = sops -d

    if ! git config diff.sopsdiffer.textconv &>/dev/null; then
        info "Configuring git sops textconv driver..."
        git config diff.sopsdiffer.textconv "sops --decrypt"
        echo "*.enc.yaml diff=sopsdiffer" >> .gitattributes
        info "Added sopsdiffer driver to git config"
    fi

    cmd "git diff HEAD -- \"${file}\""
    echo ""
    info "Tip: 'git log -p ${file}' shows full history with decrypted diffs"
}

# =============================================================================
# audit: Display decryption audit log
# =============================================================================
cmd_audit() {
    log "SOPS operation audit log"

    if [[ ! -f "${AUDIT_LOG}" ]]; then
        info "No audit log found at ${AUDIT_LOG}"
        return 0
    fi

    echo ""
    echo "Recent operations (last 50):"
    tail -50 "${AUDIT_LOG}"
    echo ""
    info "Full log: ${AUDIT_LOG}"
    info "Encrypt operations: $(grep -c ENCRYPT "${AUDIT_LOG}" 2>/dev/null || echo 0)"
    info "Decrypt operations: $(grep -c DECRYPT "${AUDIT_LOG}" 2>/dev/null || echo 0)"
    info "Rotate operations:  $(grep -c ROTATE  "${AUDIT_LOG}" 2>/dev/null || echo 0)"
}

# =============================================================================
# flux-setup: Configure Flux CD to decrypt SOPS secrets automatically
# =============================================================================
cmd_flux_setup() {
    log "Configuring Flux CD SOPS decryption"

    require kubectl "Install: https://kubernetes.io/docs/tasks/tools/"
    require flux    "Install: https://fluxcd.io/docs/installation/" || true

    # Create Kubernetes secret with age private key for Flux
    info "Creating sops-age secret in flux-system namespace:"
    echo "    \$ kubectl create secret generic sops-age \\"
    echo "        --namespace=flux-system \\"
    echo "        --from-file=age.agekey=${AGE_KEY_FILE}"
    echo ""

    # Flux Kustomization with SOPS decryption enabled
    cat <<'YAML'
# flux-kustomization-with-sops.yaml — apply with: kubectl apply -f -
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: myapp-secrets
  namespace: flux-system
spec:
  interval: 10m
  sourceRef:
    kind: GitRepository
    name: flux-system
  path: ./k8s/secrets/prod
  prune: true
  decryption:
    provider: sops
    secretRef:
      name: sops-age    # References the sops-age K8s secret above
YAML

    info "Flux will automatically decrypt *.enc.yaml files in the path using the age key"
}

# =============================================================================
# argo-setup: Configure ArgoCD SOPS plugin
# =============================================================================
cmd_argo_setup() {
    log "Configuring ArgoCD SOPS plugin (argocd-vault-plugin or helm-secrets)"

    cat <<'YAML'
# ArgoCD ConfigManagementPlugin for SOPS decryption
# Add to argocd-cm ConfigMap or as a sidecar plugin

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  # Using helm-secrets plugin (wraps helm with sops decryption)
  configManagementPlugins: |
    - name: helm-secrets
      init:
        command: ["/bin/sh", "-c"]
        args: ["helm dependency build || true"]
      generate:
        command: ["/bin/sh", "-c"]
        args: ["helm secrets template $ARGOCD_APP_NAME -n $ARGOCD_APP_NAMESPACE -f $ARGOCD_ENV_HELM_VALUES ."]

# Alternative: ArgoCD Vault Plugin with SOPS backend
# https://argocd-vault-plugin.readthedocs.io/en/stable/backends/#sops
YAML

    info "For modern ArgoCD (v2.6+), use the sidecar plugin pattern:"
    info "See: https://argo-cd.readthedocs.io/en/stable/operator-manual/config-management-plugins/"
}

# --- Main dispatcher ---------------------------------------------------------
main() {
    local command="${1:-help}"
    shift || true

    case "${command}" in
        init)         cmd_init ;;
        encrypt)      cmd_encrypt "$@" ;;
        decrypt)      cmd_decrypt "$@" ;;
        rotate-keys)  cmd_rotate_keys ;;
        diff)         cmd_diff "$@" ;;
        audit)        cmd_audit ;;
        flux-setup)   cmd_flux_setup ;;
        argo-setup)   cmd_argo_setup ;;
        help|--help|-h)
            echo "Usage: $0 <command> [args]"
            echo ""
            echo "Commands:"
            echo "  init              Initialize multi-environment SOPS config"
            echo "  encrypt <file>    Encrypt a secret file"
            echo "  decrypt <file>    Decrypt a secret file (with audit log)"
            echo "  rotate-keys       Re-encrypt all secrets with current keys"
            echo "  diff <file>       Show plaintext git diff of encrypted file"
            echo "  audit             Show SOPS operation audit log"
            echo "  flux-setup        Configure Flux CD SOPS decryption"
            echo "  argo-setup        Configure ArgoCD SOPS plugin"
            ;;
        *)
            die "Unknown command: ${command}. Run '$0 help' for usage."
            ;;
    esac
}

main "$@"
