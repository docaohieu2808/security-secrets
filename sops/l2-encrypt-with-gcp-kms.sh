#!/usr/bin/env bash
# =============================================================================
# l2 - SOPS + GCP KMS: no private key file to guard, IAM decides who can decrypt
#
# Compared with age:
#   - the data key is wrapped by a key that never leaves Cloud KMS; access is an IAM binding
#   - every encrypt/decrypt call lands in Cloud Audit Logs (the real answer to "who decrypted what")
#   - rotation of the wrapping key is automatic; CI can use Workload Identity Federation (no key files)
#
# THIS LEVEL NEEDS A GCP PROJECT. CI only lints it (shellcheck); it cannot run without cloud credentials.
#
# Usage:
#   export GCP_PROJECT=my-project            # required
#   export GCP_LOCATION=global GCP_KMS_KEYRING=sops GCP_KMS_KEY=sops-key      # optional, shown values are the defaults
#   export BREAKGLASS_AGE_PUBLIC_KEY=age1... # optional second recipient kept offline
#   ./l2-encrypt-with-gcp-kms.sh
# Needs: sops >= 3.9, gcloud (authenticated: gcloud auth application-default login)
# =============================================================================
set -euo pipefail

: "${GCP_PROJECT:?set GCP_PROJECT}"
GCP_LOCATION="${GCP_LOCATION:-global}"
GCP_KEYRING="${GCP_KMS_KEYRING:-sops}"
GCP_KEY="${GCP_KMS_KEY:-sops-key}"
GCP_KMS_RESOURCE="projects/${GCP_PROJECT}/locations/${GCP_LOCATION}/keyRings/${GCP_KEYRING}/cryptoKeys/${GCP_KEY}"
WORKDIR="${WORKDIR:-./sops-gcp-demo}"
PLAINTEXT="${WORKDIR}/example-app-secret.yaml"
ENCRYPTED="${WORKDIR}/example-app-secret.enc.yaml"

log() { printf '\n==> %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

for tool in sops gcloud; do command -v "${tool}" >/dev/null || die "${tool} not found"; done
mkdir -p "${WORKDIR}"

# 1. Key ring + key. `describe` first: a failing create is a real error (permissions, quota, API disabled)
#    and must not be mistaken for "already exists".
setup_gcp_kms() {
  log "Step 1: KMS key ${GCP_KMS_RESOURCE}"
  gcloud services enable cloudkms.googleapis.com --project="${GCP_PROJECT}"

  if gcloud kms keyrings describe "${GCP_KEYRING}" --location="${GCP_LOCATION}" --project="${GCP_PROJECT}" >/dev/null 2>&1; then
    echo "    keyring ${GCP_KEYRING} exists"
  else
    gcloud kms keyrings create "${GCP_KEYRING}" --location="${GCP_LOCATION}" --project="${GCP_PROJECT}"
  fi

  if gcloud kms keys describe "${GCP_KEY}" --keyring="${GCP_KEYRING}" --location="${GCP_LOCATION}" --project="${GCP_PROJECT}" >/dev/null 2>&1; then
    echo "    key ${GCP_KEY} exists"
  else
    local next_rotation
    next_rotation="$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+90d +%Y-%m-%dT%H:%M:%SZ)"
    gcloud kms keys create "${GCP_KEY}" --keyring="${GCP_KEYRING}" --location="${GCP_LOCATION}" \
      --project="${GCP_PROJECT}" --purpose=encryption --rotation-period=90d --next-rotation-time="${next_rotation}"
  fi

  # The caller may be a user or a service account; the IAM member prefix differs.
  local account member
  account="$(gcloud config get-value account 2>/dev/null)"
  [[ -n "${account}" ]] || die "no active gcloud account"
  case "${account}" in
    *.gserviceaccount.com) member="serviceAccount:${account}" ;;
    *) member="user:${account}" ;;
  esac
  gcloud kms keys add-iam-policy-binding "${GCP_KEY}" --keyring="${GCP_KEYRING}" --location="${GCP_LOCATION}" \
    --project="${GCP_PROJECT}" --member="${member}" --role=roles/cloudkms.cryptoKeyEncrypterDecrypter >/dev/null
  echo "    ${member} can encrypt and decrypt"
}

# 2. .sops.yaml. Rules are first-match-wins, so the specific ones come before the catch-all.
create_sops_config() {
  log "Step 2: .sops.yaml"
  {
    echo "creation_rules:"
    echo "  - path_regex: .*secret.*\\.ya?ml\$"
    echo "    encrypted_regex: ^(data|stringData)\$"
    echo "    gcp_kms: ${GCP_KMS_RESOURCE}"
    if [[ -n "${BREAKGLASS_AGE_PUBLIC_KEY:-}" ]]; then
      echo "    age: ${BREAKGLASS_AGE_PUBLIC_KEY}     # either recipient can decrypt: break-glass access"
    fi
    echo "  - path_regex: .*\\.(ya?ml|json|env)\$"
    echo "    gcp_kms: ${GCP_KMS_RESOURCE}"
  } > "${WORKDIR}/.sops.yaml"
  sed 's/^/    | /' "${WORKDIR}/.sops.yaml"
}

create_example_secret() {
  log "Step 3: plaintext Secret (demo values)"
  cat > "${PLAINTEXT}" <<'YAML'
apiVersion: v1
kind: Secret
metadata:
  name: myapp-gcp-secrets
  namespace: myapp
type: Opaque
stringData:
  db_password: "demo-password-not-real"
  oauth_client_secret: "demo-client-secret-not-real"
YAML
}

encrypt_and_decrypt() {
  log "Step 4: encrypt, then decrypt through KMS"
  sops --config "${WORKDIR}/.sops.yaml" encrypt "${PLAINTEXT}" > "${ENCRYPTED}"
  grep -q '^    gcp_kms:' "${ENCRYPTED}" || die "KMS recipient missing from ${ENCRYPTED}"
  local got
  got="$(sops decrypt --extract '["stringData"]["db_password"]' "${ENCRYPTED}")"
  [[ "${got}" == "demo-password-not-real" ]] || die "round trip failed"
  echo "    round trip OK through ${GCP_KMS_RESOURCE}"
}

setup_ci_access() {
  log "Step 5: let CI decrypt (Workload Identity Federation, no key files)"
  cat <<TXT
    gcloud kms keys add-iam-policy-binding ${GCP_KEY} --keyring=${GCP_KEYRING} --location=${GCP_LOCATION} \\
      --project=${GCP_PROJECT} --member=serviceAccount:ci-deployer@${GCP_PROJECT}.iam.gserviceaccount.com \\
      --role=roles/cloudkms.cryptoKeyDecrypter       # CI only needs decrypt
TXT
}

show_gitops_usage() {
  log "Step 6: GitHub Actions"
  cat <<'YAML'
    permissions:
      contents: read
      id-token: write                                  # required for Workload Identity Federation
    steps:
      - uses: google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093   # v3
        with:
          workload_identity_provider: projects/123456789/locations/global/workloadIdentityPools/github/providers/github
          service_account: ci-deployer@my-project.iam.gserviceaccount.com
      - run: sops decrypt k8s/secrets/myapp.enc.yaml | kubectl apply -f -
YAML
}

main() {
  setup_gcp_kms
  create_sops_config
  create_example_secret
  encrypt_and_decrypt
  setup_ci_access
  show_gitops_usage
  printf '\n=== SOPS + GCP KMS done ===\n    commit: %s and %s/.sops.yaml\n' "${ENCRYPTED}" "${WORKDIR}"
}

main "$@"
