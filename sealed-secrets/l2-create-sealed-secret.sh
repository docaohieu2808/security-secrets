#!/usr/bin/env bash
# =============================================================================
# l2 - Sealed Secrets: seal, apply, verify, scope, re-encrypt
#
# Workflow
#   1. Create a plain Secret manifest (never commit it)
#   2. kubeseal encrypts it into a SealedSecret (safe to commit)
#   3. kubectl/GitOps applies the SealedSecret, the controller creates the Secret
#
# Scopes (what the ciphertext is bound to):
#   strict          name + namespace (default, safest)
#   namespace-wide  namespace only (the Secret may be renamed)
#   cluster-wide    nothing (can move anywhere; use sparingly)
#
# Usage:  ./l2-create-sealed-secret.sh            (needs kubectl, kubeseal, openssl, a controller from l1)
# Env:    NAMESPACE (default sealed-demo), OUTPUT_DIR (default ./sealed-output), DB_PASSWORD (default: random)
#
# Secret values never go on a command line (`ps` would show them): they are written to a mode-600
# env file / piped through stdin instead.
# =============================================================================
set -euo pipefail

NAMESPACE="${NAMESPACE:-sealed-demo}"
OUTPUT_DIR="${OUTPUT_DIR:-./sealed-output}"
CERT="${OUTPUT_DIR}/sealed-secrets-public-key.pem"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
umask 077

log()  { printf '\n==> %s\n' "$*"; }
info() { printf '    [INFO] %s\n' "$*"; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
# Print the command (to stderr: stdout is often redirected into a file), then run it. "$@" (not eval) keeps quoting intact.
run()  { printf '    $ %s\n' "$*" >&2; "$@"; }

for tool in kubectl kubeseal openssl; do
  command -v "${tool}" >/dev/null || die "${tool} not found (kubeseal: see l1-install-controller.yaml)"
done
mkdir -p "${OUTPUT_DIR}"

# Wait for the controller to report the SealedSecret as decrypted (status condition Synced).
wait_synced() { # <name>
  kubectl -n "${NAMESPACE}" wait --for=condition=Synced "sealedsecret/$1" --timeout=60s
}

# 1. Public certificate. Fetching it once lets people seal offline; the cert is public, commit it if you like.
fetch_public_key() {
  log "Step 1: fetch the controller's public certificate"
  # kubeseal defaults: controller sealed-secrets-controller in kube-system (l1 sets fullnameOverride to match)
  run kubeseal --fetch-cert > "${CERT}"
  info "saved ${CERT}"
}

# 2. Strict scope: a database credentials Secret.
seal_database_credentials() {
  log "Step 2: seal database credentials (strict scope)"
  local pw="${DB_PASSWORD:-$(openssl rand -base64 18)}"
  printf 'username=myapp_user\npassword=%s\nhost=postgres.internal\nport=5432\n' "${pw}" > "${WORK}/db.env"
  kubectl create secret generic myapp-db-credentials --namespace "${NAMESPACE}" \
    --from-env-file="${WORK}/db.env" --dry-run=client -o yaml > "${WORK}/db-plaintext.yaml"
  run kubeseal --cert "${CERT}" --scope strict --format yaml \
    < "${WORK}/db-plaintext.yaml" > "${OUTPUT_DIR}/db-secret-sealed.yaml"
  info "SealedSecret (safe to commit): ${OUTPUT_DIR}/db-secret-sealed.yaml"
}

# 3. A real kubernetes.io/tls Secret from a throwaway self-signed certificate.
seal_tls_secret() {
  log "Step 3: seal a TLS Secret"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=myapp.example.internal" \
    -keyout "${WORK}/tls.key" -out "${WORK}/tls.crt" 2>/dev/null
  kubectl create secret tls myapp-tls --namespace "${NAMESPACE}" \
    --cert "${WORK}/tls.crt" --key "${WORK}/tls.key" --dry-run=client -o yaml > "${WORK}/tls-plaintext.yaml"
  run kubeseal --cert "${CERT}" --scope strict --format yaml \
    < "${WORK}/tls-plaintext.yaml" > "${OUTPUT_DIR}/tls-secret-sealed.yaml"
}

# 4. namespace-wide scope: the sealed object may be renamed without re-sealing.
seal_namespace_wide() {
  log "Step 4: seal with namespace-wide scope"
  printf 'api_key=example-not-a-real-key\n' > "${WORK}/api.env"
  kubectl create secret generic myapp-api-keys --namespace "${NAMESPACE}" \
    --from-env-file="${WORK}/api.env" --dry-run=client -o yaml > "${WORK}/api-plaintext.yaml"
  run kubeseal --cert "${CERT}" --scope namespace-wide --format yaml \
    < "${WORK}/api-plaintext.yaml" > "${OUTPUT_DIR}/api-keys-sealed.yaml"
}

# 5. Apply and wait for the controller.
apply_sealed_secrets() {
  log "Step 5: apply the SealedSecrets and wait for decryption"
  kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
  local f
  for f in "${OUTPUT_DIR}"/*-sealed.yaml; do run kubectl apply -f "${f}"; done
  wait_synced myapp-db-credentials
  wait_synced myapp-tls
  wait_synced myapp-api-keys
  run kubectl -n "${NAMESPACE}" get sealedsecrets,secrets
}

# 6. The decrypted Secret really exists (do not print values in real life).
verify_secret() {
  log "Step 6: verify the controller created the Secret"
  local user
  user="$(kubectl -n "${NAMESPACE}" get secret myapp-db-credentials -o jsonpath='{.data.username}' | base64 -d)"
  [[ "${user}" == "myapp_user" ]] || die "decrypted username is '${user}', expected myapp_user"
  local type
  type="$(kubectl -n "${NAMESPACE}" get secret myapp-tls -o jsonpath='{.type}')"
  [[ "${type}" == "kubernetes.io/tls" ]] || die "myapp-tls has type ${type}"
  info "username and TLS secret type are correct"
}

# 7. Scope in action: rename the sealed object.
#    strict         -> the controller refuses (the name is part of the encryption label)
#    namespace-wide -> still decrypts, because only the namespace is bound
demonstrate_scope() {
  log "Step 7: scope demo - rename both sealed objects"
  # First 2-space-indented `name:` is metadata.name (spec.template.metadata.name is indented deeper).
  sed -E '0,/^  name: .*/s//  name: renamed-api-keys/' "${OUTPUT_DIR}/api-keys-sealed.yaml" > "${WORK}/renamed-ns-wide.yaml"
  sed -E '0,/^  name: .*/s//  name: renamed-db-credentials/' "${OUTPUT_DIR}/db-secret-sealed.yaml" > "${WORK}/renamed-strict.yaml"
  kubectl apply -f "${WORK}/renamed-ns-wide.yaml"
  wait_synced renamed-api-keys
  info "namespace-wide: renamed SealedSecret decrypted"
  kubectl apply -f "${WORK}/renamed-strict.yaml"
  sleep 5
  local synced
  synced="$(kubectl -n "${NAMESPACE}" get sealedsecret renamed-db-credentials -o jsonpath='{.status.conditions[?(@.type=="Synced")].status}')"
  [[ "${synced}" != "True" ]] || die "strict-scope SealedSecret was decrypted after a rename; it must not be"
  info "strict: renamed SealedSecret was rejected (Synced=${synced:-unset})"
  kubectl -n "${NAMESPACE}" delete sealedsecret renamed-db-credentials >/dev/null
}

# 8. Re-encrypt: move existing SealedSecrets to the newest sealing key without ever seeing the plaintext.
reencrypt() {
  log "Step 8: re-encrypt with the latest sealing key"
  run kubeseal --re-encrypt --format yaml < "${OUTPUT_DIR}/db-secret-sealed.yaml" > "${WORK}/db-reencrypted.yaml"
  mv "${WORK}/db-reencrypted.yaml" "${OUTPUT_DIR}/db-secret-sealed.yaml"
  kubectl apply -f "${OUTPUT_DIR}/db-secret-sealed.yaml"
  wait_synced myapp-db-credentials
}

show_rotation_and_backup() {
  log "Rotation and backup notes"
  cat <<'NOTES'
    The controller makes a new sealing key every keyrenewperiod (default 30 days) and keeps the old ones,
    so nothing breaks on rotation. To move Git-stored SealedSecrets onto the newest key:
        kubeseal --re-encrypt < old-sealed.yaml > new-sealed.yaml     # server-side; plaintext never leaves the controller
    To force a new key now, set keycutofftime (chart value) or delete the active key Secret and restart the pod.
    BACK UP THE PRIVATE KEYS or a cluster rebuild loses every SealedSecret:
        kubectl -n kube-system get secret -l sealedsecrets.bitnami.com/sealed-secrets-key -o yaml > sealing-keys.backup.yaml
        # store it encrypted (SOPS/age, see ../sops); restore by applying it and restarting the controller
    Offline check of one SealedSecret (needs the private key backup):
        kubeseal --recovery-unseal --recovery-private-key sealing-keys.backup.yaml < sealed.yaml
NOTES
}

main() {
  fetch_public_key
  seal_database_credentials
  seal_tls_secret
  seal_namespace_wide
  apply_sealed_secrets
  verify_secret
  demonstrate_scope
  reencrypt
  show_rotation_and_backup
  printf '\n=== Sealed Secrets demo complete ===\n    commit: %s/*-sealed.yaml (and the public cert)\n    never commit plaintext manifests or key backups\n' "${OUTPUT_DIR}"
}

main "$@"
