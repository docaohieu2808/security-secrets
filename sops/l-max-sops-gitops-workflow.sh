#!/usr/bin/env bash
# =============================================================================
# l-max - SOPS GitOps workflow: per-environment keys, rotation, readable diffs, Flux / Argo CD
#
# Layout it manages (relative to WORKDIR):
#   .sops.yaml                  rules: dev / staging / prod / shared each get their own recipients
#   k8s/secrets/<env>/*.yaml    plaintext (gitignored)  ->  *.enc.yaml (committed)
#
# Commands:
#   init                  generate one age key per environment and write .sops.yaml
#   encrypt <file>        <name>.yaml -> <name>.enc.yaml using the rule for that path
#   decrypt <file.enc>    print plaintext (uses the key of the environment the path belongs to)
#   rotate-keys           after changing recipients in .sops.yaml: updatekeys + rotate the data keys
#   diff <file.enc>       show a plaintext git diff (git textconv driver)
#   audit                 show the LOCAL operation log
#   flux-setup            print the Flux Kustomization + sops-age Secret steps
#   argo-setup            print the Argo CD sidecar-plugin sketch
#
# Env:
#   WORKDIR   where .sops.yaml and k8s/secrets live (default: current directory)
#   KEYS_DIR  where the per-environment private keys live (default ~/.config/sops/age: dev.txt staging.txt prod.txt)
#
# Honest limits of this lab:
#   - all three environments use age keys on one machine. In production the prod recipient would be a cloud
#     KMS / HSM key (see l2) so no person holds it, and keys would live in different places.
#   - the audit log is a plain local file the same user can edit. The real audit trail is the KMS audit log.
# =============================================================================
set -euo pipefail

WORKDIR="${WORKDIR:-.}"
KEYS_DIR="${KEYS_DIR:-${HOME}/.config/sops/age}"
SECRETS_DIR="${WORKDIR}/k8s/secrets"
SOPS_CONFIG="${WORKDIR}/.sops.yaml"
AUDIT_LOG="${WORKDIR}/.sops-audit.log"

log()  { printf '\n==> %s\n' "$*"; }
info() { printf '    [INFO] %s\n' "$*"; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null || die "$1 not found. $2"; }
audit_line() { printf '%s %s %s by %s@%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "$(whoami)" "$(hostname)" >> "${AUDIT_LOG}"; }

# The environment is the directory name in the path: .../dev/... .../staging/... .../prod/... .../shared/...
env_of() {
  case "$1" in
    */dev/*) echo dev ;;
    */staging/*) echo staging ;;
    */prod/*) echo prod ;;
    */shared/*) echo dev ;;     # shared secrets list all three recipients; the dev key is enough to read them
    *) die "cannot tell the environment from path '$1' (expected .../dev/..., .../staging/..., .../prod/... or .../shared/...)" ;;
  esac
}
key_file_for() { echo "${KEYS_DIR}/$(env_of "$1").txt"; }
public_key() { age-keygen -y "${KEYS_DIR}/$1.txt"; }

cmd_init() {
  log "Initialising SOPS for dev / staging / prod"
  require age-keygen "Install: apt install age"
  require sops "Install: https://github.com/getsops/sops/releases"
  mkdir -p "${KEYS_DIR}" "${WORKDIR}"
  local env
  for env in dev staging prod; do
    if [[ ! -f "${KEYS_DIR}/${env}.txt" ]]; then
      age-keygen -o "${KEYS_DIR}/${env}.txt" 2>/dev/null
      chmod 600 "${KEYS_DIR}/${env}.txt"
      info "generated ${KEYS_DIR}/${env}.txt"
    fi
    info "${env} public key: $(public_key "${env}")"
  done

  local dev staging prod
  dev="$(public_key dev)"; staging="$(public_key staging)"; prod="$(public_key prod)"
  # path_regex is matched against the path of the file passed to sops (the plaintext input, <name>.yaml), so
  # it must NOT require ".enc". It still matches <name>.enc.yaml, which `sops updatekeys` is given later.
  cat > "${SOPS_CONFIG}" <<YAML
# Public keys only: safe to commit. Rules are first-match-wins.
creation_rules:
  - path_regex: (^|.*/)dev/.*\.ya?ml\$
    encrypted_regex: ^(data|stringData)\$
    age: ${dev}
  - path_regex: (^|.*/)staging/.*\.ya?ml\$
    encrypted_regex: ^(data|stringData)\$
    age: ${staging}
  - path_regex: (^|.*/)prod/.*\.ya?ml\$
    encrypted_regex: ^(data|stringData)\$
    # production: replace with  gcp_kms: projects/.../cryptoKeys/prod  (see l2); a break-glass age key can sit next to it
    age: ${prod}
  # Secrets every environment needs: any of the three keys decrypts.
  # For "two of three people must agree" use key_groups + shamir_threshold in the rule instead.
  - path_regex: (^|.*/)shared/.*\.ya?ml\$
    encrypted_regex: ^(data|stringData)\$
    age: >-
      ${dev},${staging},${prod}
YAML
  mkdir -p "${SECRETS_DIR}"/{dev,staging,prod,shared}
  info "wrote ${SOPS_CONFIG} and ${SECRETS_DIR}/{dev,staging,prod,shared}"
}

cmd_encrypt() {
  local file="${1:-}"
  [[ -n "${file}" ]] || die "usage: $0 encrypt <plaintext.yaml>"
  [[ -f "${file}" ]] || die "file not found: ${file}"
  [[ "${file}" != *.enc.yaml ]] || die "${file} already looks encrypted"
  [[ -f "${SOPS_CONFIG}" ]] || die "no ${SOPS_CONFIG}; run '$0 init' first"
  local encrypted
  case "${file}" in
    *.yaml) encrypted="${file%.yaml}.enc.yaml" ;;
    *.yml) encrypted="${file%.yml}.enc.yaml" ;;
    *) die "expected a .yaml or .yml file, got ${file}" ;;
  esac
  log "Encrypting ${file} -> ${encrypted}"
  sops --config "${SOPS_CONFIG}" encrypt "${file}" > "${encrypted}"
  info "safe to commit: ${encrypted}"
  audit_line ENCRYPT "${file}"
}

cmd_decrypt() {
  local file="${1:-}"
  [[ -n "${file}" ]] || die "usage: $0 decrypt <file.enc.yaml>"
  [[ -f "${file}" ]] || die "file not found: ${file}"
  audit_line DECRYPT "${file}"        # logged before the attempt so failures are visible too
  SOPS_AGE_KEY_FILE="$(key_file_for "${file}")" sops decrypt "${file}"
}

# updatekeys: change WHO can decrypt (add/remove recipients per .sops.yaml); rotate: new data key + new IV.
cmd_rotate_keys() {
  log "Applying current .sops.yaml recipients and rotating data keys"
  local count=0 f key
  while IFS= read -r -d '' f; do
    key="$(key_file_for "${f}")"
    SOPS_AGE_KEY_FILE="${key}" sops --config "${SOPS_CONFIG}" updatekeys --yes "${f}"
    SOPS_AGE_KEY_FILE="${key}" sops rotate --in-place "${f}"
    audit_line ROTATE "${f}"
    count=$((count + 1))
  done < <(find "${SECRETS_DIR}" -name '*.enc.yaml' -print0)
  info "re-keyed ${count} file(s); commit the result. To drop a person, remove their key from .sops.yaml first;"
  info "that alone does not make old Git history safe: rotate the secret VALUES too."
}

cmd_diff() {
  local file="${1:-}"
  [[ -n "${file}" ]] || die "usage: $0 diff <file.enc.yaml>"
  git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"
  log "Plaintext diff of ${file}"
  # textconv runs `sops decrypt` for each side of the diff, so the right key must be in the environment
  git config diff.sopsdiffer.textconv "sops decrypt"
  grep -qs 'diff=sopsdiffer' "${WORKDIR}/.gitattributes" || echo '*.enc.yaml diff=sopsdiffer' >> "${WORKDIR}/.gitattributes"
  SOPS_AGE_KEY_FILE="$(key_file_for "${file}")" git diff HEAD -- "${file}"
}

cmd_audit() {
  log "Local operation log (${AUDIT_LOG})"
  if [[ ! -f "${AUDIT_LOG}" ]]; then info "empty"; return 0; fi
  tail -50 "${AUDIT_LOG}"
  local kind
  for kind in ENCRYPT DECRYPT ROTATE; do
    info "${kind}: $(grep -c " ${kind} " "${AUDIT_LOG}" || true)"
  done
}

cmd_flux_setup() {
  log "Flux: decrypt SOPS files in the controller"
  cat <<'TXT'
    # 1. give the kustomize-controller the age private key of that environment
    kubectl create secret generic sops-age --namespace=flux-system --from-file=age.agekey="$HOME/.config/sops/age/prod.txt"
    # 2. tell the Kustomization to decrypt with it
TXT
  cat <<'YAML'
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: myapp-secrets
  namespace: flux-system
spec:
  interval: 10m
  sourceRef: {kind: GitRepository, name: flux-system}
  path: ./k8s/secrets/prod
  prune: true
  decryption:
    provider: sops
    secretRef:
      name: sops-age
YAML
}

# Argo CD removed the `configManagementPlugins` key of argocd-cm in 2.8; plugins are sidecar containers now.
cmd_argo_setup() {
  log "Argo CD: SOPS through a config-management-plugin sidecar"
  cat <<'YAML'
# plugin.yaml, mounted into a sidecar container of argocd-repo-server at /home/argocd/cmp-server/config/
apiVersion: argoproj.io/v1alpha1
kind: ConfigManagementPlugin
metadata:
  name: sops-kustomize
spec:
  version: v1.0
  discover:
    fileName: ./kustomization.yaml
  generate:
    command: [sh, -c]
    args: ["kustomize build --enable-alpha-plugins --enable-exec ."]    # with the KSOPS exec plugin installed in the sidecar
YAML
  cat <<'TXT'
    The sidecar also needs the age private key, for example from a Secret mounted at /home/argocd/.config/sops/age/keys.txt
    (or SOPS_AGE_KEY_FILE pointing at it). Alternatives: helm-secrets for Helm charts, or skip plugins entirely and use
    Flux's built-in decryption (flux-setup). This block is a sketch; CI does not run Argo CD.
TXT
}

usage() {
  sed -n '/^# Commands:/,/^#   argo-setup/p' "$0" | sed 's/^# \{0,1\}//'
}

main() {
  local command="${1:-help}"
  shift || true
  case "${command}" in
    init) cmd_init ;;
    encrypt) cmd_encrypt "$@" ;;
    decrypt) cmd_decrypt "$@" ;;
    rotate-keys) cmd_rotate_keys ;;
    diff) cmd_diff "$@" ;;
    audit) cmd_audit ;;
    flux-setup) cmd_flux_setup ;;
    argo-setup) cmd_argo_setup ;;
    help|--help|-h) usage ;;
    *) die "unknown command '${command}'. Run '$0 help'." ;;
  esac
}

main "$@"
