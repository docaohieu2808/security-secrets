#!/usr/bin/env bash
# =============================================================================
# l1 - SOPS + age: encrypt a Kubernetes Secret so it can live in Git
#
# SOPS encrypts the VALUES of YAML/JSON and leaves the keys readable, so a diff still shows which field
# changed. age is the small modern encryption tool that replaces GPG for this job.
#
#   1. age-keygen makes a keypair (private key stays with you / your CI, public key goes in .sops.yaml)
#   2. .sops.yaml says which recipients and which fields to encrypt
#   3. sops encrypt   -> file that is safe to commit
#   4. sops decrypt   -> needs the private key
#
# Usage:  ./l1-encrypt-yaml-with-age.sh
# Env:    WORKDIR           scratch directory for the demo files (default ./sops-demo)
#         SOPS_AGE_KEY_FILE private key file (default ~/.config/sops/age/keys.txt, where sops looks by itself)
# Needs:  age (age-keygen), sops >= 3.9 (the `sops encrypt` / `sops decrypt` subcommands)
# =============================================================================
set -euo pipefail

WORKDIR="${WORKDIR:-./sops-demo}"
export SOPS_AGE_KEY_FILE="${SOPS_AGE_KEY_FILE:-${HOME}/.config/sops/age/keys.txt}"
PLAINTEXT="${WORKDIR}/example-secret.yaml"
ENCRYPTED="${WORKDIR}/example-secret.enc.yaml"

log() { printf '\n==> %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

for tool in age-keygen sops openssl; do
  command -v "${tool}" >/dev/null || die "${tool} not found (age: apt install age; sops: https://github.com/getsops/sops/releases)"
done
mkdir -p "${WORKDIR}"

# 1. Keypair --------------------------------------------------------------------------------
generate_age_key() {
  log "Step 1: age keypair"
  if [[ -f "${SOPS_AGE_KEY_FILE}" ]]; then
    echo "    reusing ${SOPS_AGE_KEY_FILE}"
  else
    mkdir -p "$(dirname "${SOPS_AGE_KEY_FILE}")"
    age-keygen -o "${SOPS_AGE_KEY_FILE}" 2>/dev/null
    chmod 600 "${SOPS_AGE_KEY_FILE}"
    echo "    private key written to ${SOPS_AGE_KEY_FILE} - back it up; losing it means losing every secret encrypted to it"
  fi
  AGE_PUBLIC_KEY="$(age-keygen -y "${SOPS_AGE_KEY_FILE}")"
  echo "    public key: ${AGE_PUBLIC_KEY}"
}

# 2. .sops.yaml -----------------------------------------------------------------------------
# path_regex is matched against the path of the file given to `sops encrypt` (the plaintext input),
# NOT against the output name. Rules are evaluated top to bottom, first match wins.
# encrypted_regex limits encryption to the fields that hold secrets: apiVersion, kind and metadata stay
# readable, so kubeconform, Flux and humans can still read the manifest.
create_sops_config() {
  log "Step 2: .sops.yaml"
  cat > "${WORKDIR}/.sops.yaml" <<YAML
creation_rules:
  # Kubernetes Secret manifests: only data / stringData are encrypted
  - path_regex: .*secret.*\.ya?ml\$
    encrypted_regex: ^(data|stringData)\$
    age: ${AGE_PUBLIC_KEY}
  # dotenv-style files are encrypted whole
  - path_regex: \.env(\..*)?\$
    age: ${AGE_PUBLIC_KEY}
  # anything else under secrets/
  - path_regex: (^|.*/)secrets/.*\.(ya?ml|json)\$
    age: ${AGE_PUBLIC_KEY}
# Team: list several recipients, any one of them can decrypt:
#   age: >-
#     age1alice...,
#     age1bob...
YAML
  sed 's/^/    | /' "${WORKDIR}/.sops.yaml"
}

# 3. Plaintext (demo values only; gitignored) ---------------------------------------------
create_example_secret() {
  log "Step 3: plaintext Secret (never commit this)"
  cat > "${PLAINTEXT}" <<YAML
apiVersion: v1
kind: Secret
metadata:
  name: myapp-secrets
  namespace: myapp
type: Opaque
stringData:
  database_url: "postgresql://user:$(openssl rand -hex 8)@postgres:5432/myapp"
  api_key: "example-api-key-not-real"
  jwt_secret: "$(openssl rand -hex 16)"
YAML
  echo "    wrote ${PLAINTEXT}"
}

# 4. Encrypt (needs only the PUBLIC key; the private key file is not used here) ------------
encrypt_secret() {
  log "Step 4: encrypt"
  # --config is explicit here because sops searches for .sops.yaml from the current directory upwards,
  # and the demo files live in ${WORKDIR}. In a real repo the file sits at the root and no flag is needed.
  sops --config "${WORKDIR}/.sops.yaml" encrypt "${PLAINTEXT}" > "${ENCRYPTED}"
  grep -q '^sops:' "${ENCRYPTED}" || die "no sops metadata in ${ENCRYPTED}"
  if grep -q 'example-api-key-not-real' "${ENCRYPTED}"; then die "plaintext leaked into ${ENCRYPTED}"; fi
  grep -q 'name: myapp-secrets' "${ENCRYPTED}" || die "metadata.name should stay readable (encrypted_regex)"
  echo "    ${ENCRYPTED} is safe to commit. Readable parts: apiVersion, kind, metadata. Encrypted: stringData."
  sed -n '1,14p' "${ENCRYPTED}" | sed 's/^/    | /'
}

# 5. Decrypt + prove the round trip ------------------------------------------------------
decrypt_secret() {
  log "Step 5: decrypt and compare"
  local got
  got="$(sops decrypt --extract '["stringData"]["api_key"]' "${ENCRYPTED}")"
  [[ "${got}" == "example-api-key-not-real" ]] || die "decrypted api_key does not match the original"
  echo "    round trip OK: api_key decrypts back to its original value"
  # sops re-indents YAML (4 spaces), so compare values, not bytes. Whole file to stdout:
  #   sops decrypt "${ENCRYPTED}"
  # Variants worth knowing:
  #   sops decrypt --extract '["stringData"]["api_key"]' file   one value
  #   sops edit file                                            decrypt -> $EDITOR -> re-encrypt
  #   sops set file '["stringData"]["api_key"]' '"new"'          change one value without opening an editor
}

# 6. CI / GitOps ---------------------------------------------------------------------------
show_ci_usage() {
  log "Step 6: CI usage"
  cat <<'TXT'
    Keep the private key in the CI secret store and hand it to sops through the environment,
    not through a file on disk:

      env:
        SOPS_AGE_KEY: ${{ secrets.AGE_PRIVATE_KEY }}      # the whole contents of keys.txt
      run: sops decrypt k8s/secret.enc.yaml | kubectl apply -f -

    Protect plaintext from being committed (add to .gitignore):
      *-secret.yaml
      !*.enc.yaml
TXT
}

main() {
  generate_age_key
  create_sops_config
  create_example_secret
  encrypt_secret
  decrypt_secret
  show_ci_usage
  printf '\n=== SOPS + age done ===\n    commit: %s and %s/.sops.yaml\n    never commit: %s or the private key\n' "${ENCRYPTED}" "${WORKDIR}" "${PLAINTEXT}"
}

main "$@"
