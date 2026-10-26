#!/usr/bin/env bash
# Shared helpers for the Vault levels. Source it, do not run it:  source "$(dirname "$0")/lib.sh"
# The scripts only use the Vault HTTP API through the `vault` CLI, so they also run against OpenBao when its `bao`
# binary is installed under the name `vault` (see README, "Vault license and OpenBao").

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"      # dev server only; the compose file binds it to 127.0.0.1
export VAULT_ADDR VAULT_TOKEN

log()  { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

# Print the command (to stderr, so a pipe such as `run vault ... | jq` only sees the command's output), then run it. "$@" (never eval) keeps quoting intact and cannot be injected into.
run() { printf '    $ %s\n' "$*" >&2; "$@"; }

# Run quietly (the command line would show a secret): print the label instead.
run_secret() { local label="$1"; shift; printf '    $ %s\n' "${label}" >&2; "$@"; }

require() { command -v "$1" >/dev/null || die "$1 not found${2:+. $2}"; }

wait_for_vault() {
  for _ in $(seq 1 30); do
    if vault status >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  die "Vault at ${VAULT_ADDR} did not become ready (is the dev server running? docker compose -f l1-dev-server-docker-compose.yml up -d)"
}

# ensure_mount <path> <type> [extra enable args...]: enable a secrets engine unless the path is already mounted.
# (Checking first, instead of swallowing the error of `enable`, keeps real failures visible.)
ensure_mount() {
  local path="$1" type="$2"; shift 2
  if vault secrets list -format=json | jq -e --arg p "${path}/" 'has($p)' >/dev/null; then
    info "${path}/ already mounted"
  else
    run vault secrets enable -path="${path}" "$@" "${type}"
  fi
}

assert_eq() { # <what> <got> <want>
  [[ "$2" == "$3" ]] || die "$1: got '$2', want '$3'"
  info "ok: $1"
}
