#!/usr/bin/env bash
# Run the Vault labs l2..l5 against a running dev server (Vault or OpenBao), as CI does.
#   docker compose -f vault/l1-dev-server-docker-compose.yml --profile db up -d --wait
#   vault/tests/e2e.sh
# Env: VAULT_ADDR / VAULT_TOKEN (defaults: loopback dev server), DB_ROOT_PASSWORD (default postgres), DB_HOST (default
#      postgres, as seen from the Vault container), SKIP_DB=true to leave out l3.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "${OUT}"' EXIT

echo "##[group]l2 KV v2";        "${HERE}/l2-kv-secrets-engine.sh";                       echo "##[endgroup]"
if [[ "${SKIP_DB:-false}" != "true" ]]; then
  echo "##[group]l3 dynamic DB"; DB_ROOT_PASSWORD="${DB_ROOT_PASSWORD:-postgres}" ROTATE_ROOT=true "${HERE}/l3-dynamic-secrets-database.sh"; echo "##[endgroup]"
fi
echo "##[group]l4 PKI";         OUTPUT_DIR="${OUT}/pki" "${HERE}/l4-pki-certificate-authority.sh"; echo "##[endgroup]"
echo "##[group]l5 Transit";     "${HERE}/l5-transit-encryption.sh";                      echo "##[endgroup]"
echo "all Vault labs passed"
