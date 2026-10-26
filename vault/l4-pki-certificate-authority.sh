#!/usr/bin/env bash
# =============================================================================
# l4 - Vault PKI: a root CA, an intermediate CA, roles, short-lived leaf certificates, revocation
#
#   Root CA (pki/)  ->  Intermediate CA (pki-int/)  ->  leaf certificates for services
#
# Short-lived leaf certificates (hours/days) make revocation a minor concern. In production the root would live
# offline (generate it elsewhere, import only its certificate) - here it shares the Vault with the intermediate
# because this is a lab.
#
#   export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root-token
#   ./l4-pki-certificate-authority.sh                  # files go to ./pki-output (OUTPUT_DIR)
# Needs: vault, jq, openssl; a dev server from l1.
# =============================================================================
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

OUTPUT_DIR="${OUTPUT_DIR:-./pki-output}"
DOMAIN="internal.example.com"

require vault; require jq; require openssl
wait_for_vault
mkdir -p "${OUTPUT_DIR}"

log "Step 1: root CA at pki/ (private key never leaves Vault)"
ensure_mount pki pki
run vault secrets tune -max-lease-ttl=87600h pki
vault write -format=json pki/root/generate/internal \
  common_name="${DOMAIN} Root CA" organization="Example Org" country="US" \
  key_type=rsa key_bits=4096 ttl=87600h | jq -r '.data.certificate' > "${OUTPUT_DIR}/root-ca.crt"
openssl x509 -in "${OUTPUT_DIR}/root-ca.crt" -noout -subject -issuer -dates | sed 's/^/    /'
run vault write pki/config/urls \
  issuing_certificates="${VAULT_ADDR}/v1/pki/ca" \
  crl_distribution_points="${VAULT_ADDR}/v1/pki/crl" \
  ocsp_servers="${VAULT_ADDR}/v1/pki/ocsp"

log "Step 2: intermediate CA at pki-int/ (CSR -> signed by the root -> imported back)"
ensure_mount pki-int pki
run vault secrets tune -max-lease-ttl=43800h pki-int
vault write -format=json pki-int/intermediate/generate/internal \
  common_name="${DOMAIN} Intermediate CA" organization="Example Org" country="US" \
  key_type=rsa key_bits=4096 | jq -r '.data.csr' > "${OUTPUT_DIR}/intermediate-ca.csr"
# `certificate` of a pem_bundle response is the signed intermediate followed by its issuer chain
vault write -format=json pki/root/sign-intermediate csr=@"${OUTPUT_DIR}/intermediate-ca.csr" \
  common_name="${DOMAIN} Intermediate CA" format=pem_bundle ttl=43800h | jq -r '.data.certificate' > "${OUTPUT_DIR}/intermediate-ca.crt"
run vault write pki-int/intermediate/set-signed certificate=@"${OUTPUT_DIR}/intermediate-ca.crt"
run vault write pki-int/config/urls \
  issuing_certificates="${VAULT_ADDR}/v1/pki-int/ca" \
  crl_distribution_points="${VAULT_ADDR}/v1/pki-int/crl" \
  ocsp_servers="${VAULT_ADDR}/v1/pki-int/ocsp"

log "Step 3: roles = what each kind of certificate may contain"
run vault write pki-int/roles/web-server allowed_domains="${DOMAIN},svc.cluster.local" allow_subdomains=true \
  allow_bare_domains=false allow_localhost=true allow_ip_sans=true allow_any_name=false \
  key_type=rsa key_bits=2048 max_ttl=72h ttl=24h require_cn=true server_flag=true client_flag=false
run vault write pki-int/roles/client-auth allowed_domains="${DOMAIN}" allow_subdomains=true \
  key_type=ec key_bits=256 max_ttl=8h ttl=1h server_flag=false client_flag=true
run vault write pki-int/roles/etcd-peer allowed_domains="${DOMAIN},etcd.local" allow_subdomains=true allow_ip_sans=true \
  key_type=ec key_bits=384 max_ttl=24h ttl=8h server_flag=true client_flag=true
run vault list pki-int/roles

log "Step 4: issue a leaf certificate for api.${DOMAIN}"
CERT_JSON="$(vault write -format=json pki-int/issue/web-server common_name="api.${DOMAIN}" \
  alt_names="www.${DOMAIN}" ip_sans="127.0.0.1" ttl=24h)"
jq -r '.data.certificate' <<<"${CERT_JSON}" > "${OUTPUT_DIR}/example-cert.crt"
( umask 077; jq -r '.data.private_key' <<<"${CERT_JSON}" > "${OUTPUT_DIR}/example-key.pem" )
jq -r '.data.ca_chain[]' <<<"${CERT_JSON}" > "${OUTPUT_DIR}/ca-chain.crt"
openssl x509 -in "${OUTPUT_DIR}/example-cert.crt" -noout -text | grep -E 'Subject:|DNS:|IP Address:|Not (Before|After)' | sed 's/^ */    /'

log "Step 5: verify the chain and that the key matches the certificate"
openssl verify -CAfile "${OUTPUT_DIR}/root-ca.crt" -untrusted "${OUTPUT_DIR}/intermediate-ca.crt" "${OUTPUT_DIR}/example-cert.crt"
cert_pub="$(openssl x509 -in "${OUTPUT_DIR}/example-cert.crt" -noout -pubkey | openssl sha256)"
key_pub="$(openssl pkey -in "${OUTPUT_DIR}/example-key.pem" -pubout | openssl sha256)"
assert_eq "private key belongs to the certificate" "${cert_pub}" "${key_pub}"

log "Step 6: list, revoke, rotate the CRL"
run vault list pki-int/certs
serial="$(jq -r '.data.serial_number' <<<"${CERT_JSON}")"
run vault write pki-int/revoke serial_number="${serial}"
run vault read pki-int/crl/rotate        # rotating the CRL is a read in current Vault versions
assert_eq "revoked serial is in the CRL" \
  "$(curl -sf "${VAULT_ADDR}/v1/pki-int/crl/pem" | openssl crl -noout -text | grep -ci "$(tr -d ':' <<<"${serial}")")" "1"

log "Step 7: policy for automated issuance (cert-manager, Vault Agent, ESO)"
vault policy write pki-issue-web-server - <<'POLICY'
# issue from the web-server role only
path "pki-int/issue/web-server" {
  capabilities = ["create", "update"]
}
# read the chain and the CRL for trust and revocation checks
path "pki-int/cert/ca_chain" {
  capabilities = ["read"]
}
path "pki-int/ca/pem" {
  capabilities = ["read"]
}
path "pki-int/crl" {
  capabilities = ["read"]
}
POLICY

log "PKI demo complete. Root: ${OUTPUT_DIR}/root-ca.crt  Leaf: ${OUTPUT_DIR}/example-cert.crt  UI: ${VAULT_ADDR}/ui/vault/secrets/pki-int/list"
