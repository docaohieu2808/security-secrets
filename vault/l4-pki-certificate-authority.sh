#!/usr/bin/env bash
# =============================================================================
# l4-pki-certificate-authority.sh — Vault: PKI engine, Root CA, Intermediate CA, issue certs
#
# Builds a two-tier PKI hierarchy:
#   Root CA (offline simulation) → Intermediate CA (Vault-managed) → Leaf certs
#
# This is the recommended pattern:
#   - Root CA private key never leaves Vault (or is truly offline)
#   - Intermediate CA signs leaf certs for services
#   - Short-lived leaf certs (hours/days) reduce revocation complexity
#
# Usage:
#   export VAULT_ADDR=http://127.0.0.1:8200
#   export VAULT_TOKEN=dev-root-token
#   ./l4-pki-certificate-authority.sh
#
# Output files (created in ./pki-output/):
#   root-ca.crt        — Root CA certificate (distribute to trust stores)
#   intermediate-ca.crt — Intermediate CA certificate chain
#   example-cert.crt   — Sample leaf certificate
#   example-key.pem    — Sample leaf private key
# =============================================================================
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"
OUTPUT_DIR="./pki-output"
DOMAIN="internal.example.com"

export VAULT_ADDR VAULT_TOKEN

log()  { echo; echo "==> $*"; }
cmd()  { echo "    \$ $*"; eval "$@"; }

mkdir -p "${OUTPUT_DIR}"

# =============================================================================
# 1. Root CA — enable PKI engine and generate self-signed root certificate
# =============================================================================
log "Step 1: Enable PKI engine for Root CA at path 'pki/'"
vault secrets enable -path=pki pki 2>/dev/null || echo "    (already enabled)"

# Set max TTL for root CA — 10 years is typical for root CA lifetime
cmd "vault secrets tune -max-lease-ttl=87600h pki"

# Generate Root CA (internal = private key stays in Vault, never exported)
log "Generating Root CA certificate:"
cmd "vault write -format=json pki/root/generate/internal \
    common_name='${DOMAIN} Root CA' \
    organization='My Organization' \
    country='US' \
    key_type=rsa \
    key_bits=4096 \
    ttl=87600h \
    | jq -r '.data.certificate' > ${OUTPUT_DIR}/root-ca.crt"

echo "    Root CA certificate saved to ${OUTPUT_DIR}/root-ca.crt"
cmd "openssl x509 -in ${OUTPUT_DIR}/root-ca.crt -noout -subject -issuer -dates" || true

# Configure Root CA CRL and OCSP URLs
log "Configuring Root CA URLs:"
cmd "vault write pki/config/urls \
    issuing_certificates='${VAULT_ADDR}/v1/pki/ca' \
    crl_distribution_points='${VAULT_ADDR}/v1/pki/crl' \
    ocsp_servers='${VAULT_ADDR}/v1/pki/ocsp'"

# =============================================================================
# 2. Intermediate CA — separate PKI mount, signed by Root CA
# =============================================================================
log "Step 2: Enable PKI engine for Intermediate CA at path 'pki-int/'"
vault secrets enable -path=pki-int pki 2>/dev/null || echo "    (already enabled)"
cmd "vault secrets tune -max-lease-ttl=43800h pki-int"   # 5 years max

# Generate Intermediate CA CSR (Certificate Signing Request)
log "Generating Intermediate CA CSR:"
cmd "vault write -format=json pki-int/intermediate/generate/internal \
    common_name='${DOMAIN} Intermediate CA' \
    organization='My Organization' \
    country='US' \
    key_type=rsa \
    key_bits=4096 \
    | jq -r '.data.csr' > ${OUTPUT_DIR}/intermediate-ca.csr"

echo "    Intermediate CSR saved to ${OUTPUT_DIR}/intermediate-ca.csr"

# Sign the Intermediate CSR with the Root CA
log "Signing Intermediate CA with Root CA:"
cmd "vault write -format=json pki/root/sign-intermediate \
    csr=@${OUTPUT_DIR}/intermediate-ca.csr \
    common_name='${DOMAIN} Intermediate CA' \
    format=pem_bundle \
    ttl=43800h \
    | jq -r '.data.certificate' > ${OUTPUT_DIR}/intermediate-ca.crt"

echo "    Intermediate CA certificate saved to ${OUTPUT_DIR}/intermediate-ca.crt"

# Import the signed certificate back into pki-int mount
log "Importing signed Intermediate CA certificate back into Vault:"
cmd "vault write pki-int/intermediate/set-signed \
    certificate=@${OUTPUT_DIR}/intermediate-ca.crt"

# Configure Intermediate CA URLs
cmd "vault write pki-int/config/urls \
    issuing_certificates='${VAULT_ADDR}/v1/pki-int/ca' \
    crl_distribution_points='${VAULT_ADDR}/v1/pki-int/crl' \
    ocsp_servers='${VAULT_ADDR}/v1/pki-int/ocsp'"

# =============================================================================
# 3. Create PKI roles — define allowed cert parameters per use case
# =============================================================================
log "Step 3: Create PKI roles for leaf certificate issuance"

# Role: web-server (TLS for internal HTTPS services)
cmd "vault write pki-int/roles/web-server \
    allowed_domains='${DOMAIN},svc.cluster.local' \
    allow_subdomains=true \
    allow_glob_domains=false \
    allow_bare_domains=false \
    allow_localhost=true \
    allow_ip_sans=true \
    allow_any_name=false \
    key_type=rsa \
    key_bits=2048 \
    max_ttl=72h \
    default_ttl=24h \
    require_cn=true \
    server_flag=true \
    client_flag=false \
    code_signing_flag=false"

# Role: client-auth (mTLS client certificates for service-to-service auth)
cmd "vault write pki-int/roles/client-auth \
    allowed_domains='${DOMAIN}' \
    allow_subdomains=true \
    key_type=ec \
    key_bits=256 \
    max_ttl=8h \
    default_ttl=1h \
    server_flag=false \
    client_flag=true"

# Role: etcd-peer (short-lived certs for etcd cluster members)
cmd "vault write pki-int/roles/etcd-peer \
    allowed_domains='${DOMAIN},etcd.local' \
    allow_subdomains=true \
    allow_ip_sans=true \
    key_type=ec \
    key_bits=384 \
    max_ttl=24h \
    default_ttl=8h \
    server_flag=true \
    client_flag=true"

log "PKI roles:"
cmd "vault list pki-int/roles"

# =============================================================================
# 4. Issue leaf certificates
# =============================================================================
log "Step 4: Issue leaf certificate for 'api.${DOMAIN}'"
CERT_JSON=$(vault write -format=json pki-int/issue/web-server \
    common_name="api.${DOMAIN}" \
    alt_names="api.${DOMAIN},www.${DOMAIN}" \
    ip_sans="127.0.0.1" \
    ttl=24h)

echo "${CERT_JSON}" | jq -r '.data.certificate' > "${OUTPUT_DIR}/example-cert.crt"
echo "${CERT_JSON}" | jq -r '.data.private_key' > "${OUTPUT_DIR}/example-key.pem"
echo "${CERT_JSON}" | jq -r '.data.ca_chain[]' > "${OUTPUT_DIR}/ca-chain.crt"
chmod 600 "${OUTPUT_DIR}/example-key.pem"

log "Issued certificate details:"
cmd "openssl x509 -in ${OUTPUT_DIR}/example-cert.crt -noout -text | grep -E 'Subject:|DNS:|IP:|Not (Before|After)'" || true

log "Verify certificate chain:"
cmd "openssl verify -CAfile ${OUTPUT_DIR}/root-ca.crt -untrusted ${OUTPUT_DIR}/intermediate-ca.crt ${OUTPUT_DIR}/example-cert.crt" || true

# =============================================================================
# 5. List and revoke certificates
# =============================================================================
log "Step 5: List issued certificates"
cmd "vault list pki-int/certs"

CERT_SERIAL=$(echo "${CERT_JSON}" | jq -r '.data.serial_number')
log "Revoking certificate with serial: ${CERT_SERIAL}"
cmd "vault write pki-int/revoke serial_number='${CERT_SERIAL}'"

# Rotate CRL (Certificate Revocation List) after revoking
cmd "vault write pki-int/crl/rotate"

# =============================================================================
# 6. Vault policy for automated cert issuance (e.g., cert-manager integration)
# =============================================================================
log "Step 6: Create policy for automated certificate issuance"
vault policy write pki-issue-web-server - <<'EOF'
# Allow issuing certificates from the web-server role only
path "pki-int/issue/web-server" {
  capabilities = ["create", "update"]
}

# Allow reading the CA chain for trust verification
path "pki-int/cert/ca_chain" {
  capabilities = ["read"]
}

path "pki-int/ca/pem" {
  capabilities = ["read"]
}

# Allow reading CRL for revocation checking
path "pki-int/crl" {
  capabilities = ["read"]
}
EOF

log "PKI CA demo complete."
log "Root CA cert:    ${OUTPUT_DIR}/root-ca.crt"
log "Leaf cert:       ${OUTPUT_DIR}/example-cert.crt"
log "Leaf key:        ${OUTPUT_DIR}/example-key.pem"
log "Vault PKI UI:    ${VAULT_ADDR}/ui/vault/secrets/pki-int/list"
