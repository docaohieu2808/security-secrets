# Security & Secrets — Legacy Grouped Repository

Legacy grouped repository containing configurations for eight security tools: OPA/Kyverno, Sealed Secrets, External Secrets, HashiCorp Vault, Falco, SOPS, Trivy, and SonarQube. Each has been extracted into standalone repos where applicable.

## Repository Structure

```
security-secrets/
├── opa-kyverno/       → see /home/hieudc/opa-kyverno
├── sealed-secrets/    → see /home/hieudc/sealed-secrets
├── external-secrets/  → see /home/hieudc/external-secrets
├── sonarqube/         → see /home/hieudc/sonarqube-config
├── vault/             (HashiCorp Vault configs)
├── falco/             (Falco runtime security)
├── sops/              (SOPS encrypted secrets)
└── trivy/             (Trivy container/IaC scanning)
```

## Standalone Repos (preferred)

| Tool | Standalone Repo | Description |
|------|----------------|-------------|
| OPA / Kyverno | `/home/hieudc/opa-kyverno` | K8s admission policy engines |
| Sealed Secrets | `/home/hieudc/sealed-secrets` | GitOps-safe encrypted K8s secrets |
| External Secrets | `/home/hieudc/external-secrets` | Sync secrets from Vault/AWS/GCP into K8s |
| SonarQube | `/home/hieudc/sonarqube-config` | SAST, code quality, quality gates |

## Vault Levels

| File | Level | Covers |
|------|-------|--------|
| `vault/l1-dev-server-docker-compose.yml` | L1 | Vault dev server via Docker Compose |
| `vault/l2-kv-secrets-engine.sh` | L2 | KV v2 secrets engine: read/write/version |
| `vault/l3-dynamic-secrets-database.sh` | L3 | Dynamic DB credentials (PostgreSQL) |
| `vault/l4-pki-certificate-authority.sh` | L4 | PKI engine: internal CA, cert issuance |
| `vault/l5-transit-encryption.sh` | L5 | Transit engine: encrypt-as-a-service |
| `vault/l-max-vault-agent-sidecar.yaml` | L-MAX | Vault Agent sidecar: auto-inject secrets into pods |

## Falco Levels

| File | Level | Covers |
|------|-------|--------|
| `falco/l1-install-helm-values.yaml` | L1 | Helm install: eBPF driver, Prometheus metrics |
| `falco/l2-custom-rules.yaml` | L2 | Custom detection rules: exec in container, sensitive file access |
| `falco/l-max-falco-plugin-config.yaml` | L-MAX | Plugin framework: CloudTrail, K8s audit events |

## SOPS Levels

| File | Level | Covers |
|------|-------|--------|
| `sops/l1-encrypt-yaml-with-age.sh` | L1 | Encrypt YAML secrets with age key |
| `sops/l2-encrypt-with-gcp-kms.sh` | L2 | Encrypt with GCP KMS (GitOps-friendly) |
| `sops/l-max-sops-gitops-workflow.sh` | L-MAX | Full GitOps workflow: encrypt → commit → CI decrypt |

## Trivy Levels

| File | Level | Covers |
|------|-------|--------|
| `trivy/l1-container-scan.sh` | L1 | Container image vulnerability scan |
| `trivy/l2-iac-scan.sh` | L2 | IaC scan: Terraform, Helm, Kubernetes manifests |
| `trivy/l3-sbom-generate.sh` | L3 | SBOM generation (SPDX/CycloneDX) |
| `trivy/l-max-custom-policy.rego` | L-MAX | Custom Rego policies for Trivy misconfiguration checks |

## Prerequisites

- Docker + Docker Compose (Vault dev, Falco local)
- Kubernetes + `helm` 3.x (Falco DaemonSet, Vault Agent)
- `vault` CLI, `sops`, `age`, `trivy` binaries

## Quick Start

**Vault dev server:**
```bash
docker compose -f vault/l1-dev-server-docker-compose.yml up -d
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root
vault status
```

**KV secrets:**
```bash
vault secrets enable -path=secret kv-v2
vault kv put secret/myapp db_password=s3cr3t
vault kv get secret/myapp
```

**Falco on Kubernetes:**
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  -f falco/l1-install-helm-values.yaml
kubectl logs -n falco -l app.kubernetes.io/name=falco -f
```

**SOPS encrypt:**
```bash
age-keygen -o key.txt
export SOPS_AGE_KEY_FILE=key.txt
sops --encrypt --age $(grep public key.txt | cut -d' ' -f4) secrets.yaml > secrets.enc.yaml
```

**Trivy scan:**
```bash
trivy image myapp:latest --severity HIGH,CRITICAL
trivy config ./k8s/ --severity HIGH,CRITICAL
```

## Key Concepts

- **Vault dynamic secrets** — DB credentials generated on-demand with short TTL; no long-lived passwords in config
- **Vault Transit** — encryption as a service; application encrypts/decrypts via API without handling keys
- **Falco rules** — match syscall events (exec, open, connect) against YAML rules; alert on unexpected behavior at runtime
- **SOPS** — encrypts only secret values in YAML/JSON/ENV; structure and keys remain readable in Git
- **Trivy IaC scan** — detects misconfigurations in Terraform, Helm charts, K8s manifests before deployment
