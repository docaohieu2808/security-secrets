# security-secrets

Secrets management and security tooling end-to-end: scanning (Trivy, SonarQube), runtime security (Falco), policy enforcement (OPA Gatekeeper, Kyverno), secrets encryption (SOPS, Sealed Secrets, External Secrets), and Vault (l1–l5 from dev server to PKI/transit).

Highest interview value in the cluster — covers the full secrets lifecycle from detection to encryption to rotation.

## Tier map

### Vault
| Tier | Path | What it covers |
|------|------|----------------|
| l1 | `vault/l1*/` | Dev-mode Vault compose (IPC_LOCK, root token documented) |
| l2 | `vault/l2*/` | KV v2 secrets engine — write/read/version/rotate |
| l3 | `vault/l3*/` | Dynamic DB credentials — Vault generates short-lived Postgres passwords |
| l4 | `vault/l4*/` | PKI secrets engine — internal CA, issue/revoke certs |
| l5 | `vault/l5*/` | Transit encryption (encrypt-as-a-service) + agent sidecar injection |

### SOPS
| Tier | Path | What it covers |
|------|------|----------------|
| l1 | `sops/l1-encrypt-yaml-with-age.sh` | Encrypt k8s Secret YAML with age key |
| l2 | `sops/l2-encrypt-with-gcp-kms.sh` | Encrypt with GCP KMS (key never leaves KMS) |
| l-max | `sops/l-max-sops-gitops-workflow.sh` | GitOps workflow: SOPS-encrypted secrets committed to git, decrypted at deploy |

### Trivy
| Tier | Path | What it covers |
|------|------|----------------|
| l1–l-max | `trivy/` | Image scan → IaC scan → SBOM generation → custom Rego policy |

### Falco
| Tier | Path | What it covers |
|------|------|----------------|
| l1–l-max | `falco/` | Helm values, custom rules (macro/rule/priority), plugin config |

### OPA Gatekeeper + Kyverno
| Tier | Path | What it covers |
|------|------|----------------|
| l1–l-max | `opa-kyverno/` | ConstraintTemplate (Rego), Kyverno validate + generate policies |

### Sealed Secrets + External Secrets
| Tier | Path | What it covers |
|------|------|----------------|
| l1 | `sealed-secrets/` | kubeseal workflow — encrypt Secret for safe git storage |
| l1 | `external-secrets/` | ExternalSecret pulling from Vault / AWS SSM |

### SonarQube
| Tier | Path | What it covers |
|------|------|----------------|
| l1 | `sonarqube/` | SonarQube compose + scanner config for SAST |

## Run

```bash
# Vault dev mode (never use in production)
docker compose -f vault/l1-vault-dev-server-compose.yml up -d
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token
vault status

# SOPS with age
bash sops/l1-encrypt-yaml-with-age.sh   # generates key, encrypts example secret, decrypts it

# Trivy image scan
trivy image --severity HIGH,CRITICAL nginx:latest
```

## Interview talking points

- **Vault dynamic creds**: Vault generates a unique Postgres username/password per request with a TTL — leaked creds expire automatically, no shared passwords (`l3`).
- **Transit = encryption-as-a-service**: app sends plaintext to Vault `/transit/encrypt`, stores ciphertext — encryption key never leaves Vault (`l5`).
- **SOPS + GitOps**: encrypted secrets live in git (safe), decrypted only by CI/CD with access to age key or KMS — enables full GitOps without a secrets operator (`l-max`).
- **OPA vs Kyverno**: OPA/Gatekeeper uses Rego (flexible, steep learning curve); Kyverno uses YAML policies (easier for k8s teams). Both enforce at admission — show both for breadth.
- **Falco runtime**: detects anomalous syscalls (unexpected shell in container, sensitive file read) at runtime — complements static scanning (Trivy) which only catches pre-deploy.
- **Sealed Secrets vs External Secrets**: Sealed Secrets encrypts the k8s Secret object itself (offline, no external dependency); External Secrets pulls live from a secrets store (Vault/SSM) — trade-off: simplicity vs centralised rotation.

## Notes

- No real secrets in this repo. All values are demo placeholders with explicit "never commit" warnings.
- `sops/l1` demo uses `sk_test_*` (not `sk_live_*`) to avoid triggering secret scanners on the Stripe key pattern.
- `external-secrets/` uses `v1beta1` API (ESO promoted `v1` in ESO 1.x — mild staleness, functionally equivalent for learning).
