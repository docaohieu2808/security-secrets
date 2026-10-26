# security-secrets

[![ci](https://github.com/docaohieu2808/security-secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/docaohieu2808/security-secrets/actions/workflows/ci.yml)

The secrets lifecycle end to end, as runnable labs: **scan** (Trivy, SonarQube), **detect at runtime** (Falco),
**enforce at admission** (OPA Gatekeeper, Kyverno), **keep secrets in Git safely** (SOPS, Sealed Secrets),
**sync them into the cluster** (External Secrets Operator) and **serve them** (Vault / OpenBao).

Every level is exercised by CI on GitHub-hosted runners on each push and once a week (Monday 03:17 Asia/Saigon). If a
chart, image or CLI release breaks a lab, the weekly run is red before you find out in an interview.

Values below are the versions the labs are pinned to and tested against (checked 2026-10-26).

| Tool | Pinned | Notes |
|---|---|---|
| External Secrets Operator | chart 2.14.0 | `external-secrets.io/v1`; v1beta1 is no longer served (PushSecret and generators are still `v1alpha1`) |
| Falco | 0.45.1, chart 9.2.1 | chart 9 dropped the legacy eBPF probe and gRPC: use `modern_ebpf` and `http_output` / Falcosidekick |
| Kyverno | 1.19.2, chart 3.9.2 | CEL policy kinds at `policies.kyverno.io/v1`; legacy `kyverno.io/v1 ClusterPolicy` is deprecated and removed in 1.20 |
| Gatekeeper | 3.23.1 | ConstraintTemplates in Rego v1 syntax (opt-in since 3.19), tested with `gator` |
| OPA / conftest | 1.21.4 / 0.71.1 | the Rego library has `opa test` unit tests |
| Sealed Secrets | chart 2.20.0, controller + kubeseal 0.40.0 | chart repo is `https://bitnami.github.io/sealed-secrets` (it moved) |
| SOPS / age | 3.13.3 / 1.x | `sops encrypt` / `sops decrypt` subcommands |
| Trivy | 0.76.1 | installed from the release tarball with a pinned sha256, never `curl \| sh` from `main` |
| SonarQube | Community Build 26.10.0.133078 | the old `10-community` tag stopped in 2024 |
| Vault / OpenBao | 2.2.1 / 2.7.1 | see "Vault license and OpenBao" |
| kubeconform / kind | 0.8.0 / 0.33.0 | Kubernetes 1.34 schemas |

## Level map

### Vault (`vault/`)
| Tier | File | What it covers |
|------|------|----------------|
| l1 | `l1-dev-server-docker-compose.yml` | Dev-mode server on `127.0.0.1:8200` (+ optional PostgreSQL via `--profile db`) |
| l2 | `l2-kv-secrets-engine.sh` | KV v2: put/patch/get, versions, soft delete, undelete, destroy, metadata |
| l3 | `l3-dynamic-secrets-database.sh` | Dynamic PostgreSQL credentials: roles, leases, renew, revoke, root rotation |
| l4 | `l4-pki-certificate-authority.sh` | Root CA, intermediate CA, roles, leaf certs, chain check, revoke + CRL |
| l5 | `l5-transit-encryption.sh` | Encrypt/decrypt/sign/HMAC as a service, key rotation, rewrap, retire a version |
| l-max | `l-max-vault-agent-sidecar.yaml` | Agent Injector on Kubernetes (one-template TLS so cert and key match) |

### SOPS (`sops/`)
| Tier | File | What it covers |
|------|------|----------------|
| l1 | `l1-encrypt-yaml-with-age.sh` | age key, `.sops.yaml` (`encrypted_regex`), encrypt, decrypt, round-trip check |
| l2 | `l2-encrypt-with-gcp-kms.sh` | GCP KMS recipient, IAM binding, Workload Identity in CI (**needs a GCP project, lint-only in CI**) |
| l-max | `l-max-sops-gitops-workflow.sh` | dev/staging/prod/shared keys, rotation (`updatekeys` + `rotate`), git textconv diff, Flux, Argo CD sketch |

### Trivy (`trivy/`)
| Tier | File | What it covers |
|------|------|----------------|
| install | `install-trivy.sh` | Pinned version + pinned sha256 per platform (+ cosign if present) |
| l1 | `l1-container-scan.sh` | Image scan (vuln, secret, misconfig); exit 1 on findings; table from the JSON report |
| l2 | `l2-iac-scan.sh` | Terraform / Kubernetes / Dockerfile misconfiguration, optional custom checks |
| l3 | `l3-sbom-generate.sh` | CycloneDX / SPDX SBOM, then `trivy sbom` on it |
| l-max | `l-max-custom-checks/` | Six custom Rego checks (`user.kubernetes.ID00x`) with `opa test` unit tests |

### Falco (`falco/`)
| Tier | File | What it covers |
|------|------|----------------|
| l1 | `l1-install-helm-values.yaml` | Chart 9.2.1 values: `modern_ebpf`, `rules_files`, JSON output, Falcosidekick |
| l2 | `l2-custom-rules.yaml` | Macros, lists, eight rules; validated with the real `falco` binary |
| l-max | `l-max-falco-plugin-config.yaml` | k8saudit plugin as a second event source (Deployment, no driver) + two audit rules |

### OPA Gatekeeper and Kyverno (`opa-kyverno/`)
| Tier | Path | What it covers |
|------|------|----------------|
| l1 | `l1-gatekeeper/` | Four ConstraintTemplates (Rego v1) + Constraints; `gator verify` suite with pass/fail cases |
| l2 | `l2-kyverno-validating-and-mutating-policies.yaml` | `ValidatingPolicy` x3 and `MutatingPolicy` x1 (CEL), `kyverno test` fixtures |
| l3 | `l3-kyverno-generating-policies.yaml` | `GeneratingPolicy`: default-deny + DNS NetworkPolicy, LimitRange, ResourceQuota, plus the RBAC it needs |
| l-max | `rego/lib/` + `policy/` | Rego library split into four packages (`lib.kubernetes`, `lib.networking`, `lib.rbac`, `lib.images`), 26 unit tests, a conftest policy on top |

### Sealed Secrets and External Secrets
| Tier | Path | What it covers |
|------|------|----------------|
| l1 | `sealed-secrets/l1-install-controller.yaml` | Controller values that the chart actually reads |
| l2 | `sealed-secrets/l2-create-sealed-secret.sh` | Seal, apply, verify, strict vs namespace-wide scope, `--re-encrypt`, key backup |
| l1 | `external-secrets/l1-install-operator.yaml` | Operator values (HA, restricted security context, v1 only) |
| l2 | `external-secrets/l2-secretstore-vault.yaml` | Vault (Kubernetes and AppRole auth), AWS and GCP stores |
| l3 | `external-secrets/l3-externalsecret-sync.yaml` | `data`, `dataFrom`, Vault PKI through the `VaultDynamicSecret` generator, `PushSecret` |
| l4 | `external-secrets/l4-kubernetes-provider-demo.yaml` | The `kubernetes` and `fake` providers: runs on any cluster, this is what CI syncs |

### SonarQube (`sonarqube/`)
| Tier | File | What it covers |
|------|------|----------------|
| l1 | `l1-docker-compose-sonarqube.yml`, `l1-bootstrap.sh` | Community Build + PostgreSQL on loopback; replace `admin/admin`, mint a token |
| l2 | `l2-quality-gate-config.json`, `l2-apply-quality-gate.sh` | Quality gate as data, imported with the current web API parameters (`gateName`, `name`) |
| l3 | `l3-scanner-ci-integration.sh` | CI scan with `sonar.qualitygate.wait`, exit code = gate result, args array (names with spaces work) |

## Running a level

```bash
# Vault (dev mode, loopback only) and the labs
docker compose -f vault/l1-dev-server-docker-compose.yml --profile db up -d --wait
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root-token
vault/l2-kv-secrets-engine.sh
DB_ROOT_PASSWORD=postgres ROTATE_ROOT=true vault/l3-dynamic-secrets-database.sh
vault/l4-pki-certificate-authority.sh && vault/l5-transit-encryption.sh

# SOPS with age (keys and files stay under ./sops-demo and ~/.config/sops/age)
sops/l1-encrypt-yaml-with-age.sh

# Trivy: pinned install, then scan the deliberately vulnerable fixture
trivy/install-trivy.sh && cd trivy
docker build -t lab-vulnerable fixtures/image && ./l1-container-scan.sh lab-vulnerable HIGH,CRITICAL
./l2-iac-scan.sh fixtures/iac/bad && CUSTOM_CHECKS=l-max-custom-checks ./l2-iac-scan.sh fixtures/iac/bad

# Policies, no cluster needed
opa test opa-kyverno/rego opa-kyverno/policy -v
(cd opa-kyverno/l1-gatekeeper/tests && ./split.sh && gator verify .)
kyverno test opa-kyverno/tests/validate opa-kyverno/tests/mutate

# Falco rules with the real binary (Docker only)
falco/tests/validate-rules.sh

# Cluster labs: each script installs into the CURRENT kube context, so point it at a disposable one (kind create cluster)
external-secrets/tests/kind-eso.sh
sealed-secrets/tests/kind-sealed.sh
opa-kyverno/tests/kind-kyverno.sh

# SonarQube (needs vm.max_map_count=524288 on the host)
docker compose -f sonarqube/l1-docker-compose-sonarqube.yml up -d --wait
SONAR_ADMIN_PASSWORD='Choose-A-Long-0ne!' sonarqube/tests/e2e.sh
```

## What CI checks (`.github/workflows/ci.yml`)

| Job | Proves |
|-----|--------|
| lint | `shellcheck -x` on all 26 scripts, actionlint, `yamllint --strict`, every action pinned to a real commit SHA |
| rego | `opa check --strict`, `opa fmt`, `opa test` (library, conftest policy, Trivy checks); conftest passes the good fixtures and fails the bad ones with exactly 5 denies |
| policy-cli | `gator verify` (10 cases), `kyverno test` (12 cases), and that `kyverno test` fails when an expectation is wrong |
| schemas | `helm template` of ESO, Falco (both value files), Sealed Secrets and Gatekeeper; **every values file is checked for keys its chart does not define** (Helm ignores them silently); `kubeconform -strict` on all manifests and rendered charts with CRD schemas generated from the operators' own CRDs (negative controls: a `v1beta1` ESO manifest and a typo'd field both fail) |
| falco | `falco --validate` on the custom rules with the stock ruleset loaded, and on the k8s audit rules with the plugin loaded (fetched by falcoctl); a rule with an undefined macro is rejected |
| eso | kind: install chart 2.14.0 with the l1 values, CRD serves `v1` only, `kubernetes` + `fake` providers sync Secrets with correct content, source change propagates, `creationPolicy: Owner` garbage-collects, l2/l3 pass a server-side dry run |
| sealed | kind: controller from the l1 values (the settings land in the Deployment), the whole l2 walkthrough: seal, apply, decrypt, strict scope rejects a rename, namespace-wide accepts it, `--re-encrypt` |
| kyverno | kind: all policies Ready; bad namespace / pod / deployment denied; good ones admitted; MutatingPolicy adds the label; GeneratingPolicy creates NetworkPolicies, LimitRange, ResourceQuota and re-creates a deleted one |
| sops | age round trip, only `data`/`stringData` encrypted, a stranger's key fails, per-environment rules match the plaintext input path, dev key cannot read prod, `rotate-keys` changes the MAC and files still decrypt |
| vault | Vault 2.2.1 **and** OpenBao 2.7.1 (`bao` installed as `vault`): l2 to l5 with assertions, including the revoked database user being unable to log in |
| trivy | tampered checksum rejected; vulnerable image exits 1 and names its CVEs; clean image exits 0; bad IaC exits 1 with the expected IDs; custom Rego checks fire; SBOM is valid CycloneDX |
| sonarqube | Community Build + PostgreSQL: bootstrap, gate import (9 conditions, default), clean project OK, bad project ends with gate ERROR and a non-zero exit |

### Limits (stated, not hidden)
- **Falco's live driver is not run.** A hosted runner cannot be expected to load a kernel driver; the rules and chart output are
  validated instead. Run `helm install` on a real node to see alerts.
- **GCP KMS (`sops/l2`), AWS and GCP SecretStores, the Vault Agent Injector manifests** need accounts or a wired Vault; they are
  shellchecked / schema-validated only.
- **Constraints** (`K8sRequiredLabels`...) are skipped by kubeconform because their CRDs are created by the templates at runtime;
  `gator verify` covers them instead.
- SonarQube Community Build has no branch or pull-request analysis; the l3 script only passes those parameters if you set
  `BRANCH_NAME` / `PR_KEY`, for use with a paid edition.
- The Sealed Secrets controller is pinned to 0.40.0 (the chart default) because the 0.41.1 image was not on Docker Hub when this was
  written; bump `image.tag` and `KUBESEAL_VERSION` together once it is.
- Dev-mode Vault, plain HTTP database connections (`sslmode=disable`) and fixed demo passwords are lab conveniences. Production
  Vault needs Raft storage, TLS, auto-unseal and an audit device; none of that is exercised here.

## Vault license and OpenBao
HashiCorp Vault has been under the **Business Source License 1.1** since 1.15 (HashiCorp, now part of IBM): you may use it, but it is
not open source. **OpenBao** (Linux Foundation, MPL-2.0) is the open-source fork of Vault 1.14 and serves the same HTTP API, so the
scripts here are plain Vault API and CI runs them against both. External Secrets has a dedicated `openbao` provider, and the `vault`
provider works too. Everything older than Vault 2.x is end of life (1.21 ended April 2026), so the `hashicorp/vault:1.17` pin in the
earlier version of this repo was unsupported. For Kubernetes, the Vault Secrets Operator is the sidecar-free alternative to the
Agent Injector shown in `vault/l-max-vault-agent-sidecar.yaml`.

## Kyverno: legacy ClusterPolicy
`kyverno.io/v1` `ClusterPolicy` / `Policy` are deprecated and **removed in Kyverno 1.20**. The same ideas now live in the
CEL-based kinds that are GA at `policies.kyverno.io/v1`: `ValidatingPolicy`, `MutatingPolicy`, `GeneratingPolicy` (plus
`ImageValidatingPolicy`, `DeletingPolicy`, `PolicyException`). Mapping used here: `validate.pattern` / `deny` becomes a CEL
`validations[].expression`; `exclude` becomes `matchConditions` or `namespaceSelector`; `+(key)` anchors become a `matchConditions`
guard plus an `ApplyConfiguration` mutation; `generate.data` becomes `generator.apply(...)`. The old policy "require imagePullPolicy
Always" only compared the image string and never read `imagePullPolicy`; the new one checks both.

## Interview talking points
- **Vault dynamic creds**: a unique Postgres user per request with a TTL; leaked credentials expire, the audit log ties each user to a
  lease (`l3`). Revocation needs `DROP OWNED BY`, not just `DROP ROLE`, once default privileges were granted.
- **Transit = encryption as a service**: the key never leaves Vault; rotation does not force a re-encrypt, `rewrap` upgrades
  ciphertexts server-side, `min_decryption_version` retires old keys (`l5`).
- **SOPS + GitOps**: values are encrypted, keys stay readable so diffs mean something; `path_regex` matches the file you pass in, and
  recipients per environment limit the blast radius (`l-max`).
- **Sealed Secrets vs External Secrets**: sealed = ciphertext in Git, no external dependency, back up the sealing keys; external =
  live pull from a store, central rotation, needs the store to be up.
- **OPA vs Kyverno**: Rego is general (admission, CI via conftest, Terraform) but has a learning curve; Kyverno is Kubernetes-native and
  now CEL-based. Both run in CI before the cluster ever sees the object.
- **Falco vs Trivy**: Trivy finds known problems before deploy; Falco catches behaviour at runtime. A shell in a container is not a CVE.
- **Supply chain**: the March 2026 Trivy ecosystem compromise (GHSA-69fq-xp46-6x23) is why `install-trivy.sh` pins version and digest
  and why every GitHub Action here is pinned to a commit SHA.

## Notes
No real secrets are in this repository: every value is a demo placeholder (`example-...-not-real`) or generated at run time.
