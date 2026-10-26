#!/usr/bin/env bash
# External Secrets Operator against a real cluster (kind or any disposable cluster; it installs and deletes things).
#   external-secrets/tests/kind-eso.sh
# Installs the pinned chart with l1-install-operator.yaml, applies l4 (kubernetes + fake providers), and proves the
# Secrets are synced with the right content. Then server-side dry-runs l2 and l3, which makes the API server and the
# ESO admission webhook judge the external-secrets.io/v1 manifests.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ESO_CHART_VERSION="2.14.0"
fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS %s\n' "$*"; }

helm repo add external-secrets https://charts.external-secrets.io >/dev/null
helm repo update external-secrets >/dev/null
helm upgrade --install external-secrets external-secrets/external-secrets --version "${ESO_CHART_VERSION}" \
  --namespace external-secrets --create-namespace -f "${HERE}/l1-install-operator.yaml" --wait --timeout 5m
kubectl -n external-secrets get pods
pass "operator installed with l1 values (replicaCount 2 + webhook + cert controller)"

served="$(kubectl get crd externalsecrets.external-secrets.io -o jsonpath='{range .spec.versions[*]}{.name}={.served} {end}')"
[[ "${served}" == *"v1=true"* ]] || fail "CRD does not serve v1: ${served}"
[[ "${served}" != *"v1beta1=true"* ]] || fail "CRD still serves v1beta1: ${served}"
pass "CRD serves v1 and not v1beta1 (${served})"

kubectl apply -f "${HERE}/l4-kubernetes-provider-demo.yaml"
kubectl -n eso-demo wait --for=condition=Ready secretstore/k8s-store secretstore/fake-store --timeout=120s
kubectl -n eso-demo wait --for=condition=Ready externalsecret/from-kubernetes-store externalsecret/from-fake-store --timeout=120s
pass "stores and ExternalSecrets report Ready"

get() { kubectl -n eso-demo get secret "$1" -o "jsonpath={.data.$2}" | base64 -d; }
[[ "$(get from-kubernetes-store username)" == "app" ]] || fail "username not synced from the kubernetes provider"
[[ "$(get from-kubernetes-store password)" == "demo-password-not-real" ]] || fail "password not synced"
pass "kubernetes provider: Secret synced from another namespace"
[[ "$(get from-fake-store token)" == "fake-token-not-real" ]] || fail "fake provider value missing (mergePolicy Merge should keep extracted keys)"
[[ "$(get from-fake-store endpoint)" == "https://api.ap-southeast-1.example.internal" ]] || fail "template did not render"
pass "fake provider + template: extracted keys kept and derived key rendered"

# A change in the source must reach the target on the next refresh; force it instead of waiting a minute.
kubectl -n eso-source patch secret database-credentials --type merge -p '{"stringData":{"password":"rotated-not-real"}}'
kubectl -n eso-demo annotate externalsecret from-kubernetes-store force-sync="$(date +%s)" --overwrite
for _ in $(seq 1 30); do
  [[ "$(get from-kubernetes-store password)" == "rotated-not-real" ]] && break
  sleep 2
done
[[ "$(get from-kubernetes-store password)" == "rotated-not-real" ]] || fail "rotation did not propagate"
pass "source change propagated to the synced Secret"

# Owner reference: deleting the ExternalSecret removes the Secret (creationPolicy: Owner)
kubectl -n eso-demo delete externalsecret from-fake-store
for _ in $(seq 1 15); do
  kubectl -n eso-demo get secret from-fake-store >/dev/null 2>&1 || break
  sleep 2
done
if kubectl -n eso-demo get secret from-fake-store >/dev/null 2>&1; then fail "Secret survived its ExternalSecret"; fi
pass "creationPolicy Owner: Secret garbage-collected with its ExternalSecret"

# l2 / l3 point at Vault, AWS and GCP that are not there, so only the API server's view is checked.
kubectl create namespace myapp --dry-run=client -o yaml | kubectl apply -f -
kubectl apply --dry-run=server -f "${HERE}/l2-secretstore-vault.yaml"
kubectl apply --dry-run=server -f "${HERE}/l3-externalsecret-sync.yaml"
pass "l2 and l3 accepted by the API server (server-side dry run)"
