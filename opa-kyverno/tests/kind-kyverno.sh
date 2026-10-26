#!/usr/bin/env bash
# Kyverno admission control on a real (disposable) cluster: a bad object is blocked, a good one is admitted, the
# MutatingPolicy patches, the GeneratingPolicy creates the baseline objects.
#   opa-kyverno/tests/kind-kyverno.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KYVERNO_CHART_VERSION="3.9.2"      # Kyverno v1.19.2
fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS %s\n' "$*"; }

# expect_denied <description> <kubectl args...>: the command must be rejected, and by Kyverno's policy
expect_denied() {
  local what="$1" out; shift
  if out="$("$@" 2>&1)"; then fail "${what}: was admitted but must be denied"; fi
  grep -qiE 'denied|forbidden|validation|policy' <<<"${out}" || fail "${what}: failed, but not by a policy: ${out}"
  pass "${what}: denied"
  printf '     %s\n' "$(head -3 <<<"${out}" | tr '\n' ' ' | cut -c1-240)"
}

helm repo add kyverno https://kyverno.github.io/kyverno >/dev/null
helm repo update kyverno >/dev/null
helm upgrade --install kyverno kyverno/kyverno --version "${KYVERNO_CHART_VERSION}" \
  --namespace kyverno --create-namespace --wait --timeout 8m
kubectl -n kyverno get pods

# the policy CRDs this repo uses must be served at v1
for crd in validatingpolicies mutatingpolicies generatingpolicies; do
  versions="$(kubectl get crd "${crd}.policies.kyverno.io" -o jsonpath='{range .spec.versions[*]}{.name}={.served} {end}')"
  [[ "${versions}" == *"v1=true"* ]] || fail "${crd} does not serve v1: ${versions}"
done
pass "ValidatingPolicy / MutatingPolicy / GeneratingPolicy are served at policies.kyverno.io/v1"

kubectl apply -f "${HERE}/l2-kyverno-validating-and-mutating-policies.yaml"
kubectl apply -f "${HERE}/l3-kyverno-generating-policies.yaml"
kubectl wait --for=jsonpath='{.status.conditionStatus.ready}'=true validatingpolicy --all --timeout=180s
kubectl wait --for=jsonpath='{.status.conditionStatus.ready}'=true mutatingpolicy --all --timeout=180s
kubectl wait --for=jsonpath='{.status.conditionStatus.ready}'=true generatingpolicy --all --timeout=180s
pass "all policies Ready"
sleep 15   # the generated ValidatingAdmissionPolicies / webhook configs need a moment to take effect

echo "== namespaces =="
expect_denied "namespace without team/environment labels" kubectl create namespace no-labels
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
printf 'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: bad-env\n  labels: {team: payments, environment: qa}\n' > "${tmp}/ns-qa.yaml"
expect_denied "namespace with environment=qa" kubectl apply -f "${tmp}/ns-qa.yaml"
kubectl apply -f - <<'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: shop
  labels: {team: payments, environment: dev}
YAML
pass "namespace with team + environment=dev: admitted"

echo "== pods =="
expect_denied "pod nginx:latest with imagePullPolicy IfNotPresent" kubectl -n shop run bad-latest --image=nginx:latest --image-pull-policy=IfNotPresent
expect_denied "pod with an untagged image" kubectl -n shop run bad-untagged --image=nginx
kubectl -n shop run good-pinned --image=nginx:1.27 --restart=Never
kubectl -n shop run good-latest-always --image=nginx:latest --image-pull-policy=Always --restart=Never
pass "pinned tag and :latest+Always: admitted"

echo "== deployments (validate + mutate) =="
expect_denied "deployment missing the standard labels" kubectl -n shop create deployment bare --image=nginx:1.27
kubectl apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: no-managed-by
  namespace: shop
  labels:
    app.kubernetes.io/name: web
    app.kubernetes.io/version: "1.0"
    app.kubernetes.io/component: frontend
    team: payments
spec:
  replicas: 0
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers: [{name: web, image: "nginx:1.27"}]
YAML
managed_by="$(kubectl -n shop get deployment no-managed-by -o jsonpath='{.metadata.labels.app\.kubernetes\.io/managed-by}')"
[[ "${managed_by}" == "kubectl" ]] || fail "MutatingPolicy did not add managed-by (got '${managed_by}')"
pass "deployment without managed-by was admitted because the MutatingPolicy added managed-by=kubectl"

echo "== generated baseline =="
kubectl apply -f - <<'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: gen-test
  labels: {team: platform, environment: production}
YAML
wait_for() { # <description> <kubectl args...>
  local what="$1"; shift
  for _ in $(seq 1 45); do
    if kubectl "$@" >/dev/null 2>&1; then pass "generated ${what}"; return 0; fi
    sleep 2
  done
  kubectl get events -A --sort-by=.lastTimestamp | tail -15 >&2
  kubectl -n kyverno logs -l app.kubernetes.io/component=background-controller --tail=30 >&2
  fail "${what} was not generated"
}
wait_for "default-deny NetworkPolicy" -n gen-test get networkpolicy default-deny-all
wait_for "DNS egress NetworkPolicy" -n gen-test get networkpolicy allow-dns-egress
wait_for "LimitRange" -n gen-test get limitrange default-limit-range
wait_for "ResourceQuota (environment=production)" -n gen-test get resourcequota default-quota
dns_selector="$(kubectl -n gen-test get networkpolicy allow-dns-egress -o jsonpath='{.spec.egress[0].to[0].podSelector.matchLabels.k8s-app}')"
[[ "${dns_selector}" == "kube-dns" ]] || fail "DNS policy is not limited to kube-dns pods"
pass "DNS egress is limited to kube-dns pods"

# a system namespace must not get the baseline (it is excluded by matchConditions)
kubectl -n kube-system get networkpolicy default-deny-all >/dev/null 2>&1 && fail "kube-system received the baseline"
pass "excluded namespaces untouched"

# synchronize: true -> delete a generated object and it comes back
kubectl -n gen-test delete networkpolicy default-deny-all
wait_for "default-deny NetworkPolicy again after deletion (synchronize)" -n gen-test get networkpolicy default-deny-all
