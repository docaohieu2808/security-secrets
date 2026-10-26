#!/usr/bin/env bash
# Sealed Secrets controller on a real cluster: install with l1 values, run the l2 walkthrough end to end.
#   sealed-secrets/tests/kind-sealed.sh        (needs kubectl, helm, kubeseal 0.40.x, openssl)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_VERSION="2.20.0"
fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS %s\n' "$*"; }

helm repo add sealed-secrets https://bitnami.github.io/sealed-secrets >/dev/null
helm repo update sealed-secrets >/dev/null
helm upgrade --install sealed-secrets sealed-secrets/sealed-secrets --version "${CHART_VERSION}" \
  --namespace kube-system -f "${HERE}/l1-install-controller.yaml" --wait --timeout 5m
kubectl -n kube-system get deploy sealed-secrets-controller
pass "controller deployed under the name kubeseal expects"

image="$(kubectl -n kube-system get deploy sealed-secrets-controller -o jsonpath='{.spec.template.spec.containers[0].image}')"
[[ "${image}" == *":0.40.0" ]] || fail "unexpected controller image ${image}"
args="$(kubectl -n kube-system get deploy sealed-secrets-controller -o jsonpath='{.spec.template.spec.containers[0].args}')"
[[ "${args}" == *"720h"* ]] || fail "keyrenewperiod did not land in the controller args: ${args}"
uid="$(kubectl -n kube-system get deploy sealed-secrets-controller -o jsonpath='{.spec.template.spec.containers[0].securityContext.runAsUser}')"
[[ "${uid}" == "1001" ]] || fail "containerSecurityContext.runAsUser is '${uid}'"
pass "values landed in the Deployment (image pin, key renew period, security context)"

out="$(mktemp -d)"
trap 'rm -rf "${out}"' EXIT
OUTPUT_DIR="${out}" NAMESPACE=sealed-demo "${HERE}/l2-create-sealed-secret.sh"
pass "l2 walkthrough: seal, apply, decrypt, scope demo, re-encrypt"

# the committed artefact must not contain the plaintext
if grep -rq "myapp_user" "${out}"/*-sealed.yaml; then fail "plaintext username visible in a SealedSecret"; fi
pass "SealedSecret files hold ciphertext only"
