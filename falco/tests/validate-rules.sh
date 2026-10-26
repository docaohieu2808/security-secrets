#!/usr/bin/env bash
# Validate the Falco rules with the real Falco binary, without a kernel driver (`falco --validate` only parses and
# type-checks the rules, it does not capture events), so it runs on any CI runner or laptop with Docker.
#
#   falco/tests/validate-rules.sh          # run from anywhere
#
# 1. l2-custom-rules.yaml together with the stock ruleset, which defines the macros it uses (spawned_process...).
# 2. the k8s audit rules in l-max-falco-plugin-config.yaml, together with the stock k8s audit ruleset. Those need the
#    k8saudit plugin loaded, so falcoctl downloads the plugin and its rules first.
set -euo pipefail

FALCO_IMAGE="falcosecurity/falco:0.45.1"
FALCOCTL_IMAGE="falcosecurity/falcoctl:0.14.2"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
chmod 755 "${WORK}"

echo "== 1. custom rules vs the stock ruleset"
docker run --rm --entrypoint falco -v "${HERE}:/r:ro" "${FALCO_IMAGE}" \
  -V /etc/falco/falco_rules.yaml -V /r/l2-custom-rules.yaml 2>&1 | grep -v 'libs\]' | tail -6

echo "== 2. k8s audit rules (plugin + stock rules fetched with falcoctl)"
docker run --rm --user 0:0 -v "${WORK}:/p" "${FALCOCTL_IMAGE}" artifact install k8saudit:0.16 k8saudit-rules:0.16 json:0.7 \
  --plugins-dir /p --rulesfiles-dir /p >/dev/null
# the rules live inside the Helm values file; extract them so there is one source of truth
yq '.customRules."k8saudit-custom.yaml"' "${HERE}/l-max-falco-plugin-config.yaml" > "${WORK}/lab_k8saudit.yaml"
cat > "${WORK}/falco-plugins.yaml" <<'YAML'
load_plugins: [k8saudit, json]
plugins:
  - {name: k8saudit, library_path: /p/libk8saudit.so, init_config: "", open_params: "http://:9765/k8s-audit"}
  - {name: json, library_path: /p/libjson.so, init_config: ""}
YAML
docker run --rm --entrypoint falco -v "${WORK}:/p:ro" "${FALCO_IMAGE}" -c /p/falco-plugins.yaml \
  -V /p/k8s_audit_rules.yaml -V /p/lab_k8saudit.yaml 2>&1 | grep -v 'libs\]' | tail -4

echo "== 3. a broken rule must be rejected (the validator is not a rubber stamp)"
printf -- '- rule: broken\n  desc: x\n  condition: this_macro_does_not_exist\n  output: x\n  priority: WARNING\n' > "${WORK}/broken.yaml"
if docker run --rm --entrypoint falco -v "${WORK}:/p:ro" "${FALCO_IMAGE}" -V /etc/falco/falco_rules.yaml -V /p/broken.yaml >/dev/null 2>&1; then
  echo "falco accepted a rule that uses an undefined macro" >&2
  exit 1
fi
echo "rejected as expected"
