#!/usr/bin/env bash
# The Trivy labs end to end, as CI does it (needs docker, trivy on PATH, jq).
#   trivy/install-trivy.sh && trivy/tests/e2e.sh
# Every scan has an expected exit code; the point is that the gate FAILS when it should and passes when it should.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${HERE}"
OUT="$(mktemp -d)"
trap 'rm -rf "${OUT}"' EXIT
first_json() { find "$1" -name "*.json" -print -quit; }
fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS %s\n' "$*"; }
# expect_rc <want> <description> <command...>
expect_rc() {
  local want="$1" what="$2" rc=0; shift 2
  "$@" >"${OUT}/last.log" 2>&1 || rc=$?
  if [[ ${rc} -ne ${want} ]]; then tail -30 "${OUT}/last.log" >&2; fail "${what}: exit ${rc}, expected ${want}"; fi
  pass "${what} (exit ${rc})"
}

echo "== install-trivy.sh refuses a wrong checksum =="
sed 's/\[Linux-64bit\]="c7cb/[Linux-64bit]="0000/; s/\[Linux-ARM64\]="e174/[Linux-ARM64]="0000/' install-trivy.sh > "${OUT}/tampered-install.sh"
expect_rc 1 "tampered digest is rejected" bash "${OUT}/tampered-install.sh" "${OUT}/bin"
[[ ! -e "${OUT}/bin/trivy" ]] || fail "binary installed despite the checksum mismatch"

echo "== l1: container image scan =="
docker build -q -t lab-vulnerable:ci fixtures/image >/dev/null
docker build -q -t lab-clean:ci fixtures/clean-image >/dev/null
expect_rc 1 "vulnerable image fails the gate" env REPORT_DIR="${OUT}/r-l1" ./l1-container-scan.sh lab-vulnerable:ci HIGH,CRITICAL json
report="$(first_json "${OUT}/r-l1")"
found="$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.PkgName == "requests" or .PkgName == "urllib3" or .PkgName == "Jinja2" or .PkgName == "jinja2") | .VulnerabilityID] | unique | length' "${report}")"
[[ "${found}" -ge 1 ]] || fail "report does not list the expected Python package CVEs"
pass "report names the vulnerable packages (${found} distinct CVEs)"
expect_rc 0 "clean image passes the gate" env REPORT_DIR="${OUT}/r-l1-clean" ./l1-container-scan.sh lab-clean:ci HIGH,CRITICAL json

echo "== l2: IaC scan =="
expect_rc 0 "good manifests pass" env REPORT_DIR="${OUT}/r-good" ./l2-iac-scan.sh fixtures/iac/good HIGH,CRITICAL table
expect_rc 1 "bad manifests + terraform fail" env REPORT_DIR="${OUT}/r-bad" ./l2-iac-scan.sh fixtures/iac/bad HIGH,CRITICAL json
ids="$(jq -r '[.Results[]?.Misconfigurations[]?.ID] | unique | join(" ")' "$(first_json "${OUT}/r-bad")")"
for want in KSV-0017 AWS-0107; do
  [[ " ${ids} " == *" ${want} "* ]] || fail "expected ${want} among: ${ids}"
done
pass "built-in checks fired: privileged container (KSV-0017) and open security group (AWS-0107)"
expect_rc 1 "custom checks fire on the bad pod" env REPORT_DIR="${OUT}/r-custom" CUSTOM_CHECKS=l-max-custom-checks ./l2-iac-scan.sh fixtures/iac/bad HIGH,CRITICAL json
ids="$(jq -r '[.Results[]?.Misconfigurations[]?.ID] | unique | join(" ")' "$(first_json "${OUT}/r-custom")")"
for want in USER-K8S-001 USER-K8S-002 USER-K8S-005 USER-K8S-006; do
  [[ " ${ids} " == *" ${want} "* ]] || fail "expected custom check ${want} among: ${ids}"
done
pass "custom Rego checks fired"
expect_rc 0 "good manifests pass the custom checks too" env REPORT_DIR="${OUT}/r-good2" CUSTOM_CHECKS=l-max-custom-checks ./l2-iac-scan.sh fixtures/iac/good HIGH,CRITICAL table

echo "== l3: SBOM =="
expect_rc 0 "SBOM generated and scanned in report-only mode" ./l3-sbom-generate.sh lab-vulnerable:ci cyclonedx "${OUT}/sbom"
sbom="$(ls "${OUT}"/sbom/*.cdx.json)"
[[ "$(jq '.bomFormat' "${sbom}")" == '"CycloneDX"' ]] || fail "not a CycloneDX document"
[[ "$(jq '.components | length' "${sbom}")" -gt 5 ]] || fail "SBOM has too few components"
pass "CycloneDX JSON with $(jq '.components | length' "${sbom}") components"
expect_rc 0 "SPDX SBOM too" ./l3-sbom-generate.sh lab-vulnerable:ci spdx-json "${OUT}/sbom"
expect_rc 1 "SBOM_EXIT_CODE=1 turns findings in the SBOM into a failure" env SBOM_EXIT_CODE=1 ./l3-sbom-generate.sh lab-vulnerable:ci cyclonedx "${OUT}/sbom2"

docker rmi lab-vulnerable:ci lab-clean:ci >/dev/null
echo "all Trivy labs passed"
