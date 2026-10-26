#!/usr/bin/env python3
"""Turn CustomResourceDefinition YAML into the JSON Schema files kubeconform reads.

    crds-to-kubeconform-schemas.py <out-dir> <crd-yaml-or-helm-output>...

Writes <out-dir>/<group>/<kind>_<version>.json (kind lower-cased) for every served version of every CRD found in
the inputs; other documents in the inputs are ignored, so `helm template --include-crds` output can be passed
as is. Use with:
    kubeconform -strict -schema-location default \
      -schema-location '<out-dir>/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' manifests/

Why not the community CRD catalogs? They lag the operators (ESO's kept serving v1beta1 schemas long after the CRD
stopped serving it), so a manifest could pass validation and still be rejected by a real cluster.
"""
import json
import pathlib
import sys

import yaml


def convert(node):
    """OpenAPI v3 (as in a CRD) -> something JSON Schema validators understand."""
    if isinstance(node, dict):
        out = {k: convert(v) for k, v in node.items()}
        if out.get("x-kubernetes-int-or-string"):
            out.pop("type", None)
            out.pop("format", None)
            out["anyOf"] = [{"type": "integer"}, {"type": "string"}]
        if out.get("nullable") is True and isinstance(out.get("type"), str):
            out["type"] = [out["type"], "null"]
        # kubeconform's -strict only forbids unknown fields where the schema says so (its bundled Kubernetes
        # schemas do; CRD-derived ones do not unless we add it). A typo such as `refreshIntervall` must fail.
        if (
            isinstance(out.get("properties"), dict)
            and "additionalProperties" not in out
            and not out.get("x-kubernetes-preserve-unknown-fields")
        ):
            out["additionalProperties"] = False
        return out
    if isinstance(node, list):
        return [convert(v) for v in node]
    return node


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    out_dir = pathlib.Path(argv[1])
    written = 0
    for source in argv[2:]:
        with open(source, encoding="utf-8") as handle:
            for doc in yaml.safe_load_all(handle):
                if not isinstance(doc, dict) or doc.get("kind") != "CustomResourceDefinition":
                    continue
                spec = doc["spec"]
                group, kind = spec["group"], spec["names"]["kind"]
                for version in spec["versions"]:
                    schema = version.get("schema", {}).get("openAPIV3Schema")
                    if not schema or not version.get("served", True):
                        continue
                    target = out_dir / group / f"{kind.lower()}_{version['name']}.json"
                    target.parent.mkdir(parents=True, exist_ok=True)
                    converted = convert(schema)
                    converted["$schema"] = "http://json-schema.org/draft-07/schema#"
                    target.write_text(json.dumps(converted), encoding="utf-8")
                    written += 1
    if written == 0:
        sys.exit("no CustomResourceDefinition found in the inputs")
    print(f"wrote {written} schema files to {out_dir}")


if __name__ == "__main__":
    main(sys.argv)
