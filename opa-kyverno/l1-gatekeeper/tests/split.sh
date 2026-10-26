#!/usr/bin/env bash
# Split the combined templates/constraints into one file per object under ./generated/ for gator.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf generated && mkdir -p generated/templates generated/constraints
yq -s '"generated/templates/" + .metadata.name' ../templates.yaml
yq -s '"generated/constraints/" + .metadata.name' ../constraints.yaml
# yq -s writes ./generated/<...>.yml relative to cwd
find generated -name '*.yml' -exec sh -c 'mv "$1" "${1%.yml}.yaml"' _ {} \;
