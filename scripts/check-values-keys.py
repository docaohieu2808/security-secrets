#!/usr/bin/env python3
"""Fail when a Helm values file sets a key the chart does not define.

    check-values-keys.py <chart-defaults.yaml> <values.yaml> [--allow <dotted.path>]...

Helm silently ignores unknown keys, so a misspelled or removed setting (`securityContext` instead of
`containerSecurityContext`, `acceptancepolicy`, `falco.grpc`...) does nothing and nobody notices. This compares the
file against the output of `helm show values <chart> --version <v>`.

A path is only descended into when the chart default there is a non-empty mapping; free-form areas (an empty `{}`
default, lists, scalars) accept anything. `--allow` marks a path as free-form, for sub-chart values that the parent
chart does not list (for example `falcosidekick.config`).
"""
import sys

import yaml


def unknown_keys(defaults, values, path, allowed):
    found = []
    if not isinstance(values, dict) or not isinstance(defaults, dict) or not defaults:
        return found
    for key, value in values.items():
        here = f"{path}.{key}" if path else str(key)
        if any(here == a or here.startswith(a + ".") for a in allowed):
            continue
        if key not in defaults:
            found.append(here)
        else:
            found += unknown_keys(defaults[key], value, here, allowed)
    return found


def main(argv):
    args = argv[1:]
    allowed = []
    while "--allow" in args:
        i = args.index("--allow")
        allowed.append(args[i + 1])
        del args[i : i + 2]
    if len(args) != 2:
        sys.exit(__doc__)
    with open(args[0], encoding="utf-8") as f:
        defaults = yaml.safe_load(f) or {}
    with open(args[1], encoding="utf-8") as f:
        values = yaml.safe_load(f) or {}
    bad = unknown_keys(defaults, values, "", allowed)
    for key in bad:
        print(f"{args[1]}: key not defined by the chart: {key}")
    if bad:
        sys.exit(1)
    print(f"{args[1]}: every key is defined by the chart")


if __name__ == "__main__":
    main(sys.argv)
