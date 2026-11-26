#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# tools/shield-entries.py -- the catalog or feed entries of a pushed
# package, for tools/put-shields --catalog and --feed: one JSON object per
# line for each [upatches.tree] entry of its Beefile.
#
#   shield-entries.py [--feed] <beefile> <reference> <manifest_digest> <version>

import json
import re
import sys
import tomllib

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$")


def selector_of(table):
    """The entry's selector in canonical key order, with map keys sorted."""
    out = {}
    if "architecture" in table:
        out["architecture"] = list(table["architecture"])
    kcfg = table.get("kconfig") or table.get("kernel_config")
    if kcfg:
        out["kconfig"] = {k: list(kcfg[k]) for k in sorted(kcfg)}
    if "kernel_build_id" in table:
        out["kernel_build_id"] = list(table["kernel_build_id"])
    if "kernel_release_prefix" in table:
        out["kernel_release_prefix"] = list(table["kernel_release_prefix"])
    if "labels" in table:
        labels = table["labels"]
        out["labels"] = {k: list(labels[k]) for k in sorted(labels)}
    return out


def catalog_selector_of(table):
    """The entry's selector as a publication spells it: lists sorted."""
    out = {}
    for key, value in table.items():
        if isinstance(value, dict):
            out[key] = {k: sorted(v) for k, v in value.items()}
        else:
            out[key] = sorted(value)
    return out


def role_of(upatch, tree):
    role = tree.get("role")
    if role in ("mitigation", "detector"):
        return role
    source = upatch.get("source", "")
    if "detector" in tree.get("id", "") or "/observability/" in source:
        return "detector"
    return "mitigation"


def main():
    feed_mode = False
    args = sys.argv[1:]
    if args and args[0] == "--feed":
        feed_mode = True
        args = args[1:]
    if len(args) != 4:
        print("usage: shield-entries.py [--feed] <beefile> <reference>"
              " <manifest_digest> <version>", file=sys.stderr)
        return 2
    path, reference, digest, version = args
    try:
        with open(path, "rb") as f:
            beefile = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as error:
        print("put-shields: cannot read %s: %s" % (path, error),
              file=sys.stderr)
        return 1
    package = beefile["package"]
    for upatch in beefile.get("upatches", []):
        tree = upatch.get("tree")
        if not tree:
            continue
        if feed_mode:
            cves = sorted(c for c in tree.get("fixes", []) if CVE_RE.match(c))
            if not cves:
                continue
            entry = {
                "id": tree["id"],
                "cves": cves,
                "package": package["name"],
                "version": version,
                "reference": reference,
                "manifest_digest": digest,
                "role": role_of(upatch, tree),
                "selector": selector_of(tree.get("selector", {})),
                "description": package.get("description", ""),
            }
            print(json.dumps(entry, ensure_ascii=False, separators=(",", ":")))
        else:
            print(json.dumps({
                "id": tree["id"],
                "package": package["name"],
                "version": version,
                "reference": reference,
                "manifest_digest": digest,
                "fixes": sorted(tree.get("fixes", [])),
                "selector": catalog_selector_of(tree.get("selector", {})),
                "description": package.get("description", ""),
            }, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
