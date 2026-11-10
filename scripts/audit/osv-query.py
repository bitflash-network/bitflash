#!/usr/bin/env python3
"""Ask OSV (https://osv.dev) about every source dependency pinned by commit.

The tree has no package manifest for scanners to read: libsecp256k1 and
RandomX are fetched at the commits the top-level Makefile pins, and the
foreign-chain proof-of-work code is copied from tagged upstream commits listed
in src/pow_vendor/UPSTREAM.json. OSV indexes vulnerabilities by the git commits
they affect, so each pinned commit is one query.

    python3 scripts/audit/osv-query.py [repo-root]

Prints one line per dependency and every advisory OSV knows for its commit.
Exit status: 0 nothing known, 1 at least one advisory, 2 the query failed.
Only public commit hashes leave the machine.
"""
import json
import os
import re
import sys
import urllib.request

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")


def pinned():
    deps = []
    with open(os.path.join(ROOT, "Makefile"), encoding="utf-8") as f:
        mk = f.read()
    for name, var, repo in (("libsecp256k1", "SECP256K1_COMMIT", "https://github.com/bitcoin-core/secp256k1"),
                            ("RandomX", "RANDOMX_COMMIT", "https://github.com/tevador/RandomX")):
        m = re.search(r"^%s\s*:=\s*([0-9a-f]{40})\s*$" % var, mk, re.M)
        if not m:
            raise SystemExit("Makefile: %s not found" % var)
        deps.append((name, repo, m.group(1)))
    with open(os.path.join(ROOT, "src", "pow_vendor", "UPSTREAM.json"), encoding="utf-8") as f:
        up = json.load(f)
    for key in ("digibyte", "ravencoin"):
        entry = up[key]
        deps.append((key, "https://github.com/" + entry["repo"], entry["commit"]))
    return deps


def main():
    deps = pinned()
    body = json.dumps({"queries": [{"commit": c} for _, _, c in deps]}).encode()
    req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            res = json.load(r)["results"]
    except Exception as e:  # network down, API changed
        print("OSV query failed: %s" % e)
        return 2
    found = 0
    for (name, repo, commit), r in zip(deps, res):
        vulns = r.get("vulns", [])
        print("%-14s %s  %s  advisories: %d" % (name, commit[:12], repo, len(vulns)))
        for v in vulns:
            found += 1
            print("    %s  https://osv.dev/vulnerability/%s" % (v["id"], v["id"]))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
