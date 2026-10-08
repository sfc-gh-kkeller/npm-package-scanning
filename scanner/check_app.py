#!/usr/bin/env python3
"""SAR scan-gate check: the app may only resolve packages from the blessed registry.

  python3 check_app.py <app_dir> <blessed_registry_url>

REFUSE (exit 1) if:
  - no package-lock.json (unpinned tree = scanner never saw it)
  - .npmrc missing, or sets any other registry / scoped registry
  - any lockfile entry resolves outside the blessed registry, or lacks integrity
  - git/file/http tarball dependencies in package.json
"""
import json
import os
import re
import sys

app, blessed = sys.argv[1], sys.argv[2].rstrip("/") + "/"
fail = []

npmrc = os.path.join(app, ".npmrc")
if not os.path.exists(npmrc):
    fail.append(".npmrc missing (must set registry=" + blessed + ")")
else:
    for line in open(npmrc):
        m = re.match(r"\s*(@[\w-]+:)?registry\s*=\s*(\S+)", line)
        if m and m.group(2).rstrip("/") + "/" != blessed:
            fail.append(f".npmrc: {line.strip()}")

pkg = json.load(open(os.path.join(app, "package.json")))
for sect in ("dependencies", "devDependencies", "optionalDependencies"):
    for name, spec in (pkg.get(sect) or {}).items():
        if re.match(r"(git\+|git:|github:|file:|https?:|link:)", str(spec)) or "/" in str(spec) and not str(spec).startswith("npm:"):
            fail.append(f"package.json {sect}.{name} = {spec} (non-registry source)")

lockp = os.path.join(app, "package-lock.json")
if not os.path.exists(lockp):
    fail.append("package-lock.json missing")
else:
    for path, meta in json.load(open(lockp)).get("packages", {}).items():
        if not path or meta.get("link"):
            continue
        r = meta.get("resolved", "")
        if not r.startswith(blessed):
            fail.append(f"lock {path}: resolved {r or '<none>'}")
        if not meta.get("integrity"):
            fail.append(f"lock {path}: no integrity")

if fail:
    print("REFUSE")
    for f in fail[:50]:
        print("  -", f)
    sys.exit(1)
print("PASS: all packages resolve from", blessed)
