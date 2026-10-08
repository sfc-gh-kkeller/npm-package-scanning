#!/usr/bin/env python3
"""Blessed-npm scanner: mirror -> quarantine -> scan -> verdict -> promote.

Usage:
  python3 scan.py --packages packages.txt --out ./out [--cooldown-days 7]

packages.txt: one spec per line (e.g. `express@^4`, `lodash@4.17.21`).

For every spec the full dependency tree is resolved (npm --package-lock-only,
no scripts), every tarball is downloaded into out/quarantine, its integrity
is verified, and each package version gets one verdict:

  APPROVE  copied to out/blessed, served by the registry
  HOLD     needs a human / AI review (install scripts, too new, heuristics)
  REJECT   never served (known malware, high/critical vuln, bad integrity)

A root spec is only usable if its whole tree is APPROVE. The registry only
serves out/blessed, so a HOLD/REJECT dependency makes `npm install` fail
closed. Results: out/results.jsonl, out/ai_review_queue.jsonl.

"No known vulnerabilities at scan time" is the claim, not "CVE-free":
re-run this on a schedule and withdraw versions whose verdict changes.
"""
import argparse
import base64
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

REGISTRY = os.environ.get("UPSTREAM_REGISTRY", "https://registry.npmjs.org")
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"

# Scripts npm runs when installing a registry tarball. `prepare` only runs for
# git/local installs, so it is not install-time here.
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")

# Code heuristics, scanned per file. Each hit is a HOLD reason, not a REJECT:
# plenty of legitimate packages spawn processes. AI / human decides.
HEURISTICS = [
    ("child_process", re.compile(rb"require\(\s*['\"](node:)?child_process['\"]\s*\)")),
    ("eval", re.compile(rb"\beval\s*\(")),
    ("new_function", re.compile(rb"new\s+Function\s*\(")),
    ("hardcoded_ip_url", re.compile(rb"https?://\d{1,3}(\.\d{1,3}){3}")),
    ("env_harvest", re.compile(rb"JSON\.stringify\(\s*process\.env\s*\)")),
    ("long_base64", re.compile(rb"[A-Za-z0-9+/]{800,}={0,2}")),
    ("webhook_exfil", re.compile(rb"(discord(app)?\.com/api/webhooks|pastebin\.com|ngrok\.io|requestbin|pipedream\.net)")),
]
MAX_LINE = 5000  # minified bundles are normal; we only flag install-time files for this


def http_json(url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json",
                                                          "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def http_bytes(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def resolve_tree(specs):
    """Resolve the full tree without running any package code."""
    tmp = tempfile.mkdtemp(prefix="blessed-resolve-")
    with open(os.path.join(tmp, "package.json"), "w") as f:
        json.dump({"name": "blessed-resolve", "version": "0.0.0", "private": True}, f)
    cmd = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit",
           "--no-fund", "--registry", REGISTRY] + specs
    p = subprocess.run(cmd, cwd=tmp, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"resolve failed:\n{p.stderr}")
    lock = json.load(open(os.path.join(tmp, "package-lock.json")))
    root_deps = lock["packages"][""].get("dependencies", {})
    pkgs = {}
    for path, meta in lock["packages"].items():
        if not path:
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        key = f"{name}@{meta['version']}"
        pkgs[key] = {"name": name, "version": meta["version"],
                     "resolved": meta.get("resolved"), "integrity": meta.get("integrity")}
    shutil.rmtree(tmp, ignore_errors=True)
    return pkgs, lock, root_deps


def verify_integrity(blob, integrity):
    if not integrity or "-" not in integrity:
        return False
    algo, b64 = integrity.split("-", 1)
    h = hashlib.new(algo, blob).digest()
    return base64.b64encode(h).decode() == b64


def osv_lookup(pkgs):
    """Known vulns + OpenSSF malicious-package (MAL-*) entries, per version."""
    keys = list(pkgs)
    out = {k: [] for k in keys}
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        q = {"queries": [{"package": {"name": pkgs[k]["name"], "ecosystem": "npm"},
                          "version": pkgs[k]["version"]} for k in chunk]}
        res = http_json(OSV_BATCH, q)["results"]
        for k, r in zip(chunk, res):
            out[k] = [v["id"] for v in r.get("vulns", [])]
    return out


_vuln_cache = {}


def vuln_severity(vid):
    """Return (is_malware, severity_label). Malware IDs are MAL-*."""
    if vid.startswith("MAL-"):
        return True, "MALWARE"
    if vid not in _vuln_cache:
        try:
            _vuln_cache[vid] = http_json(OSV_VULN + vid)
        except Exception:
            _vuln_cache[vid] = {}
    v = _vuln_cache[vid]
    if any(a.startswith("MAL-") for a in v.get("aliases", [])):
        return True, "MALWARE"
    sev = (v.get("database_specific") or {}).get("severity") or ""
    return False, sev.upper() or "UNKNOWN"


_packument_cache = {}


def publish_time(name, version):
    if name not in _packument_cache:
        enc = name.replace("/", "%2f")
        _packument_cache[name] = http_json(f"{REGISTRY}/{enc}")
    t = _packument_cache[name].get("time", {}).get(version)
    return dt.datetime.fromisoformat(t.replace("Z", "+00:00")) if t else None


def inspect_tarball(blob):
    """Return (manifest, install_scripts, heuristic_hits, files_for_review)."""
    manifest, hits, review = {}, [], []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        members = [m for m in tf.getmembers() if m.isfile()]
        for m in members:
            if m.name.endswith("/package.json") and m.name.count("/") == 1:
                manifest = json.load(tf.extractfile(m))
        scripts = {k: v for k, v in (manifest.get("scripts") or {}).items() if k in INSTALL_SCRIPTS}
        # files that run at install time get the strictest look
        install_files = set()
        for cmd in scripts.values():
            for tok in re.findall(r"[\w./-]+\.(?:js|cjs|mjs|sh)", cmd):
                install_files.add(tok.lstrip("./"))
        for m in members:
            if not m.name.endswith((".js", ".cjs", ".mjs", ".sh")) or m.size > 5_000_000:
                continue
            data = tf.extractfile(m).read()
            rel = m.name.split("/", 1)[-1]
            file_hits = [name for name, rx in HEURISTICS if rx.search(data)]
            at_install = rel in install_files
            if at_install and any(len(l) > MAX_LINE for l in data.splitlines()):
                file_hits.append("obfuscated_install_file")
            # only install-time files or high-signal hits go to HOLD
            strong = {"env_harvest", "webhook_exfil", "hardcoded_ip_url", "obfuscated_install_file"}
            if at_install or strong.intersection(file_hits):
                if file_hits or at_install:
                    hits.extend(f"{rel}:{h}" for h in file_hits)
                    review.append({"file": rel, "hits": file_hits, "install_time": at_install,
                                   "snippet": data[:6000].decode("utf-8", "replace")})
    return manifest, scripts, hits, review


def verdict_for(osv_ids, integrity_ok, scripts, hits, age_days, cooldown, script_allow):
    reasons = []
    if not integrity_ok:
        return "REJECT", ["integrity_mismatch"]
    for vid in osv_ids:
        mal, sev = vuln_severity(vid)
        if mal:
            return "REJECT", [f"malware:{vid}"]
        if sev in ("HIGH", "CRITICAL"):
            reasons.append(f"vuln:{vid}:{sev}")
    if reasons:
        return "REJECT", reasons
    for vid in osv_ids:
        reasons.append(f"vuln:{vid}:{vuln_severity(vid)[1]}")
    if scripts and not script_allow:
        reasons.append("install_scripts:" + ",".join(scripts))
    if age_days is not None and age_days < cooldown:
        reasons.append(f"too_new:{age_days:.1f}d<{cooldown}d")
    reasons.extend(f"heuristic:{h}" for h in hits)
    hold = [r for r in reasons if not r.startswith("vuln:") or r.endswith((":MODERATE", ":UNKNOWN"))]
    return ("HOLD" if hold else "APPROVE"), reasons


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--packages", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cooldown-days", type=float, default=7)
    ap.add_argument("--results", help="dir for results.jsonl / ai_review_queue.jsonl (default: --out)")
    ap.add_argument("--allow-scripts", default="", help="comma list of names whose install scripts are pre-reviewed")
    a = ap.parse_args()

    specs = [l.strip() for l in open(a.packages) if l.strip() and not l.startswith("#")]
    script_allow = {s.strip() for s in a.allow_scripts.split(",") if s.strip()}
    quarantine = os.path.join(a.out, "quarantine")
    blessed = os.path.join(a.out, "blessed")
    os.makedirs(quarantine, exist_ok=True)
    os.makedirs(blessed, exist_ok=True)

    print(f"resolving {len(specs)} root specs ...", file=sys.stderr)
    pkgs, lock, _ = resolve_tree(specs)
    print(f"  {len(pkgs)} package versions in tree", file=sys.stderr)
    osv = osv_lookup(pkgs)
    now = dt.datetime.now(dt.timezone.utc)

    results, ai_queue = {}, []
    for key, p in sorted(pkgs.items()):
        blob = http_bytes(p["resolved"])
        fname = f"{p['name'].replace('/', '__')}-{p['version']}.tgz"
        with open(os.path.join(quarantine, fname), "wb") as f:
            f.write(blob)
        ok = verify_integrity(blob, p["integrity"])
        manifest, scripts, hits, review = inspect_tarball(blob) if ok else ({}, {}, [], [])
        pt = publish_time(p["name"], p["version"])
        age = (now - pt).total_seconds() / 86400 if pt else None
        v, reasons = verdict_for(osv[key], ok, scripts, hits, age, a.cooldown_days,
                                 p["name"] in script_allow)
        r = {"package": p["name"], "version": p["version"], "verdict": v, "reasons": reasons,
             "integrity": p["integrity"], "sha256": hashlib.sha256(blob).hexdigest(),
             "osv_ids": osv[key], "install_scripts": scripts,
             "published_at": pt.isoformat() if pt else None,
             "scanned_at": now.isoformat(), "tarball": fname,
             "manifest": {k: manifest.get(k) for k in ("name", "version", "dependencies",
                                                       "optionalDependencies", "peerDependencies",
                                                       "bin", "engines", "os", "cpu", "license")}}
        results[key] = r
        if v == "HOLD" and review:
            ai_queue.append({"package": p["name"], "version": p["version"], "reasons": reasons,
                             "install_scripts": scripts, "files": review})
        if v == "APPROVE":
            shutil.copy(os.path.join(quarantine, fname), os.path.join(blessed, fname))
        print(f"  {v:8} {key:45} {'; '.join(reasons)[:110]}", file=sys.stderr)

    rdir = a.results or a.out
    os.makedirs(rdir, exist_ok=True)
    with open(os.path.join(rdir, "results.jsonl"), "w") as f:
        for r in results.values():
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(rdir, "ai_review_queue.jsonl"), "w") as f:
        for q in ai_queue:
            f.write(json.dumps(q) + "\n")
    # registry index: only APPROVE rows
    with open(os.path.join(blessed, "index.json"), "w") as f:
        json.dump([r for r in results.values() if r["verdict"] == "APPROVE"], f, indent=1)

    counts = {}
    for r in results.values():
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(json.dumps(counts), file=sys.stderr)


if __name__ == "__main__":
    main()
