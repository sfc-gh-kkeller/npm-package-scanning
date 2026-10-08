# Blessed npm: scanned mirror that SAR builds must use

> Community example, not an official Snowflake product or supported feature. Test in a non-production account first.

Snowflake does not ship a scanned npm mirror. This folder is a customer-run one:
a mirror job pulls popular packages into quarantine, scans them, and promotes only
approved versions. A registry with **no upstream** serves those versions to SAR
builds. Anything else returns a 404, so `npm install` fails closed.

Same pattern as JFrog + Xray or Nexus + Lifecycle, built from Snowflake pieces.
If the customer already runs one of those, use it and keep only the SAR wiring
and the scan-gate check below.

## Flow

```mermaid
flowchart LR
  W[WANTED list<br/>top-N + requests] --> S
  subgraph SPCS job — EAI: registry.npmjs.org, api.osv.dev only
    S[resolve full tree<br/>--ignore-scripts] --> D[download tarballs<br/>verify integrity]
    D --> O[OSV: CVEs + MAL-* malware]
    D --> H[install scripts, age,<br/>code heuristics]
  end
  O --> V{verdict}
  H --> V
  V -->|REJECT| Q[(@QUARANTINE)]
  V -->|HOLD| Q --> AI[AI_COMPLETE advisory] --> HU[reviewer]
  V -->|APPROVE| B[(@BLESSED)]
  HU -->|APPROVE| B
  B --> R[Registry service<br/>no uplink, no EAI]
  R --> SAR[SAR build<br/>build_eai → registry only]
```

| Verdict | Rule | Who can override |
|---|---|---|
| **REJECT** | Integrity mismatch · OSV `MAL-*` / malware alias · HIGH/CRITICAL advisory | Nobody (the `SERVED` view enforces this). Bump the version. |
| **HOLD** | `preinstall`/`install`/`postinstall` scripts · published < 7 days ago · MODERATE/unknown advisory · install-time file with `child_process`, `eval`, env harvest, raw-IP URL, webhook host, obfuscation | Reviewer, after the optional AI verdict |
| **APPROVE** | none of the above (LOW advisories recorded) | — |

A root package is only usable if its **whole tree** is approved. That falls out of
the registry: a held dependency 404s.

## Files

| Path | What |
|---|---|
| `scanner/scan.py` | resolve → quarantine → OSV + heuristics → verdict → blessed + `index.json` |
| `scanner/check_app.py` | SAR scan-gate check: `.npmrc` + lockfile must resolve only from the blessed registry |
| `scanner/Dockerfile`, `entrypoint.sh` | scanner image for an SPCS job |
| `registry/server.js`, `Dockerfile` | read-only registry, serves only `index.json` rows |
| `sql/setup.sql` | DB, roles, stages, EAI (scanner only), result tables, `SERVED` view, job, service, `AI_COMPLETE` review |
| `sql/promote.sql` | copy human-approved HOLDs, rewrite `index.json` from `SERVED`, daily-rescan task |

## Tested locally (2026-10-08, real npm + OSV data)

Seed list: `express@^4, react@18.3.1, react-dom@18.3.1, zod@3.23.8, lodash@4.17.15, esbuild@0.24.0`
→ 100 versions in the tree: **98 APPROVE, 1 HOLD, 1 REJECT**

| # | Test | Result |
|---|---|---|
| 1 | `npm install express react react-dom zod` against registry | **PASS** — 74 packages, runtime `require` OK, express 4.22.3 |
| 2 | `lodash@4.17.15` (3 HIGH GHSAs) | **REJECT → E404** "not on the blessed list" |
| 3 | `esbuild@0.24.0` (postinstall + `child_process` + MODERATE) | **HOLD → E404** until a reviewer approves |
| 4 | `axios` (never requested) | **E404** — no upstream fallback |
| 5 | Guess a tarball URL for a rejected file | **404** — only indexed tarballs are served |
| 6 | Tamper a blessed tarball after approval | **EINTEGRITY** — npm refuses it (integrity is pinned at scan time) |
| 7 | `check_app.py` on an app built from blessed | **PASS** |
| 8 | `check_app.py` on an app locked against public npm, no `.npmrc` | **REFUSE** |

The first run had already caught `express@4.21.2` → `path-to-regexp@0.1.12` (HIGH).
With `express@^4`, npm resolved the patched line. That is the expected loop:
pin → scan → upgrade.

The first run also wrongly held `zod` and `mime` for a `prepare` script. npm does
not run `prepare` for registry installs, so it was removed from the
install-time set.

## Tested on aws_demo (2026-10-08, AWS test account)

Objects: `BLESSED_NPM.REG.*`, pool `BLESSED_NPM_POOL`, EAI `BLESSED_NPM_SCANNER_EAI` (scanner only).
`ALLOW_NPM_PACKAGE_DOWNLOAD` was left at TRUE (account-wide, not touched).

| # | Test | Result |
|---|---|---|
| 1 | Scanner as SPCS job (EAI: npmjs + OSV only), writes to stage volumes | **DONE** — 100 versions: 98 APPROVE / 1 HOLD / 1 REJECT, same as local |
| 2 | Load `results.jsonl` / `ai_review_queue.jsonl` into tables | 100 + 1 rows |
| 3 | Registry service, `@BLESSED` stage volume, **no EAI** | READY, 97 packages served |
| 4 | **SAR build, `.npmrc` → `http://registry.<hash>.svc.spcs.internal:4873/`, no `build_eai`** | **PASS** — registry log: 151 metadata + tarball GETs from the build pod (10.244.1.202); build DONE |
| 5 | That SAR app over HTTPS | **200** `express 4.22.3` (the blessed tarball) |
| 6 | Same app + `esbuild@0.24.0` (HOLD) | **Build FAILED**: `E404 … esbuild is not on the blessed list` — nothing deployed |
| 7 | Registry public endpoint, `Authorization: Snowflake Token="<PAT>"` | 200 (curl) |
| 8 | Registry public endpoint, `Authorization: Bearer <PAT>` (what npm sends) | **302 to login** — npm cannot authenticate to SPCS ingress |

**So use path A (internal DNS).** SAR builds reach an SPCS service in the same account
over `*.svc.spcs.internal` without any EAI. The "EAI to our own public URL" fallback
(path B) does not work with stock npm: npm can only send `Bearer`/`Basic`, and SPCS
ingress wants the `Snowflake Token` scheme. It would need a header-rewriting proxy
inside the build, which is worse in every way.

Findings from the deploy:
- Stage volumes mount root-owned. Give them `uid`/`gid` matching the container user.
  The mount parent (`/work`) is not writable, so `scan.py --results` writes into a stage mount.
- **Security note on path A:** if a SAR build can reach this internal service with no EAI,
  it can presumably reach *other* SPCS services in the account the same way, including
  their install scripts. Not tested against other services yet. Keep internal
  endpoints authenticated or read-only. This registry is read-only by design.

## Still open

- **Exclusivity on this account.** The `.npmrc` here is honored, but an app that deletes it
  would fall back to public npm while `ALLOW_NPM_PACKAGE_DOWNLOAD = TRUE`. Two controls cover that:
  - `check_app.py` in the SAR scan gate REFUSEs it.
  - Setting the parameter to FALSE closes it at the network. Proven on an Azure test account
    (`privatelink_registry_test/E2E_RESULTS.md`); not changed here because it is account-wide.
- **AI review SQL.** It is written but has not been run (model availability varies by region).
  Treat it as advisory only.
- `promote.sql` (rewrite `index.json` from `SERVED` after human approvals) has not been run yet.

## What to claim

- "No known vulnerabilities or malware matches **at time of last scan**". Do not say "CVE-free".
  Rescan daily, and a new finding withdraws the version on the next `index.json` rewrite.
- OSV catches *known* malware. A brand-new malicious version is held back by the
  **7-day cooldown** + install-script HOLD, not by OSV.
- This governs **which packages** get into the build. It does nothing about the app's own
  code: XSS, form exfiltration and over-broad grants are still the job of the SAR scan gate
  (application-code scanning is a separate control).

## Run locally

```bash
python3 scanner/scan.py --packages test/packages.txt --out out
BLESSED_DIR=out/blessed node registry/server.js &
cd /tmp/app && echo 'registry=http://localhost:4873/' > .npmrc && npm install express@^4
python3 scanner/check_app.py /tmp/app http://localhost:4873/
```
