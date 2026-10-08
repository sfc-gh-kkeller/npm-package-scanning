-- Blessed npm on Snowflake: objects, scanner job, registry service, SAR wiring.
-- Scoped to one database + roles. Nothing account-wide except the optional
-- ALLOW_NPM_PACKAGE_DOWNLOAD line at the bottom (left commented on purpose).

USE ROLE ACCOUNTADMIN;
CREATE ROLE IF NOT EXISTS BLESSED_NPM_ADMIN;     -- runs scanner + registry
CREATE ROLE IF NOT EXISTS BLESSED_NPM_REVIEWER;  -- decides HOLD items
GRANT ROLE BLESSED_NPM_ADMIN TO ROLE SYSADMIN;

CREATE DATABASE IF NOT EXISTS BLESSED_NPM;
CREATE SCHEMA IF NOT EXISTS BLESSED_NPM.REG;
GRANT OWNERSHIP ON DATABASE BLESSED_NPM TO ROLE BLESSED_NPM_ADMIN COPY CURRENT GRANTS;
GRANT OWNERSHIP ON SCHEMA BLESSED_NPM.REG TO ROLE BLESSED_NPM_ADMIN COPY CURRENT GRANTS;

-- Egress for the SCANNER only: upstream npm + OSV. The registry gets no EAI.
CREATE OR REPLACE NETWORK RULE BLESSED_NPM.REG.SCANNER_EGRESS
  MODE = EGRESS TYPE = HOST_PORT
  VALUE_LIST = ('registry.npmjs.org:443', 'api.osv.dev:443');
CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION BLESSED_NPM_SCANNER_EAI
  ALLOWED_NETWORK_RULES = (BLESSED_NPM.REG.SCANNER_EGRESS) ENABLED = TRUE;
GRANT USAGE ON INTEGRATION BLESSED_NPM_SCANNER_EAI TO ROLE BLESSED_NPM_ADMIN;

CREATE COMPUTE POOL IF NOT EXISTS BLESSED_NPM_POOL
  MIN_NODES = 1 MAX_NODES = 1 INSTANCE_FAMILY = CPU_X64_XS AUTO_SUSPEND_SECS = 600;
GRANT USAGE, MONITOR ON COMPUTE POOL BLESSED_NPM_POOL TO ROLE BLESSED_NPM_ADMIN;
GRANT BIND SERVICE ENDPOINT ON ACCOUNT TO ROLE BLESSED_NPM_ADMIN;  -- or rely on PUBLIC default

USE ROLE BLESSED_NPM_ADMIN;
USE SCHEMA BLESSED_NPM.REG;

-- Two stages = two trust zones. Only the scanner writes BLESSED.
CREATE STAGE IF NOT EXISTS QUARANTINE ENCRYPTION = (TYPE = 'SNOWFLAKE_SSE') DIRECTORY = (ENABLE = TRUE);
CREATE STAGE IF NOT EXISTS BLESSED    ENCRYPTION = (TYPE = 'SNOWFLAKE_SSE') DIRECTORY = (ENABLE = TRUE);
CREATE STAGE IF NOT EXISTS CONFIG     ENCRYPTION = (TYPE = 'SNOWFLAKE_SSE');  -- packages.txt
CREATE IMAGE REPOSITORY IF NOT EXISTS IMAGES;

-- What to mirror. Seed with your top-N list; vibe-code templates pin from here.
CREATE TABLE IF NOT EXISTS WANTED (spec STRING, requested_by STRING DEFAULT CURRENT_USER(),
                                   requested_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP());

-- One row per package version per scan. Loaded from results.jsonl.
CREATE TABLE IF NOT EXISTS SCAN_RESULTS (
  package STRING, version STRING, verdict STRING, reasons ARRAY,
  integrity STRING, sha256 STRING, osv_ids ARRAY, install_scripts VARIANT,
  published_at TIMESTAMP_TZ, scanned_at TIMESTAMP_TZ, tarball STRING, manifest VARIANT);

-- HOLD items with the suspicious file snippets, for AI and/or human review.
CREATE TABLE IF NOT EXISTS AI_REVIEW_QUEUE (
  package STRING, version STRING, reasons ARRAY, install_scripts VARIANT, files ARRAY,
  ai_verdict VARIANT, human_verdict STRING, human_by STRING, human_at TIMESTAMP_LTZ);

-- Current truth the registry serves = latest scan + human overrides.
CREATE OR REPLACE VIEW SERVED AS
WITH latest AS (
  SELECT * FROM SCAN_RESULTS
  QUALIFY ROW_NUMBER() OVER (PARTITION BY package, version ORDER BY scanned_at DESC) = 1)
SELECT l.*,
       CASE WHEN l.verdict = 'REJECT' THEN 'REJECT'              -- humans cannot override malware/HIGH
            WHEN q.human_verdict = 'APPROVE' THEN 'APPROVE'
            WHEN q.human_verdict = 'REJECT'  THEN 'REJECT'
            ELSE l.verdict END AS effective_verdict
FROM latest l
LEFT JOIN AI_REVIEW_QUEUE q ON q.package = l.package AND q.version = l.version;

GRANT USAGE ON DATABASE BLESSED_NPM TO ROLE BLESSED_NPM_REVIEWER;
GRANT USAGE ON SCHEMA BLESSED_NPM.REG TO ROLE BLESSED_NPM_REVIEWER;
GRANT SELECT ON TABLE SCAN_RESULTS TO ROLE BLESSED_NPM_REVIEWER;
GRANT SELECT, UPDATE ON TABLE AI_REVIEW_QUEUE TO ROLE BLESSED_NPM_REVIEWER;
GRANT SELECT ON VIEW SERVED TO ROLE BLESSED_NPM_REVIEWER;

-- ---------------------------------------------------------------------------
-- Scanner: SPCS job. Reads @CONFIG/packages.txt, writes @QUARANTINE and
-- @BLESSED (volumes), then the loader below ingests results.jsonl.
-- Build/push: see ../Dockerfile.scanner and ../README.md.
-- ---------------------------------------------------------------------------
EXECUTE JOB SERVICE IN COMPUTE POOL BLESSED_NPM_POOL
  NAME = BLESSED_NPM.REG.SCAN_JOB
  EXTERNAL_ACCESS_INTEGRATIONS = (BLESSED_NPM_SCANNER_EAI)
  FROM SPECIFICATION $$
spec:
  containers:
  - name: scanner
    image: /blessed_npm/reg/images/blessed-scanner:latest
    command: ["/app/entrypoint.sh"]
    volumeMounts:
    - {name: config, mountPath: /config}
    - {name: quarantine, mountPath: /work/quarantine}
    - {name: blessed, mountPath: /work/blessed}
  volumes:
  - {name: config, source: "@BLESSED_NPM.REG.CONFIG", uid: 1001, gid: 1001}
  - {name: quarantine, source: "@BLESSED_NPM.REG.QUARANTINE", uid: 1001, gid: 1001}
  - {name: blessed, source: "@BLESSED_NPM.REG.BLESSED", uid: 1001, gid: 1001}
$$;
-- Stage volumes mount root-owned: uid/gid must match the image user (scanner = 1001).
-- entrypoint.sh writes results.jsonl / ai_review_queue.jsonl to
-- /work/quarantine/_results/ (the mount parent /work is not writable).

-- Load results.
CREATE FILE FORMAT IF NOT EXISTS JSONL TYPE = JSON;
COPY INTO SCAN_RESULTS FROM (
  SELECT $1:package, $1:version, $1:verdict, $1:reasons, $1:integrity, $1:sha256,
         $1:osv_ids, $1:install_scripts, $1:published_at::TIMESTAMP_TZ,
         $1:scanned_at::TIMESTAMP_TZ, $1:tarball, $1:manifest
  FROM @QUARANTINE/_results/results.jsonl) FILE_FORMAT = JSONL FORCE = TRUE;
COPY INTO AI_REVIEW_QUEUE (package, version, reasons, install_scripts, files) FROM (
  SELECT $1:package, $1:version, $1:reasons, $1:install_scripts, $1:files
  FROM @QUARANTINE/_results/ai_review_queue.jsonl) FILE_FORMAT = JSONL FORCE = TRUE;

-- ---------------------------------------------------------------------------
-- Optional AI review of HOLD items. ADVISORY: it writes ai_verdict only.
-- Promotion still needs human_verdict = 'APPROVE' (or a policy you choose).
-- Never let a model approve something OSV marked REJECT — SERVED enforces that.
-- ---------------------------------------------------------------------------
UPDATE AI_REVIEW_QUEUE q
SET ai_verdict = AI_COMPLETE(
  model => 'claude-sonnet-4-5',
  prompt => 'You review npm package code for supply-chain malware before it enters a '
         || 'private registry. Judge ONLY the evidence below. Benign examples: downloading '
         || 'a platform binary from the package''s own GitHub/npm release, node-gyp builds. '
         || 'Malicious examples: reading process.env/~/.npmrc/ssh keys and sending them out, '
         || 'obfuscated payloads, contacting raw IPs or webhooks, writing outside the package dir.\n'
         || 'Package: ' || q.package || '@' || q.version || '\n'
         || 'Scanner reasons: ' || ARRAY_TO_STRING(q.reasons, '; ') || '\n'
         || 'Install scripts: ' || COALESCE(TO_JSON(q.install_scripts), '{}') || '\n'
         || 'Files (truncated):\n' || LEFT(TO_JSON(q.files), 40000),
  response_format => {
    'type': 'json',
    'schema': {'type': 'object',
               'properties': {'verdict': {'type': 'string', 'enum': ['BENIGN', 'SUSPICIOUS', 'MALICIOUS']},
                              'confidence': {'type': 'number'},
                              'evidence': {'type': 'string'}},
               'required': ['verdict', 'confidence', 'evidence']}})
WHERE q.ai_verdict IS NULL;

-- Reviewer decides (example).
-- UPDATE AI_REVIEW_QUEUE SET human_verdict='APPROVE', human_by=CURRENT_USER(), human_at=CURRENT_TIMESTAMP()
--  WHERE package='esbuild' AND version='0.24.0';

-- Republish index.json from SERVED so human approvals/withdrawals take effect.
-- (A human-approved HOLD tarball must also be copied QUARANTINE -> BLESSED;
--  see promote.sql.)

-- ---------------------------------------------------------------------------
-- Registry: long-running service, stage volume, NO external access.
-- ---------------------------------------------------------------------------
CREATE SERVICE IF NOT EXISTS BLESSED_NPM.REG.REGISTRY
  IN COMPUTE POOL BLESSED_NPM_POOL
  FROM SPECIFICATION $$
spec:
  containers:
  - name: registry
    image: /blessed_npm/reg/images/blessed-registry:latest
    env:
      BLESSED_DIR: /blessed
      PORT: "4873"
      RELOAD_MS: "30000"
      # no PUBLIC_URL: tarball URLs follow the Host the client used (internal DNS)
    volumeMounts:
    - {name: blessed, mountPath: /blessed}
    readinessProbe: {port: 4873, path: /healthz}
  endpoints:
  - {name: npm, port: 4873, public: false}   # SAR builds use internal DNS; public not needed
  volumes:
  - {name: blessed, source: "@BLESSED_NPM.REG.BLESSED", uid: 1000, gid: 1000}
$$;

-- ---------------------------------------------------------------------------
-- SAR wiring (how apps are forced to use it)
-- ---------------------------------------------------------------------------
-- app.yml:     no build_eai needed for the internal-DNS path
-- .npmrc:      registry=http://<dns_name>:4873/   (template-locked; scan gate REFUSEs other registries)
-- lockfile:    package-lock.json resolved/integrity must point at the blessed registry
--
-- Tested (AWS): a SAR build reaches this service over its internal DNS
--   (<service>.<hash>.svc.spcs.internal, from DESCRIBE SERVICE -> dns_name)
--   with NO build_eai. Put that URL in .npmrc. The public endpoint does not work
--   for npm: ingress wants `Snowflake Token=`, npm only sends Bearer/Basic.
-- Also tested (Azure): PRIVATE_HOST_PORT -> PrivateLink -> no-uplink registry
--   + ALLOW_NPM_PACKAGE_DOWNLOAD = FALSE  => builds could ONLY reach that registry.
--
-- Account-wide switch (do NOT run on shared demo accounts without agreement):
-- ALTER ACCOUNT SET ALLOW_NPM_PACKAGE_DOWNLOAD = FALSE;
