-- Promote / withdraw. Run after each scan load and after reviewer decisions.
USE ROLE BLESSED_NPM_ADMIN;
USE SCHEMA BLESSED_NPM.REG;

-- 1. Human-approved HOLD tarballs: quarantine -> blessed.
--    (APPROVE ones were already written to @BLESSED by the scanner.)
--    COPY FILES copies by exact name; run once per approved row, e.g.:
-- COPY FILES INTO @BLESSED FROM @QUARANTINE FILES = ('esbuild-0.24.0.tgz');
SELECT 'COPY FILES INTO @BLESSED FROM @QUARANTINE FILES = (''' || tarball || ''');' AS run_me
FROM SERVED
WHERE effective_verdict = 'APPROVE' AND verdict = 'HOLD';

-- 2. Rewrite index.json from SERVED. The registry reloads it every RELOAD_MS.
--    Anything not APPROVE here stops being served, which is also how a new CVE
--    or MAL-* finding withdraws a version: rescan -> REJECT -> drops out.
COPY INTO @BLESSED/index.json FROM (
  SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
           'package', package, 'version', version, 'verdict', effective_verdict,
           'reasons', reasons, 'integrity', integrity, 'tarball', tarball,
           'manifest', manifest, 'install_scripts', install_scripts,
           'published_at', published_at, 'scanned_at', scanned_at))
  FROM SERVED WHERE effective_verdict = 'APPROVE')
FILE_FORMAT = (TYPE = JSON COMPRESSION = NONE)
SINGLE = TRUE OVERWRITE = TRUE HEADER = FALSE;

-- 3. Who was affected by a withdrawal: apps whose lockfile pinned it.
--    (Needs the SAR scan gate to store each app's package-lock.json in a table.)
-- SELECT app_name FROM SAR_WF.GOVERNANCE.APP_LOCKFILES l, LATERAL FLATTEN(l.lock:packages) p
-- WHERE p.value:name = 'lodash' AND p.value:version = '4.17.15';

-- Schedule: rescan daily (CVEs appear after approval).
-- CREATE TASK RESCAN_DAILY WAREHOUSE = <wh> SCHEDULE = 'USING CRON 0 3 * * * UTC'
--   AS EXECUTE JOB SERVICE ... (same as setup.sql);
