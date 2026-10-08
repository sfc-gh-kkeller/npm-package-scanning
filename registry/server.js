// Blessed npm registry: serves ONLY versions in $BLESSED_DIR/index.json.
// No uplink. An unknown package or version is a 404, so `npm install` fails
// closed instead of falling back to registry.npmjs.org.
//
// In SPCS, $BLESSED_DIR is a stage volume (@BLESSED_NPM.REG.BLESSED).
// Promotion = scanner writes tarball + index.json to that stage.
// Withdrawal = remove the row from index.json; the next reload stops serving it.
const http = require("http");
const fs = require("fs");
const path = require("path");

const DIR = process.env.BLESSED_DIR || path.join(__dirname, "..", "out", "blessed");
const PORT = +(process.env.PORT || 4873);
// Tarball URLs must point back at whatever host the client used (internal
// SPCS DNS vs public ingress), so derive them per request unless pinned.
const PUBLIC_URL = (process.env.PUBLIC_URL || "").replace(/\/$/, "");
function baseUrl(req) {
  if (PUBLIC_URL) return PUBLIC_URL;
  const proto = (req.headers["x-forwarded-proto"] || "http").split(",")[0].trim();
  return `${proto}://${req.headers["x-forwarded-host"] || req.headers.host}`;
}
const RELOAD_MS = +(process.env.RELOAD_MS || 30000);

let byName = new Map();

function cmpSemver(a, b) {
  const pa = a.split(/[.+-]/).map((x) => (isNaN(x) ? x : +x));
  const pb = b.split(/[.+-]/).map((x) => (isNaN(x) ? x : +x));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if (pa[i] === pb[i]) continue;
    if (pa[i] === undefined) return 1;   // 1.0.0 > 1.0.0-beta
    if (pb[i] === undefined) return -1;
    return typeof pa[i] === typeof pb[i] ? (pa[i] > pb[i] ? 1 : -1) : typeof pa[i] === "number" ? 1 : -1;
  }
  return 0;
}

function load() {
  let rows;
  try {
    rows = JSON.parse(fs.readFileSync(path.join(DIR, "index.json"), "utf8"));
  } catch (e) {
    console.error("index load failed, keeping previous index:", e.message);
    return;
  }
  const m = new Map();
  for (const r of rows) {
    if (r.verdict !== "APPROVE") continue;          // defence in depth
    if (!fs.existsSync(path.join(DIR, r.tarball))) continue;
    if (!m.has(r.package)) m.set(r.package, []);
    m.get(r.package).push(r);
  }
  byName = m;
  console.log(`index: ${m.size} packages, ${rows.length} rows`);
}

function packument(name, rows, base) {
  const versions = {};
  const time = {};
  for (const r of rows) {
    const mf = r.manifest || {};
    versions[r.version] = {
      name, version: r.version,
      dependencies: mf.dependencies || {},
      optionalDependencies: mf.optionalDependencies || undefined,
      peerDependencies: mf.peerDependencies || undefined,
      bin: mf.bin || undefined, engines: mf.engines || undefined,
      os: mf.os || undefined, cpu: mf.cpu || undefined, license: mf.license || undefined,
      // install scripts were reviewed; flag lets npm know they exist
      hasInstallScript: Object.keys(r.install_scripts || {}).length > 0 || undefined,
      dist: {
        integrity: r.integrity,
        tarball: `${base}/-/tarball/${encodeURIComponent(r.tarball)}`,
      },
      _blessed: { scanned_at: r.scanned_at, notes: r.reasons },
    };
    time[r.version] = r.published_at;
  }
  const latest = Object.keys(versions).sort(cmpSemver).pop();
  return { name, "dist-tags": { latest }, versions, time };
}

function send(res, code, body, type = "application/json") {
  res.writeHead(code, { "Content-Type": type });
  res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

http.createServer((req, res) => {
  const url = decodeURIComponent(req.url.split("?")[0]);
  console.log(req.method, url, "host=" + req.headers.host, "from=" + req.socket.remoteAddress);
  if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, { error: "read-only registry" });
  if (url === "/-/ping" || url === "/healthz") return send(res, 200, {});
  if (url.startsWith("/-/tarball/")) {
    const f = path.basename(url.slice("/-/tarball/".length));
    // only serve tarballs that are in the index, not anything on the volume
    const ok = [...byName.values()].some((rows) => rows.some((r) => r.tarball === f));
    if (!ok) return send(res, 404, { error: "not blessed" });
    return fs.readFile(path.join(DIR, f), (e, b) => (e ? send(res, 404, { error: "missing" })
      : send(res, 200, b, "application/octet-stream")));
  }
  if (url.startsWith("/-/")) return send(res, 404, { error: "unsupported" });  // audit, search, etc.
  const name = url.slice(1);
  const rows = byName.get(name);
  if (!rows) return send(res, 404, { error: `${name} is not on the blessed list` });
  return send(res, 200, packument(name, rows, baseUrl(req)));
}).listen(PORT, "0.0.0.0", () => console.log(`blessed registry on :${PORT}, dir=${DIR}`));

load();
setInterval(load, RELOAD_MS);
