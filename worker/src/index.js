// ip-risk Worker - daily IP risk dashboard + data API (HTML / JSON / CSV) with map.
//
// Routes:
//   GET /                       HTML dashboard (with risk map)
//   GET /?format=json|csv       dashboard data as JSON or CSV
//   GET /ip_only                JSON array of distinct attacker IPs (threat-ranked)
//   GET /ip_only?format=csv     CSV (header "ip", one IP per line)
//   GET /ping                   debug
//
// Query params (ALL validated before reaching SQL):
//   days   int 1..90      (default 7)      dashboard window
//   limit  int 1..5000    (default 1000)   ip_only page size (hard cap 5000)
//   offset int >=0        (default 0)       ip_only page offset
//   source ssh|mysql|web  (optional)        allowlist filter; 400 if invalid
//   format html|json|csv  (default html)
//   fields csv list of    log_date,ip,attempts,sources,categories,nsrc,reporters,last_seen
//
// Injection safety: integers via clampInt(); source/format/fields via allowlists;
// every SQL value is a BOUND parameter; field selection is a JS-side projection.
// Map: attacker IPs geolocated via ip-api batch (cached in caches.default), drawn
// client-side with Leaflet.

import { createConnection } from "mysql2/promise";

const ALLOWED_SOURCES = new Set(["ssh", "mysql", "web"]);
const ALLOWED_FORMATS = new Set(["html", "json", "csv"]);
const FIELD_ORDER = ["log_date", "ip", "attempts", "sources", "categories", "nsrc", "reporters", "last_seen", "country", "country_code"];
const ALLOWED_FIELDS = new Set(FIELD_ORDER);
const DEFAULT_FIELDS = ["log_date", "ip", "attempts", "sources", "categories", "reporters", "last_seen"];

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;",
  }[c]));
}

function clampInt(raw, def, min, max) {
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n)) return def;
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

function fmtDate(v) {
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  return v == null ? "" : String(v).slice(0, 10);
}
function fmtDateTime(v) {
  if (v instanceof Date) return v.toISOString().slice(0, 19).replace("T", " ");
  return v == null ? "" : String(v);
}

const FIELD_GET = {
  log_date: (r) => fmtDate(r.log_date),
  ip: (r) => r.ip,
  attempts: (r) => Number(r.attempts),
  sources: (r) => r.sources,
  categories: (r) => r.categories,
  nsrc: (r) => Number(r.nsrc),
  reporters: (r) => Number(r.reporters),
  last_seen: (r) => fmtDateTime(r.last_seen),
  country: (r) => r.country,
  country_code: (r) => r.country_code,
};
function projectRow(r, fields) {
  const o = {};
  for (const f of fields) o[f] = FIELD_GET[f](r);
  return o;
}

function csvCell(v) {
  let s = v == null ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  if (/[",\n\r]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
}
function toCsv(headers, rows) {
  const out = [headers.map(csvCell).join(",")];
  for (const r of rows) out.push(r.map(csvCell).join(","));
  return out.join("\r\n") + "\r\n";
}
function csvResponse(body, filename) {
  return new Response(body, {
    headers: {
      "content-type": "text/csv; charset=utf-8",
      "content-disposition": 'attachment; filename="' + filename + '"',
    },
  });
}

function risk(attempts, nsrc, reporters) {
  const score = attempts + (nsrc - 1) * 200 + (reporters - 1) * 100;
  if (score >= 200 || nsrc >= 2) return { label: "HIGH", color: "#dc2626" };
  if (score >= 20) return { label: "MED", color: "#d97706" };
  return { label: "LOW", color: "#16a34a" };
}

function flagEmoji(cc) {
  if (!cc || cc.length !== 2) return "";
  return [...cc.toUpperCase()].map((c) => String.fromCodePoint(0x1F1E6 + c.charCodeAt(0) - 65)).join("");
}

// Geo comes from the security.ip_geo table (filled at the source by badip_logger),
// joined in below — the Worker no longer calls any geolocation API.
function dashboardQuery(hasSource) {
  return "SELECT b.log_date AS log_date, b.ip AS ip, " +
    "SUM(b.attempts) AS attempts, " +
    "GROUP_CONCAT(DISTINCT b.source ORDER BY b.source) AS sources, " +
    "GROUP_CONCAT(DISTINCT b.category ORDER BY b.category) AS categories, " +
    "COUNT(DISTINCT b.source) AS nsrc, " +
    "COUNT(DISTINCT b.reporter_ip) AS reporters, " +
    "MAX(b.last_seen) AS last_seen, " +
    "MAX(g.country) AS country, MAX(g.country_code) AS country_code, " +
    "MAX(g.lat) AS lat, MAX(g.lon) AS lon " +
    "FROM bad_login b LEFT JOIN ip_geo g ON g.ip = b.ip " +
    "WHERE b.log_date >= (CURDATE() - INTERVAL ? DAY) " +
    (hasSource ? "AND b.source = ? " : "") +
    "GROUP BY b.log_date, b.ip " +
    "ORDER BY b.log_date DESC, attempts DESC " +
    "LIMIT 500";
}

function page(rows, days, source, points, countries) {
  const enriched = rows.map((r) => ({
    ...r,
    _risk: risk(Number(r.attempts), Number(r.nsrc), Number(r.reporters)),
  }));
  const totalIps = new Set(enriched.map((r) => r.ip)).size;
  const totalAtt = enriched.reduce((a, r) => a + Number(r.attempts), 0);
  const high = enriched.filter((r) => r._risk.label === "HIGH").length;

  const srcQ = source ? "&source=" + encodeURIComponent(source) : "";
  const dataQ = "days=" + days + srcQ;
  const winLink = (d, label) => `<a class="${days === d ? "on" : ""}" href="?days=${d}${srcQ}">${label}</a>`;
  const srcLink = (s, label) => {
    const href = s ? "?days=" + days + "&source=" + s : "?days=" + days;
    return `<a class="${(s || null) === source ? "on" : ""}" href="${href}">${label}</a>`;
  };
  const ipListHref = "/ip_only?format=csv" + (source ? "&source=" + encodeURIComponent(source) : "");

  const countryChips = countries.slice(0, 12).map((c) =>
    `<span class="chip">${flagEmoji(c.cc)} ${esc(c.country || c.cc || "?")} <b>${c.attempts}</b></span>`).join("");

  const rowsHtml = enriched.map((r) => `
    <tr>
      <td class="mono">${esc(fmtDate(r.log_date))}</td>
      <td class="mono ip">${esc(r.ip)}</td>
      <td class="num">${esc(r.attempts)}</td>
      <td>${(esc(r.sources) || "").split(",").map((s) => `<span class="tag t-${esc(s)}">${esc(s)}</span>`).join(" ")}</td>
      <td class="cats">${esc(r.categories)}</td>
      <td class="num">${esc(r.reporters)}</td>
      <td class="mono dim">${esc(fmtDateTime(r.last_seen))}</td>
      <td><span class="badge" style="background:${r._risk.color}">${r._risk.label}</span></td>
    </tr>`).join("");

  const pointsJson = JSON.stringify(points).replace(/</g, "\\u003c");

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Daily IP Risk</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
  :root{color-scheme:dark}
  *{box-sizing:border-box}
  body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#0b1220;color:#e2e8f0}
  .wrap{max-width:1180px;margin:0 auto;padding:24px}
  header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  h1{font-size:20px;margin:0}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:16px 0}
  .card{background:#111c33;border:1px solid #243049;border-radius:12px;padding:14px 16px}
  .card .k{color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
  .card .v{font-size:24px;font-weight:700;margin-top:2px}
  #map{height:400px;border-radius:12px;overflow:hidden;border:1px solid #243049;background:#0b1220}
  .leaflet-popup-content{font:13px/1.4 ui-monospace,Menlo,monospace}
  .bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:14px 0}
  .bar .lbl{color:#64748b;font-size:12px;margin-left:8px}
  .bar .lbl:first-child{margin-left:0}
  .bar a{color:#cbd5e1;text-decoration:none;padding:4px 11px;border:1px solid #243049;border-radius:8px;font-size:13px;background:#111c33}
  .bar a:hover{border-color:#3b82f6}
  .bar a.on{background:#2563eb;border-color:#2563eb;color:#fff;font-weight:600}
  .chips{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 4px}
  .chip{background:#111c33;border:1px solid #243049;border-radius:999px;padding:3px 11px;font-size:13px}
  .chip b{color:#f87171}
  table{width:100%;border-collapse:collapse;background:#111c33;border:1px solid #243049;border-radius:12px;overflow:hidden}
  th,td{padding:9px 12px;text-align:left;border-bottom:1px solid #1e2940;vertical-align:top}
  thead th{position:sticky;top:0;background:#0b1220;color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
  tbody tr:last-child td{border-bottom:0}
  tbody tr:hover td{background:#16223c}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .ip{font-weight:600}.dim{color:#94a3b8}
  .num{text-align:right;font-variant-numeric:tabular-nums}
  .cats{color:#cbd5e1;font-size:12px;max-width:280px}
  .badge{color:#fff;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700}
  .tag{font-size:11px;padding:1px 7px;border-radius:6px;background:#334155;color:#e2e8f0}
  .t-ssh{background:#7c3aed}.t-mysql{background:#0891b2}.t-web{background:#be185d}
  .legend{display:flex;gap:14px;align-items:center;color:#94a3b8;font-size:12px;margin:10px 0 0}
  .legend span{display:inline-flex;align-items:center;gap:5px}
  .dot{width:9px;height:9px;border-radius:50%;display:inline-block}
  footer{color:#475569;margin-top:18px;font-size:12px}
</style></head><body><div class="wrap">
  <header><h1>🛡️ Daily IP Risk</h1></header>

  <div class="cards">
    <div class="card"><div class="k">Unique IPs</div><div class="v">${totalIps}</div></div>
    <div class="card"><div class="k">Total attempts</div><div class="v">${totalAtt.toLocaleString("en-US")}</div></div>
    <div class="card"><div class="k">HIGH risk</div><div class="v" style="color:#f87171">${high}</div></div>
    <div class="card"><div class="k">Countries</div><div class="v">${countries.length}</div></div>
  </div>

  <div id="map"></div>
  <div class="chips">${countryChips || '<span class="chip" style="color:#94a3b8">no geolocated IPs</span>'}</div>

  <div class="bar">
    <span class="lbl">Window</span>${winLink(1, "1d")}${winLink(7, "7d")}${winLink(30, "30d")}
    <span class="lbl">Source</span>${srcLink(null, "all")}${srcLink("ssh", "ssh")}${srcLink("mysql", "mysql")}${srcLink("web", "web")}
    <span class="lbl">Export</span>
    <a href="?${dataQ}&format=csv">CSV</a>
    <a href="?${dataQ}&format=json">JSON</a>
    <a href="${ipListHref}">IP list</a>
  </div>

  <table>
    <thead><tr><th>Report date</th><th>Attempt IP</th><th class="num">Attempts</th><th>Sources</th><th>Categories</th><th class="num">Reporters</th><th>Last seen (UTC)</th><th>Risk</th></tr></thead>
    <tbody>${rowsHtml || '<tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:28px">No data in this window yet</td></tr>'}</tbody>
  </table>

  <div class="legend">
    <span><i class="dot" style="background:#dc2626"></i>HIGH = multi-source or score&ge;200</span>
    <span><i class="dot" style="background:#d97706"></i>MED = score&ge;20</span>
    <span><i class="dot" style="background:#16a34a"></i>LOW</span>
  </div>
  <footer>Generated ${new Date().toISOString()} &middot; map &copy; OpenStreetMap/CARTO &middot; geo from ip_geo table</footer>
</div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const POINTS = ${pointsJson};
(function(){
  var el=document.getElementById('map');
  if(!window.L){ el.innerHTML='<div style="padding:20px;color:#94a3b8">map library failed to load</div>'; return; }
  if(!POINTS.length){ el.innerHTML='<div style="padding:20px;color:#94a3b8">No geolocated IPs in this window</div>'; return; }
  var map=L.map('map',{worldCopyJump:true,attributionControl:false,minZoom:1}).setView([25,10],2);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{subdomains:'abcd',maxZoom:8}).addTo(map);
  POINTS.forEach(function(p){
    var r=Math.min(24,5+Math.sqrt(p.attempts));
    L.circleMarker([p.lat,p.lon],{radius:r,color:p.color,weight:1,fillColor:p.color,fillOpacity:0.5})
      .addTo(map)
      .bindPopup('<b>'+p.ip+'</b><br>'+(p.country||'')+'<br>attempts: '+p.attempts);
  });
})();
</script>
</body></html>`;
}

async function connect(env) {
  const c = await createConnection({
    host: env.HYPERDRIVE.host,
    user: env.HYPERDRIVE.user,
    password: env.HYPERDRIVE.password,
    database: env.HYPERDRIVE.database,
    port: env.HYPERDRIVE.port,
    disableEval: true,
  });
  c.on("error", () => {});
  return c;
}

function dbError(err) {
  const msg = "Database error: " + (err && err.message ? err.message : String(err)) +
    (err && err.code ? " [code=" + err.code + "]" : "");
  return new Response(msg, { status: 502, headers: { "content-type": "text/plain; charset=utf-8" } });
}
function badRequest(msg) {
  return new Response(msg, { status: 400, headers: { "content-type": "text/plain; charset=utf-8" } });
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (err) {
      return new Response(
        "WORKER EXCEPTION:\n" + (err && (err.stack || err.message) ? (err.stack || err.message) : String(err)),
        { status: 500, headers: { "content-type": "text/plain; charset=utf-8" } });
    }
  },
};

async function handle(request, env) {
  const url = new URL(request.url);

  if (url.pathname === "/ping") {
    const h = env.HYPERDRIVE || {};
    return new Response("pong | host=" + h.host + " port=" + h.port +
      " user=" + h.user + " db=" + h.database, { headers: { "content-type": "text/plain" } });
  }
  if (!env.HYPERDRIVE) return new Response("HYPERDRIVE binding is not configured", { status: 500 });

  const format = url.searchParams.get("format") || "html";
  if (!ALLOWED_FORMATS.has(format)) return badRequest('invalid "format" (allowed: html, json, csv)');
  const days = clampInt(url.searchParams.get("days"), 7, 1, 90);

  const sourceRaw = url.searchParams.get("source");
  let source = null;
  if (sourceRaw !== null && sourceRaw !== "") {
    if (!ALLOWED_SOURCES.has(sourceRaw)) return badRequest('invalid "source" (allowed: ssh, mysql, web)');
    source = sourceRaw;
  }

  let fields = DEFAULT_FIELDS;
  const fieldsRaw = url.searchParams.get("fields");
  if (fieldsRaw) {
    const req = fieldsRaw.split(",").map((s) => s.trim()).filter(Boolean);
    const bad = req.filter((f) => !ALLOWED_FIELDS.has(f));
    if (bad.length) return badRequest('invalid fields: ' + bad.join(", ") + ' (allowed: ' + FIELD_ORDER.join(", ") + ')');
    if (req.length) fields = req;
  }

  if (url.pathname === "/ip_only") {
    const limit = clampInt(url.searchParams.get("limit"), 1000, 1, 5000);
    const offset = clampInt(url.searchParams.get("offset"), 0, 0, 1000000000);
    let c;
    try {
      c = await connect(env);
      const sql = "SELECT ip FROM bad_login " +
        (source ? "WHERE source = ? " : "") +
        "GROUP BY ip ORDER BY SUM(attempts) DESC, ip LIMIT ? OFFSET ?";
      const params = source ? [source, limit, offset] : [limit, offset];
      const [ipRows] = await c.query(sql, params);
      const ips = ipRows.map((r) => r.ip);
      if (format === "csv") return csvResponse(toCsv(["ip"], ips.map((ip) => [ip])), "ip_only.csv");
      return Response.json(ips);
    } catch (err) {
      return dbError(err);
    } finally {
      try { if (c) await c.end(); } catch (e) { /* ignore */ }
    }
  }

  let conn;
  let rows;
  try {
    conn = await connect(env);
    const params = source ? [days, source] : [days];
    const [result] = await conn.query(dashboardQuery(!!source), params);
    rows = result;
  } catch (err) {
    return dbError(err);
  } finally {
    try { if (conn) await conn.end(); } catch (e) { /* ignore */ }
  }

  if (format === "json") {
    return Response.json({ days, source, fields, count: rows.length, rows: rows.map((r) => projectRow(r, fields)) });
  }
  if (format === "csv") {
    const data = rows.map((r) => fields.map((f) => FIELD_GET[f](r)));
    return csvResponse(toCsv(fields, data), "ip-risk.csv");
  }

  // HTML: aggregate per IP (geo already joined from ip_geo), build map + countries
  const ipAgg = new Map();
  for (const r of rows) {
    let a = ipAgg.get(r.ip);
    if (!a) {
      a = { attempts: 0, nsrc: 0, reporters: 0, lat: r.lat, lon: r.lon, country: r.country, cc: r.country_code };
      ipAgg.set(r.ip, a);
    }
    a.attempts += Number(r.attempts);
    a.nsrc = Math.max(a.nsrc, Number(r.nsrc));
    a.reporters = Math.max(a.reporters, Number(r.reporters));
  }

  const points = [];
  const countryMap = new Map();
  for (const [ip, a] of ipAgg) {
    if (typeof a.lat === "number" && a.lat != null) {
      points.push({ lat: a.lat, lon: a.lon, ip, attempts: a.attempts, country: a.country, color: risk(a.attempts, a.nsrc, a.reporters).color });
      const k = a.cc || "??";
      const cm = countryMap.get(k) || { cc: a.cc, country: a.country, attempts: 0, ips: 0 };
      cm.attempts += a.attempts; cm.ips += 1; countryMap.set(k, cm);
    }
  }
  const countries = [...countryMap.values()].sort((x, y) => y.attempts - x.attempts);

  return new Response(page(rows, days, source, points, countries), {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}
