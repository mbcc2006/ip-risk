// ip-risk Worker — async dashboard + data API (HTML / JSON / CSV) with map.
//
// Routes:
//   GET /          HTML dashboard. Serves a static shell that loads its data
//                  asynchronously from /risk-ip (so the page is cacheable and
//                  renders instantly). Map shows up to 500 IPs; the table below
//                  paginates 50 per page, client-side.
//   GET /risk-ip   THE data API — dashboard rows as JSON (default) or CSV.
//   GET /ip_only   JSON/CSV array of distinct attacker IPs (threat-ranked).
//   GET /docs      HTML API documentation (linked from the dashboard).
//   GET /ping      debug.
//
// Query params (ALL validated before reaching SQL):
//   days   int 1..90      (default 7)        window
//   source ssh|mysql|web  (optional)         allowlist filter; 400 if invalid
//   limit  int 1..5000    (risk-ip def 500, ip_only def 1000)
//   offset int >=0        (default 0)
//   format json|csv       (default json on the data endpoints)
//   fields csv subset of FIELD_ORDER         (JSON/CSV projection)
//
// Injection safety: integers via clampInt(); source/format/fields via allowlists;
// every SQL value is a BOUND parameter; field selection is a JS-side projection.
// Geo comes from the security.ip_geo table (filled at the source) — the Worker
// calls no geolocation API.

import { createConnection } from "mysql2/promise";

// Contact for IP-removal requests (shown on the dashboard + docs).
const CONTACT_NAME = "世界第一好吃";
const CONTACT_EMAIL = "admin@ivjn.us";

const ALLOWED_SOURCES = new Set(["ssh", "mysql", "web"]);
const ALLOWED_FORMATS = new Set(["json", "csv"]);
const FIELD_ORDER = ["log_date", "ip", "attempts", "sources", "categories", "nsrc", "reporters", "last_seen", "country", "country_code", "risk"];
const ALLOWED_FIELDS = new Set(FIELD_ORDER);
const DEFAULT_FIELDS = ["log_date", "ip", "attempts", "sources", "categories", "reporters", "last_seen", "country", "risk"];

const MAP_MAX = 500;   // IPs plotted on the map / fetched for the dashboard
const PAGE_SIZE = 50;  // table rows per page (client-side pagination)

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

// Risk scoring — SINGLE source of truth (server side). The client mirrors only
// the colour thresholds for the aggregated map markers; see riskColor() there.
function risk(attempts, nsrc, reporters) {
  const score = attempts + (nsrc - 1) * 200 + (reporters - 1) * 100;
  if (score >= 200 || nsrc >= 2) return { label: "HIGH", color: "#dc2626" };
  if (score >= 20) return { label: "MED", color: "#d97706" };
  return { label: "LOW", color: "#16a34a" };
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
  risk: (r) => risk(Number(r.attempts), Number(r.nsrc), Number(r.reporters)).label,
};

// One JSON row of the /risk-ip response (geo + computed risk included).
function apiRow(r) {
  const attempts = Number(r.attempts), nsrc = Number(r.nsrc), reporters = Number(r.reporters);
  const rk = risk(attempts, nsrc, reporters);
  const lat = r.lat == null ? null : Number(r.lat);
  const lon = r.lon == null ? null : Number(r.lon);
  return {
    log_date: fmtDate(r.log_date),
    ip: r.ip,
    attempts,
    sources: r.sources,
    categories: r.categories,
    nsrc,
    reporters,
    last_seen: fmtDateTime(r.last_seen),
    country: r.country || null,
    country_code: r.country_code || null,
    lat: Number.isFinite(lat) ? lat : null,
    lon: Number.isFinite(lon) ? lon : null,
    risk: rk.label,
    risk_color: rk.color,
  };
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

const CORS = { "access-control-allow-origin": "*" };

function htmlResponse(body) {
  return new Response(body, { headers: { "content-type": "text/html; charset=utf-8" } });
}
function jsonResponse(obj) {
  return new Response(JSON.stringify(obj), {
    headers: { "content-type": "application/json; charset=utf-8", ...CORS },
  });
}
function csvResponse(body, filename) {
  return new Response(body, {
    headers: {
      "content-type": "text/csv; charset=utf-8",
      "content-disposition": 'attachment; filename="' + filename + '"',
      ...CORS,
    },
  });
}

// Geo joined from ip_geo; rows are aggregated per (log_date, ip).
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
    "LIMIT ? OFFSET ?";
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
  return new Response(JSON.stringify({ error: msg }), {
    status: 502, headers: { "content-type": "application/json; charset=utf-8", ...CORS },
  });
}
function badRequest(msg) {
  return new Response(JSON.stringify({ error: msg }), {
    status: 400, headers: { "content-type": "application/json; charset=utf-8", ...CORS },
  });
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

  // Static HTML (no DB needed) — render even if the DB is down.
  if (url.pathname === "/") return htmlResponse(shellPage());
  if (url.pathname === "/docs") return htmlResponse(docsPage());

  // ---- data endpoints (need the DB) ----
  if (!env.HYPERDRIVE) return new Response("HYPERDRIVE binding is not configured", { status: 500 });

  const format = url.searchParams.get("format") || "json";
  if (!ALLOWED_FORMATS.has(format)) return badRequest('invalid "format" (allowed: json, csv)');
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
      return jsonResponse(ips);
    } catch (err) {
      return dbError(err);
    } finally {
      try { if (c) await c.end(); } catch (e) { /* ignore */ }
    }
  }

  if (url.pathname === "/risk-ip") {
    const limit = clampInt(url.searchParams.get("limit"), MAP_MAX, 1, 5000);
    const offset = clampInt(url.searchParams.get("offset"), 0, 0, 1000000000);
    let conn, rows;
    try {
      conn = await connect(env);
      const params = source ? [days, source, limit, offset] : [days, limit, offset];
      const [result] = await conn.query(dashboardQuery(!!source), params);
      rows = result;
    } catch (err) {
      return dbError(err);
    } finally {
      try { if (conn) await conn.end(); } catch (e) { /* ignore */ }
    }
    if (format === "csv") {
      const data = rows.map((r) => fields.map((f) => FIELD_GET[f](r)));
      return csvResponse(toCsv(fields, data), "risk-ip.csv");
    }
    return jsonResponse({
      generated: new Date().toISOString(),
      days, source, count: rows.length, limit, offset,
      rows: rows.map(apiRow),
    });
  }

  return new Response("Not found. See /docs for the available endpoints.",
    { status: 404, headers: { "content-type": "text/plain; charset=utf-8" } });
}

// ---------------------------------------------------------------------------
// HTML: dashboard shell (data loaded client-side from /risk-ip)
// ---------------------------------------------------------------------------
function shellPage() {
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
  header a.docs{margin-left:auto;color:#93c5fd;text-decoration:none;font-size:13px;border:1px solid #243049;border-radius:8px;padding:4px 11px;background:#111c33}
  header a.docs:hover{border-color:#3b82f6}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:16px 0}
  .card{background:#111c33;border:1px solid #243049;border-radius:12px;padding:14px 16px}
  .card .k{color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
  .card .v{font-size:24px;font-weight:700;margin-top:2px}
  #map{height:400px;border-radius:12px;overflow:hidden;border:1px solid #243049;background:#0b1220}
  .leaflet-popup-content{font:13px/1.4 ui-monospace,Menlo,monospace}
  .bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:14px 0}
  .bar .lbl{color:#64748b;font-size:12px;margin-left:8px}
  .bar .lbl:first-child{margin-left:0}
  .bar a{color:#cbd5e1;text-decoration:none;padding:4px 11px;border:1px solid #243049;border-radius:8px;font-size:13px;background:#111c33;cursor:pointer}
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
  .pager{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin:12px 0}
  .pager button{background:#111c33;border:1px solid #243049;color:#cbd5e1;border-radius:8px;padding:4px 10px;font-size:13px;cursor:pointer}
  .pager button:hover:not(:disabled){border-color:#3b82f6}
  .pager button.on{background:#2563eb;border-color:#2563eb;color:#fff;font-weight:600}
  .pager button:disabled{opacity:.4;cursor:default}
  .pager .info{color:#64748b;font-size:12px;margin-right:6px}
  footer{color:#64748b;margin-top:18px;font-size:12px;line-height:1.7}
  footer a{color:#93c5fd}
</style></head><body><div class="wrap">
  <header><h1>🛡️ Daily IP Risk</h1><a class="docs" href="/docs">API docs &amp; IP removal →</a></header>

  <div class="cards" id="cards">
    <div class="card"><div class="k">Unique IPs</div><div class="v" id="c-ips">–</div></div>
    <div class="card"><div class="k">Total attempts</div><div class="v" id="c-att">–</div></div>
    <div class="card"><div class="k">HIGH risk</div><div class="v" id="c-high" style="color:#f87171">–</div></div>
    <div class="card"><div class="k">Countries</div><div class="v" id="c-cc">–</div></div>
  </div>

  <div id="map"></div>
  <div class="chips" id="chips"></div>

  <div class="bar" id="bar"></div>

  <table>
    <thead><tr><th>Report date</th><th>Attempt IP</th><th class="num">Attempts</th><th>Sources</th><th>Categories</th><th class="num">Reporters</th><th>Last seen (UTC)</th><th>Risk</th></tr></thead>
    <tbody id="tbody"><tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:28px">Loading…</td></tr></tbody>
  </table>
  <div class="pager" id="pager"></div>

  <div class="legend">
    <span><i class="dot" style="background:#dc2626"></i>HIGH = multi-source or score&ge;200</span>
    <span><i class="dot" style="background:#d97706"></i>MED = score&ge;20</span>
    <span><i class="dot" style="background:#16a34a"></i>LOW</span>
  </div>
  <footer>
    Map shows up to ${MAP_MAX} IPs · table paginates ${PAGE_SIZE} per page · geo from the ip_geo table.<br>
    To request removal of an IP from this list, contact <b>${esc(CONTACT_NAME)}</b>
    &lt;<a href="mailto:${esc(CONTACT_EMAIL)}?subject=IP%20removal%20request">${esc(CONTACT_EMAIL)}</a>&gt;
    · <a href="/docs">API documentation</a>
  </footer>
</div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
(function(){
  var PAGE_SIZE=${PAGE_SIZE}, MAP_MAX=${MAP_MAX};
  function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function flag(cc){if(!cc||cc.length!==2)return '';return Array.from(cc.toUpperCase()).map(function(c){return String.fromCodePoint(0x1F1E6+c.charCodeAt(0)-65);}).join('');}
  function intc(n){return Number(n||0).toLocaleString('en-US');}
  // mirrors server risk() colour thresholds for aggregated map markers
  function riskColor(att,nsrc,rep){var s=att+(nsrc-1)*200+(rep-1)*100;if(s>=200||nsrc>=2)return '#dc2626';if(s>=20)return '#d97706';return '#16a34a';}

  var qs=new URLSearchParams(location.search);
  var days=parseInt(qs.get('days'),10); if(!(days>=1&&days<=90))days=7;
  var source=qs.get('source'); if(['ssh','mysql','web'].indexOf(source)<0)source=null;

  var state={rows:[],page:1};

  // ---- static filter / export bar ----
  (function bar(){
    var srcQ=source?('&source='+encodeURIComponent(source)):'';
    function win(d,label){return '<a class="'+(days===d?'on':'')+'" href="?days='+d+srcQ+'">'+label+'</a>';}
    function src(s,label){var href=s?('?days='+days+'&source='+s):('?days='+days);return '<a class="'+(((s||null)===source)?'on':'')+'" href="'+href+'">'+label+'</a>';}
    var dataQ='days='+days+srcQ;
    var ipQ='/ip_only?format=csv'+(source?('&source='+encodeURIComponent(source)):'');
    document.getElementById('bar').innerHTML=
      '<span class="lbl">Window</span>'+win(1,'1d')+win(7,'7d')+win(30,'30d')+
      '<span class="lbl">Source</span>'+src(null,'all')+src('ssh','ssh')+src('mysql','mysql')+src('web','web')+
      '<span class="lbl">Export</span>'+
      '<a href="/risk-ip?'+dataQ+'&format=csv">CSV</a>'+
      '<a href="/risk-ip?'+dataQ+'&format=json">JSON</a>'+
      '<a href="'+ipQ+'">IP list</a>';
  })();

  function fail(msg){
    document.getElementById('tbody').innerHTML='<tr><td colspan="8" style="text-align:center;color:#f87171;padding:28px">'+esc(msg)+'</td></tr>';
    document.getElementById('map').innerHTML='<div style="padding:20px;color:#94a3b8">could not load data</div>';
  }

  function drawCards(rows){
    var ips={},att=0,high=0;
    rows.forEach(function(r){ips[r.ip]=1;att+=Number(r.attempts);if(r.risk==='HIGH')high++;});
    document.getElementById('c-ips').textContent=intc(Object.keys(ips).length);
    document.getElementById('c-att').textContent=intc(att);
    document.getElementById('c-high').textContent=intc(high);
  }

  function drawMapAndChips(rows){
    var agg={},order=[];
    rows.forEach(function(r){
      var a=agg[r.ip];
      if(!a){a={ip:r.ip,attempts:0,nsrc:0,reporters:0,lat:r.lat,lon:r.lon,country:r.country,cc:r.country_code};agg[r.ip]=a;order.push(r.ip);}
      a.attempts+=Number(r.attempts);a.nsrc=Math.max(a.nsrc,Number(r.nsrc));a.reporters=Math.max(a.reporters,Number(r.reporters));
    });
    var points=[],countries={},ccOrder=[];
    order.forEach(function(ip){
      var a=agg[ip];
      if(typeof a.lat==='number'&&a.lat!==null){
        points.push({lat:a.lat,lon:a.lon,ip:ip,attempts:a.attempts,country:a.country,color:riskColor(a.attempts,a.nsrc,a.reporters)});
        var k=a.cc||'??';var cm=countries[k];if(!cm){cm={cc:a.cc,country:a.country,attempts:0};countries[k]=cm;ccOrder.push(k);}
        cm.attempts+=a.attempts;
      }
    });
    var clist=ccOrder.map(function(k){return countries[k];}).sort(function(x,y){return y.attempts-x.attempts;});
    document.getElementById('c-cc').textContent=intc(clist.length);
    document.getElementById('chips').innerHTML=clist.length?clist.slice(0,12).map(function(c){
      return '<span class="chip">'+flag(c.cc)+' '+esc(c.country||c.cc||'?')+' <b>'+intc(c.attempts)+'</b></span>';
    }).join(''):'<span class="chip" style="color:#94a3b8">no geolocated IPs</span>';

    var el=document.getElementById('map');
    if(!window.L){el.innerHTML='<div style="padding:20px;color:#94a3b8">map library failed to load</div>';return;}
    if(!points.length){el.innerHTML='<div style="padding:20px;color:#94a3b8">No geolocated IPs in this window</div>';return;}
    var map=L.map('map',{worldCopyJump:true,attributionControl:false,minZoom:1}).setView([25,10],2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{subdomains:'abcd',maxZoom:8}).addTo(map);
    points.forEach(function(p){
      var r=Math.min(24,5+Math.sqrt(p.attempts));
      L.circleMarker([p.lat,p.lon],{radius:r,color:p.color,weight:1,fillColor:p.color,fillOpacity:0.5})
        .addTo(map).bindPopup('<b>'+esc(p.ip)+'</b><br>'+esc(p.country||'')+'<br>attempts: '+intc(p.attempts));
    });
  }

  function drawTable(){
    var rows=state.rows, total=rows.length;
    var pages=Math.max(1,Math.ceil(total/PAGE_SIZE));
    if(state.page>pages)state.page=pages;
    var start=(state.page-1)*PAGE_SIZE, slice=rows.slice(start,start+PAGE_SIZE);
    document.getElementById('tbody').innerHTML=slice.length?slice.map(function(r){
      var tags=(esc(r.sources)||'').split(',').map(function(s){return '<span class="tag t-'+esc(s)+'">'+esc(s)+'</span>';}).join(' ');
      return '<tr>'+
        '<td class="mono">'+esc(r.log_date)+'</td>'+
        '<td class="mono ip">'+esc(r.ip)+'</td>'+
        '<td class="num">'+intc(r.attempts)+'</td>'+
        '<td>'+tags+'</td>'+
        '<td class="cats">'+esc(r.categories)+'</td>'+
        '<td class="num">'+intc(r.reporters)+'</td>'+
        '<td class="mono dim">'+esc(r.last_seen)+'</td>'+
        '<td><span class="badge" style="background:'+esc(r.risk_color)+'">'+esc(r.risk)+'</span></td>'+
        '</tr>';
    }).join(''):'<tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:28px">No data in this window yet</td></tr>';

    var pg=document.getElementById('pager');
    if(total<=PAGE_SIZE){pg.innerHTML='';return;}
    var shown=total?('Showing '+(start+1)+'–'+(start+slice.length)+' of '+intc(total)):'';
    var html='<span class="info">'+shown+'</span>';
    html+='<button '+(state.page<=1?'disabled':'')+' data-go="'+(state.page-1)+'">‹ Prev</button>';
    for(var p=1;p<=pages;p++)html+='<button class="'+(p===state.page?'on':'')+'" data-go="'+p+'">'+p+'</button>';
    html+='<button '+(state.page>=pages?'disabled':'')+' data-go="'+(state.page+1)+'">Next ›</button>';
    pg.innerHTML=html;
    Array.prototype.forEach.call(pg.querySelectorAll('button[data-go]'),function(b){
      b.addEventListener('click',function(){var g=parseInt(b.getAttribute('data-go'),10);if(g>=1&&g<=pages){state.page=g;drawTable();window.scrollTo(0,document.querySelector('table').offsetTop-10);}});
    });
  }

  var api='/risk-ip?days='+days+(source?('&source='+encodeURIComponent(source)):'')+'&limit='+MAP_MAX;
  fetch(api).then(function(resp){
    if(!resp.ok)return resp.text().then(function(t){throw new Error('HTTP '+resp.status+': '+t);});
    return resp.json();
  }).then(function(d){
    state.rows=d.rows||[];
    drawCards(state.rows);
    drawMapAndChips(state.rows);
    drawTable();
  }).catch(function(e){fail('Failed to load data: '+e.message);});
})();
</script>
</body></html>`;
}

// ---------------------------------------------------------------------------
// HTML: API documentation
// ---------------------------------------------------------------------------
function docsPage() {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IP Risk — API documentation</title>
<style>
  :root{color-scheme:dark}
  *{box-sizing:border-box}
  body{font:15px/1.65 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#0b1220;color:#e2e8f0}
  .wrap{max-width:880px;margin:0 auto;padding:28px 24px 64px}
  a{color:#93c5fd}
  h1{font-size:24px;margin:0 0 4px}
  h2{font-size:18px;margin:30px 0 8px;border-bottom:1px solid #243049;padding-bottom:6px}
  h3{font-size:15px;margin:20px 0 6px;font-family:ui-monospace,Menlo,monospace}
  code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#111c33;border:1px solid #243049;border-radius:5px;padding:1px 6px;font-size:13px}
  pre{background:#0f1830;border:1px solid #243049;border-radius:10px;padding:14px 16px;overflow:auto;font-size:13px;line-height:1.5}
  table{width:100%;border-collapse:collapse;margin:8px 0;font-size:14px}
  th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #1e2940;vertical-align:top}
  thead th{color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
  .method{display:inline-block;background:#2563eb;color:#fff;border-radius:6px;padding:1px 8px;font-size:12px;font-weight:700;margin-right:6px}
  .lead{color:#94a3b8}
  .note{background:#111c33;border:1px solid #243049;border-left:3px solid #3b82f6;border-radius:8px;padding:12px 16px;margin:14px 0}
  .contact{background:#111c33;border:1px solid #243049;border-radius:12px;padding:16px 18px;margin:18px 0}
  footer{color:#64748b;margin-top:34px;font-size:12px}
</style></head><body><div class="wrap">
  <p><a href="/">← Back to dashboard</a></p>
  <h1>IP Risk — API documentation</h1>
  <p class="lead">A read-only feed of malicious source IPs collected from multiple hosts'
  logs (SSH / MySQL / web probes), aggregated per attacker IP and geolocated.
  All endpoints are <code>GET</code>, need no auth, and send
  <code>Access-Control-Allow-Origin: *</code>.</p>

  <h2>Endpoints</h2>

  <h3><span class="method">GET</span>/risk-ip</h3>
  <p>The main data feed: one row per <code>(report&nbsp;date, IP)</code> in the window,
  ordered by date then attempts. Default <code>format=json</code>.</p>
  <table>
    <thead><tr><th>param</th><th>type</th><th>default</th><th>meaning</th></tr></thead>
    <tbody>
      <tr><td><code>days</code></td><td>int 1–90</td><td>7</td><td>look-back window (whole days)</td></tr>
      <tr><td><code>source</code></td><td>ssh \| mysql \| web</td><td><i>all</i></td><td>filter by source (400 if invalid)</td></tr>
      <tr><td><code>limit</code></td><td>int 1–5000</td><td>${MAP_MAX}</td><td>max rows returned</td></tr>
      <tr><td><code>offset</code></td><td>int ≥0</td><td>0</td><td>skip N rows (for paging)</td></tr>
      <tr><td><code>format</code></td><td>json \| csv</td><td>json</td><td>response format</td></tr>
      <tr><td><code>fields</code></td><td>csv list</td><td><i>preset</i></td><td>columns for csv/json projection (see below)</td></tr>
    </tbody>
  </table>
  <p>Example: <code>/risk-ip?days=30&amp;source=ssh&amp;limit=100</code></p>
  <pre>{
  "generated": "2026-06-27T08:00:00.000Z",
  "days": 7, "source": null, "count": 500, "limit": 500, "offset": 0,
  "rows": [
    {
      "log_date": "2026-06-27", "ip": "203.0.113.10",
      "attempts": 1432, "sources": "ssh,web", "categories": "ssh_bruteforce,web_env",
      "nsrc": 2, "reporters": 3, "last_seen": "2026-06-27 04:51:02",
      "country": "United States", "country_code": "US",
      "lat": 37.75, "lon": -97.82, "risk": "HIGH", "risk_color": "#dc2626"
    }
  ]
}</pre>
  <p class="lead">Field names available to <code>fields=</code>:
  <code>${FIELD_ORDER.join("</code>, <code>")}</code>.</p>

  <h3><span class="method">GET</span>/ip_only</h3>
  <p>Just the distinct attacker IPs, threat-ranked (most attempts first) — handy for
  blocklists / firewall imports.</p>
  <table>
    <thead><tr><th>param</th><th>type</th><th>default</th><th>meaning</th></tr></thead>
    <tbody>
      <tr><td><code>source</code></td><td>ssh \| mysql \| web</td><td><i>all</i></td><td>filter by source</td></tr>
      <tr><td><code>limit</code></td><td>int 1–5000</td><td>1000</td><td>page size</td></tr>
      <tr><td><code>offset</code></td><td>int ≥0</td><td>0</td><td>page offset</td></tr>
      <tr><td><code>format</code></td><td>json \| csv</td><td>json</td><td>JSON array, or one IP per line</td></tr>
    </tbody>
  </table>
  <p>Example: <code>/ip_only?format=csv&amp;limit=5000</code> → <code>ip</code> header then one IP per line.</p>

  <h3><span class="method">GET</span>/</h3>
  <p>The HTML dashboard. It loads its data asynchronously from <code>/risk-ip</code>,
  draws up to ${MAP_MAX} IPs on the map, and paginates the table ${PAGE_SIZE} rows per page.</p>

  <h2>Risk scoring</h2>
  <p>Per IP: <code>score = attempts + (sources−1)×200 + (reporters−1)×100</code>.</p>
  <ul>
    <li><b style="color:#dc2626">HIGH</b> — score ≥ 200, or seen on ≥ 2 different sources</li>
    <li><b style="color:#d97706">MED</b> — score ≥ 20</li>
    <li><b style="color:#16a34a">LOW</b> — otherwise</li>
  </ul>

  <div class="contact">
    <h2 style="margin-top:0;border:0;padding:0">Request removal of an IP</h2>
    <p>If one of your addresses appears here in error and you'd like it removed,
    email <b>${esc(CONTACT_NAME)}</b>
    &lt;<a href="mailto:${esc(CONTACT_EMAIL)}?subject=IP%20removal%20request">${esc(CONTACT_EMAIL)}</a>&gt;
    with the IP address. Please send from an address you can prove control of.</p>
  </div>

  <footer>ip-risk · data refreshed daily from multiple reporters.</footer>
</div></body></html>`;
}
