# threat-ip-monitor

A small, self-hostable pipeline that collects malicious source IPs from a host's
logs, classifies them, geolocates them, and serves a **daily IP-risk dashboard +
JSON/CSV API** on the edge via a Cloudflare Worker.

```
┌────────────┐   logs    ┌──────────────────┐   MySQL    ┌───────────────┐  Hyperdrive  ┌──────────────┐
│ host logs  │──────────▶│ badip_logger.py  │──────────▶│  security DB   │◀────────────│ ip-risk      │
│ btmp /     │  parse +  │  (cron, per host)│  upsert   │  bad_login     │   query      │ Worker       │
│ mysqld.log │  classify │  + geo enrich    │           │  ip_geo        │             │ (dashboard / │
│ caddy logs │           └──────────────────┘           │  threat_summary│             │  API + map)  │
└────────────┘                                           └───────────────┘             └──────────────┘
```

## Sources & classification

| source | from | category examples |
|--------|------|-------------------|
| `ssh`  | `lastb` / btmp | `ssh_bruteforce` |
| `mysql`| MySQL error log (`log_error_verbosity=3`, "Access denied") | `mysql_bruteforce` |
| `web`  | Caddy JSON access logs (discovered from the Caddy config) | `web_env`, `web_git`, `web_wordpress`, `web_phpmyadmin`, `web_rce`, `web_secrets`, `web_traversal`, `web_scan` |

Rows are keyed by `(reporter_ip, ip, source, category, log_date)`, so multiple
hosts can write to one shared database without overwriting each other.

## Repo layout

```
collector/   badip_logger.py   - run on each host via cron
worker/      Cloudflare Worker - dashboard + API, reads the DB through Hyperdrive
```

---

## 1. Collector (`collector/`)

Runs on every host you want to monitor. Python 3.6+, one dependency (PyMySQL).

```bash
cd collector
pip3 install -r requirements.txt
cp .env.example .env          # then edit .env with your DB credentials
chmod 600 .env
python3 badip_logger.py --hours 0     # first run: creates tables + backfills
```

Configuration is read from the environment (or a `.env` file next to the script):

| env var | default | meaning |
|---------|---------|---------|
| `BADIP_DB_HOST` | `127.0.0.1` | MySQL host |
| `BADIP_DB_PORT` | `3306` | MySQL port |
| `BADIP_DB_USER` | `badip` | MySQL user |
| `BADIP_DB_PASSWORD` | _(empty)_ | MySQL password |
| `BADIP_DB_NAME` | `security` | database name |
| `REPORTER_IP` | auto-detect | this host's identifying IP (set explicitly on NAT'd hosts) |
| `CADDYFILE` | `/etc/caddy/Caddyfile` | where to discover Caddy access-log paths |
| `GEOIP_DB` | `dbip.dat` (next to script) | local GeoIP City `.dat` path |
| `GEOIP_URL` | miyuru dbip city `.dat.gz` | URL to auto-download the GeoIP db from if missing |

CLI:

```
--hours N        only consider events from the last N hours (default: all)
--sources LIST   comma list of sources to run (default: ssh,mysql,web)
```

**Daily cron** (25h window overlaps the previous run by 1h; the GREATEST upsert
makes overlap/slow runs lossless):

```cron
11 0 * * * /usr/bin/python3 /opt/threat-ip-monitor/collector/badip_logger.py --hours 25 >> /var/log/badip_logger.log 2>&1
```

### Prerequisites for full coverage

- **MySQL failed logins** are only written to the error log at verbosity 3:
  ```sql
  SET PERSIST log_error_verbosity = 3;
  ```
- **Web probes** are only captured for sites Caddy actually logs. To catch
  scanners hitting the bare IP / unknown hostnames, add an HTTP catch-all:
  ```caddyfile
  http:// {
      log { output file /var/log/caddy.probe.log }
      respond 404
  }
  ```
  The collector auto-discovers every `output file` path in your Caddy config.

---

## 2. Worker (`worker/`)

A Cloudflare Worker that reads the shared database through **Hyperdrive** and
renders the dashboard + API. No database credentials live in the code — they are
stored in the Hyperdrive config on Cloudflare.

### Setup

1. Create a Hyperdrive config pointing at your MySQL (`wrangler hyperdrive create
   …` or the dashboard). Put its id in `wrangler.toml`.
2. Set your account id and (optionally) a custom domain — see comments in
   `wrangler.toml`.
3. Set the IP-removal contact shown on the dashboard/`/docs` — edit the
   `CONTACT_NAME` / `CONTACT_EMAIL` vars in `wrangler.toml` (`[vars]`).
4. Deploy:
   ```bash
   cd worker
   npm install
   export CLOUDFLARE_ACCOUNT_ID=...           # your account id
   export CLOUDFLARE_API_TOKEN=...            # token with Workers + Hyperdrive edit
   npx wrangler deploy
   ```

### Local dev

```bash
export WRANGLER_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE="mysql://user:pass@host:3306/security"
npx wrangler dev
```

### Routes

| route | description |
|-------|-------------|
| `GET /` | HTML dashboard. A static shell that loads its data **asynchronously** from `/risk-ip`; the map plots up to 500 IPs and the table paginates 50 per page. |
| `GET /risk-ip` | **The data API** — dashboard rows as JSON (default) or CSV. |
| `GET /ip_only` | distinct attacker IPs, threat-ranked — JSON array or (`format=csv`) one per line. |
| `GET /docs` | HTML API documentation (linked from the dashboard). |
| `GET /ping` | debug. |

Query params (all validated — allowlists + clamped integers, every SQL value bound):

| param | applies to | type / values | default | meaning |
|-------|-----------|---------------|---------|---------|
| `days` | `/risk-ip` | int 1–90 | 7 | look-back window |
| `source` | `/risk-ip`, `/ip_only` | `ssh\|mysql\|web` | all | filter by source (400 if invalid) |
| `limit` | `/risk-ip` | int 1–20000 | 20000 (full window) | rows per page; page large windows with `offset` |
| `limit` | `/ip_only` | int 1–50000 | 50000 (full list) | page size for the blocklist |
| `offset` | `/risk-ip`, `/ip_only` | int ≥ 0 | 0 | page offset |
| `format` | data routes | `json\|csv` | json | response format |
| `fields` | `/risk-ip` | csv subset | preset | column projection (`log_date,ip,attempts,sources,categories,nsrc,reporters,last_seen,country,country_code,risk`) |

Full reference and examples live at **`/docs`** on the deployed Worker.

**IP removal:** to request an address be removed from the feed, contact
世界第一好吃 &lt;admin@ivjn.us&gt; (also shown on the dashboard and `/docs`).

---

## Schema (auto-created)

- `bad_login` — one row per `(reporter_ip, ip, source, category, log_date)`
- `ip_geo` — `ip → country / country_code / region / city / lat / lon / isp`
  (filled at the source; the Worker never calls a geo API)
- `threat_summary` (view) — every attacker IP rolled up across reporters/sources

## Security notes

- Never commit `.env` / real credentials (see `.gitignore`).
- Use a least-privilege MySQL user for the collector (INSERT/SELECT on the
  `security` DB), not a superuser.
- Geolocation is done locally against a DB-IP City `.dat` (read with `pygeoip`),
  auto-downloaded from `GEOIP_URL` on first use — no per-lookup API calls. The
  default source is [db-ip.com](https://db-ip.com) lite via miyuru.lk (free,
  non-commercial). Point `GEOIP_URL` at your own mirror/CDN for hosts that can't
  reach it, and refresh the `.dat` periodically (the DB updates monthly).

## License

MIT — see [LICENSE](LICENSE).
