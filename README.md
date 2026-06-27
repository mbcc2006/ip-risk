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
| `REPORTER_IP` | auto-detect | this host's identifying IP |
| `CADDYFILE` | `/etc/caddy/Caddyfile` | where to discover Caddy access-log paths |

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
3. Deploy:
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
| `GET /` | HTML dashboard with risk map |
| `GET /?format=json\|csv` | data export (`fields=` to pick columns) |
| `GET /?source=ssh\|mysql\|web` | filter by source |
| `GET /ip_only` | JSON array of distinct IPs, threat-ranked (`limit` ≤ 5000, `offset`) |
| `GET /ip_only?format=csv` | one IP per line |

All query params are validated (allowlists + clamped integers) and every SQL
value is bound — no string concatenation of user input into SQL.

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
- Geolocation uses the free [ip-api.com](https://ip-api.com) batch endpoint
  (non-commercial use); swap it out in the collector if you need commercial use.

## License

MIT — see [LICENSE](LICENSE).
