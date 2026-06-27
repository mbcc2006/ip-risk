#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
badip_logger.py - Daily multi-source collector of malicious source IPs.

Sources (each tagged with a `source` and a finer `category`):
  * ssh    - failed SSH/login attempts from btmp (via `lastb`)
  * mysql  - failed MySQL auth attempts (performance_schema.host_cache)
  * web    - Caddy "common probe" requests (scanners hitting /.env, /.git,
             wp-login, phpMyAdmin, RCE paths, etc.) from the Caddy JSON access
             log. The real client IP is taken from the Cf-Connecting-Ip header
             because Caddy sits behind Cloudflare.

Everything is upserted into a SHARED MySQL table `security.bad_login`, keyed by
(reporter_ip, ip, source, category, log_date) so multiple machines and multiple
attack types never overwrite each other. The `threat_summary` view rolls every
attacker IP up across reporters/sources/categories.

reporter_ip: this machine's own IP (source IP of default route; override via the
REPORTER_IP env var).

  --hours N   only consider events from the last N hours (default: all).
              The daily cron uses 25 (24h coverage + 1h overlap; GREATEST upsert
              makes overlap/slow runs lossless).

Target: CentOS Stream 8 / Python 3.6 (no datetime.fromisoformat).
"""
import argparse
import glob
import gzip
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import ipaddress
import urllib.request
from datetime import datetime, timedelta, timezone

import pymysql

# --- config (from environment / optional .env) -----------------------------
def _load_env_file(path):
    """Minimal .env loader (KEY=VALUE per line). Existing env vars win."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass


_load_env_file(os.environ.get(
    "BADIP_ENV_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")))

DB = dict(
    host=os.environ.get("BADIP_DB_HOST", "127.0.0.1"),
    port=int(os.environ.get("BADIP_DB_PORT", "3306")),
    user=os.environ.get("BADIP_DB_USER", "badip"),
    password=os.environ.get("BADIP_DB_PASSWORD", ""),
    charset="utf8mb4",
    connect_timeout=10,
)
DB_NAME = os.environ.get("BADIP_DB_NAME", "security")
TABLE = "bad_login"

# Caddy access-log paths are discovered from the Caddy config itself (the
# `log { output file <path> }` directives), so new sites are picked up
# automatically instead of relying on a hard-coded glob.
CADDYFILE = os.environ.get("CADDYFILE", "/etc/caddy/Caddyfile")
CADDY_OUTPUT_RE = re.compile(r"^\s*output\s+file\s+(\S+)", re.M)
CADDY_IMPORT_RE = re.compile(r"^\s*import\s+(\S+)", re.M)

DDL_DB = "CREATE DATABASE IF NOT EXISTS `{0}` DEFAULT CHARACTER SET utf8mb4".format(DB_NAME)

DDL_TABLE = """
CREATE TABLE IF NOT EXISTS `{db}`.`{tbl}` (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  reporter_ip VARCHAR(45)  NOT NULL,
  ip          VARCHAR(45)  NOT NULL,
  source      VARCHAR(16)  NOT NULL DEFAULT 'ssh',
  category    VARCHAR(48)  NOT NULL DEFAULT 'ssh_bruteforce',
  attempts    INT          NOT NULL DEFAULT 0,
  detail      VARCHAR(255) DEFAULT NULL,
  first_seen  DATETIME     DEFAULT NULL,
  last_seen   DATETIME     DEFAULT NULL,
  log_date    DATE         NOT NULL,
  updated_at  DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_event (reporter_ip, ip, source, category, log_date),
  KEY idx_ip (ip),
  KEY idx_date (log_date),
  KEY idx_source (source),
  KEY idx_reporter (reporter_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
""".format(db=DB_NAME, tbl=TABLE)

DDL_VIEW = """
CREATE OR REPLACE VIEW `{db}`.`threat_summary` AS
SELECT
  ip,
  SUM(attempts)                                   AS total_attempts,
  COUNT(DISTINCT reporter_ip)                     AS reporters,
  COUNT(DISTINCT source)                          AS sources,
  GROUP_CONCAT(DISTINCT source ORDER BY source)   AS source_list,
  GROUP_CONCAT(DISTINCT category ORDER BY category) AS categories,
  MIN(first_seen)                                 AS first_seen,
  MAX(last_seen)                                  AS last_seen,
  MAX(log_date)                                   AS last_date
FROM `{db}`.`{tbl}`
GROUP BY ip
""".format(db=DB_NAME, tbl=TABLE)

UPSERT = """
INSERT INTO `{db}`.`{tbl}`
  (reporter_ip, ip, source, category, attempts, detail, first_seen, last_seen, log_date)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
ON DUPLICATE KEY UPDATE
  attempts   = GREATEST(attempts, VALUES(attempts)),
  detail     = IF(CHAR_LENGTH(VALUES(detail)) > CHAR_LENGTH(COALESCE(detail,'')),
                  VALUES(detail), detail),
  first_seen = LEAST(first_seen, VALUES(first_seen)),
  last_seen  = GREATEST(last_seen, VALUES(last_seen))
""".format(db=DB_NAME, tbl=TABLE)

# ip -> geo lookup table (shared across reporters; filled at the source so the
# Worker never has to call a geo API).
DDL_GEO = """
CREATE TABLE IF NOT EXISTS `{db}`.`ip_geo` (
  ip           VARCHAR(45) PRIMARY KEY,
  country      VARCHAR(64)  DEFAULT NULL,
  country_code CHAR(2)      DEFAULT NULL,
  region       VARCHAR(96)  DEFAULT NULL,
  city         VARCHAR(96)  DEFAULT NULL,
  lat          DOUBLE       DEFAULT NULL,
  lon          DOUBLE       DEFAULT NULL,
  isp          VARCHAR(128) DEFAULT NULL,
  status       VARCHAR(16)  DEFAULT NULL,
  updated_at   DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_cc (country_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
""".format(db=DB_NAME)

GEO_UPSERT = """
INSERT INTO `{db}`.`ip_geo`
  (ip, country, country_code, region, city, lat, lon, isp, status)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
ON DUPLICATE KEY UPDATE
  country=VALUES(country), country_code=VALUES(country_code), region=VALUES(region),
  city=VALUES(city), lat=VALUES(lat), lon=VALUES(lon), isp=VALUES(isp), status=VALUES(status)
""".format(db=DB_NAME)

# Local GeoIP City database (DB-IP legacy ".dat", IPv6 edition) read via pygeoip.
# Auto-downloaded from GEOIP_URL on first use if GEOIP_DB is missing.
GEOIP_DB = os.environ.get(
    "GEOIP_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "dbip.dat"))
GEOIP_URL = os.environ.get("GEOIP_URL",
                           "https://dl.miyuru.lk/geoip/dbip/city/dbip.dat.gz")

# Web "common probe" signatures, checked in order; first match wins.
WEB_SIGNATURES = [
    ("web_env",        re.compile(r"/\.env(\.|/|$)|/\.aws/|/\.git-credentials", re.I)),
    ("web_git",        re.compile(r"/\.git(/|$)|/\.svn(/|$)|/\.hg(/|$)", re.I)),
    ("web_wordpress",  re.compile(r"wp-login\.php|/wp-admin|xmlrpc\.php|/wp-content|/wp-includes|/wordpress", re.I)),
    ("web_phpmyadmin", re.compile(r"phpmyadmin|/pma(/|$)|/dbadmin|/adminer|/mysqladmin|/sqladmin", re.I)),
    ("web_rce",        re.compile(r"/cgi-bin/|/boaform|/vendor/phpunit|eval-stdin\.php|/think/app|/\?\s*xdebug|/actuator|/solr/|/manager/html|/jenkins|/console/|/druid/|/_ignition|/hudson", re.I)),
    ("web_secrets",    re.compile(r"/\.ssh/|/config\.json|/\.vscode|/\.docker|/credentials|/server-status|/\.htpasswd|/phpinfo|/info\.php", re.I)),
    ("web_traversal",  re.compile(r"\.\./|%2e%2e|%252e|/etc/passwd", re.I)),
    ("web_scan",       re.compile(r"/owa/|/autodiscover|/\.well-known/.+\.php|/setup\.php|/install\.php|/shell|/backup|\.bak$|\.sql$|/login\.action|/struts", re.I)),
]


def log(msg):
    print("[{0}] {1}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg),
          flush=True)


def get_reporter_ip():
    override = os.environ.get("REPORTER_IP")
    if override:
        return override.strip()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 53))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "0.0.0.0"
    finally:
        try:
            s.close()
        except Exception:
            pass


def is_public_ip(s):
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


def _file_maybe_in_window(path, cutoff):
    """False if the file's newest possible event is older than cutoff.

    Log files are append-ordered, so a file's mtime is the timestamp of its last
    line. When mtime < cutoff every event in it predates the window, so the whole
    (often rotated / .gz) file can be skipped instead of decompressed and scanned.
    Returns True if we can't stat the file (never skip on uncertainty)."""
    if not cutoff:
        return True
    try:
        return datetime.fromtimestamp(os.path.getmtime(path)) >= cutoff
    except OSError:
        return True


def _bump(agg, ip, source, category, dt, detail_item):
    """Accumulate one event into agg keyed by (ip, source, category, date)."""
    key = (ip, source, category, dt.date())
    rec = agg.get(key)
    if rec is None:
        rec = {"attempts": 0, "details": set(), "first": dt, "last": dt}
        agg[key] = rec
    rec["attempts"] += 1
    if detail_item:
        if len(rec["details"]) < 30:
            rec["details"].add(detail_item)
    if dt < rec["first"]:
        rec["first"] = dt
    if dt > rec["last"]:
        rec["last"] = dt


# ----------------------------- SSH (btmp) ----------------------------------
def parse_ssh_dt(token):
    try:
        return datetime.strptime(token[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def collect_ssh(agg, cutoff):
    # btmp can be huge on a brute-forced host, so stream lastb's output line by
    # line instead of buffering the whole dump (check_output + decode +
    # splitlines would hold ~3 full copies in RAM at once).
    try:
        proc = subprocess.Popen(
            ["lastb", "-i", "-w", "--time-format", "iso"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        log("WARN ssh/lastb failed: {0!r}".format(exc))
        return
    try:
        for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", "replace").strip()
            if not line or line.startswith("btmp begins"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            user, _term, host, tstamp = parts[0], parts[1], parts[2], parts[3]
            dt = parse_ssh_dt(tstamp)
            if dt is None:
                continue
            # lastb prints newest-first: once we pass the cutoff every remaining
            # entry is older too, so stop reading the rest of btmp.
            if cutoff and dt < cutoff:
                break
            if not is_public_ip(host):
                continue
            _bump(agg, host, "ssh", "ssh_bruteforce", dt, user)
    finally:
        try:
            proc.stdout.close()    # SIGPIPE-terminates lastb if we broke early
        except Exception:
            pass
        proc.wait()


# ----------------------------- MySQL (error log) ---------------------------
# Requires log_error_verbosity >= 3 so "Access denied" notes are written.
# Colon-separated glob list (the error log lives in different places per distro:
# /var/log/mysqld.log on EL/community, /var/log/mysql/mysqld.log on the module/
# distro builds). Override with the MYSQL_LOG_GLOB env var.
MYSQL_LOG_GLOBS = os.environ.get(
    "MYSQL_LOG_GLOB",
    "/var/log/mysqld.log*:/var/log/mysql/mysqld.log*:/var/log/mysql/error.log*").split(":")
MYSQL_DENIED_RE = re.compile(r"Access denied for user '([^']*)'@'([^']*)'")
# error-log timestamps are UTC ("...Z"); convert to local to match ssh/web.
# (now(tz).replace(tzinfo=None) gives naive UTC without the deprecated utcnow().)
LOCAL_MINUS_UTC = datetime.now() - datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_mysql_ts(line):
    try:
        return datetime.strptime(line[:19], "%Y-%m-%dT%H:%M:%S") + LOCAL_MINUS_UTC
    except ValueError:
        return None


def collect_mysql(agg, cutoff):
    paths = sorted(set(p for pat in MYSQL_LOG_GLOBS for p in glob.glob(pat)))
    for path in paths:
        if not _file_maybe_in_window(path, cutoff):
            continue  # rotated archive entirely older than the window
        op = gzip.open if path.endswith(".gz") else open
        try:
            fh = op(path, "rt", encoding="utf-8", errors="replace")
        except Exception:
            continue
        with fh:
            for line in fh:
                if "Access denied for user" not in line:
                    continue
                m = MYSQL_DENIED_RE.search(line)
                if not m:
                    continue
                user, host = m.group(1), m.group(2)
                if not is_public_ip(host):        # skip localhost / internal
                    continue
                dt = _parse_mysql_ts(line)
                if dt is None or (cutoff and dt < cutoff):
                    continue
                _bump(agg, host, "mysql", "mysql_bruteforce", dt, user or "?")


# ----------------------------- Web (Caddy) ---------------------------------
def classify_web(uri):
    for category, rx in WEB_SIGNATURES:
        if rx.search(uri):
            return category
    return None


def _open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _read_caddy_text(path, seen=None):
    """Read a Caddy config file, inlining any `import` directives it references."""
    if seen is None:
        seen = set()
    path = os.path.abspath(path)
    if path in seen:
        return ""
    seen.add(path)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception:
        return ""
    parts = [text]
    base = os.path.dirname(path)
    for m in CADDY_IMPORT_RE.finditer(text):
        pat = m.group(1)
        if not os.path.isabs(pat):
            pat = os.path.join(base, pat)
        for inc in sorted(glob.glob(pat)):
            parts.append(_read_caddy_text(inc, seen))
    return "\n".join(parts)


def caddy_log_paths():
    """Access-log file paths declared in the Caddy config (+ rotated siblings)."""
    text = _read_caddy_text(CADDYFILE)
    if not text:
        log("WARN could not read Caddy config at {0}".format(CADDYFILE))
        return []
    roots = sorted(set(m.group(1) for m in CADDY_OUTPUT_RE.finditer(text)))
    files = []
    for p in roots:
        files.extend(sorted(glob.glob(p + "*")) or [p])
    return files


def collect_caddy(agg, cutoff):
    for path in caddy_log_paths():
        if not _file_maybe_in_window(path, cutoff):
            continue  # rotated archive entirely older than the window
        try:
            fh = _open_log(path)
        except Exception:
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line or '"handled request"' not in line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                req = obj.get("request") or {}
                uri = req.get("uri") or ""
                category = classify_web(uri)
                if not category:
                    continue
                ts = obj.get("ts")
                if ts is None:
                    continue
                try:
                    dt = datetime.fromtimestamp(float(ts))
                except (ValueError, OverflowError, OSError):
                    continue
                if cutoff and dt < cutoff:
                    continue
                headers = req.get("headers") or {}
                cf = headers.get("Cf-Connecting-Ip") or headers.get("Cf-connecting-ip")
                ip = (cf[0] if isinstance(cf, list) and cf else None) \
                    or req.get("client_ip") or req.get("remote_ip")
                if not ip or not is_public_ip(ip):
                    continue
                _bump(agg, ip, "web", category, dt, uri[:80])


# ----------------------------- geo enrichment ------------------------------
_GEO = None
_GEO_TRIED = False


def _ensure_geo_db():
    """Download + decompress the GeoIP .dat from GEOIP_URL if it's not present."""
    if os.path.exists(GEOIP_DB) and os.path.getsize(GEOIP_DB) > 0:
        return True
    log("geo: db missing, downloading {0}".format(GEOIP_URL))
    gz_tmp = GEOIP_DB + ".gz.tmp"
    dat_tmp = GEOIP_DB + ".tmp"
    try:
        d = os.path.dirname(GEOIP_DB)
        if d and not os.path.isdir(d):
            os.makedirs(d)
        # per-operation socket timeout (not a total deadline); generous so very
        # slow / low-bandwidth links can still complete the ~50 MB download.
        with urllib.request.urlopen(GEOIP_URL, timeout=600) as resp, open(gz_tmp, "wb") as f:
            shutil.copyfileobj(resp, f)
        with gzip.open(gz_tmp, "rb") as gz, open(dat_tmp, "wb") as out:
            shutil.copyfileobj(gz, out)
        os.replace(dat_tmp, GEOIP_DB)
        log("geo: downloaded {0} ({1:.1f} MB)".format(GEOIP_DB, os.path.getsize(GEOIP_DB) / 1048576.0))
        return True
    except Exception as exc:
        log("WARN geo db download failed: {0!r}".format(exc))
        return False
    finally:
        for p in (gz_tmp, dat_tmp):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass


def _geo_reader():
    """Lazily open the local GeoIP .dat (pygeoip, mmap-backed). None if missing."""
    global _GEO, _GEO_TRIED
    if _GEO_TRIED:
        return _GEO
    _GEO_TRIED = True
    if not _ensure_geo_db():
        _GEO = None
        return _GEO
    try:
        import pygeoip
        _GEO = pygeoip.GeoIP(GEOIP_DB, pygeoip.const.MMAP_CACHE)
    except Exception as exc:
        log("WARN local GeoIP db unavailable ({0}): {1!r}".format(GEOIP_DB, exc))
        _GEO = None
    return _GEO


def geo_batch(ips):
    """Look up IPs in the local GeoIP City db; returns ip-api-shaped dicts.

    The miyuru/geolite2legacy "city" .dat is an IPv6 edition that stores IPv4 as
    IPv4-mapped addresses, so v4 must be queried as '::ffff:<ip>'."""
    reader = _geo_reader()
    out = []
    if reader is None:
        return out
    for ip in ips:
        try:
            v = ipaddress.ip_address(ip)
            rec = reader.record_by_addr(("::ffff:" + ip) if v.version == 4 else ip)
        except Exception:
            rec = None
        if not rec:
            continue  # not in db -> leave for a later run / db refresh
        out.append({
            "query": ip,
            "status": "success",
            "country": rec.get("country_name"),
            "countryCode": rec.get("country_code"),
            "regionName": rec.get("region_name") or rec.get("region_code"),
            "city": rec.get("city"),
            "lat": rec.get("latitude"),
            "lon": rec.get("longitude"),
            "isp": None,  # city db has no ISP/ASN
        })
    return out


def enrich_geo(conn):
    """Fill security.ip_geo for any bad_login IPs that don't have geo yet.

    Shared table: once any reporter geolocates an IP, every reporter skips it."""
    with conn.cursor() as cur:
        cur.execute(DDL_GEO)
    conn.commit()

    with conn.cursor() as cur:
        cur.execute(
            "SELECT DISTINCT b.ip FROM `{db}`.bad_login b "
            "LEFT JOIN `{db}`.ip_geo g ON g.ip = b.ip "
            "WHERE g.ip IS NULL".format(db=DB_NAME))
        todo = [r[0] for r in cur.fetchall()]

    if not todo:
        log("geo: all IPs already located")
        return

    rows = [(r["query"], r.get("country"), r.get("countryCode"),
             r.get("regionName"), r.get("city"),
             r.get("lat"), r.get("lon"), r.get("isp"), r.get("status"))
            for r in geo_batch(todo)]
    if rows:
        with conn.cursor() as cur:
            cur.executemany(GEO_UPSERT, rows)
        conn.commit()
    log("geo: located {0}/{1} new IPs (local db)".format(len(rows), len(todo)))


# ----------------------------- main ----------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Collect malicious IPs (ssh/mysql/web) into MySQL.")
    p.add_argument("--hours", type=float, default=None, metavar="N",
                   help="only consider events from the last N hours "
                        "(default: all). The daily cron uses 25.")
    p.add_argument("--sources", default="ssh,mysql,web",
                   help="comma list of sources to collect (default: all).")
    return p.parse_args()


def main():
    args = parse_args()
    sources = set(s.strip() for s in args.sources.split(",") if s.strip())
    reporter_ip = get_reporter_ip()
    cutoff = None
    if args.hours and args.hours > 0:
        cutoff = datetime.now() - timedelta(hours=args.hours)
    window = "all" if not cutoff else "last {0}h".format(args.hours)

    conn = pymysql.connect(**DB)
    try:
        with conn.cursor() as cur:
            cur.execute(DDL_DB)
            cur.execute(DDL_TABLE)
            cur.execute(DDL_VIEW)
            cur.execute(DDL_GEO)
        conn.commit()

        agg = {}
        if "ssh" in sources:
            collect_ssh(agg, cutoff)
        if "mysql" in sources:
            collect_mysql(agg, cutoff)
        if "web" in sources:
            collect_caddy(agg, cutoff)

        if agg:
            rows = []
            for (ip, source, category, day), rec in agg.items():
                detail = ",".join(sorted(rec["details"]))[:255]
                rows.append((reporter_ip, ip, source, category, rec["attempts"],
                             detail, rec["first"], rec["last"], day))

            with conn.cursor() as cur:
                cur.executemany(UPSERT, rows)
            conn.commit()

            by_source = {}
            for r in rows:
                by_source[r[2]] = by_source.get(r[2], 0) + 1
            breakdown = ", ".join("{0}={1}".format(k, v) for k, v in sorted(by_source.items()))
            total = sum(r[4] for r in rows)
            log("reporter={0} window={1}: upserted {2} rows ({3}) | unique IPs={4} | total attempts={5}".format(
                reporter_ip, window, len(rows), breakdown,
                len(set(r[1] for r in rows)), total))
        else:
            log("reporter={0} window={1}: nothing collected".format(reporter_ip, window))

        # Enrich geo for any IPs still missing it (runs every time, cheap if done).
        try:
            enrich_geo(conn)
        except Exception as exc:
            log("WARN geo enrichment failed: {0!r}".format(exc))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
