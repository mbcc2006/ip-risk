#!/usr/bin/env python3
"""Multi-port honeypot: listen on commonly-probed ports, batch-upload prober IPs.

Accepts a TCP connection on each configured port, aggregates the source IP in an
in-memory pool, then closes immediately -- no banner, no real service. The pool
is flushed to the shared threat DB in batches on a timer (default 60s), so a
flood of probes never becomes a flood of DB writes. Rows are written as
source='honeypot', category='port_probe' through the same idempotent UPSERT as
badip_logger.py, whose DB config / schema / helpers this reuses.

Which ports are on is controlled by honeypot.conf (JSON): the `ports` object
maps "<port>": true/false -- flip a value and restart (`supervisorctl restart
honeypot`) to toggle a port. A port whose bind fails (already in use / not
permitted) is skipped, so the honeypot never collides with a real service.

Python 3.6+ (CentOS Stream 8). Runs under supervisor as root (to bind <1024).
"""
import json
import os
import selectors
import socket
import sys
import time
from datetime import datetime

import pymysql
import badip_logger as bl       # reuse DB config, schema, UPSERT, helpers

HERE = os.path.dirname(os.path.abspath(__file__))
CONF_PATH = os.environ.get("HONEYPOT_CONF", os.path.join(HERE, "honeypot.conf"))

# Commonly-probed ports, all free on the target host (any that turn out to be
# bound are skipped). ssh(22)/http(80)/https(443) and live services are absent.
DEFAULT_PORTS = [21, 23, 25, 110, 135, 139, 143, 445, 465, 587, 993, 995,
                 1080, 1433, 1521, 2121, 2222, 2375, 3306, 3389, 4444, 5060,
                 5555, 5900, 7001, 8443, 9200, 11211, 27017]
DEFAULTS = {
    "bind": "0.0.0.0",
    "ports": {str(p): True for p in DEFAULT_PORTS},
    "flush_secs": 60,           # batch-upload interval
    "max_batch": 2000,          # early flush once this many keys are pending
}

SOURCE = "honeypot"
CATEGORY = "port_probe"


def log(msg):
    print("[{0}] {1}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg),
          flush=True)


def load_conf():
    conf = dict(DEFAULTS)
    try:
        with open(CONF_PATH) as f:
            conf.update(json.load(f))
    except IOError:
        log("no config at {0}, using built-in defaults".format(CONF_PATH))
    except Exception as exc:
        log("WARN bad config {0!r}, using built-in defaults".format(exc))
    return conf


def enabled_ports(conf):
    ports = conf.get("ports", {})
    items = ((p, True) for p in ports) if isinstance(ports, list) else ports.items()
    out = set()
    for p, on in items:
        if not on:
            continue
        try:
            n = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= n <= 65535:
            out.add(n)
    return sorted(out)


class Pool(object):
    """In-memory aggregation pool, flushed to MySQL in batches.

    Aggregates cumulatively per (ip, source, category, day) via badip_logger's
    _bump, tracking which keys changed since the last flush ("dirty"). Each
    flush re-sends the running totals of the dirty keys through the GREATEST/
    LEAST UPSERT, so it stays idempotent and lossless even across flushes -- a
    failed flush just keeps the data for the next one.
    """

    def __init__(self, reporter_ip, max_batch):
        self.reporter_ip = reporter_ip
        self.max_batch = max(1, int(max_batch))
        self.agg = {}
        self.dirty = set()

    def add(self, ip, port):
        dt = datetime.now()
        bl._bump(self.agg, ip, SOURCE, CATEGORY, dt, str(port))
        self.dirty.add((ip, SOURCE, CATEGORY, dt.date()))

    def full(self):
        return len(self.dirty) >= self.max_batch

    def flush(self):
        if not self.dirty:
            return
        rows = []
        for key in self.dirty:
            rec = self.agg.get(key)
            if not rec:
                continue
            ip, source, category, day = key
            detail = ",".join(sorted(rec["details"]))[:255]
            rows.append((self.reporter_ip, ip, source, category, rec["attempts"],
                         detail, rec["first"], rec["last"], day))
        if not rows:
            self.dirty.clear()
            return
        try:
            conn = pymysql.connect(**bl.DB)
            try:
                with conn.cursor() as cur:
                    cur.executemany(bl.UPSERT, rows)
                conn.commit()
            finally:
                conn.close()
        except Exception as exc:
            log("WARN db flush failed ({0} rows kept for retry): {1!r}".format(
                len(rows), exc))
            return                          # keep dirty -> retry next interval
        self.dirty.clear()
        log("flushed {0} rows ({1} ips) to db".format(
            len(rows), len(set(r[1] for r in rows))))
        self._prune()

    def _prune(self):
        # Drop already-flushed keys from past days so memory stays bounded.
        today = datetime.now().date()
        for k in [k for k in self.agg if k[3] < today]:
            del self.agg[k]


def ensure_schema():
    try:
        conn = pymysql.connect(**bl.DB)
        try:
            with conn.cursor() as cur:
                cur.execute(bl.DDL_DB)
                cur.execute(bl.DDL_TABLE)
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        log("WARN ensure_schema failed (will retry on flush): {0!r}".format(exc))


def make_listeners(conf):
    sel = selectors.DefaultSelector()
    bound = []
    for port in enabled_ports(conf):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setblocking(False)
        try:
            s.bind((conf["bind"], port))
            s.listen(128)
        except OSError as exc:
            log("skip :{0} ({1})".format(port, exc.strerror or exc))
            s.close()
            continue
        sel.register(s, selectors.EVENT_READ, port)
        bound.append(port)
    return sel, bound


def serve(conf):
    reporter_ip = bl.get_reporter_ip()
    ensure_schema()
    pool = Pool(reporter_ip, conf["max_batch"])
    flush_secs = max(5, int(conf["flush_secs"]))
    sel, bound = make_listeners(conf)
    if not bound:
        log("no ports could be bound, exiting")
        return 1
    log("reporter={0} listening on {1} port(s): {2}".format(
        reporter_ip, len(bound), bound))
    log("batch-upload to DB every {0}s (or once {1} keys pending)".format(
        flush_secs, pool.max_batch))
    last_flush = time.time()
    try:
        while True:
            for key, _mask in sel.select(timeout=flush_secs):
                lsock, port = key.fileobj, key.data
                while True:                         # drain backlog, non-blocking
                    try:
                        conn, addr = lsock.accept()
                    except (BlockingIOError, InterruptedError):
                        break
                    except OSError:
                        break
                    try:
                        conn.close()
                    except OSError:
                        pass
                    if bl.is_public_ip(addr[0]):
                        pool.add(addr[0], port)
            now = time.time()
            if pool.full() or (now - last_flush) >= flush_secs:
                pool.flush()
                last_flush = now
    except KeyboardInterrupt:
        log("interrupted, final flush")
        pool.flush()
        return 0


def main():
    return serve(load_conf())


if __name__ == "__main__":
    sys.exit(main() or 0)
