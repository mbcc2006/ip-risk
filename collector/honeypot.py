#!/usr/bin/env python3
"""Multi-port honeypot: listen on commonly-probed ports, cache prober IPs.

Accepts a TCP connection on each configured port, records (ts, source IP, port)
to a cache file, then closes immediately -- no banner, no real service. The
cache is consumed by badip_logger.py's `honeypot` source, which upserts the IPs
into the shared threat DB on its cron (cache now, upload later).

Which ports are on is controlled by honeypot.conf (JSON) next to this file:
the `ports` object maps "<port>": true/false -- flip a value and restart
(`supervisorctl restart honeypot`) to enable/disable a port. A port whose bind
fails (already in use / not permitted) is skipped, so the honeypot never
collides with a real service.

Python 3.6+ (CentOS Stream 8). Runs under supervisor as root (to bind <1024).
"""
import ipaddress
import json
import os
import selectors
import socket
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
CONF_PATH = os.environ.get("HONEYPOT_CONF", os.path.join(HERE, "honeypot.conf"))

# Commonly-probed ports, all free on the target host (the honeypot skips any
# that turn out to be bound). ssh(22)/http(80)/https(443) and the box's other
# live services are intentionally absent.
DEFAULT_PORTS = [21, 23, 25, 110, 135, 139, 143, 445, 465, 587, 993, 995,
                 1080, 1433, 1521, 2121, 2222, 2375, 3306, 3389, 4444, 5060,
                 5555, 5900, 7001, 8443, 9200, 11211, 27017]
DEFAULTS = {
    "bind": "0.0.0.0",
    "ports": {str(p): True for p in DEFAULT_PORTS},
    "cache_file": "/var/log/honeypot_hits.jsonl",
    "throttle_secs": 60,
    "max_cache_bytes": 10 * 1024 * 1024,
}


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
    if isinstance(ports, list):                     # tolerate a plain list too
        items = ((p, True) for p in ports)
    else:
        items = ports.items()
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


def is_recordable(ip):
    """Public IPs only -- never cache our own / internal traffic."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_unspecified or a.is_reserved)


class Cache(object):
    """Append-only JSON-lines cache, throttled per (ip,port) and size-rotated."""

    def __init__(self, path, max_bytes, throttle):
        self.path = path
        self.max_bytes = int(max_bytes)
        self.throttle = max(1, int(throttle))
        self.last = {}                              # (ip,port) -> last write ts
        d = os.path.dirname(path)
        if d and not os.path.isdir(d):
            try:
                os.makedirs(d)
            except OSError:
                pass

    def _prune(self, now):
        cutoff = now - self.throttle
        for k in [k for k, t in self.last.items() if t < cutoff]:
            del self.last[k]

    def record(self, ip, port):
        now = time.time()
        key = (ip, port)
        prev = self.last.get(key)
        if prev is not None and (now - prev) < self.throttle:
            return                                  # throttled: bound file size
        self.last[key] = now
        if len(self.last) > 50000:
            self._prune(now)
        line = json.dumps({"ts": int(now), "ip": ip, "port": port},
                          separators=(",", ":"))
        try:
            if (os.path.exists(self.path)
                    and os.path.getsize(self.path) >= self.max_bytes):
                os.replace(self.path, self.path + ".1")
            with open(self.path, "a") as f:
                f.write(line + "\n")
        except OSError as exc:
            log("WARN cache write failed: {0!r}".format(exc))


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
    cache = Cache(conf["cache_file"], conf["max_cache_bytes"],
                  conf["throttle_secs"])
    sel, bound = make_listeners(conf)
    if not bound:
        log("no ports could be bound, exiting")
        return 1
    log("listening on {0} port(s): {1}".format(len(bound), bound))
    log("caching prober IPs to {0} (throttle {1}s)".format(
        conf["cache_file"], conf["throttle_secs"]))
    while True:
        for key, _mask in sel.select(timeout=None):
            lsock, port = key.fileobj, key.data
            while True:                             # drain backlog, non-blocking
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
                if is_recordable(addr[0]):
                    cache.record(addr[0], port)


def main():
    try:
        return serve(load_conf())
    except KeyboardInterrupt:
        log("interrupted, exiting")
        return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
