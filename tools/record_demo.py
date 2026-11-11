#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Record real lumtail sessions in a PTY and render GIFs with asciinema agg."""

import argparse
import codecs
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import random
import re
import select
import shutil
import signal
import struct
import subprocess
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parents[1]
FILTER = "service=api AND status>=500"
DURATION = 19.6
THEME = {
    "bg": "#1d1f1e", "fg": "#eee9df",
    "palette": ":".join(("#1d1f1e", "#f07178", "#9ac98a", "#e9a84c",
                         "#8cb4e8", "#c7a0d8", "#85c6c0", "#eee9df",
                         "#777b75", "#ff9298", "#b4dda1", "#f2c078",
                         "#a9c9f3", "#d9b8e8", "#a1d9d3", "#ffffff")),
}
EVENTS = (
    ("info", "api", 200, "Server ready on :8080"),
    ("info", "worker", 202, "Batch completed"),
    ("info", "api", 200, "GET /health 200"),
    ("warn", "api", 429, "GET /search 429"),
    ("error", "worker", 503, "Queue connection lost"),
    ("error", "api", 503, "POST /checkout 503"),
    ("info", "api", 200, "GET /catalog 200"),
    ("error", "api", 500, "POST /orders 500"),
    ("info", "worker", 202, "Retry scheduled"),
    ("info", "api", 200, "GET /health 200"),
    ("error", "api", 502, "GET /payments 502"),
    ("info", "worker", 202, "Batch completed"),
    ("warn", "api", 429, "GET /catalog 429"),
    ("error", "api", 503, "POST /checkout 503"),
    ("info", "api", 200, "GET /health 200"),
    ("error", "worker", 503, "Queue connection lost"),
    ("info", "api", 200, "GET /catalog 200"),
    ("error", "api", 500, "POST /orders 500"),
    ("info", "worker", 202, "Batch completed"),
    ("info", "api", 200, "GET /health 200"),
    ("error", "api", 502, "GET /payments 502"),
    ("info", "api", 200, "GET /catalog 200"),
    ("warn", "api", 429, "GET /search 429"),
    ("error", "worker", 503, "Queue connection lost"),
    ("info", "api", 200, "GET /health 200"),
    ("error", "api", 503, "POST /checkout 503"),
)


def records():
    return [{"timestamp": f"12:00:{index + 1:02d}", "level": level,
             "service": service, "status": status, "message": f"req={100 + index} {message}"}
            for index, (level, service, status, message) in enumerate(EVENTS)]


def schedule(mobile):
    events = []

    def type_command(at, command, delay=0.025, filtered=False):
        for index, character in enumerate(command):
            events.append((at + index * delay, "input", character))
        events.append((at + len(command) * delay + 0.1,
                       "filtered" if filtered else "input", "\r"))

    continuation = " \\\n  "
    first = (continuation.join(("lumtail --follow",
                                "--template '{level}: {message}' app.log"))
             if mobile else "lumtail --follow app.log")
    second = (continuation.join(("lumtail --follow", f"--filter '{FILTER}'",
                                 "--template '{level}: {message}' app.log"))
              if mobile else f"lumtail --follow --filter '{FILTER}' app.log")
    type_command(0.25, first, 0.02 if mobile else 0.03)
    events.append((6.8, "input", "\x03"))
    type_command(7.1, "clear")
    type_command(7.7, "# Focus on API failures", 0.02)
    type_command(8.65, second, 0.02 if mobile else 0.025, filtered=True)
    events.append((18.8, "input", "\x03"))
    events.extend((1.6 + index * 0.65, "record", record)
                  for index, record in enumerate(records()))
    return sorted(events, key=lambda event: event[0])


def close_session(pid, master):
    # Closing the PTY hangs up both shell and foreground job.
    os.close(master)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if os.waitpid(pid, os.WNOHANG)[0]:
            return
        time.sleep(0.02)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)


SEARCH_FILTER = "service=payments AND status>=500 AND duration_ms>=1000"
SEARCH_BYTES = 2 << 30
# Documentation addresses (RFC 5737) keep the recordings free of real hosts.
VISITORS = ("203.0.113.42", "198.51.100.17", "192.0.2.66", "203.0.113.108", "198.51.100.230",
            "192.0.2.14", "203.0.113.9")
BROWSERS = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/19.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Mobile Safari/537.36",
)
SITE = "https://shop.example.com"
PODS = {
    "catalog": ("catalog-5b7c4d8f9-a1s2d", "catalog-5b7c4d8f9-f3g4h", "catalog-5b7c4d8f9-j5k6l"),
    "search": ("search-7c6b5a4d3-u8y7t", "search-7c6b5a4d3-r6e5w"),
    "cart": ("cart-84f6d5c7b-z9x8c", "cart-84f6d5c7b-v7b6n"),
    "auth": ("auth-69b8c7d5f-p0o9i",),
    "checkout": ("checkout-7d9f8c6b5-x2k4p", "checkout-7d9f8c6b5-m8q1z"),
    "payments": ("payments-6c8d9f7b4-k2x9q", "payments-6c8d9f7b4-w5n3r"),
}
ROUTES = {
    "catalog": (("GET", "/v1/items/SKU-{n5}", "item served"),
                ("GET", "/v1/items?category={category}&page={page}", "items listed")),
    "search": (("GET", "/v1/search?q={query}", "search completed"),),
    "cart": (("GET", "/v1/carts/c_{h8}", "cart loaded"),
             ("POST", "/v1/carts/c_{h8}/items", "item added to cart")),
    "auth": (("POST", "/v1/sessions", "session issued"),
             ("POST", "/v1/tokens/refresh", "token refreshed")),
    "checkout": (("POST", "/v1/orders", "order created"),
                 ("POST", "/v1/orders/ord_{h8}/confirm", "order confirmed")),
    "payments": (("POST", "/v1/charges", "charge authorized"),
                 ("POST", "/v1/charges/ch_{h10}/capture", "charge captured")),
}
FAILURES = {
    "catalog": ((404, "item not found", "sku not found"),
                (503, "inventory replica lagging, serving stale stock", "replica lag 14s")),
    "search": ((504, "search backend timed out", "opensearch query timeout"),),
    "cart": ((409, "cart version conflict, client must retry", "stale cart version"),),
    "auth": ((401, "invalid credentials", "password mismatch"),
             (429, "too many login attempts", "rate limited")),
    "checkout": ((500, "order confirmation failed: payments returned 502", "upstream status 502"),
                 (409, "order already confirmed", "conflict")),
    "payments": ((502, "upstream timeout after 3000ms calling card-gateway",
                  "context deadline exceeded"),
                 (503, "card-gateway circuit open, rejecting charge", "circuit breaker open"),
                 (500, "charge failed: unexpected response from acquirer",
                  "acquirer returned HTTP 500"),
                 (402, "charge declined by issuer", "card_declined")),
}
TRAFFIC = tuple(service for service, weight in (("catalog", 38), ("search", 18), ("cart", 16),
                                                ("auth", 10), ("checkout", 10), ("payments", 8))
                for _ in range(weight))
CATEGORIES = ("shoes", "jackets", "outdoor", "kids", "sale", "accessories")
QUERIES = ("running+shoes", "rain+jacket", "gift+card", "backpack", "wool+socks", "trail")


def service_record(rng, clock, service=None, failure=None):
    """Return one JSON request record as a microservice in the shop would log it."""
    service = service or rng.choice(TRAFFIC)
    method, route, message = rng.choice(ROUTES[service])
    path = route.format(n5=rng.randrange(10000, 99999), h8=f"{rng.getrandbits(32):08x}",
                        h10=f"{rng.getrandbits(40):010x}", page=rng.randrange(1, 9),
                        category=rng.choice(CATEGORIES), query=rng.choice(QUERIES))
    rate = 0.035 if service == "payments" else 0.012
    if failure is None and rng.random() < rate:
        failure = rng.choice(FAILURES[service])
    status, error = (201 if method == "POST" else 200), None
    duration = int(rng.lognormvariate(3.4, 0.7))
    if failure:
        status, message, error = failure
        if status in (502, 504):
            duration = 3000 + rng.randrange(12)
        elif status >= 500:
            duration += rng.randrange(200, 1800)
    level = "error" if status >= 500 else "warn" if status >= 400 else "info"
    record = (f'{{"ts":"{clock}","level":"{level}","service":"{service}",'
              f'"pod":"{rng.choice(PODS[service])}","trace_id":"{rng.getrandbits(128):032x}",'
              f'"user_id":"u_{rng.randrange(1000, 99999)}","method":"{method}","path":"{path}",'
              f'"status":{status},"duration_ms":{duration},"message":"{message}"')
    record += f',"error":"{error}"}}\n' if error else "}\n"
    return record, service == "payments" and status >= 500 and duration >= 1000


def write_requests(path):
    """Write SEARCH_BYTES of distinct service records; return how many SEARCH_FILTER keeps."""
    rng = random.Random(11)
    microseconds = 0
    written = matches = 0
    with path.open("w", encoding="ascii") as output:
        while written < SEARCH_BYTES:
            chunk = []
            for _ in range(20000):
                microseconds += int(rng.expovariate(1 / 700))
                seconds, fraction = divmod(microseconds // 1000, 1000)
                minutes, seconds = divmod(seconds, 60)
                hours, minutes = divmod(minutes, 60)
                clock = f"2026-11-11T{6 + hours:02d}:{minutes:02d}:{seconds:02d}.{fraction:03d}Z"
                record, matched = service_record(rng, clock)
                chunk.append(record)
                matches += matched
            text = "".join(chunk)
            output.write(text)
            written += len(text)
    return matches


HISTORY_BYTES = 1536 << 20
HISTORY_FILTER = "status>=500 AND method=POST AND path~/api/v1/checkout/*"
HISTORY_PAGES = (
    ("GET", "/", "-", 200), ("GET", "/c/shoes", SITE + "/", 200),
    ("GET", "/c/jackets", SITE + "/", 200), ("GET", "/p/trail-runner-2", SITE + "/c/shoes", 200),
    ("GET", "/p/storm-shell", SITE + "/c/jackets", 200),
    ("GET", "/api/v1/catalog/items?category=shoes&page={page}", SITE + "/c/shoes", 200),
    ("POST", "/api/v1/cart/items", SITE + "/p/trail-runner-2", 201),
    ("GET", "/static/js/app.3f9c1a.js", SITE + "/", 304),
    ("GET", "/static/css/site.8d2e41.css", SITE + "/", 304),
    ("POST", "/api/v1/checkout/{order}/pay", SITE + "/checkout", 200),
)
# The outage the demo finds: card-gateway timeouts on 17 October, 14:02:00 to 14:03:30 UTC.
HISTORY_OUTAGE = (16 * 86400 + 14 * 3600 + 2 * 60, 16 * 86400 + 14 * 3600 + 3 * 60 + 30)
MONTH_SECONDS = 31 * 86400


def write_history(path):
    """Write HISTORY_BYTES of October nginx traffic; return how many HISTORY_FILTER keeps."""
    rng = random.Random(17)
    visitors = [f"{prefix}.{host}" for prefix in ("192.0.2", "198.51.100", "203.0.113")
                for host in range(1, 255)]
    lines_needed = HISTORY_BYTES // 245
    step = MONTH_SECONDS * 1_000_000 // lines_needed
    microseconds = written = matches = 0
    with path.open("w", encoding="ascii") as output:
        while written < HISTORY_BYTES:
            chunk = []
            for _ in range(20000):
                microseconds += int(rng.expovariate(1 / step))
                second = min(microseconds // 1_000_000, MONTH_SECONDS - 1)
                day, rest = divmod(second, 86400)
                hours, rest = divmod(rest, 3600)
                minutes, seconds = divmod(rest, 60)
                method, page, referer, status = rng.choice(HISTORY_PAGES)
                page = page.format(page=rng.randrange(1, 9), order=f"{rng.getrandbits(32):08x}")
                size = 0 if status == 304 else rng.randrange(400, 26000)
                if page.endswith("/pay") and HISTORY_OUTAGE[0] <= second < HISTORY_OUTAGE[1]:
                    status, size = 502, 166
                elif rng.random() < 0.004:
                    status, size = rng.choice((404, 404, 499, 500, 503)), rng.randrange(150, 600)
                    if page.endswith("/pay"):
                        status = 404
                if status >= 500 and method == "POST" and page.startswith("/api/v1/checkout/"):
                    matches += 1
                chunk.append(f'{rng.choice(visitors)} - - [{day + 1:02d}/Oct/2026:{hours:02d}:'
                             f'{minutes:02d}:{seconds:02d} +0000] "{method} {page} HTTP/2.0" '
                             f'{status} {size} "{referer}" "{rng.choice(BROWSERS)}"\n')
            text = "".join(chunk)
            output.write(text)
            written += len(text)
    return matches


def write_incident(folder):
    """Write the nginx, sshd and service logs of one checkout incident at 09:14 UTC."""
    rng = random.Random(5)
    pages = (("/", "-"), ("/c/shoes", SITE + "/"), ("/p/trail-runner-2", SITE + "/c/shoes"),
             ("/api/v1/catalog/items?category=shoes&page=2", SITE + "/c/shoes"),
             ("/api/v1/cart/items", SITE + "/p/trail-runner-2"),
             ("/static/js/app.3f9c1a.js", SITE + "/"))
    access = []
    for second in range(0, 30, 2):
        page, referer = rng.choice(pages)
        method = "POST" if page.endswith("/items") and rng.random() < 0.5 else "GET"
        status = 304 if page.startswith("/static") else 200
        access.append((second, rng.choice(VISITORS), method, page, status,
                       0 if status == 304 else rng.randrange(900, 24000), referer,
                       rng.choice(BROWSERS)))
    for second in (7, 13, 19, 26):
        order = f"{rng.getrandbits(32):08x}"
        access.append((second, rng.choice(VISITORS), "POST", f"/api/v1/checkout/{order}/pay", 502,
                       166, SITE + "/checkout", rng.choice(BROWSERS)))
    for second, page in ((10, "/wp-login.php"), (11, "/.env")):
        access.append((second, "192.0.2.201", "GET", page, 404, 153, "-",
                       "Mozilla/5.0 zgrab/0.x"))
    access.sort(key=lambda entry: entry[0])
    (folder / "access.log").write_text("".join(
        f'{ip} - - [11/Nov/2026:09:14:{second:02d} +0000] "{method} {page} HTTP/2.0" {status} '
        f'{size} "{referer}" "{agent}"\n'
        for second, ip, method, page, status, size, referer, agent in access), encoding="ascii")

    auth = ["Nov 11 09:14:00 bastion-01 CRON[48190]: pam_unix(cron:session): session opened "
            "for user root(uid=0) by root(uid=0)"]
    pid = 48201
    for second, user in ((2, "admin"), (5, "oracle"), (14, "postgres"), (23, "git")):
        port = rng.randrange(40000, 61000)
        auth += [f"Nov 11 09:14:{second:02d} bastion-01 sshd[{pid}]: Invalid user {user} "
                 f"from 203.0.113.77 port {port}",
                 f"Nov 11 09:14:{second + 1:02d} bastion-01 sshd[{pid}]: Failed password for "
                 f"invalid user {user} from 203.0.113.77 port {port} ssh2"]
        pid += rng.randrange(3, 9)
    auth += ["Nov 11 09:14:21 bastion-01 sshd[48262]: Accepted publickey for deploy from "
             "198.51.100.8 port 60412 ssh2: ED25519 SHA256:q1Xb4p0cE2m9Lk7TfZ3uYc8RwN5aHd6J",
             "Nov 11 09:14:21 bastion-01 sshd[48262]: pam_unix(sshd:session): session opened "
             "for user deploy(uid=1001) by deploy(uid=0)"]
    (folder / "auth.log").write_text("\n".join(sorted(auth, key=lambda line: line[7:15])) + "\n",
                                     encoding="ascii")

    service = []
    timeout = FAILURES["payments"][0]
    for second in range(0, 30):
        millis = rng.randrange(800)
        clock = f"2026-11-11T09:14:{second:02d}.{millis:03d}Z"
        if second in (7, 13, 19, 26):
            # Checkout logs its own failure once the payments call returns.
            service.append(service_record(rng, clock, "payments", timeout)[0])
            service.append(service_record(rng, f"{clock[:-4]}{millis + 104:03d}Z", "checkout",
                                          FAILURES["checkout"][0])[0])
        elif second % 3 == 0:
            service.append(service_record(rng, clock, rng.choice(("checkout", "payments")),
                                          False)[0])
    (folder / "checkout.log").write_text("".join(service), encoding="ascii")


def joined(mobile, *parts):
    return " \\\n  ".join(parts) if mobile else " ".join(parts)


LOGS = ("access.log", "auth.log", "checkout.log")


def scene_read(mobile):
    return {
        "title": "Lumtail: nginx, sshd and JSON in one stream",
        "steps": [("run", "head -n 1 " + " ".join(LOGS), 3.5),
                  ("run", "clear", 0.2),
                  ("run", "# Three formats, one stream: warnings and worse", 0.4),
                  ("run", joined(mobile, "lumtail --min-level warn",
                                 *(("--template '{level}: {message}'",) if mobile else ()),
                                 *LOGS), 4.5)],
        "expect": ("Failed password for invalid user", "POST /api/v1/checkout/",
                   "upstream timeout after 3000ms calling card-gateway", "/wp-login.php"),
    }


def scene_record(mobile):
    query = "service=payments AND status>=500"
    return {
        "title": "Lumtail: filter, then read the full record",
        "steps": [("run", joined(mobile, "lumtail", f"--filter '{query}'", "checkout.log"), 2.6),
                  ("run", "clear", 0.2),
                  ("run", "# Every field of the first failure, plus file, line and raw", 0.4),
                  ("run", joined(mobile, "lumtail", f"--filter '{query}'",
                                 "--limit 1 --output json checkout.log"), 6.5)],
        "expect": ('"format":"json"', '"trace_id":"', '"raw":"', '"line":4',
                   "context deadline exceeded"),
    }


def scene_history(mobile):
    return {
        "title": "Lumtail: filter a month of nginx history",
        "steps": [("run", "du -h access-2026-10.log", 0.8),
                  ("run", "# When did checkout payments fail in October?", 0.4),
                  ("run", joined(mobile, "lumtail --stats", f"--filter '{HISTORY_FILTER}'",
                                 *(("--template '{timestamp} {status} {remote_addr}'",)
                                   if mobile else ()),
                                 "access-2026-10.log"), 6.0)],
        "expect": ("1.5G", "17/Oct/2026:14:0", "502", "lumtail: stats: read 1.5 GiB"),
    }


def scene_search(mobile):
    return {
        "title": "Lumtail: search 2 GiB of service logs and report throughput",
        "steps": [("run", "du -h requests.log", 0.8),
                  ("run", "head -n 2 requests.log", 2.5),
                  ("run", "# Slow payment failures; --stats reports on stderr", 0.4),
                  ("run", joined(mobile, "lumtail --stats", f"--filter '{SEARCH_FILTER}'",
                                 "requests.log > slow-payments.log"), 5.0),
                  ("run", "wc -l slow-payments.log", 0.8),
                  ("run", "tail -n 2 slow-payments.log", 4.0)],
        "expect": ("2.0G", '"service":"', "lumtail: stats: read 2.0 GiB", "workers",
                   "payments"),
    }


SCENES = {
    "read-logs": (scene_read, (112, 26, 18), (46, 36, 20)),
    "inspect-record": (scene_record, (84, 20, 22), (46, 40, 20)),
    "history-filter": (scene_history, (140, 27, 16), (46, 40, 20)),
    "search-speed": (scene_search, (140, 20, 16), (46, 34, 20)),
}


def start_shell(folder, binary, columns, rows):
    (folder / "bin").mkdir()
    (folder / "bin/lumtail").symlink_to(binary)
    environment = os.environ.copy()
    environment.update({"PATH": str(folder / "bin") + os.pathsep + os.defpath,
                        "PS1": "$ ", "PS2": "> ", "ENV": "/dev/null",
                        "TERM": "xterm-256color", "LC_ALL": "C"})
    environment.pop("NO_COLOR", None)
    pid, master = pty.fork()
    if pid == 0:
        os.chdir(folder)
        os.execve("/bin/sh", ["/bin/sh", "-i"], environment)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
    return pid, master


class Terminal:
    """Feed a shell scripted keystrokes and keep its output as an asciicast."""

    ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

    def __init__(self, master):
        self.master = master
        self.started = time.monotonic()
        self.decoder = codecs.getincrementaldecoder("utf-8")()
        self.events = []
        self.captured = 0
        self.plain = ""

    def elapsed(self):
        return time.monotonic() - self.started

    def pump(self, seconds):
        deadline = time.monotonic() + seconds
        while (remaining := deadline - time.monotonic()) > 0:
            if not select.select([self.master], [], [], min(0.05, remaining))[0]:
                continue
            try:
                chunk = os.read(self.master, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b""
            if not chunk:
                raise RuntimeError("demo shell exited before the recording finished")
            self.captured += len(chunk)
            if self.captured > 1024 * 1024:
                raise RuntimeError("demo transcript exceeded 1 MiB")
            if text := self.decoder.decode(chunk):
                self.events.append([round(self.elapsed(), 6), "o", text])
                self.plain += self.ansi.sub("", text)

    def send(self, text):
        encoded = text.encode()
        if os.write(self.master, encoded) != len(encoded):
            raise RuntimeError("incomplete terminal input")

    def run(self, command, pause, timeout=60):
        for character in command:
            self.send(character)
            self.pump(0.035 if not command.startswith("#") else 0.025)
        mark = len(self.plain)
        self.send("\r")
        deadline = time.monotonic() + timeout
        # The prompt returns once the command, and any wait it causes, is over.
        while not self.plain[mark:].replace("\r", "").endswith("\n$ "):
            if time.monotonic() > deadline:
                raise RuntimeError(f"demo command did not finish: {command}")
            self.pump(0.05)
        self.pump(pause)


def record_scene(binary, folder, scene, columns, rows, data):
    write_incident(folder)
    if data:
        os.link(data[0], folder / data[0].name)
    pid, master = start_shell(folder, binary, columns, rows)
    terminal = Terminal(master)
    try:
        terminal.pump(0.4)
        for _, command, pause in scene["steps"]:
            terminal.run(command, pause)
        terminal.decoder.decode(b"", final=True)
    finally:
        close_session(pid, master)
    missing = [text for text in scene["expect"] if text not in terminal.plain]
    if missing:
        raise RuntimeError(f"recording is missing expected output: {missing}")
    if data:
        stats = re.search(r"lumtail: stats: read [^,]+, wrote (\d+) records", terminal.plain)
        if not stats or int(stats.group(1)) != data[1]:
            raise RuntimeError(f"filter wrote {stats and stats.group(1)} records, "
                               f"expected {data[1]}")
    duration = round(terminal.elapsed(), 3)
    header = {"version": 2, "width": columns, "height": rows, "title": scene["title"],
              "duration": duration, "env": {"SHELL": "/bin/sh", "TERM": "xterm-256color"},
              "theme": THEME}
    return header, terminal.events


def record_session(binary, folder, columns, rows, mobile):
    logfile = folder / "app.log"
    logfile.touch()
    (folder / "bin").mkdir()
    (folder / "bin/lumtail").symlink_to(binary)
    environment = os.environ.copy()
    environment.update({"PATH": str(folder / "bin") + os.pathsep + os.defpath,
                        "PS1": "$ ", "PS2": "> ", "ENV": "/dev/null",
                        "TERM": "xterm-256color", "LC_ALL": "C"})
    environment.pop("NO_COLOR", None)
    started = time.monotonic()
    pid, master = pty.fork()
    if pid == 0:
        os.chdir(folder)
        os.execve("/bin/sh", ["/bin/sh", "-i"], environment)
    transcript = []
    filtered_output = []
    filtering = False
    decoder = codecs.getincrementaldecoder("utf-8")()
    pending = schedule(mobile)
    index = 0
    captured = 0
    try:
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
        while time.monotonic() - started < DURATION:
            elapsed = time.monotonic() - started
            while index < len(pending) and pending[index][0] <= elapsed:
                _, kind, data = pending[index]
                if kind == "record":
                    with logfile.open("a", encoding="utf-8") as output:
                        output.write(json.dumps(data, separators=(",", ":")) + "\n")
                else:
                    if kind == "filtered":
                        filtering = True
                        transcript.append([round(elapsed, 6), "m", "API failures"])
                    encoded = data.encode()
                    if os.write(master, encoded) != len(encoded):
                        raise RuntimeError("incomplete terminal input")
                index += 1
            next_event = pending[index][0] if index < len(pending) else DURATION
            timeout = min(0.05, max(0, next_event - elapsed))
            if select.select([master], [], [], timeout)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    chunk = b""
                if not chunk:
                    raise RuntimeError("demo shell exited before the recording finished")
                captured += len(chunk)
                if captured > 1024 * 1024:
                    raise RuntimeError("demo transcript exceeded 1 MiB")
                text = decoder.decode(chunk)
                if text:
                    transcript.append([round(time.monotonic() - started, 6), "o", text])
                    if filtering:
                        filtered_output.append(text)
        decoder.decode(b"", final=True)
    finally:
        close_session(pid, master)

    ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
    unfiltered = ansi.sub("", "".join(event[2] for event in transcript
                                      if event[1] == "o" and event[0] < 6.8))
    if any(record["message"] not in unfiltered for record in records()[:8]):
        raise RuntimeError("unfiltered recording is missing expected live records")
    plain = ansi.sub("", "".join(filtered_output))
    selected = [record for record in records()
                if record["service"] == "api" and record["status"] >= 500]
    if any(record["message"] not in plain for record in selected):
        raise RuntimeError("filtered recording is missing expected API failures")
    if any(record["message"] in plain for record in records() if record not in selected):
        raise RuntimeError("filtered recording contains a nonmatching record")
    header = {"version": 2, "width": columns, "height": rows,
              "title": "Lumtail: follow and filter a live log", "duration": DURATION,
              "env": {"SHELL": "/bin/sh", "TERM": "xterm-256color"}, "theme": THEME}
    return header, transcript


def render(agg, folder, name, header, events, font_size, output_dir):
    cast = folder / f"{name}.cast"
    cast.write_text("\n".join(json.dumps(event, ensure_ascii=False)
                               for event in [header, *events]) + "\n", encoding="utf-8")
    gif = folder / f"{name}.gif"
    subprocess.run([agg, "--font-family", "Menlo,DejaVu Sans Mono,Liberation Mono",
                    "--font-size", str(font_size), "--line-height", "1.35",
                    "--fps-cap", "15", "--last-frame-duration", "2.5",
                    str(cast), str(gif)], check=True)
    if gif.stat().st_size > 2 * 1024 * 1024:
        raise RuntimeError("demo GIF exceeded the 2 MiB asset budget")
    shutil.copyfile(cast, output_dir / cast.name)
    shutil.copyfile(gif, output_dir / gif.name)
    print(f"Saved {gif.name}: {gif.stat().st_size / 1024:.0f} KiB", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "build-gate/lumtail")
    parser.add_argument("--agg", default="agg", help="path to asciinema agg (validated with 1.9.0)")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "assets/demo")
    parser.add_argument("--data-dir", type=Path,
                        help="where to write the large demo logs (default: system temp)")
    parser.add_argument("--only", action="append", choices=("follow-filter", *SCENES),
                        help="record only this demo; repeatable")
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("build Lumtail first, or supply --binary /path/to/lumtail")
    agg = shutil.which(args.agg)
    if not agg:
        parser.error("install asciinema agg separately, or supply --agg /path/to/agg")
    selected = args.only or ("follow-filter", *SCENES)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    shared = Path(tempfile.mkdtemp(prefix="lumtail-demo-data-", dir=args.data_dir))
    try:
        data = {}
        for scene, name, writer in (("search-speed", "requests.log", write_requests),
                                    ("history-filter", "access-2026-10.log", write_history)):
            if scene in selected:
                print(f"Writing {name}", flush=True)
                data[scene] = (shared / name, writer(shared / name))
        record_all(binary, agg, selected, data, shared, args.output_dir)
    finally:
        shutil.rmtree(shared)


def record_all(binary, agg, selected, data, shared, output_dir):
    for base in selected:
        if base == "follow-filter":
            variants = ((base, 84, 16, 22, False), (f"{base}-mobile", 46, 22, 20, True))
        else:
            _, desktop, mobile = SCENES[base]
            variants = ((base, *desktop, False), (f"{base}-mobile", *mobile, True))
        for name, columns, rows, font_size, is_mobile in variants:
            print(f"Recording {name}: real PTY, {columns} columns", flush=True)
            with tempfile.TemporaryDirectory(prefix="lumtail-demo-",
                                             dir=shared) as temporary:
                folder = Path(temporary)
                if base == "follow-filter":
                    header, events = record_session(binary, folder, columns, rows, is_mobile)
                else:
                    scene = SCENES[base][0](is_mobile)
                    header, events = record_scene(binary, folder, scene, columns, rows,
                                                  data.get(base))
                render(agg, folder, name, header, events, font_size, output_dir)


if __name__ == "__main__":
    main()
