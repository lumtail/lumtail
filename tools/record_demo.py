#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Record real follow/filter sessions in a PTY and render GIFs with asciinema agg."""

import argparse
import codecs
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "build-gate/lumtail")
    parser.add_argument("--agg", default="agg", help="path to asciinema agg (validated with 1.9.0)")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "assets/demo")
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("build Lumtail first, or supply --binary /path/to/lumtail")
    agg = shutil.which(args.agg)
    if not agg:
        parser.error("install asciinema agg separately, or supply --agg /path/to/agg")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, columns, rows, font_size in (("follow-filter", 84, 16, 22),
                                          ("follow-filter-mobile", 46, 22, 20)):
        print(f"Recording {name}: real PTY, {columns} columns, {DURATION}s", flush=True)
        with tempfile.TemporaryDirectory(prefix="lumtail-demo-") as temporary:
            folder = Path(temporary)
            header, events = record_session(binary, folder, columns, rows, name.endswith("mobile"))
            cast = folder / f"{name}.cast"
            cast.write_text("\n".join(json.dumps(event, ensure_ascii=False)
                                       for event in [header, *events]) + "\n", encoding="utf-8")
            gif = folder / f"{name}.gif"
            subprocess.run([agg, "--font-family", "Menlo,DejaVu Sans Mono,Liberation Mono",
                            "--font-size", str(font_size), "--line-height", "1.35",
                            "--fps-cap", "15", "--last-frame-duration", "1.5",
                            str(cast), str(gif)], check=True)
            if gif.stat().st_size > 2 * 1024 * 1024:
                raise RuntimeError("demo GIF exceeded the 2 MiB asset budget")
            shutil.copyfile(cast, args.output_dir / cast.name)
            shutil.copyfile(gif, args.output_dir / gif.name)
            print(f"Saved {gif.name}: {gif.stat().st_size / 1024:.0f} KiB", flush=True)


if __name__ == "__main__":
    main()
