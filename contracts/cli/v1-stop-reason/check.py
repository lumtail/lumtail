#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Standalone API 1 consumer for the --stats-version 2 line; Python standard library only."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
SCHEMA = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
KEYWORDS = {"$schema", "$id", "title", "type", "required", "dependentRequired", "properties",
            "additionalProperties", "enum", "minimum"}
TYPES = {"object": dict, "integer": int, "boolean": bool, "string": str}
REASONS = SCHEMA["properties"]["stop_reason"]["enum"]
VERSION_ONE_KEYS = {"bytes_read", "complete", "cpu_system_us", "cpu_user_us", "peak_rss_bytes",
                    "records", "stats_version", "wall_us", "workers"}
SIZE = r"(?:\d+ B|\d+\.\d (?:KiB|MiB|GiB|TiB))"
SECONDS = r"\d+\.\d{3}"
PREFIX = (rf"lumtail: stats: read (?P<bytes>{SIZE}), wrote (?P<records>\d+) records?, "
          rf"{SECONDS} s, (?:n/a|{SIZE}/s), (?P<workers>\d+) workers?, "
          rf"CPU (?:n/a|{SECONDS} s user \+ {SECONDS} s system), peak RSS (?:n/a|{SIZE})"
          rf"(?P<incomplete>, incomplete)?")
TEXT = re.compile(PREFIX + r", stop: (?P<stop>" + "|".join(REASONS) + r")\n")
TEXT_ONE = re.compile(PREFIX + r"\n")


def check_vocabulary(schema):
    if schema.keys() - KEYWORDS or schema.get("type", "object") not in TYPES:
        raise AssertionError("unsupported schema vocabulary")
    for child in schema.get("properties", {}).values():
        check_vocabulary(child)


def valid(value, schema=SCHEMA):
    kind = schema.get("type")
    # bool is an int subclass in Python; JSON keeps them distinct.
    if kind and type(value) is not TYPES[kind]:
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    if "minimum" in schema and value < schema["minimum"]:
        return False
    if isinstance(value, dict):
        if set(schema.get("required", [])) - value.keys():
            return False
        for key, needed in schema.get("dependentRequired", {}).items():
            if key in value and set(needed) - value.keys():
                return False
        properties = schema.get("properties", {})
        for key, child in value.items():
            if key not in properties:
                if schema.get("additionalProperties", True) is False:
                    return False
            elif not valid(child, properties[key]):
                return False
    return True


def plain_bytes(text):
    return int(text[:-2]) if text.endswith(" B") else None


def without_stats(args):
    plain = []
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg == "--stats-version":
            skip = True
        elif arg != "--stats" and not arg.startswith("--stats-version="):
            plain.append(arg)
    return plain


def check_schema():
    check_vocabulary(SCHEMA)
    sample = {"bytes_read": 1, "complete": True, "records": 1, "stats_version": 2,
              "stop_reason": "eof", "wall_us": 1, "workers": 1}
    if not valid(sample):
        raise AssertionError("schema rejected a minimal line")
    for key, value in (("bytes_read", -1), ("complete", 1), ("records", True),
                       ("stats_version", 1), ("stop_reason", "done"), ("stop_reason", 0),
                       ("workers", 1.5), ("unexpected", 0)):
        if valid(dict(sample, **{key: value})):
            raise AssertionError(f"schema accepted invalid {key}: {value!r}")
    if valid({key: value for key, value in sample.items() if key != "stop_reason"}):
        raise AssertionError("schema accepted a line without stop_reason")


def parse_line(name, line, form):
    if form == "json":
        if not line.endswith("\n") or "\n" in line[:-1]:
            raise AssertionError(f"{name}: not one JSON line: {line!r}")
        stats = json.loads(line)
        if not valid(stats) or list(stats) != sorted(stats):
            raise AssertionError(f"{name}: invalid stats line: {line!r}")
        return stats
    match = TEXT.fullmatch(line)
    if match is None:
        raise AssertionError(f"{name}: malformed text line: {line!r}")
    stats = {"records": int(match["records"]), "complete": match["incomplete"] is None,
             "stop_reason": match["stop"]}
    if plain_bytes(match["bytes"]) is not None:
        stats["bytes_read"] = plain_bytes(match["bytes"])
    return stats


def check_values(name, stats, expect):
    if any(stats.get(key) != value for key, value in expect.items()):
        raise AssertionError(f"{name}: wrong values {stats!r}, expected {expect!r}")
    if stats["complete"] != (stats["stop_reason"] != "error"):
        raise AssertionError(f"{name}: complete disagrees with stop_reason: {stats!r}")


def main():
    binary = str(Path(sys.argv[1]).resolve())
    scale = min(10, max(1, float(os.environ.get("LUMTAIL_TEST_TIMEOUT_SCALE", "1"))))
    manifest = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))
    check_schema()

    def run(selection, args, stdin=""):
        return subprocess.run([binary, *selection, *args], input=stdin.encode(),
                              capture_output=True, timeout=10 * scale)

    def stats_line(name, result, plain):
        if plain.stdout != result.stdout or plain.returncode != result.returncode:
            raise AssertionError(f"{name}: statistics changed stdout or exit status")
        if not result.stderr.startswith(plain.stderr):
            raise AssertionError(f"{name}: diagnostics changed or moved")
        return result.stderr[len(plain.stderr):].decode()

    seen = set()
    with tempfile.TemporaryDirectory(prefix="lumtail-stop-reason-") as directory:
        for selection in ([], ["--api-version=1"]):
            for case in manifest["cases"]:
                result = run(selection, case["args"], case["stdin"])
                if result.returncode != case["exit"]:
                    raise AssertionError(f"{case['name']}: exit {result.returncode}: {result!r}")
                plain = run(selection, without_stats(case["args"]), case["stdin"])
                line = stats_line(case["name"], result, plain)
                stats = parse_line(case["name"], line, case["format"])
                check_values(case["name"], stats, case["expect"])
                seen.add(stats["stop_reason"])

            for case in manifest["follow_cases"]:
                path = Path(directory) / f"{case['name']}.log"
                path.write_text(case["content"], encoding="utf-8")
                result = run(selection, [*case["args"], str(path)])
                if result.returncode != 0:
                    raise AssertionError(f"{case['name']}: exit {result.returncode}: {result!r}")
                line = result.stderr.decode()
                form = "json" if line.startswith("{") else "text"
                stats = parse_line(case["name"], line, form)
                check_values(case["name"], stats, case["expect"])
                seen.add(stats["stop_reason"])

            # The reader closes stdout while lumtail still follows a live file.
            path = Path(directory) / "closure.log"
            path.write_text("first\n", encoding="utf-8")
            process = subprocess.Popen(
                [binary, *selection, "--stats-version=2", "--output=json", "--threads=1",
                 "--follow", "--duration-ms=60000", str(path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                first = process.stdout.readline()
                process.stdout.close()
                started = time.monotonic()
                _, error = process.communicate(timeout=20 * scale)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            if not first.startswith(b"{") or process.returncode != 0:
                raise AssertionError(f"output closure: exit {process.returncode}: {error!r}")
            if time.monotonic() - started > 15 * scale:
                raise AssertionError("output closure did not end the follow")
            stats = parse_line("output closure", error.decode(), "json")
            check_values("output closure", stats, {"complete": True, "records": 1,
                                                   "stop_reason": "output_closed"})
            seen.add(stats["stop_reason"])

            for case in manifest["version_one_cases"]:
                result = run(selection, case["args"], "a\n")
                line = stats_line(case["name"], result, run(selection, without_stats(case["args"]),
                                                            "a\n"))
                if case["format"] == "json":
                    stats = json.loads(line)
                    if (stats.keys() - VERSION_ONE_KEYS or stats.get("stats_version") != 1 or
                            list(stats) != sorted(stats)):
                        raise AssertionError(f"{case['name']}: not a version 1 line: {line!r}")
                elif TEXT_ONE.fullmatch(line) is None:
                    raise AssertionError(f"{case['name']}: not a version 1 line: {line!r}")

            for case in manifest["silent_cases"]:
                result = run(selection, case["args"])
                if (result.returncode != case["exit"] or b"lumtail: stats:" in result.stderr or
                        b'"stats_version"' in result.stderr):
                    raise AssertionError(f"{case['name']}: unexpected stats output: {result!r}")

    missing = {"eof", "limit", "duration", "output_closed", "error"} - seen
    if missing:
        raise AssertionError(f"stop reasons never observed: {sorted(missing)}")
    count = (len(manifest["cases"]) + len(manifest["follow_cases"]) + 1 +
             len(manifest["version_one_cases"]) + len(manifest["silent_cases"]))
    print(f"Stop reason: {count} cases under both API selectors passed.")


if __name__ == "__main__":
    main()
