#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Standalone API 1 consumer for the --stats line; Python standard library only."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
SCHEMA = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
KEYWORDS = {"$schema", "$id", "title", "type", "required", "dependentRequired", "properties",
            "additionalProperties", "enum", "minimum"}
TYPES = {"object": dict, "integer": int, "boolean": bool, "string": str}
SIZE = r"(?:\d+ B|\d+\.\d (?:KiB|MiB|GiB|TiB))"
SECONDS = r"\d+\.\d{3}"
TEXT = re.compile(
    rf"lumtail: stats: read (?P<bytes>{SIZE}), wrote (?P<records>\d+) records?, "
    rf"{SECONDS} s, (?:n/a|{SIZE}/s), (?P<workers>\d+) workers?, "
    rf"CPU (?:n/a|{SECONDS} s user \+ {SECONDS} s system), peak RSS (?:n/a|{SIZE})"
    rf"(?P<incomplete>, incomplete)?, stop: (?P<stop>"
    + "|".join(SCHEMA["properties"]["stop_reason"]["enum"]) + r")\n")


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


def main():
    binary = str(Path(sys.argv[1]).resolve())
    scale = min(10, max(1, float(os.environ.get("LUMTAIL_TEST_TIMEOUT_SCALE", "1"))))
    manifest = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))
    check_vocabulary(SCHEMA)
    sample = {"bytes_read": 1, "complete": True, "records": 1, "stats_version": 1,
              "stop_reason": "eof", "wall_us": 1, "workers": 1}
    if not valid(sample):
        raise AssertionError("schema rejected a minimal line")
    for key, value in (("bytes_read", -1), ("complete", 1), ("records", True),
                       ("stats_version", 2), ("stop_reason", "done"), ("workers", 1.5),
                       ("unexpected", 0)):
        if valid(dict(sample, **{key: value})):
            raise AssertionError(f"schema accepted invalid {key}: {value!r}")
    if valid(dict(sample, cpu_user_us=1)) or valid(dict(sample, peak_rss_bytes=1)):
        raise AssertionError("schema accepted partial resource usage")

    def run(selection, args, stdin):
        return subprocess.run([binary, *selection, *args], input=stdin.encode(),
                              capture_output=True, timeout=10 * scale)

    for selection in ([], ["--api-version=1"]):
        for case in manifest["cases"]:
            result = run(selection, case["args"], case["stdin"])
            if result.returncode != case["exit"]:
                raise AssertionError(f"{case['name']}: exit {result.returncode}: {result!r}")
            plain = run(selection, [arg for arg in case["args"] if arg != "--stats"],
                        case["stdin"])
            if plain.stdout != result.stdout or plain.returncode != result.returncode:
                raise AssertionError(f"{case['name']}: --stats changed stdout or exit status")
            if not result.stderr.startswith(plain.stderr):
                raise AssertionError(f"{case['name']}: diagnostics changed or moved")
            line = result.stderr[len(plain.stderr):].decode()
            expect = case["expect"]
            if case["format"] == "json":
                if not line.endswith("\n") or "\n" in line[:-1]:
                    raise AssertionError(f"{case['name']}: not one JSON line: {line!r}")
                stats = json.loads(line)
                if not valid(stats) or list(stats) != sorted(stats):
                    raise AssertionError(f"{case['name']}: invalid stats line: {line!r}")
                if any(stats[key] != value for key, value in expect.items()):
                    raise AssertionError(f"{case['name']}: wrong values: {line!r}")
            else:
                match = TEXT.fullmatch(line)
                if match is None:
                    raise AssertionError(f"{case['name']}: malformed text line: {line!r}")
                if (plain_bytes(match["bytes"]) != expect["bytes_read"] or
                        int(match["records"]) != expect["records"] or
                        int(match["workers"]) != expect["workers"] or
                        (match["incomplete"] is None) != expect["complete"]):
                    raise AssertionError(f"{case['name']}: wrong values: {line!r}")
        for case in manifest["silent_cases"]:
            result = run(selection, case["args"], "")
            if (result.returncode != case["exit"] or b"lumtail: stats:" in result.stderr or
                    b'"stats_version"' in result.stderr):
                raise AssertionError(f"{case['name']}: unexpected stats output: {result!r}")
    count = len(manifest["cases"]) + len(manifest["silent_cases"])
    print(f"Stats line: {count} cases under both API selectors passed.")


if __name__ == "__main__":
    main()
