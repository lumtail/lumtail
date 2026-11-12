#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Standalone API 1 consumer for --list-fields; Python standard library only."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
MAX_FIELDS = 256
MAX_NAME_BYTES = 128


def unique_keys(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise AssertionError(f"duplicate JSON key in {keys!r}")
    return dict(pairs)


def parse(line):
    return json.loads(line, object_pairs_hook=unique_keys)


def plain(key):
    # Printable ASCII without quote or backslash encodes as itself, so byte order is visible.
    return all(" " <= char <= "~" and char not in "\\\"" for char in key)


def check_lines(name, text):
    if not text:
        return []
    if not text.endswith("\n"):
        raise AssertionError(f"{name}: output does not end with a newline")
    summary = [parse(line) for line in text[:-1].split("\n")]
    formats = set()
    for line in summary:
        if "more_formats" in line:
            if line != {"more_formats": True} or line is not summary[-1]:
                raise AssertionError(f"{name}: bad more_formats line {line!r}")
            continue
        extra = set(line) - {"format", "records", "fields", "more_fields", "truncated"}
        fields = line.get("fields")
        if (extra or not isinstance(line.get("format"), str) or line["format"] in formats or
                type(line.get("records")) is not int or line["records"] < 1 or
                not isinstance(fields, dict) or len(fields) > MAX_FIELDS or
                any(type(count) is not int or not 1 <= count for count in fields.values()) or
                (all(plain(key) for key in fields) and list(fields) != sorted(fields)) or
                any(line.get(flag, True) is not True for flag in ("more_fields", "truncated"))):
            raise AssertionError(f"{name}: bad summary line {line!r}")
        formats.add(line["format"])
    return summary


def json_equivalent(summary, json_text):
    """Rebuild the summary from --output json records of the same query."""
    formats = {}
    clipped = set()
    for record in map(parse, json_text.splitlines()):
        entry = formats.setdefault(record["format"], {})
        entry[""] = entry.get("", 0) + 1
        for key in record["fields"]:
            if len(json.dumps(key, ensure_ascii=False).encode()) - 2 > MAX_NAME_BYTES:
                clipped.add(record["format"])
                continue
            entry[key] = entry.get(key, 0) + 1
    rebuilt = []
    for name, entry in formats.items():
        records = entry.pop("")
        line = {"format": name, "records": records}
        line["fields"] = entry
        rebuilt.append(line)
    comparable = []
    for line in summary:
        line = dict(line)
        if line.pop("truncated", False):
            # Clipped names cannot be rebuilt from complete keys; compare the rest.
            line["fields"] = {key: count for key, count in line["fields"].items()
                              if len(json.dumps(key, ensure_ascii=False).encode()) - 2 <
                              MAX_NAME_BYTES}
        comparable.append(line)
    for line in rebuilt:
        if line["format"] in clipped:
            line["fields"] = {key: count for key, count in line["fields"].items()
                              if len(json.dumps(key, ensure_ascii=False).encode()) - 2 <
                              MAX_NAME_BYTES}
    return comparable == rebuilt


def main():
    binary = str(Path(sys.argv[1]).resolve())
    scale = min(10, max(1, float(os.environ.get("LUMTAIL_TEST_TIMEOUT_SCALE", "1"))))
    manifest = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))
    checked = 0
    for selection in ([], ["--api-version=1"]):
        for case in manifest["cases"]:
            with tempfile.TemporaryDirectory(prefix="lumtail-list-fields-") as directory:
                for name, content in case.get("files", {}).items():
                    (Path(directory) / name).write_text(content, encoding="utf-8")

                def run(args):
                    return subprocess.run([binary, *selection, *args], cwd=directory,
                                          input=case.get("stdin", "").encode(),
                                          capture_output=True, timeout=10 * scale)

                result = run(case["args"])
                stdout = result.stdout.decode()
                if result.returncode != case["exit"] or stdout != "".join(case["stdout"]):
                    raise AssertionError(f"{case['name']}: got exit {result.returncode}, "
                                         f"stdout {stdout!r}, stderr {result.stderr!r}")
                if case["exit"] == 2 and (stdout or not result.stderr.startswith(b"lumtail: ")):
                    raise AssertionError(f"{case['name']}: usage error wrote output")
                summary = check_lines(case["name"], stdout)
                if case["exit"] == 0 and "json_limit" in case:
                    args = [arg for arg in case["args"] if arg != "--list-fields"]
                    records = run(["--output=json", f"--limit={case['json_limit']}", *args])
                    if records.returncode != 0 or not json_equivalent(
                            summary, records.stdout.decode()):
                        raise AssertionError(f"{case['name']}: differs from --output json")
            checked += 1
    print(f"list-fields: {checked} cases passed")


if __name__ == "__main__":
    main()
