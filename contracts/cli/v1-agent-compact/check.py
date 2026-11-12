#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Standalone API 1 consumer for --output agent-compact; Python standard library only."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
SCHEMA = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
SCHEMA_ID = "urn:lumtail:agent-compact:v1"
FIXED = ["timestamp", "level", "message", "line", "format"]
LEVELS = {"UNKNOWN", "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"}


def unique_keys(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise AssertionError(f"duplicate JSON key in {keys!r}")
    return dict(pairs)


def parse(line):
    return json.loads(line, object_pairs_hook=unique_keys)


def check_lines(name, text):
    """Check the line grammar and return (columns, [(file, record), ...])."""
    if not text:
        return None, []
    if not text.endswith("\n"):
        raise AssertionError(f"{name}: output does not end with a newline")
    header, *lines = (parse(line) for line in text[:-1].split("\n"))
    if set(header) != {"schema", "columns"} or header["schema"] != SCHEMA_ID:
        raise AssertionError(f"{name}: bad header {header!r}")
    columns = header["columns"]
    if columns[:5] != FIXED or len(columns) > 5 + 16 or len(set(columns[5:])) != len(columns) - 5:
        raise AssertionError(f"{name}: bad columns {columns!r}")
    records, current = [], None
    for line in lines:
        if isinstance(line, dict):
            if set(line) != {"file"} or not isinstance(line["file"], str) or line["file"] == current:
                raise AssertionError(f"{name}: bad file line {line!r}")
            current = line["file"]
            continue
        if current is None or not isinstance(line, list):
            raise AssertionError(f"{name}: record before a file line: {line!r}")
        values = line
        if len(values) == len(columns) + 1:
            marker = values[-1]
            if (not isinstance(marker, dict) or set(marker) != {"truncated"} or
                    not marker["truncated"] or len(set(marker["truncated"])) !=
                    len(marker["truncated"])):
                raise AssertionError(f"{name}: bad truncation marker {marker!r}")
            values = values[:-1]
        if len(values) != len(columns):
            raise AssertionError(f"{name}: record width {len(line)} for {len(columns)} columns")
        timestamp, level, message, number, parser, *fields = values
        if (not (timestamp is None or isinstance(timestamp, str)) or level not in LEVELS or
                not isinstance(message, str) or type(number) is not int or number < 1 or
                not isinstance(parser, str) or
                not all(value is None or isinstance(value, str) for value in fields)):
            raise AssertionError(f"{name}: bad record {line!r}")
        records.append((current, line))
    return columns, records


def agent_equivalent(records, agent_text, columns):
    """Rebuild compact records from --output agent rows of the same query."""
    rebuilt = []
    for row in map(parse, agent_text.splitlines()):
        line = [row["timestamp"], row["level"], row["message"], row["line"], row["format"],
                *(row.get("fields", {}).get(name) for name in columns[5:])]
        clipped = [name for name in row.get("truncated_fields", []) if name != "file"]
        if clipped:
            line.append({"truncated": clipped})
        rebuilt.append((row["file"], line))
    return rebuilt == records


def main():
    binary = str(Path(sys.argv[1]).resolve())
    scale = min(10, max(1, float(os.environ.get("LUMTAIL_TEST_TIMEOUT_SCALE", "1"))))
    manifest = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))
    checked = 0
    for selection in ([], ["--api-version=1"]):
        schema = subprocess.run([binary, *selection, "--output=agent-compact", "--agent-schema"],
                                capture_output=True, timeout=10 * scale)
        if schema.returncode != 0 or schema.stderr or json.loads(schema.stdout) != SCHEMA:
            raise AssertionError("--agent-schema does not print schema.json")
        for case in manifest["cases"]:
            with tempfile.TemporaryDirectory(prefix="lumtail-agent-compact-") as directory:
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
                    raise AssertionError(f"{case['name']}: usage error wrote records")
                columns, records = check_lines(case["name"], stdout)
                agent = run([arg.replace("agent-compact", "agent") for arg in case["args"]])
                if agent.returncode != case.get("agent_exit", case["exit"]):
                    raise AssertionError(f"{case['name']}: agent output exits {agent.returncode}")
                if agent.returncode == 0 and not agent_equivalent(
                        records, agent.stdout.decode(), columns or FIXED):
                    raise AssertionError(f"{case['name']}: differs from agent records")
            checked += 1
    print(f"agent-compact: {checked} cases passed")


if __name__ == "__main__":
    main()
