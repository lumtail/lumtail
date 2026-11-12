#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Standalone API 1 full-record consumer; Python standard library only."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
SCHEMA = json.loads((ROOT / "record-schema.json").read_text(encoding="utf-8"))
KEYWORDS = {"$schema", "$id", "title", "type", "required", "properties",
            "additionalProperties", "enum", "minimum"}
TYPES = {"object": dict, "string": str, "integer": int}


def check_vocabulary(schema):
    if schema.keys() - KEYWORDS or schema.get("type", "object") not in TYPES:
        raise AssertionError("unsupported schema vocabulary")
    for child in schema.get("properties", {}).values():
        check_vocabulary(child)
    extra = schema.get("additionalProperties", True)
    if isinstance(extra, dict):
        check_vocabulary(extra)


def valid(value, schema=SCHEMA):
    kind = schema.get("type")
    if kind == "integer":
        if type(value) is not int and not (type(value) is float and value.is_integer()):
            return False
    elif kind and type(value) is not TYPES[kind]:
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    if "minimum" in schema and (type(value) not in (int, float) or value < schema["minimum"]):
        return False
    if isinstance(value, dict):
        if set(schema.get("required", [])) - value.keys():
            return False
        properties = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for key, child in value.items():
            if key in properties:
                if not valid(child, properties[key]):
                    return False
            elif extra is False or (isinstance(extra, dict) and not valid(child, extra)):
                return False
    return True


def contains(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return all(key in actual and contains(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(map(lambda pair: contains(*pair), zip(actual, expected)))
    return actual == expected


def main():
    binary = str(Path(sys.argv[1]).resolve())
    scale = min(10, max(1, float(os.environ.get("LUMTAIL_TEST_TIMEOUT_SCALE", "1"))))
    cases = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))["cases"]
    check_vocabulary(SCHEMA)
    sample = cases[0]["stdout"][0]
    if not valid(dict(sample, line=1.0)):
        raise AssertionError("JSON Schema integer values include integral decimals")
    for key, value in (("line", 0), ("line", True), ("line", 1.5), ("raw", None),
                       ("fields", {"x": 7}), ("level", "BROKEN"), ("continuation", 0),
                       ("unexpected", "value")):
        invalid = dict(sample, **{key: value})
        if valid(invalid):
            raise AssertionError(f"schema accepted invalid {key}: {value!r}")
    missing = copy.deepcopy(sample)
    del missing["raw"]
    if valid(missing):
        raise AssertionError("schema accepted a missing raw value")
    earlier = 0
    for folder in (".", "auditd-raw", "pipeline-assertions", "security-json"):
        published = json.loads((ROOT.parent / folder / "cases.json").read_text(encoding="utf-8"))
        for case in published["cases"]:
            if case.get("mode") != "jsonl":
                continue
            for record in case["stdout"]:
                if isinstance(record, dict) and "raw" in record and "fields" in record:
                    if not valid(record):
                        raise AssertionError(f"schema rejected {folder}/{case['name']}")
                    earlier += 1
    for selection in ([], ["--api-version=1"]):
        query = subprocess.run([binary, *selection, "--record-schema"], capture_output=True,
                               timeout=10 * scale, check=True)
        if query.stderr or json.loads(query.stdout) != SCHEMA:
            raise AssertionError("the discovery schema differs from the published schema")
        for case in cases:
            result = subprocess.run([binary, *selection, "--output=json", *case["args"]],
                                    input=case["stdin"].encode(), capture_output=True,
                                    timeout=10 * scale, check=True)
            records = [json.loads(line) for line in result.stdout.split(b"\n") if line]
            if result.stderr or not contains(records, case["stdout"]) or not all(map(valid, records)):
                raise AssertionError(f"invalid records for {case['name']}: {result!r}")
            if case["name"] == "unicode":
                for point in (0x9b, 0x202e, 0x2028, 0x2029):
                    if chr(point).encode() in result.stdout or f"\\u{point:04x}".encode() not in result.stdout:
                        raise AssertionError("Unicode control was not escaped")
    print(f"Full JSON records: {earlier} earlier golden records, 4 cases under both API selectors passed.")


if __name__ == "__main__":
    main()
