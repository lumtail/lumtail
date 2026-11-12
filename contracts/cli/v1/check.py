#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""CLI API 1 consumer tests; run this unchanged against future binaries.

This suite uses only Python's standard library and files beside this script.
It imports no implementation or test code from the candidate and has no
update/accept mode. Run as a script, it also runs every area checker below it.
"""

import json
import os
from pathlib import Path
import resource
import select
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent
BINARY = str(Path(sys.argv.pop(1)).resolve())
CONTRACT = json.loads((ROOT / "contract.json").read_text(encoding="utf-8"))
CASES = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))["cases"]
AGENT_SCHEMA = json.loads((ROOT / "agent-schema.json").read_text(encoding="utf-8"))
SCALE = min(10.0, max(1.0, float(os.environ.get("LUMTAIL_TEST_TIMEOUT_SCALE", "1"))))
ENV = dict(os.environ, NO_COLOR="1", TERM="dumb")
OUTPUT_LIMIT = 1024 * 1024
FILE_LIMIT = 64 * OUTPUT_LIMIT


def bounded_child_output():
    # This standalone checker is single-threaded. Limit child output files
    # without changing the parent's resource limits or accumulating pipe data.
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    # Leave room for instrumentation profile files, independently of the much
    # smaller stdout/stderr capture budget for these finite consumer fixtures.
    soft = FILE_LIMIT if soft == resource.RLIM_INFINITY else min(soft, FILE_LIMIT)
    hard = FILE_LIMIT if hard == resource.RLIM_INFINITY else min(hard, FILE_LIMIT)
    resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))


def invoke(args, data=b"", cwd=None):
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen([BINARY, *args], stdin=subprocess.PIPE,
                                   stdout=stdout, stderr=stderr, cwd=cwd, env=ENV,
                                   preexec_fn=bounded_child_output)
        try:
            process.communicate(data, timeout=10 * SCALE)
            if stdout.tell() > OUTPUT_LIMIT or stderr.tell() > OUTPUT_LIMIT:
                raise AssertionError("candidate exceeded the consumer output budget")
            stdout.seek(0)
            stderr.seek(0)
            return subprocess.CompletedProcess(process.args, process.returncode,
                                               stdout.read(OUTPUT_LIMIT), stderr.read(OUTPUT_LIMIT))
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


class CliV1(unittest.TestCase):
    def assert_json_value(self, actual, expected):
        # Python equality alone would accept true or 1.0 in place of integer 1.
        self.assertIs(type(actual), type(expected))
        if isinstance(expected, dict):
            self.assertEqual(set(actual), set(expected))
            for key, value in expected.items():
                self.assert_json_value(actual[key], value)
        elif isinstance(expected, list):
            self.assertEqual(len(actual), len(expected))
            for left, right in zip(actual, expected):
                self.assert_json_value(left, right)
        else:
            self.assertEqual(actual, expected)

    def assert_json_record(self, actual, expected, full):
        # The full JSON field dictionary is an explicit extension point; the
        # envelope and previously published key values must remain compatible.
        if full:
            self.assertEqual(set(actual), set(expected))
            self.assertIsInstance(actual["fields"], dict)
            self.assertTrue(all(isinstance(value, str) for value in actual["fields"].values()))
            for key, value in expected["fields"].items():
                self.assertEqual(actual["fields"].get(key), value, key)
            actual = {key: value for key, value in actual.items() if key != "fields"}
            expected = {key: value for key, value in expected.items() if key != "fields"}
        self.assert_json_value(actual, expected)

    def test_published_invocations(self):
        for case in CASES:
            # Both unversioned scripts and explicitly pinned scripts stay v1.
            for pin in ([], ["--api-version", "1"]):
                with self.subTest(case=case["name"], pin=pin), tempfile.TemporaryDirectory(
                        prefix="lumtail-cli-v1-") as temporary:
                    for name, content in case["files"].items():
                        self.assertEqual(Path(name).name, name, "fixtures must use flat relative paths")
                        (Path(temporary) / name).write_bytes(bytes.fromhex(content))
                    args = case["args"]
                    result = invoke([*pin, *args], bytes.fromhex(case["stdin_hex"]), temporary)
                    self.assertEqual(result.returncode, case["exit"], result.stderr)
                    if case["diagnostic"]:
                        self.assertTrue(result.stderr.startswith(b"lumtail: "), result.stderr)
                        self.assertNotIn(b"\x1b", result.stderr)
                    else:
                        self.assertEqual(result.stderr, b"")
                    if case["mode"] == "jsonl":
                        self.assertNotIn(b"\x1b", result.stdout)
                        self.assertNotIn(b"\r", result.stdout)
                        self.assertTrue(not result.stdout or result.stdout.endswith(b"\n"))
                        lines = result.stdout.splitlines()
                        self.assertTrue(all(line.startswith(b"{") and line.endswith(b"}")
                                            for line in lines), "one compact object per line")
                        rows = [json.loads(line) for line in lines]
                        self.assertEqual(len(rows), len(case["stdout"]))
                        full = any(value in args for value in ("json", "--output=json"))
                        for actual, expected in zip(rows, case["stdout"]):
                            self.assert_json_record(actual, expected, full)
                    elif case["mode"] == "json":
                        self.assert_json_value(json.loads(result.stdout), case["stdout"])
                    elif case["name"] == "module-list":
                        # New recognized formats can be inserted. Existing
                        # names, priorities and relative ordering stay stable.
                        expected = bytes.fromhex(case["stdout_hex"]).splitlines()
                        rows = result.stdout.splitlines()
                        names = set()
                        for row in rows:
                            columns = row.split(b"\t")
                            self.assertEqual(len(columns), 2, "module stdout must remain TSV")
                            self.assertTrue(columns[0])
                            self.assertNotIn(columns[0], names)
                            names.add(columns[0])
                            int(columns[1])
                        actual = iter(rows)
                        for line in expected:
                            self.assertIn(line, actual)
                    else:
                        self.assertEqual(result.stdout, bytes.fromhex(case["stdout_hex"]))

    def test_contract_discovery_is_offline_and_does_not_open_inputs(self):
        for selector in ([], ["--api-version=1"]):
            result = invoke([*selector, "--cli-contract", "--rules", "missing-rules.json",
                             "missing-input.log"])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b"")
            self.assert_json_value(json.loads(result.stdout), CONTRACT)
        result = invoke(["--agent-schema"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_json_value(json.loads(result.stdout), AGENT_SCHEMA)

    def test_value_spellings_and_pinned_selection(self):
        data = b'{"level":"error","message":"failure","user":"alice"}\n'
        values = ["--api-version", "1", "--output", "json", "--threads", "1",
                  "--color", "never", "--where", "user=alice", "--filter", "level=error",
                  "--min-level", "WARN", "--multiline", "off", "--max-line-bytes", "1000",
                  "--max-record-bytes", "1000", "--multiline-timeout-ms", "60000",
                  "--limit", "1", "--duration-ms", "86400000"]
        joined = [f"{flag}={value}" for flag, value in zip(values[::2], values[1::2])]
        first = invoke(values, data)
        second = invoke(joined, data)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stderr, second.stderr)
        alias = invoke(["--api-version=1", "-j=1", "--output=json"], data)
        self.assertEqual(alias.returncode, 0, alias.stderr)
        self.assertEqual(first.stdout, alias.stdout)
        for option, maximum in (("--threads", "256"), ("--multiline-timeout-ms", "60000"),
                                ("--duration-ms", "86400000")):
            accepted = invoke(["--api-version=1", option, maximum, "--help"])
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
        for args in (["--api-version"], ["--api-version="], ["--api-version=01"],
                     ["--api-version=invalid"], ["--cli-contract=yes"]):
            result = invoke(args)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, b"")
            self.assertTrue(result.stderr)

    def test_human_metadata_is_not_a_record_protocol(self):
        for pin in ([], ["--api-version", "1"]):
            short = invoke([*pin, "--help"])
            alias = invoke([*pin, "-h"])
            full = invoke([*pin, "--help-all", "--rules", "missing.json", "missing.log"])
            self.assertEqual(short.returncode, 0, short.stderr)
            self.assertEqual(full.returncode, 0, full.stderr)
            self.assertEqual(short.stdout, alias.stdout)
            self.assertIn(b"--help-all", short.stdout)
            self.assertIn(b"--api-version", full.stdout)
            self.assertIn(b"--cli-contract", full.stdout)
            version = invoke([*pin, "--version"])
            self.assertEqual(version.returncode, 0, version.stderr)
            self.assertRegex(version.stdout.decode(), r"^lumtail [0-9]+\.[0-9]+\.[0-9]+[^\n]*\n$")
            status = invoke([*pin, "--sandbox-status"])
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertIn(b"Required confinement:", status.stdout)
            required = invoke([*pin, "--require-sandbox", "--sandbox-status"])
            available = b"Required confinement: available" in status.stdout
            self.assertEqual(required.returncode, 0 if available else 1, required.stderr)

    def test_line_buffering_and_broken_output(self):
        process = subprocess.Popen([BINARY, "--api-version=1", "--line-buffered", "--threads=1",
                                    "--output=raw"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=ENV)
        try:
            process.stdin.write(b"available now\n")
            process.stdin.flush()
            self.assertTrue(select.select([process.stdout], [], [], 5 * SCALE)[0],
                            "line-buffered output waited for stdin EOF")
            output = bytearray()
            deadline = time.monotonic() + 5 * SCALE
            while len(output) < 14:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0, "incomplete line-buffered output")
                self.assertTrue(select.select([process.stdout], [], [], remaining)[0])
                chunk = os.read(process.stdout.fileno(), 14 - len(output))
                self.assertTrue(chunk, "unexpected EOF")
                output.extend(chunk)
            self.assertEqual(output, b"available now\n")
            # Closing the last reader must remain ordinary EPIPE cancellation.
            process.stdout.close()
            process.stdin.write(b"downstream closed\n")
            process.stdin.close()
            self.assertEqual(process.wait(timeout=5 * SCALE), 0, process.stderr.read())
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                if not stream.closed:
                    stream.close()

    def test_live_input_deadline_without_fabricating_eof(self):
        # Deadline completion is tested on an owned, idle pipe. Golden follow
        # record counts use --limit instead: scheduling must not turn a timing
        # variation into an apparent change of record semantics.
        for pin in ([], ["--api-version=1"]):
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                process = subprocess.Popen([BINARY, *pin, "--agent", "--duration-ms=50"],
                                           stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                           env=ENV, preexec_fn=bounded_child_output)
                try:
                    self.assertEqual(process.wait(timeout=5 * SCALE), 0)
                    self.assertEqual(stdout.tell(), 0)
                    self.assertEqual(stderr.tell(), 0)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                    process.stdin.close()


AREAS = ("auditd-raw", "pipeline-assertions", "security-json", "json-records", "stats",
         "stop-reason", "agent-compact", "list-fields")


def check_areas():
    processes = [(area, subprocess.Popen(
        [sys.executable, "-I", str(ROOT / area / "check.py"), BINARY],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)) for area in AREAS]
    failed = []
    for area, process in processes:
        output, _ = process.communicate()
        sys.stdout.write(f"== {area}\n" + output.decode("utf-8", "replace"))
        if process.returncode != 0:
            failed.append(area)
    return failed


if __name__ == "__main__":
    core = unittest.main(exit=False).result.wasSuccessful()
    failed = check_areas()
    if failed:
        print("Failed CLI API 1 areas: " + ", ".join(failed), file=sys.stderr)
    sys.exit(0 if core and not failed else 1)
