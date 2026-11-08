#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Independent, append-only consumer for pipeline assertions and truncation failure."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "published_auditd", ROOT.parent / "v1-auditd-raw/check.py")
if spec is None or spec.loader is None:
    raise RuntimeError("published auditd consumer is missing")
published = importlib.util.module_from_spec(spec)
spec.loader.exec_module(published)
base = published.parent
MANIFEST = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))
base.CASES += MANIFEST["cases"]


class PipelineAssertionsV1(published.AuditdV1):
    def test_exact_pipelines_with_pipefail(self):
        for case in MANIFEST["pipelines"]:
            for pin in ([], ["--api-version=1"]):
                with self.subTest(case=case["name"], pin=pin), tempfile.TemporaryFile() as source, \
                        tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                    data = bytes.fromhex(case["stdin_hex"]) * case["repeat"]
                    self.assertLessEqual(len(data), 4 * base.OUTPUT_LIMIT)
                    self.assertEqual(source.write(data), len(data))
                    source.seek(0)
                    producer = subprocess.Popen(
                        [base.BINARY, *pin, *case["producer_args"]], stdin=source,
                        stdout=subprocess.PIPE, stderr=errors, env=base.ENV,
                        preexec_fn=base.bounded_child_output)
                    consumer = None
                    try:
                        self.assertEqual(case["consumer_args"], ["head", "-n", "1"])
                        consumer = subprocess.Popen(case["consumer_args"], stdin=producer.stdout,
                                                    stdout=output, stderr=errors, env=base.ENV,
                                                    preexec_fn=base.bounded_child_output)
                        producer.stdout.close()
                        consumer_exit = consumer.wait(timeout=10 * base.SCALE)
                        producer_exit = producer.wait(timeout=10 * base.SCALE)
                        self.assertEqual(producer_exit, case["producer_exit"])
                        self.assertEqual(consumer_exit, case["consumer_exit"])
                        self.assertEqual(consumer_exit or producer_exit, case["pipefail_exit"])
                        self.assertLessEqual(output.tell(), base.OUTPUT_LIMIT)
                        output.seek(0)
                        self.assertEqual(output.read(base.OUTPUT_LIMIT),
                                         bytes.fromhex(case["stdout_hex"]))
                        self.assertLessEqual(errors.tell(), base.OUTPUT_LIMIT)
                        errors.seek(0)
                        diagnostic = errors.read(base.OUTPUT_LIMIT)
                        if case["diagnostic"]:
                            self.assertTrue(diagnostic.startswith(b"lumtail: "))
                        else:
                            self.assertEqual(diagnostic, b"")
                    finally:
                        for process in (consumer, producer):
                            if process is not None:
                                if process.poll() is None:
                                    process.kill()
                                process.wait()
                        if not producer.stdout.closed:
                            producer.stdout.close()

    def test_closed_output_without_a_known_match_is_inconclusive(self):
        for case in MANIFEST["closed_output_cases"]:
            with self.subTest(args=case["args"]), tempfile.TemporaryFile() as errors:
                process = subprocess.Popen([base.BINARY, *case["args"]], stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=errors, env=base.ENV,
                                           preexec_fn=base.bounded_child_output)
                try:
                    process.stdout.close()
                    self.assertEqual(process.wait(timeout=5 * base.SCALE), case["exit"])
                    errors.seek(0)
                    self.assertTrue(errors.read(base.OUTPUT_LIMIT).startswith(b"lumtail: "))
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                    process.stdin.close()

    def test_required_native_policy_has_no_automatic_fallback(self):
        available = base.invoke(["--require-sandbox", "--sandbox-status"]).returncode == 0
        for case in MANIFEST["native_cases"]:
            with self.subTest(args=case["args"]), tempfile.TemporaryDirectory() as temporary:
                for name, data in case["files"].items():
                    self.assertEqual(Path(name).name, name)
                    (Path(temporary) / name).write_bytes(bytes.fromhex(data))
                result = base.invoke(case["args"], cwd=temporary)
                self.assertEqual(result.returncode,
                                 case["exit_native" if available else "exit_unavailable"],
                                 result.stderr)
                self.assertEqual(result.stdout, b"")
                if available:
                    self.assertEqual(result.stderr, b"")
                else:
                    self.assertTrue(result.stderr.startswith(b"lumtail: "))

    def test_output_errors_precede_assertion_results(self):
        for case in MANIFEST["readonly_output_cases"]:
            with self.subTest(args=case["args"]), open(os.devnull, "rb") as output, \
                    tempfile.TemporaryFile() as errors:
                result = subprocess.run([base.BINARY, *case["args"]],
                                        input=bytes.fromhex(case["stdin_hex"]), stdout=output,
                                        stderr=errors, env=base.ENV, timeout=10 * base.SCALE,
                                        preexec_fn=base.bounded_child_output)
                self.assertEqual(result.returncode, case["exit"])

    def test_metadata_is_not_a_record_assertion(self):
        for case in MANIFEST["metadata_cases"]:
            with self.subTest(args=case["args"]):
                result = base.invoke(case["args"])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                if case["kind"] == "help":
                    for flag in (b"--expect-none", b"--expect-some", b"--fail-on-truncation"):
                        self.assertIn(flag, result.stdout)
                else:
                    expected = base.CONTRACT if case["kind"] == "contract" else base.AGENT_SCHEMA
                    self.assert_json_value(json.loads(result.stdout), expected)

    def test_empty_time_windows_do_not_require_input_eof(self):
        for case in MANIFEST["window_cases"]:
            with self.subTest(args=case["args"]), tempfile.TemporaryFile() as output, \
                    tempfile.TemporaryFile() as errors:
                process = subprocess.Popen([base.BINARY, *case["args"]], stdin=subprocess.PIPE,
                                           stdout=output, stderr=errors, env=base.ENV,
                                           preexec_fn=base.bounded_child_output)
                try:
                    self.assertEqual(process.wait(timeout=5 * base.SCALE), case["exit"])
                    self.assertEqual(output.tell(), 0)
                    self.assertEqual(errors.tell(), 0)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                    process.stdin.close()


if __name__ == "__main__":
    unittest.main()
