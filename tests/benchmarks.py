# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Benchmark contracts: validate measurements and reports without speed gates."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BINARY = str(Path(sys.argv.pop(1)).resolve())
CORE = str(Path(sys.argv.pop(1)).resolve()) if len(sys.argv) > 1 else None
ALLOCATIONS = str(Path(sys.argv.pop(1)).resolve()) if len(sys.argv) > 1 else None
SCALE = float(os.environ.get("LUMTAIL_TEST_TIMEOUT_SCALE", "1"))
spec = importlib.util.spec_from_file_location("benchmark_suite", ROOT / "benchmarks/suite.py")
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)
worker_spec = importlib.util.spec_from_file_location("benchmark_worker", ROOT / "benchmarks/worker.py")
worker = importlib.util.module_from_spec(worker_spec)
worker_spec.loader.exec_module(worker)


def run_suite(*flags, code=0):
    completed = subprocess.run([sys.executable, str(ROOT / "benchmarks/suite.py"), BINARY, *map(str, flags)],
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60 * SCALE)
    if completed.returncode != code:
        raise AssertionError(f"exit {completed.returncode}, expected {code}: {completed.stderr}")
    return completed


class BenchmarkTests(unittest.TestCase):
    def test_kubernetes_corpus_preserves_both_request_stages(self):
        data = b"".join(suite.samples()["kubernetes"])
        self.assertEqual(data, b"".join(suite.samples()["kubernetes"]))
        result = subprocess.run([BINARY, "--output=json", "--threads=1"], input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15 * SCALE)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(rows), 8)
        self.assertEqual([row["fields"]["audit_id"] for row in rows], [f"synthetic-request-{i // 2}" for i in range(8)])
        self.assertEqual([row["fields"]["audit_stage"] for row in rows], ["RequestReceived", "ResponseComplete"] * 4)

    def test_zeek_corpus_is_recognized_and_deterministic(self):
        records = suite.samples()["zeek"]
        self.assertEqual(records, suite.samples()["zeek"])
        source = b"".join(records)
        completed = subprocess.run([BINARY, "--output=json", "--threads=1"], input=source,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15 * SCALE)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        rows = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(len(rows), len(records))
        self.assertTrue(all(row["fields"]["zeek_log_type"] == "conn" for row in rows))
        self.assertEqual([row["fields"]["flow_id"] for row in rows], [f"CSynthetic{i}" for i in range(8)])
        generic = subprocess.run([BINARY, "--output=json", "--threads=1"], input=b"".join(suite.samples()["json-ts"]),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15 * SCALE)
        self.assertEqual(generic.returncode, 0, generic.stderr)
        rows = [json.loads(line) for line in generic.stdout.splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertTrue(all("zeek_log_type" not in row["fields"] for row in rows))

    def test_kernel_rss_units_and_unavailable_observation(self):
        for system in ("linux", "darwin", "freebsd15", "openbsd8", "netbsd11"):
            with self.subTest(system=system):
                observed = worker.memory_usage(7, system)
                self.assertEqual(observed["peak_rss_bytes"], 7 if system == "darwin" else 7 * 1024)
                self.assertEqual(observed["ru_maxrss"], 7)
                self.assertEqual(observed["ru_maxrss_unit"], "bytes" if system == "darwin" else "KiB")
                self.assertEqual(observed["rss_status"], "available")
        with self.assertRaises(ValueError):
            worker.memory_usage(-1, "freebsd15")
        with mock.patch.object(worker.resource, "getrusage", return_value=SimpleNamespace(
                ru_maxrss=0, ru_utime=0, ru_stime=0)):
            result = worker.measure({"command": [sys.executable, "-c", "pass"], "timeout": 5 * SCALE})
        self.assertIsNone(result["peak_rss_bytes"])
        self.assertEqual(result["rss_status"], "unavailable_kernel_zero")
        self.assertEqual(result["ru_maxrss"], 0)
        self.assertGreater(result["seconds"], 0)

    def test_incomplete_rss_samples_do_not_produce_a_partial_summary(self):
        args = SimpleNamespace(timeout=1, warmups=0, repetitions=2)
        for values in ((None, None), (None, 1024), (1024, 2048)):
            with self.subTest(values=values):
                samples = [{"seconds": 1.0, "peak_rss_bytes": value} for value in values]
                with mock.patch.object(suite, "invoke_worker", side_effect=samples):
                    row = suite.measure_case(args, "rss-contract", ["unused"])
                self.assertEqual(row["samples"], samples)
                self.assertEqual(row["peak_rss_available_samples"], sum(value is not None for value in values))
                if None in values:
                    self.assertIsNone(row["peak_rss_bytes"])
                else:
                    self.assertEqual(row["peak_rss_bytes"], suite.distribution(values))

    def test_percentiles_use_nearest_rank_and_median(self):
        self.assertEqual(suite.distribution([4, 1, 3, 2]),
                         {"min": 1, "median": 2.5, "p95": 4, "p99": 4, "max": 4})
        self.assertEqual(suite.distribution([7])["p99"], 7)

    def test_native_clock_resolution_preserves_unavailable_observations(self):
        for values in ((0, 0), (0, 7), (5, 7)):
            with self.subTest(values=values):
                samples = [{"payload": {"results": [{
                    "case": "short", "ns_per_operation": value,
                    "timing_status": "available" if value > 0 else "below_clock_resolution"
                }]}} for value in values]
                row = suite.core_operations(samples)[0]
                self.assertEqual([sample["payload"]["results"][0]["ns_per_operation"]
                                  for sample in samples], list(values))
                self.assertEqual(row["timing_available_samples"], sum(value > 0 for value in values))
                self.assertEqual(row["ns_per_operation"],
                                 suite.distribution(values) if all(values) else None)
        for value, status in ((-1, "available"), (float("nan"), "available"),
                              (float("inf"), "available"), (0, "available"),
                              (1, "below_clock_resolution"), (1, "unknown")):
            with self.subTest(value=value, status=status), self.assertRaises(ValueError):
                suite.core_operations([{"payload": {"results": [{
                    "case": "invalid", "ns_per_operation": value, "timing_status": status
                }]}}])

    def test_corpus_counts_and_hash_are_repeatable(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, second = Path(temporary) / "a", Path(temporary) / "b"
            for name, records in suite.samples().items():
                with self.subTest(corpus=name):
                    info = suite.write_corpus(first, records, 17)
                    self.assertEqual(info, suite.write_corpus(second, records, 17))
                    self.assertEqual(info["records"], 17)
                    self.assertEqual(info["physical_lines"], 51 if name == "multiline" else 17)
                    self.assertEqual(info["bytes"], len(first.read_bytes()))

    @unittest.skipIf(CORE is not None, "covered by the regular benchmark contract target")
    def test_complete_suite_smoke_and_report_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "reports/result.json"
            result = json.loads(run_suite(
                "--lines", 17, "--repetitions", 2, "--warmups", 1,
                "--latency-records", 2, "--latency-source", "pipe", "follow", "--multiline-timeout-ms", 1,
                "--rules-counts", 1, 3, "--threads", 1, "--mode", "json", "raw",
                "--corpus", "mixed", "multiline", "--directory", temporary,
                "--output", output, "--timeout", 15 * SCALE).stdout)
            self.assertEqual(result, json.loads(output.read_text()))
            self.assertEqual(result["schema_version"], 2)
            self.assertEqual({row["suite"] for row in result["results"]},
                             {"pipeline", "filter", "save", "latency", "startup", "rules"})
            self.assertEqual({row["source"] for row in result["results"] if row["suite"] == "latency"},
                             {"pipe", "follow"})
            for row in result["results"]:
                self.assertEqual(len(row["samples"]), 2)
                self.assertGreater(row["seconds"]["median"], 0)
                available = sum(sample["peak_rss_bytes"] is not None for sample in row["samples"])
                self.assertEqual(row["peak_rss_available_samples"], available)
                if available == len(row["samples"]):
                    self.assertEqual(row["peak_rss_bytes"], suite.distribution(
                        [sample["peak_rss_bytes"] for sample in row["samples"]]))
                    self.assertGreater(row["peak_rss_bytes"]["min"], 0)
                else:
                    self.assertIsNone(row["peak_rss_bytes"])
                for sample in row["samples"]:
                    expected = worker.memory_usage(sample["ru_maxrss"], sys.platform)
                    for key, value in expected.items():
                        self.assertEqual(sample[key], value)
                if row["suite"] == "save":
                    for sample in row["samples"]:
                        self.assertGreater(sample["output_bytes"], 0)
                        self.assertGreaterEqual(sample["fsync_seconds"], 0)
                        self.assertAlmostEqual(sample["save_seconds"], sample["seconds"] + sample["fsync_seconds"])
                        if row["mode"] == "raw":
                            self.assertEqual(sample["output_bytes"], row["input_bytes"])
                if row["suite"] == "latency":
                    self.assertGreater(row["first_response_seconds"]["median"], 0)
                    self.assertTrue(all(len(sample["response_seconds"]) == 2 for sample in row["samples"]))
            self.assertEqual(sorted(path.name for path in Path(temporary).iterdir()), ["reports"])

    def test_invalid_options_and_missing_binary_fail(self):
        for flags in (("--threads", "0"), ("--threads", "257"), ("--lines", "0"),
                      ("--repetitions", "0"), ("--warmups", "-1"), ("--timeout", "nan"),
                      ("--rules-counts", "121")):
            with self.subTest(flags=flags):
                run_suite(*flags, code=2)
        with tempfile.TemporaryDirectory() as temporary:
            missing = subprocess.run([sys.executable, str(ROOT / "benchmarks/suite.py"),
                                      str(Path(temporary) / "missing"), "--suite", "startup"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10 * SCALE)
            self.assertEqual(missing.returncode, 1)
            self.assertEqual(missing.stdout, b"")

    def test_worker_reports_child_failure_and_bounds_time(self):
        for command, timeout in (([sys.executable, "-c", "raise SystemExit(7)"], 5),
                                 ([sys.executable, "-c", "import time; time.sleep(5)"], 0.05)):
            with self.subTest(command=command):
                with self.assertRaises(RuntimeError):
                    suite.invoke_worker({"command": command, "timeout": timeout})

    @unittest.skipUnless(CORE is not None, "optional native probes are disabled")
    def test_native_probes_report_output_failures(self):
        for command in ([CORE, str(ROOT / "examples/modules.json"), "1"], [ALLOCATIONS, "1"]):
            with self.subTest(command=command), open(os.devnull, "rb") as readonly:
                result = subprocess.run(command, stdout=readonly, stderr=subprocess.PIPE,
                                        timeout=15 * SCALE)
                self.assertEqual(result.returncode, 1)

    @unittest.skipUnless(CORE is not None, "optional native probes are disabled")
    def test_native_rule_diagnostics_escape_terminal_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rules.json"
            path.write_text(json.dumps({"version": 1, "modules": [{
                "name": "invalid", "pattern": "{\x1b[2J\u202e}"
            }]}))
            failed = subprocess.run([CORE, str(path), "1"], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=15 * SCALE)
            self.assertEqual(failed.returncode, 1)
            self.assertEqual(failed.stdout, b"")
            self.assertNotIn(b"\x1b", failed.stderr)
            self.assertNotIn("\u202e".encode(), failed.stderr)
            self.assertIn(b"\\x1b[2J\\xe2\\x80\\xae", failed.stderr)

    @unittest.skipUnless(CORE is not None, "optional native probes are disabled")
    def test_native_probes_are_integrated_and_validated(self):
        report = json.loads(run_suite(
            "--suite", "rules", "--lines", 5, "--threads", 1, "--rules-counts", 1,
            "--warmups", 0, "--repetitions", 2, "--core", CORE, "--allocations", ALLOCATIONS,
            "--core-iterations", 3, "--timeout", 15 * SCALE).stdout)
        core = next(row for row in report["results"] if row["suite"] == "core")
        cases = {row["case"] for row in core["operations"]}
        self.assertTrue({"registry_construct", "rules_text_with_registry", "rules_file_with_registry",
                         "parse_auto/json", "parse_forced/json", "render/json/json"}.issubset(cases))
        for sample in core["samples"]:
            for operation in sample["payload"]["results"]:
                self.assertEqual(operation["requested_iterations"], 3)
                self.assertGreaterEqual(operation["iterations"], 3)
                self.assertEqual(operation["iterations"] % 3, 0)
                self.assertGreaterEqual(operation["seconds"], 0.001)
                self.assertGreater(operation["checksum"], 0)
                self.assertGreater(operation["ns_per_operation"], 0)
                self.assertAlmostEqual(operation["ns_per_operation"],
                                       operation["seconds"] * 1e9 / operation["iterations"])
        allocation = next(row for row in report["results"] if row["suite"] == "allocations")
        self.assertEqual(len(allocation["samples"]), 2)
        invalid = subprocess.run([CORE, str(ROOT / "examples/modules.json"), "0"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15 * SCALE)
        self.assertEqual(invalid.returncode, 2)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text('{"version": 1, "modules": [{"name": "bad"}]}')
            failed = subprocess.run([CORE, str(path), "1"], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=15 * SCALE)
            self.assertEqual(failed.returncode, 1)
            self.assertEqual(failed.stdout, b"")
            path.write_bytes(b" " * (1024 * 1024 + 1))
            oversized = subprocess.run([CORE, str(path), "1"], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, timeout=15 * SCALE)
            self.assertEqual(oversized.returncode, 1)
            self.assertEqual(oversized.stdout, b"")
            self.assertIn(b"rules file exceeds 1 MiB", oversized.stderr)


if __name__ == "__main__":
    unittest.main()
