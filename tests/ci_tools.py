# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Check CI evidence rendering, including incomplete and unavailable samples."""

import copy
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from benchmark_summary import summary

spec = importlib.util.spec_from_file_location(
    "lumtail_coverage", Path(__file__).resolve().parents[1] / "tools/coverage.py")
coverage_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage_tool)

tidy_spec = importlib.util.spec_from_file_location(
    "lumtail_tidy", Path(__file__).resolve().parents[1] / "tools/tidy.py")
tidy_tool = importlib.util.module_from_spec(tidy_spec)
tidy_spec.loader.exec_module(tidy_tool)


class TidyScopeTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="lumtail-tidy-scope-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.build = self.root / "build"
        self.build.mkdir()
        self.sources = []
        for name in ("src/main.cpp", "tests/unit.cpp", "benchmarks/core.cpp", "fuzz/parser.cpp"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
            self.sources.append(path)
        self.dependency = self.build / "_deps/library.cpp"
        self.dependency.parent.mkdir()
        self.dependency.touch()

    def exercise(self, *, missing=(), strict=False, status=0, relative=False):
        entries = []
        for path in (*self.sources, self.dependency):
            if path in missing:
                continue
            entries.append({"directory": str(self.root),
                            "file": str(path.relative_to(self.root) if relative else path),
                            "arguments": ["clang++", "-c", str(path)]})
        (self.build / "compile_commands.json").write_text(json.dumps(entries))
        arguments = ["tidy.py", str(self.build), "--clang-tidy", "selected-clang-tidy"]
        if strict:
            arguments.append("--require-complete")
        output = io.StringIO()
        with patch.object(tidy_tool, "ROOT", self.root), \
                patch.object(sys, "argv", arguments), \
                patch.object(tidy_tool.subprocess, "run", return_value=
                             subprocess.CompletedProcess([], status)) as backend, \
                redirect_stdout(output):
            result = tidy_tool.main()
        return result, output.getvalue(), backend

    def test_covers_all_project_folders_and_excludes_dependencies(self):
        status, _, backend = self.exercise(strict=True, relative=True)
        self.assertEqual(status, 0)
        self.assertEqual(backend.call_args.args[0],
                         ["selected-clang-tidy", "-p", str(self.build),
                          *sorted(map(str, self.sources))])

    def test_complete_mode_rejects_unconfigured_sources_before_analysis(self):
        status, output, backend = self.exercise(missing=(self.sources[-1],), strict=True)
        self.assertEqual(status, 2)
        self.assertIn(str(self.sources[-1]), output)
        backend.assert_not_called()

    def test_partial_build_checks_configured_sources(self):
        status, _, backend = self.exercise(missing=(self.sources[-1],))
        self.assertEqual(status, 0)
        self.assertNotIn(str(self.sources[-1]), backend.call_args.args[0])

    def test_keeps_analyzer_failure_status(self):
        self.assertEqual(self.exercise(status=7)[0], 7)


class CoverageProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="lumtail-coverage-contracts-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "src").mkdir()
        self.files = ("first.cpp", "second.cpp")
        for name in self.files:
            (self.root / "src" / name).touch()
        (self.root / "build/profiles").mkdir(parents=True)
        self.profiles = [self.root / "build/profiles" / name
                         for name in ("cli.profraw", "unit.profraw")]
        for profile in self.profiles:
            profile.touch()

    def exercise(self, *, files=None, warning="", lines=95, branches=85):
        summary = json.dumps({"data": [{
            "files": [{"filename": str(self.root / "src" / name)}
                      for name in (self.files if files is None else files)],
            "totals": {"lines": {"percent": lines}, "branches": {"percent": branches}},
            "functions": [{"name": "function", "count": 3}],
        }]})

        def run(command, **kwargs):
            return subprocess.CompletedProcess(
                command, 0, "coverage report\n", warning if "report" in command else "")

        output = io.StringIO()
        with patch.object(coverage_tool, "ROOT", self.root), \
                patch.object(sys, "argv", ["coverage.py", str(self.root / "build")]), \
                patch.object(coverage_tool.subprocess, "run", side_effect=run) as backend, \
                patch.object(coverage_tool.subprocess, "check_output", return_value=summary), \
                redirect_stdout(output), redirect_stderr(output):
            try:
                status = coverage_tool.main()
            except SystemExit as error:
                status = error.code
        return status, output.getvalue(), backend.call_args_list

    def test_accepts_complete_mapping_and_merges_all_test_profiles(self):
        status, _, calls = self.exercise()
        self.assertEqual(status, 0)
        for profile in self.profiles:
            self.assertIn(str(profile), calls[0].args[0])

    def test_rejects_missing_source_mapping(self):
        status, output, _ = self.exercise(files=("first.cpp",))
        self.assertEqual(status, 2)
        self.assertIn("missing source coverage mappings: src/second.cpp", output)

    def test_rejects_every_profile_mismatch_and_retains_diagnostics(self):
        for detail in ("hash-mismatch: No profile record found for 'function' with hash = 0x0\n",
                       "hash-mismatch: No profile record found for 'function' with hash = 0x123\n",
                       "unknown detail\n", ""):
            diagnostic = "warning: 1 functions have mismatched data\n" + detail
            with self.subTest(detail=detail):
                status, output, _ = self.exercise(warning=diagnostic)
                self.assertEqual(status, 2)
                self.assertIn(diagnostic, output)
                self.assertIn("stale or incompatible profiles", output)

    def test_rejects_insufficient_line_coverage(self):
        self.assertEqual(self.exercise(lines=84)[0], 1)

    def test_rejects_insufficient_branch_coverage(self):
        self.assertEqual(self.exercise(branches=69)[0], 1)

    def test_requires_raw_profiles(self):
        for profile in self.profiles:
            profile.unlink()
        status, output, calls = self.exercise()
        self.assertEqual(status, 2)
        self.assertIn("no profiles", output)
        self.assertEqual(calls, [])


class BenchmarkSummaryTests(unittest.TestCase):
    def setUp(self):
        self.report = {"schema_version": 1, "binaries": [{}, {}], "repetitions": 3,
                       "results": [{"corpus": "json", "mode": "text", "threads": "1",
                                    "samples": [[{"seconds": value, "peak_rss_bytes": None}
                                                 for value in (0.001, 0.004, 0.003)],
                                                [{"seconds": value, "peak_rss_bytes": 1024}
                                                 for value in (0.001, 0.002, 0.006)]]}]}

    def test_uses_sample_medians_and_preserves_missing_rss(self):
        self.assertIn("| json/text/1 | 3.000 | 2.000 | 1.500x | 0/3, 3/3 |",
                      summary(self.report))
        self.assertIn("timing is informational", summary(self.report))

    def test_rejects_missing_samples_and_invalid_times(self):
        broken = copy.deepcopy(self.report)
        broken["results"][0]["samples"][1].pop()
        with self.assertRaises(ValueError):
            summary(broken)
        for value in (0, -1, True, float("nan"), float("inf"), "1"):
            with self.subTest(value=value):
                broken = copy.deepcopy(self.report)
                broken["results"][0]["samples"][0][0]["seconds"] = value
                with self.assertRaises(ValueError):
                    summary(broken)

    def test_rejects_empty_report(self):
        self.report["results"] = []
        with self.assertRaises(ValueError):
            summary(self.report)

    def test_escapes_table_delimiters(self):
        self.report["results"][0]["corpus"] = "a|b\nc"
        self.assertIn("a&#124;b c/text/1", summary(self.report))


if __name__ == "__main__":
    unittest.main()
