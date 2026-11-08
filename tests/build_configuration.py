# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Exercise offline failure semantics and portable fuzzer packaging."""

import hashlib
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from package_fuzzers import package
from run_fuzz import TARGETS


class OfflineDependencies(unittest.TestCase):
    def check_source(self, name, populated, override):
        with TemporaryDirectory(prefix="lumtail-offline-contract-") as temporary:
            root = Path(temporary)
            source = root / ("local source" if override else f"deps/{name}-src")
            if populated is not None:
                source.mkdir(parents=True)
            if populated:
                (source / "CMakeLists.txt").write_text("# Local source fixture\n")
            script = root / "check.cmake"
            script.write_text(
                f'include("{ROOT / "cmake/Dependencies.cmake"}")\n'
                'set(FETCHCONTENT_FULLY_DISCONNECTED ON)\n'
                f'set(FETCHCONTENT_BASE_DIR "{root / "deps"}")\n'
                + (f'set(FETCHCONTENT_SOURCE_DIR_{name.upper()} "{source}")\n' if override else "")
                + f'lumtail_require_dependency_source({name})\n')
            return subprocess.run(["cmake", "-P", str(script)], capture_output=True, text=True, timeout=15)

    def test_disconnected_rejects_missing_and_empty_sources(self):
        for name in ("json", "simdjson", "hwy"):
            for override in (False, True):
                for populated in (None, False):
                    with self.subTest(name=name, override=override, populated=populated):
                        result = self.check_source(name, populated, override)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(f"Offline dependency '{name}' is missing", result.stderr)
                        self.assertIn(f"FETCHCONTENT_SOURCE_DIR_{name.upper()}", result.stderr)

    def test_accepts_populated_default_and_explicit_source_locations(self):
        for name in ("json", "simdjson", "hwy"):
            for override in (False, True):
                with self.subTest(name=name, override=override):
                    result = self.check_source(name, True, override)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_cmake_accepts_every_configure_build_and_test_preset(self):
        result = subprocess.run(["cmake", "--list-presets=all"], cwd=ROOT,
                                capture_output=True, text=True, timeout=15, check=True)
        for name in ("native", "asan-ubsan", "tsan", "fuzz", "offline"):
            self.assertEqual(result.stdout.count(f'"{name}"'), 3, result.stdout)


class ExternalFuzzing(unittest.TestCase):
    def test_rejects_missing_fuzz_mode_and_mixed_instrumentation(self):
        for options in ("", "set(LUMTAIL_FUZZING ON)\nset(LUMTAIL_SANITIZERS ON)",
                        "set(LUMTAIL_FUZZING ON)\nset(LUMTAIL_THREAD_SANITIZER ON)",
                        "set(LUMTAIL_FUZZING ON)\nset(LUMTAIL_COVERAGE ON)"):
            with self.subTest(options=options), TemporaryDirectory(prefix="lumtail-external-fuzz-") as temporary:
                script = Path(temporary) / "check.cmake"
                script.write_text('cmake_minimum_required(VERSION 3.24)\n'
                                  'set(LUMTAIL_EXTERNAL_FUZZING ON)\n' + options
                                  + f'\ninclude("{ROOT / "cmake/Quality.cmake"}")\n')
                result = subprocess.run(["cmake", "-P", str(script)], capture_output=True,
                                        text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("External fuzzing requires LUMTAIL_FUZZING=ON", result.stderr)


class SanitizerSelection(unittest.TestCase):
    def test_rejects_empty_unknown_and_incompatible_selections(self):
        for selection in ("", "none", "thread", "address,thread", "undefined,address"):
            with self.subTest(selection=selection), TemporaryDirectory() as temporary:
                script = Path(temporary) / "check.cmake"
                script.write_text(
                    f'set(LUMTAIL_SANITIZER_SET "{selection}" CACHE STRING "")\n'
                    f'include("{ROOT / "cmake/Quality.cmake"}")\n')
                result = subprocess.run(["cmake", "-P", str(script)], capture_output=True,
                                        text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("LUMTAIL_SANITIZER_SET must be", result.stderr)


class FuzzerPackaging(unittest.TestCase):
    def test_exports_all_targets_reproducibly_without_changing_seeds(self):
        with TemporaryDirectory(prefix="lumtail-fuzzer-package-") as temporary:
            root = Path(temporary)
            (root / "build/fuzz").mkdir(parents=True)
            for name in TARGETS:
                binary = root / "build/fuzz" / f"fuzz_{name}"
                binary.write_bytes(b"executable fixture\n")
                binary.chmod(0o755)
            seeds = list((ROOT / "fuzz/corpus").rglob("*"))
            before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in seeds if path.is_file()}
            package(root / "build", root / "first")
            package(root / "build", root / "second")
            for name in TARGETS:
                target = f"fuzz_{name}"
                self.assertTrue((root / "first" / target).stat().st_mode & 0o111)
                self.assertEqual((root / "first" / f"{target}.dict").read_bytes(),
                                 (ROOT / "fuzz/tokens.dict").read_bytes())
                options = (root / "first" / f"{target}.options").read_text()
                self.assertIn("timeout = 10", options)
                self.assertIn("rss_limit_mb = 2048", options)
                archive = root / "first" / f"{target}_seed_corpus.zip"
                self.assertEqual(archive.read_bytes(), (root / "second" / archive.name).read_bytes())
                with zipfile.ZipFile(archive) as zipped:
                    for seed in (ROOT / "fuzz/corpus" / name).iterdir():
                        if seed.is_file():
                            self.assertEqual(zipped.read(seed.name), seed.read_bytes())
                    if name == "parser":
                        self.assertIn("depth-4096", zipped.namelist())
            self.assertEqual(before, {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in before})

    def test_missing_target_is_a_failure_before_any_export(self):
        with TemporaryDirectory(prefix="lumtail-fuzzer-missing-") as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "missing executable fuzzer"):
                package(root / "missing", root / "output")
            self.assertFalse((root / "output").exists())


if __name__ == "__main__":
    unittest.main()
