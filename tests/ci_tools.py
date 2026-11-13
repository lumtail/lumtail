# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Check CI policies and reports, including incomplete and unavailable samples."""

import copy
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import textwrap
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from benchmark_summary import summary
from release_checks import missing_checks

spec = importlib.util.spec_from_file_location(
    "lumtail_coverage", Path(__file__).resolve().parents[1] / "tools/coverage.py")
coverage_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage_tool)

tidy_spec = importlib.util.spec_from_file_location(
    "lumtail_tidy", Path(__file__).resolve().parents[1] / "tools/tidy.py")
tidy_tool = importlib.util.module_from_spec(tidy_spec)
tidy_spec.loader.exec_module(tidy_tool)


class MergePolicyTests(unittest.TestCase):
    def test_release_checks_require_the_latest_success_from_the_configured_app(self):
        required = [{"context": "CI required", "integration_id": 15368}]
        good = {"head_sha": "commit", "name": "CI required", "app": {"id": 15368},
                "id": 1, "status": "completed", "conclusion": "success"}
        wrong_commit = dict(good, head_sha="other", id=2)
        wrong_app = dict(good, app={"id": 1}, id=3)
        no_app = dict(good, app=None, id=6)
        running = dict(good, id=4, status="in_progress", conclusion=None)
        failed = dict(good, id=5, conclusion="failure")
        self.assertEqual(missing_checks("commit", [{"check_runs": [wrong_commit, wrong_app, no_app]}],
                                        required), [("CI required", "missing")])
        self.assertEqual(missing_checks("commit", [{"check_runs": [good]}], required), [])
        self.assertEqual(missing_checks("commit", [{"check_runs": [running]},
                                                    {"check_runs": [good]}], required),
                         [("CI required", "in_progress")])
        self.assertEqual(missing_checks("commit", [{"check_runs": [good, failed]}], required),
                         [("CI required", "failure")])

    def test_main_requires_every_quality_gate_from_github_actions(self):
        path = Path(__file__).resolve().parents[1] / ".github/rulesets/cli-api-main.json"
        policy = json.loads(path.read_text())
        self.assertEqual(policy["enforcement"], "active")
        self.assertEqual(policy["bypass_actors"], [])
        self.assertIn("refs/heads/main", policy["conditions"]["ref_name"]["include"])
        checks = next(rule["parameters"] for rule in policy["rules"]
                      if rule["type"] == "required_status_checks")
        required = {check["context"]: check["integration_id"]
                    for check in checks["required_status_checks"]}
        self.assertEqual(required, {name: 15368 for name in (
            "CLI API v1 required", "CI required", "Security required", "BSD required",
            "Workflow and tooling checks")})
        self.assertTrue(checks["strict_required_status_checks_policy"])
        self.assertFalse(checks["do_not_enforce_on_create"])

    def test_release_workflow_creates_only_a_new_draft(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/release.yml").read_text()
        step = workflow.split("      - name: Create a new draft release\n", 1)[1]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        with TemporaryDirectory(prefix="lumtail-release-policy-") as folder:
            root = Path(folder)
            log = root / "gh.log"
            gh = root / "gh"
            gh.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$CALL_LOG"
if [ "$1" = api ]; then
    printf '%s\\n' "$TAG_REVISION"
    exit 0
fi
case "$2" in
view) exit "$VIEW_STATUS" ;;
create) exit 0 ;;
*) exit 1 ;;
esac
''')
            gh.chmod(0o755)
            (root / "dist").mkdir()
            (root / "dist/SHA256SUMS").touch()
            env = os.environ | {"PATH": folder + os.pathsep + os.environ["PATH"],
                                "CALL_LOG": str(log), "GITHUB_REPOSITORY": "test/lumtail",
                                "TAG": "v1.0.0",
                                "REVISION": "commit", "TAG_REVISION": "commit"}
            api = "api repos/test/lumtail/commits/refs/tags/v1.0.0 --jq .sha"
            moved = subprocess.run(["sh", "-ec", script], cwd=root, capture_output=True,
                                   env=env | {"TAG_REVISION": "other"})
            self.assertEqual(moved.returncode, 1, moved.stderr)
            self.assertEqual(log.read_text().splitlines(), [api])
            log.unlink()
            existing = subprocess.run(["sh", "-ec", script], cwd=root, capture_output=True,
                                      env=env | {"VIEW_STATUS": "0"})
            self.assertEqual(existing.returncode, 1, existing.stderr)
            self.assertEqual(log.read_text().splitlines(),
                             [api, "release view v1.0.0 --repo test/lumtail"])
            log.unlink()
            missing = subprocess.run(["sh", "-ec", script], cwd=root, capture_output=True,
                                     env=env | {"VIEW_STATUS": "1"})
            self.assertEqual(missing.returncode, 0, missing.stderr)
            self.assertEqual(log.read_text().splitlines(), [
                api, "release view v1.0.0 --repo test/lumtail",
                "release create v1.0.0 --repo test/lumtail --verify-tag --draft "
                "--title lumtail 1.0.0 --generate-notes dist/SHA256SUMS"])
            log.unlink()
            beta = subprocess.run(["sh", "-ec", script], cwd=root, capture_output=True,
                                  env=env | {"TAG": "v1.0.0-beta", "VIEW_STATUS": "1"})
            self.assertEqual(beta.returncode, 0, beta.stderr)
            self.assertEqual(log.read_text().splitlines(), [
                api.replace("v1.0.0", "v1.0.0-beta"),
                "release view v1.0.0-beta --repo test/lumtail",
                "release create v1.0.0-beta --repo test/lumtail --verify-tag --draft "
                "--title lumtail 1.0.0-beta --generate-notes --prerelease dist/SHA256SUMS"])

    def test_release_workflow_requires_version_before_starting_the_matrix(self):
        repo = Path(__file__).resolve().parents[1]
        workflow = (repo / ".github/workflows/release.yml").read_text()
        step = workflow.split("      - name: Match tag to CMake project version\n", 1)[1]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1].split("\n  macos:", 1)[0])
        with TemporaryDirectory(prefix="lumtail-release-version-") as folder:
            root = Path(folder)
            output = root / "output"
            env = os.environ | {"EVENT": "pull_request", "GITHUB_OUTPUT": str(output)}
            (root / "CMakeLists.txt").write_text((repo / "CMakeLists.txt").read_text())
            git = root / "git"
            git.write_text("#!/bin/sh\ncase \"$1\" in\n"
                           "rev-parse) printf '%s\\n' 0123456789abcdef ;;\n"
                           "merge-base) exit 0 ;;\n*) exit 1 ;;\nesac\n")
            git.chmod(0o755)
            env["PATH"] = folder + os.pathsep + os.environ["PATH"]
            valid = subprocess.run(["sh", "-ec", script], cwd=root, capture_output=True,
                                   env=env)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            values = output.read_text()
            self.assertRegex(values, r"\Aversion=\d+\.\d+\.\d+\nrevision=[a-f0-9]+\n\Z")
            version = values.splitlines()[0].removeprefix("version=")
            gh = root / "gh"
            gh.write_text("#!/bin/sh\nexit 0\n")
            gh.chmod(0o755)
            (root / "tools").mkdir()
            (root / "tools/release_checks.py").touch()
            push = env | {"EVENT": "push", "GITHUB_REPOSITORY": "test/lumtail", "RUNNER_TEMP": folder}
            for tag, error in ((f"v{version}", b""), (f"v{version}-beta", b""),
                               (f"v{version}-beta.1", b"Expected vMAJOR.MINOR.PATCH"),
                               (f"v{version}0-beta", b"does not match CMake version")):
                with self.subTest(tag=tag):
                    result = subprocess.run(["sh", "-ec", script], cwd=root, capture_output=True,
                                            env=push | {"TAG": tag})
                    self.assertEqual(result.returncode, int(bool(error)), result.stderr)
                    self.assertIn(error, result.stderr)
            output.unlink()
            (root / "CMakeLists.txt").write_text("project(lumtail LANGUAGES CXX)\n")
            invalid = subprocess.run(["sh", "-ec", script], cwd=root, capture_output=True,
                                     env=env)
            self.assertEqual(invalid.returncode, 1, invalid.stderr)
            self.assertIn(b"three-part project version", invalid.stderr)
            self.assertFalse(output.exists())

    def test_release_collects_native_packages_without_overwriting(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/release.yml").read_text()
        step = workflow.split("      - name: Collect archives\n", 1)[1]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1].split(
            "\n      - name: Create a new draft release", 1)[0])
        packages = {
            "release-amazon2023-aarch64": "lumtail-0.1.0-1.amzn2023.aarch64.rpm",
            "release-arch-x86_64": "lumtail-0.1.0-1-x86_64.pkg.tar.zst",
            "release-gentoo-aarch64": "lumtail-0.1.0-gentoo-aarch64.gpkg.tar",
            "release-gentoo-x86_64": "lumtail-0.1.0-gentoo-x86_64.gpkg.tar",
            "release-nixos-aarch64": "lumtail-0.1.0-nixos-aarch64.tar.gz",
        }
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate), TemporaryDirectory() as folder:
                root = Path(folder)
                gh = root / "gh"
                gh.write_text("#!/bin/sh\nexit 0\n")
                gh.chmod(0o755)
                sha256sum = root / "sha256sum"
                sha256sum.write_text(
                    "#!/bin/sh\nshift\nfor file do printf 'checksum  %s\\n' \"$file\"; done\n")
                sha256sum.chmod(0o755)
                for artifact, name in packages.items():
                    path = root / "artifacts" / artifact / name
                    path.parent.mkdir(parents=True)
                    path.write_text(artifact)
                if duplicate:
                    path = root / "artifacts/release-extra" / packages["release-arch-x86_64"]
                    path.parent.mkdir()
                    path.write_text("duplicate")
                result = subprocess.run(["bash", "-ec", script], cwd=root, capture_output=True,
                                        env=os.environ | {"PATH": folder + os.pathsep +
                                                          os.environ["PATH"]})
                if duplicate:
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(b"duplicate release file", result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    sums = (root / "dist/SHA256SUMS").read_text()
                    self.assertEqual({line.split()[1] for line in sums.splitlines()},
                                     set(packages.values()))


class NetBSDPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="lumtail-netbsd-packages-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "packages.log"
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/bsd.yml").read_text()
        section = workflow.split("      - name: Start NetBSD\n", 1)[1]
        section = section.split("          prepare: |\n", 1)[1]
        lines = []
        for line in section.splitlines():
            if line and not line.startswith("            "):
                break
            lines.append(line)
        self.script = textwrap.dedent("\n".join(lines))
        self.script = self.script.replace("/usr/sbin/certctl", "certctl")
        self.script = self.script.replace("/usr/sbin/pkg_add", "pkg_add")
        self.command("certctl", "exit 0")
        self.command("git", "exit 0")
        self.command("sleep", "exit 0")
        self.command("uname", """case "$1" in
-r) printf '11.1_STABLE\\n' ;;
-p) printf 'x86_64\\n' ;;
*) exit 1 ;;
esac""")
        self.command("pkg_add", """printf '%s|%s\\n' "$PKG_PATH" "$*" >> "$CALL_LOG"
count=$(wc -l < "$CALL_LOG")
test "$count" -gt "$FAIL_ATTEMPTS"
""")

    def command(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
        path.chmod(0o755)

    def prepare(self, failures):
        return subprocess.run(
            ["sh", "-c", self.script], cwd=self.root, capture_output=True, text=True,
            env=os.environ | {"PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                              "CALL_LOG": str(self.log), "FAIL_ATTEMPTS": str(failures),
                              "PKG_PATH": "https://stale.invalid/quarterly/All"})

    def test_uses_live_release_mirrors_instead_of_the_bootstrap_configuration(self):
        result = self.prepare(0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.log.read_text().splitlines(), [
            "https://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/x86_64/11.1/All;"
            "https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/x86_64/11.1/All|"
            "cmake gmake python312"])

    def test_retries_transient_package_failures(self):
        result = self.prepare(2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.log.read_text().splitlines()), 3)

    def test_persistent_package_failures_stop_the_job(self):
        result = self.prepare(3)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.log.read_text().splitlines()), 3)


class UbuntuPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="lumtail-apt-packages-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "apt.log"
        self.script = Path(__file__).resolve().parents[1] / "tools/ci_apt_install.sh"
        self.command("dpkg-query", """for package; do :; done
case " $INSTALLED " in
*" $package "*) printf 'install ok installed\\n' ;;
*) exit 1 ;;
esac""")
        self.command("sudo", '"$@"')
        self.command("getent", 'case " $RESOLVES " in *" $2 "*) printf "1.2.3.4 %s\\n" "$2" ;; *) exit 2 ;; esac')
        self.mirrors = self.root / "apt-mirrors.txt"
        self.mirrors.write_text("http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n"
                                "https://archive.ubuntu.com/ubuntu/\tpriority:2\n")
        self.command("sleep", 'printf "sleep %s\\n" "$1" >> "$CALL_LOG"')
        self.command("apt-get", """for argument; do :; done
printf '%s\\n' "$*" >> "$CALL_LOG"
case "$*" in
*" install "*)
    count=$(grep -c ' install ' "$CALL_LOG")
    test "$count" -gt "$FAIL_ATTEMPTS"
    ;;
esac""")

    def command(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
        path.chmod(0o755)

    def install(self, *packages, installed="", failures=0, resolves="azure.archive.ubuntu.com"):
        return subprocess.run(
            ["sh", str(self.script), *packages], cwd=self.root, capture_output=True, text=True,
            env=os.environ | {"PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                              "CALL_LOG": str(self.log), "FAIL_ATTEMPTS": str(failures),
                              "INSTALLED": installed, "CI_APT_DELAY": "7",
                              "CI_APT_MIRRORS": str(self.mirrors), "RESOLVES": resolves})

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_preinstalled_packages_skip_the_network(self):
        result = self.install("g++-14", installed="g++-14")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_installs_only_missing_packages(self):
        result = self.install("clang-19", "g++-14", installed="g++-14")
        self.assertEqual(result.returncode, 0, result.stderr)
        installs = [call for call in self.calls() if " install " in call]
        self.assertEqual(len(installs), 1)
        self.assertTrue(installs[0].endswith("install -y clang-19"), installs[0])

    def test_retries_unreachable_mirrors_with_growing_delay(self):
        result = self.install("clang-19", failures=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call for call in self.calls() if call.startswith("sleep")],
                         ["sleep 7", "sleep 14"])
        self.assertEqual(len([call for call in self.calls() if " install " in call]), 3)

    def test_persistent_mirror_failures_stop_the_job(self):
        result = self.install("clang-19", failures=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed after 3 attempts", result.stderr)
        self.assertEqual(len([call for call in self.calls() if " install " in call]), 3)

    def test_resolving_azure_mirror_keeps_the_runner_list(self):
        before = self.mirrors.read_text()
        result = self.install("clang-19")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.mirrors.read_text(), before)

    def test_unresolvable_azure_mirror_switches_to_ubuntu_archives(self):
        result = self.install("clang-19", resolves="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.mirrors.read_text().splitlines(),
                         ["http://archive.ubuntu.com/ubuntu/", "http://security.ubuntu.com/ubuntu/"])
        self.assertIn("using archive.ubuntu.com", result.stderr)


class BenchmarkBaselineTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="lumtail-benchmark-history-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Benchmark test")
        self.git("config", "user.email", "benchmark@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("commit", "--allow-empty", "--quiet", "-m", "retained root")
        self.parent = self.git("rev-parse", "HEAD")
        self.git("commit", "--allow-empty", "--quiet", "-m", "candidate")
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/benchmarks.yml").read_text()
        resolver = workflow.split("      - name: Resolve immutable baseline\n        run: |\n", 1)[1]
        self.script = textwrap.dedent(resolver.split("          git worktree add", 1)[0])
        self.script += '\nprintf "%s\\n" "$baseline"\n'

    def git(self, *arguments):
        return subprocess.check_output(["git", *arguments], cwd=self.root, text=True).strip()

    def resolve(self, *, push="", pr=""):
        return subprocess.run(["sh", "-e", "-c", self.script],
                              cwd=self.root, env=os.environ | {"PUSH_BASE": push, "PR_BASE": pr},
                              capture_output=True, text=True)

    def test_keeps_the_exact_ancestor_push_and_pr_bases(self):
        for arguments in ({"push": self.parent}, {"pr": self.parent}):
            with self.subTest(arguments=arguments):
                result = self.resolve(**arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), self.parent)

    def test_history_reset_uses_new_parent_for_absent_or_unrelated_push(self):
        unrelated = self.git("commit-tree", "HEAD^{tree}", "-m", "removed history")
        for previous in ("1" * 40, unrelated):
            with self.subTest(previous=previous):
                result = self.resolve(push=previous)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), self.parent)

    def test_missing_pr_base_still_fails(self):
        self.assertNotEqual(self.resolve(pr="1" * 40, push=self.parent).returncode, 0)

    def test_rejects_invalid_push_ids_before_reset_fallback(self):
        for previous in ("1" * 39, "g" * 40, "a" * 40 + "\n"):
            with self.subTest(previous=previous):
                self.assertNotEqual(self.resolve(push=previous).returncode, 0)

    def test_scheduled_and_initial_push_use_the_parent(self):
        for previous in ("", "0" * 40):
            with self.subTest(previous=previous):
                result = self.resolve(push=previous)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), self.parent)


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
