#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Check coverage failure policy independently of the installed LLVM version."""

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "coverage_tool", Path(__file__).resolve().parents[1] / "tools/coverage.py")
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


def exercise(root, files, *, warning="", lines=95, branches=85):
    summary = json.dumps({"data": [{
        "files": [{"filename": str(root / "src" / name)} for name in files],
        "totals": {"lines": {"percent": lines}, "branches": {"percent": branches}},
    }]})

    def run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 0, "coverage report\n", warning if "report" in command else "")

    output = io.StringIO()
    with patch.object(coverage, "ROOT", root), \
            patch.object(sys, "argv", ["coverage.py", str(root / "build")]), \
            patch.object(coverage.subprocess, "run", side_effect=run), \
            patch.object(coverage.subprocess, "check_output", return_value=summary), \
            redirect_stdout(output), redirect_stderr(output):
        try:
            status = coverage.main()
        except SystemExit as error:
            status = error.code
    return status, output.getvalue()


with TemporaryDirectory(prefix="lumtail-coverage-contracts-") as directory:
    root = Path(directory)
    (root / "src").mkdir()
    for name in ("first.cpp", "second.cpp"):
        (root / "src" / name).touch()
    (root / "build/profiles").mkdir(parents=True)
    (root / "build/profiles/test.profraw").touch()

    assert exercise(root, ("first.cpp", "second.cpp"))[0] == 0
    status, output = exercise(root, ("first.cpp",))
    assert status == 2 and "missing source coverage mappings: src/second.cpp" in output
    diagnostic = "warning: 1 functions have mismatched data\nhash-mismatch: retained detail\n"
    status, output = exercise(root, ("first.cpp", "second.cpp"), warning=diagnostic)
    assert status == 2 and diagnostic in output and "stale or incompatible profiles" in output
    assert exercise(root, ("first.cpp", "second.cpp"), lines=84)[0] == 1
    assert exercise(root, ("first.cpp", "second.cpp"), branches=69)[0] == 1
    (root / "build/profiles/test.profraw").unlink()
    status, output = exercise(root, ("first.cpp", "second.cpp"))
    assert status == 2 and "no profiles" in output

print("Coverage tool contracts passed")
