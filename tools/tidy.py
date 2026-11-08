#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Run the checked-in clang-tidy policy on configured project translation units."""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FOLDERS = ("src", "include/lumtail", "tests", "benchmarks", "fuzz")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--clang-tidy", default="clang-tidy")
    parser.add_argument("--require-complete", action="store_true",
                        help="reject builds missing project C++ sources")
    args = parser.parse_args()
    build = args.build.resolve()
    database = json.loads((build / "compile_commands.json").read_text())
    files = set()
    for entry in database:
        path = (Path(entry.get("directory", build)) / entry["file"]).resolve()
        if path.suffix == ".cpp" and any(path.is_relative_to(ROOT / name) for name in FOLDERS):
            files.add(path)
    if not files:
        parser.error("no project sources found in compile_commands.json")
    if args.require_complete:
        expected = {path.resolve() for name in FOLDERS for path in (ROOT / name).rglob("*.cpp")}
        missing = sorted(expected - files)
        if missing:
            print("Unconfigured C++ sources:\n" + "\n".join(map(str, missing)))
            return 2
    selected = sorted(map(str, files))
    print(f"Checking {len(selected)} configured project translation units", flush=True)
    return subprocess.run([args.clang_tidy, "-p", str(build), *selected],
                          cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
