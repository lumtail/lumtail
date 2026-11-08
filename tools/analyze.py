#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Run Clang Static Analyzer on every project translation unit; fail on diagnostics."""

import argparse
import json
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--compiler", default="clang++", help="Clang matching the build's standard library")
    args = parser.parse_args()
    build = args.build.resolve()
    commands = json.loads((build / "compile_commands.json").read_text())
    output_dir = build / "analysis"
    output_dir.mkdir(exist_ok=True)
    failed = False
    for index, entry in enumerate(commands):
        source = Path(entry["file"]).resolve()
        root = Path(__file__).resolve().parents[1]
        if source.suffix != ".cpp" or not any(source.is_relative_to(root / folder) for folder in ("src", "tests")):
            continue
        command = entry.get("arguments") or shlex.split(entry["command"])
        flags = []
        skip = False
        for arg in command[1:]:
            if skip:
                skip = False
                continue
            if arg in ("-o", "-MF", "-MT", "-MQ"):
                skip = True
            elif arg not in ("-c", "-MD", "-MMD", entry["file"]):
                flags.append(arg)
        report = output_dir / f"{index}-{Path(entry['file']).stem}.plist"
        command = [args.compiler, *flags, "--analyze", "-Xanalyzer", "-analyzer-output=plist",
                   "-Xanalyzer", "-analyzer-checker=core,cplusplus,deadcode,security,unix",
                   "-Werror", entry["file"], "-o", str(report)]
        print(f"Analyzing {entry['file']}", flush=True)
        result = subprocess.run(command, cwd=entry["directory"], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        if result.stdout:
            print(result.stdout, end="", flush=True)
        failed |= result.returncode != 0
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
