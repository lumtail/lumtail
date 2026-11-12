#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Merge Clang profiles, export HTML/LCOV and enforce project-source coverage."""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--llvm-profdata", default="llvm-profdata")
    parser.add_argument("--llvm-cov", default="llvm-cov")
    parser.add_argument("--profiles", type=Path, help="raw profile directory (default: BUILD/profiles)")
    parser.add_argument("--min-lines", type=float, default=85)
    parser.add_argument("--min-branches", type=float, default=70)
    args = parser.parse_args()
    build = args.build.resolve()
    profiles = sorted((args.profiles or build / "profiles").glob("*.profraw"))
    if not profiles:
        parser.error("no profiles; run CTest with LLVM_PROFILE_FILE=BUILD/profiles/%p-%m.profraw")
    merged = build / "coverage.profdata"
    subprocess.run([args.llvm_profdata, "merge", "-sparse", *map(str, profiles), "-o", str(merged)], check=True)
    sources = sorted((ROOT / "src").glob("*.cpp"))
    # Load one linked source map to avoid conflicting inline maps.
    common = [str(build / "lumtail"), f"-instr-profile={merged}",
              *map(str, sources)]
    report = subprocess.run([args.llvm_cov, "report", "--dump", *common], check=True, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (build / "coverage-report.txt").write_text(report.stdout + report.stderr)
    print(report.stdout, end="")
    if report.stderr:
        print(report.stderr, end="")
    if "mismatched data" in report.stderr:
        parser.error("stale or incompatible profiles: use a fresh profiles directory and rerun tests")
    summary = subprocess.check_output([args.llvm_cov, "export", *common], text=True)
    (build / "coverage.json").write_text(summary)
    data = json.loads(summary)["data"][0]
    mapped = {Path(file["filename"]).resolve() for file in data["files"]}
    missing = [str(source.relative_to(ROOT)) for source in sources if source.resolve() not in mapped]
    if missing:
        parser.error(f"missing source coverage mappings: {', '.join(missing)}")
    with (build / "coverage.lcov").open("w") as output:
        subprocess.run([args.llvm_cov, "export", "-format=lcov", *common], stdout=output, check=True)
    subprocess.run([args.llvm_cov, "show", "-format=html", f"-output-dir={build / 'coverage-html'}",
                    "-show-branches=count", *common], stdout=subprocess.DEVNULL, check=True)
    totals = data["totals"]
    lines, branches = totals["lines"]["percent"], totals["branches"]["percent"]
    print(f"Project coverage: lines {lines:.2f}%, branches {branches:.2f}%", flush=True)
    return int(lines < args.min_lines or branches < args.min_branches)


if __name__ == "__main__":
    raise SystemExit(main())
