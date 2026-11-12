#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Render paired benchmark evidence without enforcing noisy timing thresholds."""

import argparse
import json
import math
from pathlib import Path
import statistics
import sys


def summary(report):
    if report["schema_version"] != 1 or len(report["binaries"]) != 2 or not report["results"]:
        raise ValueError("expected a nonempty paired benchmark report with two binaries")
    repetitions = report["repetitions"]
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions < 1:
        raise ValueError("invalid repetition count")
    lines = ["Paired Release measurements on one runner; timing is informational.",
             "Exact output equality is checked before measurement.", "",
             "| Case | Baseline median (ms) | Candidate median (ms) | Speedup | RSS samples |",
             "| --- | ---: | ---: | ---: | --- |"]
    for row in report["results"]:
        if len(row["samples"]) != 2:
            raise ValueError("expected two sample series")
        medians, available = [], []
        for series in row["samples"]:
            if len(series) != repetitions:
                raise ValueError("incomplete sample series")
            times = [sample["seconds"] for sample in series]
            if any(isinstance(value, bool) or not isinstance(value, (int, float))
                   or not math.isfinite(value) or value <= 0 for value in times):
                raise ValueError("invalid elapsed time")
            medians.append(statistics.median(times))
            available.append(sum(sample["peak_rss_bytes"] is not None for sample in series))
        label = "/".join(str(row[key]) for key in ("corpus", "mode", "threads"))
        label = label.replace("|", "&#124;").replace("\n", " ").replace("\r", " ")
        lines.append(f"| {label} | {medians[0] * 1000:.3f} | {medians[1] * 1000:.3f} | "
                     f"{medians[0] / medians[1]:.3f}x | {available[0]}/{repetitions}, "
                     f"{available[1]}/{repetitions} |")
    lines += ["", "RSS counts show available observations for baseline and candidate; "
              "missing kernel observations remain unavailable. Download the artifact "
              "for raw samples, hashes, commands and build metadata."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        print(summary(json.loads(args.report.read_text(encoding="utf-8"))), end="")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"benchmark summary: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
