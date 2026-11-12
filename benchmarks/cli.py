# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Reproducible, dependency-free end-to-end throughput measurements for Lumtail."""

import argparse
import json
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time


def positive_integer(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--lines", type=positive_integer, default=200000)
    parser.add_argument("--repetitions", type=positive_integer, default=3)
    parser.add_argument("--mode", choices=["text", "json", "raw"], action="append")
    args = parser.parse_args()
    binary = args.binary.resolve()
    root = Path(__file__).resolve().parents[1]
    version = subprocess.check_output([str(binary), "--version"], text=True).strip()
    samples = (root / "examples/mixed.log").read_bytes().splitlines(keepends=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="lumtail-benchmark-") as folder:
        source = Path(folder) / "mixed.log"
        with source.open("wb") as stream:
            for index in range(args.lines):
                stream.write(samples[index % len(samples)].rstrip(b"\r\n") + b"\n")
        size = source.stat().st_size
        for mode in args.mode or ["text", "json", "raw"]:
            command = [str(binary), "--color=never", "--rules", str(root / "examples/modules.json"),
                       "--output", mode, str(source)]
            durations = []
            for repetition in range(args.repetitions + 1):
                started = time.perf_counter()
                completed = subprocess.run(command, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.PIPE, timeout=120, check=False)
                elapsed = time.perf_counter() - started
                if completed.returncode:
                    raise SystemExit(completed.stderr.decode("utf-8", errors="replace"))
                if repetition:  # Exclude the filesystem/cache warm-up.
                    durations.append(elapsed)
            median = statistics.median(durations)
            results.append({"mode": mode, "seconds": durations,
                            "median_seconds": median, "records_per_second": args.lines / median,
                            "input_mib_per_second": size / (1024 * 1024) / median})
    print(json.dumps({"version": version, "system": platform.system(), "machine": platform.machine(),
                      "input_records": args.lines, "input_bytes": size,
                      "repetitions": args.repetitions, "output_sink": "devnull",
                      "results": results}, indent=2))


if __name__ == "__main__":
    main()
