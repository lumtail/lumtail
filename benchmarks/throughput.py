# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Compare complete pipeline throughput using cached inputs and a /dev/null sink."""

import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def worker_count(value):
    if value == "auto":
        return value
    number = positive(value)
    if number > 256:
        raise argparse.ArgumentTypeError("must be auto or an integer from 1 to 256")
    return str(number)


def measure(commands, repeats):
    timings = [[] for _ in commands]
    with open(os.devnull, "wb") as sink:
        for iteration in range(repeats + 1):
            order = range(len(commands))
            if iteration % 2:
                order = reversed(order)
            for index in order:
                start = time.perf_counter()
                subprocess.run(commands[index], stdout=sink, check=True, timeout=120)
                duration = time.perf_counter() - start
                if iteration:
                    timings[index].append(duration)
    return timings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--threads", nargs="+", type=worker_count, default=["1", "4", "8", "auto"])
    parser.add_argument("--lines", type=positive, default=1000000)
    parser.add_argument("--repeats", type=positive, default=5)
    parser.add_argument("--directory", type=Path, default=Path("build/bench"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    samples = {
        "json": (json.dumps({"timestamp": "2026-11-07T18:30:00+01:00", "level": "error",
                             "service": "api", "message": "Connection failure during payment processing",
                             "request_id": "a" * 32, "duration_ms": 42}, separators=(",", ":")) + "\n").encode(),
        "access": b'127.0.0.1 - alice [07/Nov/2026:18:30:02 +0100] "GET /health HTTP/1.1" 200 12 "-" "ExampleClient/1.0"\n',
        "syslog": b'<11>Nov  7 18:30:01 host app[42]: Connection failed while processing payment\n',
        "access_rejected": b'127.0.0.1 - alice [07/Nov/2026:18:30:02 +0100] "GET /health HTTP/1.1" 200 12 "-" "ExampleClient/1.0" trailing\n',
        "plain": b"ordinary log line with no structured fields, repeated for throughput measurement\n",
    }
    paths = {}
    for name, sample in samples.items():
        path = args.directory / (name + ".log")
        with path.open("wb") as target:
            for start in range(0, args.lines, 10000):
                target.write(sample * min(10000, args.lines - start))
        paths[name] = path
    result = {"machine": platform.platform(), "architecture": platform.machine(),
              "logical_cpus": os.cpu_count(), "lines_per_corpus": args.lines,
              "repeats": args.repeats, "warmups": 1, "output_sink": os.devnull,
              "comparison": "same worker count; alternating binary order per repetition",
              "results": []}
    for corpus, mode in (("json", "text"), ("access", "text"), ("syslog", "text"),
                         ("plain", "text"), ("access_rejected", "text"),
                         ("json", "json"), ("json", "raw")):
        for threads in args.threads:
            candidates = [(args.binary, "candidate")]
            if args.baseline:
                candidates.insert(0, (args.baseline, "baseline"))
            commands = [[str(binary.resolve()), "--output", mode, "--threads", threads,
                         str(paths[corpus])] for binary, _ in candidates]
            measurements = measure(commands, args.repeats)
            for (binary, role), timings in zip(candidates, measurements):
                median = statistics.median(timings)
                size = paths[corpus].stat().st_size
                row = {"corpus": corpus, "mode": mode, "binary": str(binary), "role": role,
                       "threads": threads, "bytes": size,
                       "median_seconds": median, "MB_per_second": size / median / 1e6,
                       "lines_per_second": args.lines / median, "samples_seconds": timings}
                if args.baseline and role == "candidate":
                    row["speedup_vs_baseline"] = statistics.median(measurements[0]) / median
                result["results"].append(row)
                print(json.dumps(row), flush=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
