# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Measure Lumtail throughput, RSS, startup, streaming response, saving and rules."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SUITES = ("pipeline", "startup", "latency", "save", "rules")
CORPORA = ("json", "syslog", "access", "plain", "mixed", "multiline", "long", "zeek", "json-ts", "kubernetes")


def integer(value, minimum=1, maximum=None):
    number = int(value)
    if number < minimum or (maximum is not None and number > maximum):
        raise argparse.ArgumentTypeError(f"expected an integer in [{minimum}, {maximum or 'unbounded'}]")
    return number


def threads(value):
    return value if value == "auto" else str(integer(value, maximum=256))


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("expected a finite positive number")
    return number


def distribution(values):
    ordered = sorted(values)
    return {"min": ordered[0], "median": statistics.median(ordered),
            "p95": ordered[math.ceil(len(ordered) * 0.95) - 1],
            "p99": ordered[math.ceil(len(ordered) * 0.99) - 1], "max": ordered[-1]}


def samples():
    # Use distinct records to make filtering observable.
    structured = tuple((json.dumps({"timestamp": "2026-11-07T18:30:00Z",
                                   "level": "error" if i % 4 == 0 else "info",
                                   "service": "api" if i % 2 == 0 else "worker", "seq": i,
                                   "message": f"Request {i}: payment processed", "duration_ms": i},
                                  separators=(",", ":")) + "\n").encode() for i in range(8))
    syslog = (b"<11>Nov  7 18:30:01 host app[42]: Connection failed\n",
              b"<14>Nov  7 18:30:02 host app[42]: Connection accepted\n")
    access = (b'127.0.0.1 - alice [07/Nov/2026:18:30:02 +0100] "GET /health HTTP/1.1" 503 12\n',
              b'127.0.0.1 - bob [07/Nov/2026:18:30:03 +0100] "GET / HTTP/1.1" 200 256\n')
    plain = (b"An ordinary unstructured log record for pipeline measurement\n",)
    zeek = tuple((json.dumps({"ts": 1794076200.125, "uid": f"CSynthetic{i}",
                             "id.orig_h": "192.0.2.10", "id.orig_p": 50123,
                             "id.resp_h": "2001:db8::20", "id.resp_p": 443,
                             "proto": "tcp", "conn_state": "SF", "missed_bytes": 0,
                             "orig_bytes": i, "resp_bytes": i * 2}, separators=(",", ":")) + "\n").encode()
                 for i in range(8))
    generic_ts = tuple((json.dumps(record, separators=(",", ":")) + "\n").encode() for record in (
        {"ts": 1794076200.125, "level": "info", "msg": "Synthetic application event", "pid": 42},
        {"ts": 1794076200.125, "uid": "business-identifier", "message": "Synthetic application event",
         **{f"field_{i:02}": "synthetic context" for i in range(64)}}))
    kubernetes = tuple((json.dumps({"apiVersion": "audit.k8s.io/v1", "kind": "Event", "level": "Metadata",
                                   "auditID": f"synthetic-request-{i // 2}",
                                   "stage": "ResponseComplete" if i % 2 else "RequestReceived",
                                   "verb": "get", "requestURI": "/api/v1/namespaces/demo/pods",
                                   "user": {"username": "alice"},
                                   "objectRef": {"namespace": "demo", "resource": "pods"}},
                                  separators=(",", ":")) + "\n").encode() for i in range(8))
    return {"json": structured, "syslog": syslog, "access": access, "plain": plain, "zeek": zeek,
            "kubernetes": kubernetes,
            "json-ts": generic_ts,
            "mixed": structured + syslog + access + plain,
            "multiline": tuple(line + b"  at service.handle(service.cpp:42)\n\tcaused by timeout\n"
                               for line in structured),
            "long": (json.dumps({"level": "error", "service": "api", "message": "x" * 4096}).encode() + b"\n",)}


def write_corpus(path, records, count):
    digest = hashlib.sha256()
    physical_lines = 0
    # Generate outside timing with bounded working memory.
    cycle = b"".join(records)
    batch_cycles = max(1, 65536 // len(cycle))
    with path.open("wb") as target:
        cycles, tail = divmod(count, len(records))
        while cycles:
            take = min(batch_cycles, cycles)
            chunk = cycle * take
            target.write(chunk)
            digest.update(chunk)
            physical_lines += chunk.count(b"\n")
            cycles -= take
        chunk = b"".join(records[:tail])
        target.write(chunk)
        digest.update(chunk)
        physical_lines += chunk.count(b"\n")
    return {"records": count, "physical_lines": physical_lines, "bytes": path.stat().st_size,
            "sha256": digest.hexdigest()}


def write_rules(path, count):
    modules = [{"name": f"bench_{i}", "priority": 100,
                "pattern": f"bench{i} [{{level}}] {{service}}: {{message}}",
                "levels": {"FAIL": "error", "OK": "info"},
                "display": {"template": "{level} {service}: {message}", "color": "none"}}
               for i in range(count)]
    path.write_text(json.dumps({"version": 1, "modules": modules}) + "\n", encoding="utf-8")


def invoke_worker(spec):
    completed = subprocess.run([sys.executable, str(ROOT / "benchmarks/worker.py")],
                               input=json.dumps(spec), text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=spec["timeout"] + 10, check=False)
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or f"worker exited {completed.returncode}")
    return json.loads(completed.stdout)


def build_metadata(binary):
    cache = Path(binary).parent / "CMakeCache.txt"
    if not cache.is_file():
        return {"cmake_cache": None}
    keys = {"CMAKE_BUILD_TYPE", "CMAKE_CXX_COMPILER", "CMAKE_CXX_FLAGS", "CMAKE_CXX_FLAGS_RELEASE",
            "LUMTAIL_NATIVE", "LUMTAIL_LTO", "LUMTAIL_SANITIZERS", "LUMTAIL_THREAD_SANITIZER",
            "LUMTAIL_HARDENING", "LUMTAIL_COVERAGE", "LUMTAIL_FUZZING"}
    entries = {}
    for line in cache.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        key = name.partition(":")[0]
        if separator and key in keys:
            entries[key] = value
    return {"cmake_cache": str(cache), "options": entries}


def measure_case(args, label, command, **spec):
    print(f"Measuring {label}", file=sys.stderr, flush=True)
    request = {"command": command, "timeout": args.timeout, **spec}
    for _ in range(args.warmups):
        invoke_worker(request)
    measured = [invoke_worker(request) for _ in range(args.repetitions)]
    row = {"case": label, "command": command, "samples": measured}
    for key in ("seconds", "user_seconds", "system_seconds", "fsync_seconds",
                "save_seconds", "first_response_seconds"):
        if key in measured[0]:
            row[key] = distribution([sample[key] for sample in measured])
    rss = [sample["peak_rss_bytes"] for sample in measured]
    row["peak_rss_available_samples"] = sum(value is not None for value in rss)
    # Keep partial samples from producing an optimistic summary.
    row["peak_rss_bytes"] = distribution(rss) if all(value is not None for value in rss) else None
    if "response_seconds" in measured[0]:
        row["response_seconds"] = distribution([value for sample in measured
                                                for value in sample["response_seconds"]])
    return row


def run(args, folder):
    binary = str(args.binary.resolve(strict=True))
    version = subprocess.check_output([binary, "--version"], text=True, timeout=args.timeout).strip()
    selected = args.suite or SUITES
    result = {"schema_version": 2, "created_utc": datetime.now(timezone.utc).isoformat(),
              "binary": binary, "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
              "version": version, "platform": platform.platform(), "machine": platform.machine(),
              "build": build_metadata(binary),
              "logical_cpus": os.cpu_count(), "python": platform.python_version(),
              "repetitions": args.repetitions, "warmups": args.warmups,
              "settings": {"suites": list(selected), "threads": args.threads, "modes": args.mode,
                           "latency_records": args.latency_records,
                           "latency_sources": args.latency_source,
                           "multiline_timeout_ms": args.multiline_timeout_ms,
                           "rules_counts": args.rules_counts, "timeout_seconds": args.timeout},
              "measurement": {"clock": "perf_counter",
                              "rss": "per-child ru_maxrss, normalized to bytes; kernel zero is unavailable (null), not zero memory",
                              "input": "deterministic generated files; warm filesystem cache",
                              "save": "process completion plus separately measured fsync; file creation excluded",
                              "latency": "one outstanding stdin request or file append; JSON pipe response; first response includes startup"},
              "corpora": {}, "results": []}
    data = samples()
    if "pipeline" in selected or "save" in selected:
        for corpus in args.corpus:
            path = folder / f"{corpus}.log"
            result["corpora"][corpus] = write_corpus(path, data[corpus], args.lines)
            flags = ["--multiline=indent"] if corpus == "multiline" else []
            for mode in args.mode:
                for workers in args.threads:
                    command = [binary, "--color=never", f"--threads={workers}", f"--output={mode}", *flags]
                    variants = [("pipeline", [])] if "pipeline" in selected else []
                    if "pipeline" in selected and mode != "raw":
                        variants.append(("filter", ["--min-level=error", "--where=service=api"]))
                    if "save" in selected:
                        variants.append(("save", []))
                    for scenario, extra in variants:
                        spec = {"destination": str(folder / "saved.log"), "sync": True} if scenario == "save" else {}
                        row = measure_case(args, f"{scenario}/{corpus}/{mode}/{workers}",
                                           [*command, *extra, str(path)], **spec)
                        row.update(suite=scenario, corpus=corpus, mode=mode, threads=workers,
                                   input_records=args.lines, input_bytes=path.stat().st_size)
                        elapsed = row["seconds"]["median"]
                        row["records_per_second"] = args.lines / elapsed
                        row["input_mib_per_second"] = path.stat().st_size / (1024 * 1024) / elapsed
                        result["results"].append(row)
    if "startup" in selected:
        for name, flags in (("version", ["--version"]), ("registry", ["--list-modules"])):
            row = measure_case(args, f"startup/{name}", [binary, *flags])
            row["suite"] = "startup"
            result["results"].append(row)
    if "latency" in selected:
        for source in args.latency_source:
            for workers in args.threads:
                for multiline in (False, True):
                    flags = ["--multiline=indent", f"--multiline-timeout-ms={args.multiline_timeout_ms}"] if multiline else []
                    follow = folder / "follow.log"
                    input_flags = ["--follow", str(follow)] if source == "follow" else ["-"]
                    spec = {"follow_path": str(follow)} if source == "follow" else {}
                    row = measure_case(args, f"latency/{source}/{'multiline' if multiline else 'line'}/{workers}",
                                       [binary, "--color=never", "--output=json", "--line-buffered",
                                        f"--threads={workers}", *flags, *input_flags],
                                       kind="latency", requests=args.latency_records, multiline=multiline, **spec)
                    row.update(suite="latency", threads=workers, multiline=multiline, source=source)
                    result["results"].append(row)
    if "rules" in selected:
        for count in args.rules_counts:
            rules = folder / f"rules-{count}.json"
            write_rules(rules, count)
            row = measure_case(args, f"rules/startup/{count}", [binary, "--rules", str(rules), "--list-modules"])
            row.update(suite="rules", modules=count, rules_bytes=rules.stat().st_size)
            result["results"].append(row)
            custom = folder / "custom.log"
            write_corpus(custom, (f"bench{count - 1} [FAIL] api: Payment failed\n".encode(),), args.lines)
            for source, corpus in ((custom, "last-match"), (folder / "unmatched.log", "no-match")):
                if corpus == "no-match":
                    write_corpus(source, data["plain"], args.lines)
                for workers in args.threads:
                    row = measure_case(args, f"rules/{corpus}/{count}/{workers}",
                                       [binary, "--color=never", f"--threads={workers}", "--rules", str(rules), str(source)])
                    row.update(suite="rules", modules=count, corpus=corpus, threads=workers,
                               input_records=args.lines, input_bytes=source.stat().st_size,
                               records_per_second=args.lines / row["seconds"]["median"])
                    result["results"].append(row)
            if args.core:
                row = measure_case(args, f"core/{count}", [str(args.core.resolve(strict=True)),
                                   str(rules), str(args.core_iterations)], kind="capture")
                row.update(suite="core", modules=count)
                row["operations"] = core_operations(row["samples"])
                result["results"].append(row)
    if args.allocations:
        row = measure_case(args, "allocations", [str(args.allocations.resolve(strict=True)),
                           str(args.core_iterations)], kind="capture")
        row["suite"] = "allocations"
        result["results"].append(row)
    return result


def core_operations(samples):
    operations = []
    for index, operation in enumerate(samples[0]["payload"]["results"]):
        values = []
        for sample in samples:
            measured = sample["payload"]["results"][index]
            value = measured["ns_per_operation"]
            status = measured.get("timing_status", "available" if value > 0 else "below_clock_resolution")
            if (measured["case"] != operation["case"] or not math.isfinite(value) or value < 0
                    or status not in ("available", "below_clock_resolution")
                    or (status == "available") != (value > 0)):
                raise ValueError("invalid native timing observation")
            if status == "available":
                values.append(value)
        operations.append({"case": operation["case"],
                           "timing_available_samples": len(values),
                           "ns_per_operation": distribution(values) if len(values) == len(samples) else None})
    return operations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--suite", choices=SUITES, action="append")
    parser.add_argument("--corpus", choices=CORPORA, nargs="+", default=list(CORPORA))
    parser.add_argument("--mode", choices=("text", "json", "raw"), nargs="+", default=["text", "json", "raw"])
    parser.add_argument("--threads", type=threads, nargs="+", default=["1", "4", "auto"])
    parser.add_argument("--lines", type=integer, default=100000)
    parser.add_argument("--repetitions", type=integer, default=5)
    parser.add_argument("--warmups", type=lambda value: integer(value, minimum=0), default=1)
    parser.add_argument("--latency-records", type=integer, default=100)
    parser.add_argument("--latency-source", choices=("pipe", "follow"), nargs="+", default=["pipe"],
                        help="streaming input sources (default: pipe); follow includes file polling")
    parser.add_argument("--multiline-timeout-ms", type=lambda value: integer(value, maximum=60000), default=20)
    parser.add_argument("--rules-counts", type=lambda value: integer(value, maximum=120), nargs="+", default=[1, 16, 64])
    parser.add_argument("--timeout", type=positive_float, default=120)
    parser.add_argument("--directory", type=Path, help="parent directory for temporary input/output; selects the filesystem")
    parser.add_argument("--output", type=Path, help="also save the JSON report to this file")
    parser.add_argument("--core", type=Path, help="optional lumtail_benchmarks executable")
    parser.add_argument("--allocations", type=Path, help="optional lumtail_allocations executable")
    parser.add_argument("--core-iterations", type=integer, default=1000)
    args = parser.parse_args()
    try:
        if args.directory:
            args.directory.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="lumtail-suite-", dir=args.directory) as temporary:
            report = run(args, Path(temporary))
        rendered = json.dumps(report, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"benchmark suite: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
