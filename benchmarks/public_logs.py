# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Run the manual public-log workload; download, check, measure and remove each input."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

from suite import ROOT, build_metadata, distribution, integer, positive_float, threads

SOURCES = {
    "json": {
        "title": "Splunk CloudTrail JSON", "license": "Apache-2.0",
        "credit": "Patrick Bareiss / Splunk Inc., Attack Data, aws_delete_acl, revision c8af10d015d392fca97f9eb65181e9f06bc18e40",
        "page": "https://github.com/splunk/attack_data/tree/c8af10d015d392fca97f9eb65181e9f06bc18e40/datasets/attack_techniques/T1562.007/aws_delete_acl",
        "license_page": "https://github.com/splunk/attack_data/blob/c8af10d015d392fca97f9eb65181e9f06bc18e40/LICENSE",
        "benchmark": "https://github.com/splunk/attack_data#readme",
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/c8af10d015d392fca97f9eb65181e9f06bc18e40/datasets/attack_techniques/T1562.007/aws_delete_acl/aws_cloudtrail_events.json",
        "bytes": 16030714,
        "sha256": "d31cf164315d63a20b92558852d11d2b00a43a31cd091b745c16e7f0c1cc306d",
        "origin": "AWS CloudTrail telemetry captured in Splunk Attack Range for public detection testing",
    },
    "syslog": {
        "title": "Vulcan SIEM RFC 5424", "license": "MIT",
        "credit": "VulcanSIEM / sartimo, synthetic-syslog-1B, revision 2e8204a084de2ba490f7f452b9dfbd39d074c670",
        "page": "https://huggingface.co/datasets/vulcansiem/synthetic-syslog-1B",
        "license_page": "https://huggingface.co/datasets/vulcansiem/synthetic-syslog-1B/blob/2e8204a084de2ba490f7f452b9dfbd39d074c670/README.md",
        "benchmark": "https://huggingface.co/datasets/vulcansiem/synthetic-syslog-1B",
        "url": "https://huggingface.co/datasets/vulcansiem/synthetic-syslog-1B/resolve/2e8204a084de2ba490f7f452b9dfbd39d074c670/synthetic_syslog_rfc5424.txt",
        "bytes": 268435456, "total_bytes": 14930735753,
        "sha256": "ed877a90fcd2af30024977f124b9051407eb9c8de2d8d0cc4ea4a9318823615f",
        "origin": "Synthetic SIEM benchmark; first 256 MiB, cut back to the last complete record",
    },
}

QUOTED = rb'"(?:[^"\\\r\n]|\\.)*"'
SYSLOG = re.compile(r'<(\d+)>1 (\S+) (\S+) (\S+) (\S+) (\S+) ((?:\[[^\]]*\])+|-) (.*)')
SD = re.compile(r'\[([^ ]+) ([^\]]*)\]')
SD_VALUE = re.compile(r'(\w+)="([^"]*)"')


def queries(name):
    if name == "json":
        selective = ('(eventName~"Delete*" OR eventName~"Create*" OR eventName~"Authorize*" OR eventName~"Revoke*") '
                     'AND readOnly=false AND eventSource=ec2.amazonaws.com AND eventVersion>=1.05 AND eventVersion<2 '
                     'AND (awsRegion=eu-central-1 OR awsRegion=us-east-2 OR awsRegion=us-west-2) '
                     'AND userAgent!="" AND NOT sourceIPAddress=127.0.0.1')
        broad = ('(eventName~"Describe*" OR eventName~"Get*" OR eventName~"List*") '
                 'AND (awsRegion~"us-*" OR awsRegion~"eu-*") AND eventVersion>=1.05 AND eventVersion<2 '
                 'AND readOnly=true AND (userAgent~"eks*" OR userAgent~"autoscaling*" OR userAgent~"aws-internal*" '
                 'OR userAgent~"Boto3*" OR userAgent~"aws-sdk-go*" OR userAgent~"console.ec2*") '
                 'AND sourceIPAddress!=""')
        predicates = {
            "selective": lambda f: (f["eventName"].startswith(("Delete", "Create", "Authorize", "Revoke"))
                                     and f.get("readOnly") is False and f["eventSource"] == "ec2.amazonaws.com"
                                     and 1.05 <= float(f["eventVersion"]) < 2
                                     and f["awsRegion"] in {"eu-central-1", "us-east-2", "us-west-2"}
                                     and bool(f.get("userAgent")) and f.get("sourceIPAddress") != "127.0.0.1"),
            "broad": lambda f: (f["eventName"].startswith(("Describe", "Get", "List"))
                                and f["awsRegion"].startswith(("us-", "eu-")) and 1.05 <= float(f["eventVersion"]) < 2
                                and f.get("readOnly") is True
                                and f.get("userAgent", "").startswith(("eks", "autoscaling", "aws-internal", "Boto3", "aws-sdk-go", "console.ec2"))
                                and bool(f.get("sourceIPAddress"))),
        }
        field, prefix = "userAgent", "aws-internal/3 aws-sdk-java/1.11.922 benchmark-absent-"
    else:
        selective = ('format=syslog AND (source=sshd OR source=nginx OR source=kernel) AND '
                     'priority>=0 AND priority<=191 AND NOT host=host99.example.com AND '
                     '((syslog_sd.auth.result=failure AND (syslog_sd.auth.user=root OR syslog_sd.auth.user=admin) '
                     'AND message~"Failed password for *") OR '
                     '(syslog_sd.http.status>=500 AND syslog_sd.http.method=POST AND syslog_sd.http.path~"/admin*") '
                     'OR (syslog_sd.net.action=DROP AND syslog_sd.net.dst_port>=1024))')
        broad = ('format=syslog AND priority>=0 AND priority<=191 AND NOT host=host99.example.com AND '
                 '((message~"Connection *" AND syslog_sd.net.dst_port>=22) OR '
                 '(source=sshd AND (message~"Failed password *" OR message~"Accepted password *")) OR '
                 '(source=nginx AND syslog_sd.http.status>=200) OR '
                 '(message~"cron *" OR message~"sudo *" OR message~"kernel *" OR message~"nginx *" OR message~"sshd *"))')
        predicates = {
            "selective": lambda f: (f["format"] == "syslog" and f["source"] in {"sshd", "nginx", "kernel"}
                                     and 0 <= int(f["priority"]) <= 191 and f["host"] != "host99.example.com"
                                     and ((f.get("syslog_sd.auth.result") == "failure"
                                           and f.get("syslog_sd.auth.user") in {"root", "admin"}
                                           and f["message"].startswith("Failed password for "))
                                          or (numeric(f, "syslog_sd.http.status", 500)
                                              and f.get("syslog_sd.http.method") == "POST"
                                              and f.get("syslog_sd.http.path", "").startswith("/admin"))
                                          or (f.get("syslog_sd.net.action") == "DROP"
                                              and numeric(f, "syslog_sd.net.dst_port", 1024)))),
            "broad": lambda f: (f["format"] == "syslog" and 0 <= int(f["priority"]) <= 191
                                and f["host"] != "host99.example.com"
                                and ((f["message"].startswith("Connection ") and numeric(f, "syslog_sd.net.dst_port", 22))
                                     or (f["source"] == "sshd" and f["message"].startswith(("Failed password ", "Accepted password ")))
                                     or (f["source"] == "nginx" and numeric(f, "syslog_sd.http.status", 200))
                                     or f["message"].startswith(("cron ", "sudo ", "kernel ", "nginx ", "sshd ")))),
        }
        field, prefix = "message", "Failed password for benchmark-absent-"
    alternatives = [prefix + f"{i:02}" for i in range(24)]
    late = " OR ".join(f'{field}~"{value}*"' for value in alternatives)
    return [
        {"name": "parse", "filter": None, "predicate": lambda f: True},
        {"name": "selective", "filter": selective, "predicate": predicates["selective"]},
        {"name": "broad", "filter": broad, "predicate": predicates["broad"]},
        {"name": "late-miss", "filter": late,
         "predicate": lambda f: f.get(field, "").startswith(tuple(alternatives))},
    ]


def numeric(fields, key, minimum):
    value = fields.get(key, "")
    return value.isdecimal() and int(value) >= minimum


def record(name, raw):
    line = raw.rstrip(b"\r\n")
    if name == "json":
        fields = json.loads(line)
        return line + b"\n", {**fields, "format": "json"}, False
    match = SYSLOG.fullmatch(line.decode("utf-8"))
    if not match:
        raise ValueError("unexpected RFC 5424 record in pinned source")
    priority, timestamp, host, source, pid, msgid, data, message = match.groups()
    fields = dict(format="syslog", priority=priority, timestamp=timestamp, host=host, source=source,
                  pid=pid, msgid=msgid, message=message)
    for group, content in SD.findall(data):
        fields.update((f"syslog_sd.{group}.{key}", value) for key, value in SD_VALUE.findall(content))
    return line + b"\n", fields, False


def download(source, destination):
    print(f'Downloading {source["title"]}', file=sys.stderr, flush=True)
    headers = {"User-Agent": "lumtail-public-log-benchmark/1"}
    if "total_bytes" in source:
        headers["Range"] = f'bytes=0-{source["bytes"] - 1}'
    request = urllib.request.Request(source["url"], headers=headers)
    digest, count = hashlib.sha256(), 0
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as target:
        if "total_bytes" in source and (response.status != 206 or response.headers.get("Content-Range") !=
                                       f'bytes 0-{source["bytes"] - 1}/{source["total_bytes"]}'):
            raise ValueError("server did not honor the pinned byte range")
        for chunk in iter(lambda: response.read(1024 * 1024), b""):
            count += len(chunk)
            if count > source["bytes"]:
                raise ValueError("download exceeds pinned size")
            target.write(chunk)
            digest.update(chunk)
    if count != source["bytes"] or digest.hexdigest() != source["sha256"]:
        raise ValueError(f'download size or SHA-256 mismatch: {source["title"]}')


def prepare(name, source, folder, target_bytes):
    downloaded = folder / "download"
    download(source, downloaded)
    archive = zipfile.ZipFile(downloaded) if "member" in source else None
    if archive and archive.getinfo(source["member"]).file_size != source["member_bytes"]:
        archive.close()
        raise ValueError("unexpected archive member size")
    cases = queries(name)
    counts = Counter()
    formats = Counter()
    hashes = {case["name"]: hashlib.sha256() for case in cases}
    base, changed, dropped = folder / "source.log", 0, 0
    try:
        with (archive.open(source["member"]) if archive else downloaded.open("rb")) as stream, base.open("wb") as target:
            for raw in stream:
                if "total_bytes" in source and not raw.endswith(b"\n"):
                    dropped = len(raw)
                    break
                if len(raw) > 1024 * 1024:
                    raise ValueError("source record exceeds 1 MiB")
                normalized, fields, modified = record(name, raw)
                target.write(normalized)
                changed += modified
                formats[fields["format"]] += 1
                for case in cases:
                    if case["predicate"](fields):
                        counts[case["name"]] += 1
                        hashes[case["name"]].update(normalized)
    finally:
        if archive:
            archive.close()
    downloaded.unlink()
    if not counts["parse"] or not 0 < counts["selective"] < counts["parse"] or not counts["broad"]:
        raise ValueError("source did not exercise both accepted and rejected content")
    if counts["late-miss"]:
        raise ValueError("the absent-prefix control matched source content")
    size = base.stat().st_size
    passes = max(1, math.ceil(target_bytes / size))
    path = base
    if passes > 1:
        path = folder / "input.log"
        with path.open("wb") as output:
            for _ in range(passes):
                with base.open("rb") as stream:
                    shutil.copyfileobj(stream, output, 1024 * 1024)
    info = {"source": source, "source_records": counts["parse"], "source_bytes": size,
            "source_formats": dict(formats), "normalized_records": changed, "dropped_range_tail_bytes": dropped,
            "passes": passes, "input_records": counts["parse"] * passes, "input_bytes": size * passes,
            "input_sha256": file_hash(path),
            "queries": [{"name": case["name"], "filter": case["filter"],
                         "source_matches": counts[case["name"]],
                         "source_raw_sha256": hashes[case["name"]].hexdigest(),
                         "matches": counts[case["name"]] * passes} for case in cases]}
    return base, path, info


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command(binary, path, query, mode, workers, records, stats=True):
    return [str(binary), "--api-version=1", "--color=never", f"--threads={workers}", f"--output={mode}",
            *(["--stats"] if stats else []), *([f"--limit={records + 1}"] if mode == "agent" else []),
            *(["--filter", query["filter"]] if query["filter"] else []), str(path)]


def validate_sample(sample, info, query):
    stats = sample["stats"]
    if stats.get("stats_version") != 1 or stats.get("complete") is not True or stats.get("bytes_read") != info["input_bytes"]:
        raise ValueError("measurement did not finish reading the complete input")
    if stats.get("records") != query["matches"]:
        raise ValueError(f'expected {query["matches"]} matches, got {stats.get("records")}')


def invoke_worker(spec):
    # A private process group lets cancellation stop the worker and its measured child.
    with subprocess.Popen([sys.executable, str(ROOT / "benchmarks/worker.py")],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, start_new_session=True) as process:
        try:
            output, error = process.communicate(json.dumps(spec), timeout=spec["timeout"] + 10)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        if process.returncode:
            raise RuntimeError(error.strip() or f"worker exited {process.returncode}")
        return json.loads(output)


def measure(args, binary, base, path, info, checkpoint):
    for query in info["queries"]:
        result = invoke_worker({"command": command(binary, base, query, "raw", "1", info["source_records"], False),
                                "kind": "hash", "timeout": args.timeout})
        if result["output_records"] != query["source_matches"] or result["output_sha256"] != query["source_raw_sha256"]:
            raise ValueError(f'independent raw selection differs: {query["name"]}')
    rows = []
    for query in info["queries"]:
        for mode in args.mode:
            reference = None
            for workers in args.threads:
                cmd = command(binary, path, query, mode, workers, info["input_records"])
                print(f'Checking {args.current}/{query["name"]}/{mode}/{workers}', file=sys.stderr, flush=True)
                checked = invoke_worker({"command": cmd, "kind": "hash", "stats": True, "timeout": args.timeout})
                validate_sample(checked, info, query)
                if checked["output_records"] != query["matches"]:
                    raise ValueError("output line count differs from the independent count")
                if reference is not None and checked["output_sha256"] != reference:
                    raise ValueError("complete output differs across worker counts")
                reference = checked["output_sha256"]
                row = {"corpus": args.current, "query": query["name"], "mode": mode, "threads": workers,
                       "command": cmd, "output_sha256": reference, "output_bytes": checked["output_bytes"],
                       "matches": query["matches"], "samples": [], "warmup_samples": []}
                for _ in range(args.warmups):
                    sample = invoke_worker({"command": cmd, "stats": True, "timeout": args.timeout})
                    validate_sample(sample, info, query)
                    row["warmup_samples"].append(sample)
                rows.append(row)
    rng = random.Random(args.seed)
    for repetition in range(args.repetitions):
        order = list(rows)
        rng.shuffle(order)
        for row in order:
            print(f'Measuring {args.current}/{row["query"]}/{row["mode"]}/{row["threads"]} '
                  f'{repetition + 1}/{args.repetitions}', file=sys.stderr, flush=True)
            sample = invoke_worker({"command": row["command"], "stats": True, "timeout": args.timeout})
            query = next(q for q in info["queries"] if q["name"] == row["query"])
            validate_sample(sample, info, query)
            row["samples"].append(sample)
            checkpoint(rows)
    for row in rows:
        for key in ("seconds", "user_seconds", "system_seconds"):
            row[key] = distribution([sample[key] for sample in row["samples"]])
        rss = [sample["peak_rss_bytes"] for sample in row["samples"]]
        row["peak_rss_bytes"] = distribution(rss) if all(value is not None for value in rss) else None
        row["cpu_seconds"] = distribution([s["user_seconds"] + s["system_seconds"] for s in row["samples"]])
        row["input_mib_per_second"] = info["input_bytes"] / 1048576 / row["seconds"]["median"]
        row["input_records_per_second"] = info["input_records"] / row["seconds"]["median"]
    return rows


def host_metadata(binary):
    # This script runs from ROOT, so trusting ROOT's owner adds no trust; CI VMs copy it as another user.
    git = ["git", "-c", f"safe.directory={ROOT}"]

    def capture(cmd):
        return subprocess.check_output(cmd, text=True, cwd=ROOT, timeout=15).strip()
    build = build_metadata(binary)
    if build.get("cmake_cache"):
        build["cmake_cache_sha256"] = file_hash(Path(build["cmake_cache"]))
        for line in Path(build["cmake_cache"]).read_text().splitlines():
            key, separator, value = line.partition("=")
            key = key.partition(":")[0]
            if separator and key in {"LUMTAIL_SIMD", "CMAKE_OSX_SYSROOT", "LUMTAIL_WARNINGS_AS_ERRORS"}:
                build["options"][key] = value
    compiler = build.get("options", {}).get("CMAKE_CXX_COMPILER")
    return {"platform": platform.platform(), "machine": platform.machine(), "logical_cpus": os.cpu_count(),
            "cpu": capture(["sysctl", "-n", "machdep.cpu.brand_string"]) if sys.platform == "darwin" else platform.processor(),
            "python": platform.python_version(), "build": build,
            "compiler_version": capture([compiler, "--version"]) if compiler else None,
            "runtime_libraries": capture(["otool", "-L", str(binary)]) if sys.platform == "darwin" else None,
            "revision": capture([*git, "rev-parse", "HEAD"]), "workspace_status": capture([*git, "status", "--short"]),
            "tracked_diff_sha256": hashlib.sha256(
                subprocess.check_output([*git, "diff", "HEAD"], cwd=ROOT, timeout=15)).hexdigest(),
            "driver_sha256": file_hash(Path(__file__)), "worker_sha256": file_hash(ROOT / "benchmarks/worker.py")}


def save(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--corpus", choices=SOURCES, nargs="+", default=list(SOURCES))
    parser.add_argument("--target-mib", type=integer, default=1024, help="minimum input per corpus; repeat complete source passes")
    parser.add_argument("--threads", type=threads, nargs="+", default=["1", "auto"])
    parser.add_argument("--mode", choices=("json", "agent"), nargs="+", default=["json", "agent"])
    parser.add_argument("--warmups", type=lambda v: integer(v, 0), default=1)
    parser.add_argument("--repetitions", type=integer, default=5)
    parser.add_argument("--timeout", type=positive_float, default=600)
    parser.add_argument("--seed", type=int, default=20261110)
    parser.add_argument("--directory", type=Path, default=ROOT / ".cache/benchmark-inputs")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema_version": 1, "license": "MIT", "copyright": "2026 lumtail contributors",
              "status": "running", "created_utc": datetime.now(timezone.utc).isoformat(),
              "invocation": shlex.join([sys.executable, *sys.argv]), "settings": {
                  key: getattr(args, key) for key in ("corpus", "target_mib", "threads", "mode", "warmups", "repetitions", "timeout", "seed")},
              "measurement": "warm filesystem cache; full read/parse/filter/render to /dev/null; startup included; seeded shuffled rounds",
              "corpora": {}, "results": [], "cleanup": []}
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        binary = args.binary.resolve(strict=True)
        report.update(binary=str(binary), binary_sha256=file_hash(binary), host=host_metadata(binary))
        args.directory.mkdir(parents=True, exist_ok=True)
        for name in dict.fromkeys(args.corpus):
            args.current = name
            temporary = None
            try:
                with tempfile.TemporaryDirectory(prefix=f"lumtail-public-{name}-", dir=args.directory) as temporary:
                    folder = Path(temporary)
                    base, path, info = prepare(name, SOURCES[name], folder, args.target_mib * 1048576)
                    report["corpora"][name] = info
                    completed = list(report["results"])
                    def checkpoint(rows):
                        report["results"] = completed + rows
                        save(args.output, report)
                    report["results"] = completed + measure(args, binary, base, path, info, checkpoint)
            finally:
                if temporary is not None:
                    report["cleanup"].append({"corpus": name, "temporary_directory": temporary,
                                              "removed": not Path(temporary).exists()})
                    print(f"Removed temporary input/cache for {name}", file=sys.stderr, flush=True)
                save(args.output, report)
        if file_hash(binary) != report["binary_sha256"]:
            raise ValueError("measured executable changed during the run")
        report["status"] = "complete"
    except KeyboardInterrupt:
        report.update(status="interrupted", error="interrupted")
        return 130
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        report.update(status="failed", error=str(error))
        print(f"public logs: {error}", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save(args.output, report)
    print(f"Report: {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
