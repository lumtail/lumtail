# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Isolated measurement worker; invoke suite.py for the public benchmark CLI."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import resource
import select
import signal
import subprocess
import sys
import tempfile
import time


def memory_usage(raw, system):
    """Retain the kernel observation without presenting a zero as measured RSS."""
    if raw < 0:
        raise ValueError("negative kernel ru_maxrss")
    unit = "bytes" if system == "darwin" else "KiB"
    return {"peak_rss_bytes": int(raw * (1 if unit == "bytes" else 1024)) if raw else None,
            "rss_status": "available" if raw else "unavailable_kernel_zero",
            "ru_maxrss": raw, "ru_maxrss_unit": unit}


def read_record(stream, deadline):
    """Read one response without buffering bytes belonging to the next response."""
    result = bytearray()
    while not result.endswith(b"\n"):
        remaining = deadline - time.perf_counter()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            raise TimeoutError("timed out waiting for a complete response")
        chunk = os.read(stream.fileno(), 65536)
        if not chunk:
            raise RuntimeError("process closed stdout before returning a response")
        result.extend(chunk)
    return bytes(result)


def measure(spec):
    timeout = spec["timeout"]
    kind = spec.get("kind", "batch")
    with tempfile.TemporaryFile() as error, tempfile.TemporaryFile() as captured, ExitStack() as streams:
        follow = spec.get("follow_path")
        source = streams.enter_context(open(follow, "wb", buffering=0)) if follow else None
        with open(spec.get("destination", os.devnull), "wb", buffering=0) as sink:
            started = time.perf_counter()
            process = subprocess.Popen(
                spec["command"], stdin=subprocess.PIPE if kind == "latency" and not follow else subprocess.DEVNULL,
                stdout=subprocess.PIPE if kind == "latency" else (captured if kind == "capture" else sink),
                stderr=error, bufsize=0,
            )
            deadline = started + timeout

            def expired(signum, frame):
                raise TimeoutError("benchmark exceeded its time limit")

            previous_handler = signal.signal(signal.SIGALRM, expired)
            signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline - time.perf_counter()))
            responses = []
            first_response = None
            try:
                if kind == "latency":
                    for index in range(spec["requests"] + 1):
                        payload = json.dumps({"level": "error", "service": "api", "seq": index,
                                              "message": "benchmark response"}).encode() + b"\n"
                        if spec.get("multiline"):
                            payload += b"  at benchmark.frame(example.cpp:42)\n"
                        sent = time.perf_counter()
                        (source if follow else process.stdin).write(payload)
                        raw = read_record(process.stdout, deadline)
                        received = time.perf_counter()
                        response = json.loads(raw)
                        if response["fields"]["seq"] != str(index):
                            raise RuntimeError("response did not match the submitted record")
                        if spec.get("multiline") and "continuation" not in response:
                            raise RuntimeError("response did not contain the submitted continuation")
                        if index == 0:
                            first_response = received - started
                        else:
                            responses.append(received - sent)
                    if follow:
                        # Stop follow after the final response to collect CPU and RSS.
                        process.terminate()
                    else:
                        process.stdin.close()
                # Use SIGALRM to avoid wait polling in startup measurements.
                process.wait()
                elapsed = time.perf_counter() - started
                if process.returncode and not (follow and process.returncode == -signal.SIGTERM):
                    error.seek(0)
                    raise RuntimeError(f"exit {process.returncode}: " +
                                       error.read(8192).decode("utf-8", errors="replace"))
                # Measure one child so earlier peaks cannot affect its RSS.
                usage = resource.getrusage(resource.RUSAGE_CHILDREN)
                sync_seconds = None
                if spec.get("sync"):
                    sync_started = time.perf_counter()
                    os.fsync(sink.fileno())
                    sync_seconds = time.perf_counter() - sync_started
                result = {"seconds": elapsed, **memory_usage(usage.ru_maxrss, sys.platform),
                          "user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime}
                if "destination" in spec:
                    result["output_bytes"] = Path(spec["destination"]).stat().st_size
                if sync_seconds is not None:
                    result["fsync_seconds"] = sync_seconds
                    result["save_seconds"] = elapsed + sync_seconds
                if kind == "latency":
                    result.update(first_response_seconds=first_response, response_seconds=responses)
                if kind == "capture":
                    captured.seek(0)
                    result["payload"] = json.load(captured)
                return result
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous_handler)
                if process.poll() is None:
                    process.kill()
                process.wait()
                for stream in (process.stdin, process.stdout):
                    if stream is not None:
                        stream.close()


def main():
    try:
        result = measure(json.load(sys.stdin))
        print(json.dumps(result, allow_nan=False))
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as error:
        print(f"benchmark worker: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
