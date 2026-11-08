# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Ordered parallel output, bounded expansion and cancellation regressions."""

import hashlib
import json
import os
from pathlib import Path
import random
import select
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())
ROOT = Path(__file__).resolve().parents[1]
TIMEOUT_SCALE = float(os.environ.get("LUMTAIL_TEST_TIMEOUT_SCALE", "1"))


def run(*args, data=b"", code=0):
    result = subprocess.run([BINARY, *map(str, args)], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20 * TIMEOUT_SCALE)
    if result.returncode != code:
        raise AssertionError(f"exit {result.returncode}, expected {code}: {result.stderr!r}")
    return result


class ConcurrencyTests(unittest.TestCase):
    def test_order_and_equivalence_across_files_modes_and_worker_counts(self):
        generator = random.Random(77319)
        records = []
        for index in range(4000):
            message = f"record {index}: " + "x" * generator.randrange(1, 220)
            records.append(json.dumps({"level": "error" if index % 7 == 0 else "info",
                                       "message": message}) if index % 3 else message)
        # Cross input blocks and batches; preserve empty lines, CRLF and final LF.
        records[31] = "L" * 300000
        records[57] = ""
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder) / f"{index}.log" for index in range(3)]
            for index, path in enumerate(paths):
                path.write_bytes("\r\n".join(records[index::3]).encode())
            for mode in ("raw", "text", "json"):
                for filtered in (False, True):
                    flags = ["--output", mode, "--rules", ROOT / "examples/modules.json"]
                    if filtered:
                        flags.append("--errors-only")
                    expected = run("--threads=1", *flags, *paths).stdout
                    for workers in (2, 4, 16):
                        with self.subTest(mode=mode, filtered=filtered, workers=workers):
                            self.assertEqual(run(f"--threads={workers}", *flags, *paths).stdout,
                                             expected)

    def test_expanded_output_is_streamed_instead_of_accumulated(self):
        template = "z" * 60000
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "empty-lines.log"
            path.write_bytes(b"\n" * 512)
            for workers in (1, 4):
                with self.subTest(workers=workers):
                    # Hash stdout incrementally, without buffering its 29 MiB.
                    with subprocess.Popen([BINARY, f"--threads={workers}", "--template", template,
                                           str(path)], stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE) as process:
                        digest = hashlib.sha256()
                        count = 0
                        deadline = time.monotonic() + 30 * TIMEOUT_SCALE
                        while True:
                            self.assertGreater(deadline, time.monotonic(), "output expansion stalled")
                            self.assertTrue(select.select([process.stdout], [], [], 5)[0],
                                            "expanded output stalled")
                            chunk = os.read(process.stdout.fileno(), 1024 * 1024)
                            if not chunk:
                                break
                            count += len(chunk)
                            digest.update(chunk)
                        self.assertEqual(process.wait(timeout=5), 0)
                        self.assertEqual(process.stderr.read(), b"")
                    expected = hashlib.sha256()
                    for _ in range(512):
                        expected.update((template + "\n").encode())
                    self.assertEqual(count, 512 * 60001)
                    self.assertEqual(digest.digest(), expected.digest())

    def test_invalid_thread_counts(self):
        for count in ("0", "257", "-1", "1x", "4294967296", ""):
            with self.subTest(count=count):
                self.assertIn(b"threads", run(f"--threads={count}", code=2).stderr)
        for flag in ("--threads=auto", "-j=2", "--threads=256"):
            self.assertEqual(run(flag, "--output=raw", data=b"ok\n").stdout, b"ok\n")
        self.assertEqual(run("--threads=256", "--template={raw}", data=b"ok\n").stdout, b"ok\n")

    def test_expanded_json_limit_preserves_the_exact_prefix(self):
        # Escaping expands each short input batch into several output chunks.
        # Limits must cancel queued work without losing a spanning record's end.
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "expanded.log"
            path.write_bytes(b"".join(f"{index} ".encode() + b"\\" * 131069 + b"\n"
                                     for index in range(8)))
            for limit in (1, 2, 3, 7):
                flags = ["--output=json", f"--limit={limit}", path]
                expected = run("--threads=1", *flags).stdout
                self.assertEqual(len(expected.splitlines()), limit)
                for workers in (2, 4, 16):
                    with self.subTest(limit=limit, workers=workers):
                        self.assertEqual(run(f"--threads={workers}", *flags).stdout, expected)

    def test_valid_prefix_and_next_file_survive_input_error(self):
        with tempfile.TemporaryDirectory() as folder:
            first, second = Path(folder) / "first", Path(folder) / "second"
            first.write_bytes(b"valid\n" * 100 + b"longer than permitted\n")
            second.write_bytes(b"next\n")
            for workers in (1, 4):
                result = run(f"--threads={workers}", "--max-line-bytes=5", "--output=raw",
                             first, second, code=1)
                self.assertEqual(result.stdout, b"valid\n" * 100 + b"next\n")
                self.assertIn(b"exceeds", result.stderr)

    def test_worker_exception_wakes_the_entire_pipeline(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "large.log"
            path.write_bytes((b"x" * (1024 * 1024) + b"\n") * 4)
            for workers in (1, 4, 16):
                result = run(f"--threads={workers}", "--template", "{raw}" * 17, path, code=1)
                self.assertIn(b"rendered line exceeds", result.stderr)

    def test_closed_output_cancels_a_reader_waiting_for_more_stdin(self):
        for workers in (1, 2, 16):
            with self.subTest(workers=workers):
                process = subprocess.Popen([BINARY, f"--threads={workers}", "--template={raw}"],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
                try:
                    process.stdout.close()
                    process.stdin.write(b"a record\n")
                    process.stdin.flush()
                    # Keep stdin open: the reader must observe writer cancellation.
                    self.assertEqual(process.wait(timeout=5), 0)
                    self.assertEqual(process.stderr.read(), b"")
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=5)

    def test_slow_consumer_keeps_output_order(self):
        data = b"".join(f"{index:06d} ".encode() + b"a" * 90 + b"\n"
                        for index in range(12000))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.log"
            path.write_bytes(data)
            with subprocess.Popen([BINARY, "--threads=16", "--template={raw}", str(path)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
                actual = bytearray()
                while True:
                    self.assertTrue(select.select([process.stdout], [], [], 5)[0], "writer stalled")
                    chunk = os.read(process.stdout.fileno(), 8192)
                    if not chunk:
                        break
                    actual.extend(chunk)
                    time.sleep(0.0005)
                self.assertEqual(process.wait(timeout=5), 0)
                self.assertEqual(process.stderr.read(), b"")
            self.assertEqual(actual, data)

    def test_follow_pipe_closure_terminates_without_new_input(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "follow.log"
            path.write_text("ready\n")
            process = subprocess.Popen([BINARY, "--threads=4", "--follow", "--template={raw}", str(path)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertTrue(select.select([process.stdout], [], [], 5)[0], "initial record was held")
                self.assertEqual(process.stdout.readline(), b"ready\n")
                process.stdout.close()
                self.assertEqual(process.wait(timeout=5), 0)
                self.assertEqual(process.stderr.read(), b"")
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_named_pipe_emits_live_records_and_observes_cancellation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.fifo"
            os.mkfifo(path)
            process = subprocess.Popen([BINARY, "--threads=4", "--template={raw}", str(path)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            writer = None
            try:
                deadline = time.monotonic() + 3 * TIMEOUT_SCALE
                while writer is None:
                    try:
                        writer = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
                    except OSError:
                        self.assertLess(time.monotonic(), deadline, "FIFO reader did not open")
                        time.sleep(0.01)
                os.write(writer, b"live fifo\n")
                self.assertTrue(select.select([process.stdout], [], [], 3)[0])
                self.assertEqual(os.read(process.stdout.fileno(), 4096), b"live fifo\n")
                process.stdout.close()
                os.write(writer, b"closed downstream\n")
                self.assertEqual(process.wait(timeout=5), 0)
                self.assertEqual(process.stderr.read(), b"")
            finally:
                if writer is not None:
                    os.close(writer)
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_cancellation_while_opening_the_next_fifo(self):
        with tempfile.TemporaryDirectory() as folder:
            first, fifo = Path(folder) / "first", Path(folder) / "fifo"
            first.write_bytes(b"record\n" * 100000)
            os.mkfifo(fifo)
            process = subprocess.Popen([BINARY, "--threads=4", "--template={raw}", str(first), str(fifo)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                process.stdout.close()
                self.assertEqual(process.wait(timeout=5), 0)
                self.assertEqual(process.stderr.read(), b"")
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
