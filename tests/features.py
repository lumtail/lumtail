# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Logical records, normalized filters and portable metadata output contracts."""

import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())
SCALE = float(os.environ.get("LUMTAIL_TEST_TIMEOUT_SCALE", "1"))


def run(*args, data="", code=0):
    result = subprocess.run([BINARY, *map(str, args)], input=data, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15 * SCALE)
    if result.returncode != code:
        raise AssertionError(f"exit {result.returncode}, expected {code}: {result.stderr}")
    return result


def rows(*args, data=""):
    return [json.loads(line) for line in run("--output=json", *args, data=data).stdout.splitlines()]


class FeatureTests(unittest.TestCase):
    def test_grouping_keeps_header_fields_raw_and_first_physical_line(self):
        first = json.dumps({"level": "info", "message": "first"})
        second = json.dumps({"level": "error", "message": "second"})
        data = first + "\n  first frame\n\tsecond frame\n" + second + "\n  failed frame\nplain\n"
        default = rows(data=data)
        self.assertEqual(len(default), 6)
        grouped = rows("--multiline=indent", data=data)
        self.assertEqual([row["line"] for row in grouped], [1, 4, 6])
        self.assertEqual([row["format"] for row in grouped], ["json", "json", "plain"])
        self.assertEqual(grouped[0]["raw"], first + "\n  first frame\n\tsecond frame")
        self.assertEqual(grouped[0]["continuation"], "  first frame\n\tsecond frame")
        self.assertEqual(grouped[0]["fields"]["message"], "first")
        self.assertNotIn("continuation", grouped[2])
        filtered = rows("--multiline=indent", "--errors-only", data=data)
        self.assertEqual(filtered, [grouped[1]])

    def test_threshold_uses_normalized_severity_and_excludes_unknown(self):
        data = "\n".join(json.dumps({"level": level, "message": str(level)})
                         for level in ["trace", "debug", "info", "warning", "err", "fatal", "other"])
        self.assertEqual([r["level"] for r in rows("--min-level=info", data=data)],
                         ["INFO", "WARN", "ERROR", "CRITICAL"])
        self.assertEqual([r["level"] for r in rows("--min-level=50", data=data)], ["ERROR", "CRITICAL"])
        self.assertEqual([r["level"] for r in rows("--min-level=critical", "--errors-only", data=data)], ["CRITICAL"])
        self.assertEqual(len(rows("--min-level=trace", data=data)), 6)

    def test_where_is_exact_and_repeated_conditions_use_and(self):
        data = '\n'.join(json.dumps(record) for record in [
            {"service": "api", "env": "prod", "level": "error", "token": "a=b"},
            {"service": "api", "env": "dev", "level": "error"},
            {"service": "worker", "env": "prod", "level": "error"},
        ])
        selected = rows("--where", "service=api", "--where=env=prod", "--where=level=ERROR", data=data)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["fields"]["token"], "a=b")
        self.assertEqual(len(rows("--where=token=a=b", data=data)), 1)
        self.assertEqual(rows("--where=service=API", data=data), [])
        self.assertEqual(rows("--where=service=api", "--where=service=worker", data=data), [])

    def test_empty_values_do_not_match_missing_fields(self):
        data = '{"label":"","message":"present"}\n{"message":"absent"}\n'
        selected = rows("--where=label=", data=data)
        self.assertEqual([r["fields"]["message"] for r in selected], ["present"])
        self.assertEqual(rows("--where=missing=", data=data), [])

    def test_metadata_filters_keep_physical_line_numbers(self):
        data = '{"level":"info"}\n  frame\n{"level":"error"}\n  failed\n'
        selected = rows("--multiline=indent", "--where=line=3", "--where=file=-", "--where=format=json", data=data)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["line"], 3)
        self.assertEqual(selected[0]["continuation"], "  failed")
        raw = selected[0]["raw"]
        self.assertEqual(len(rows("--multiline=indent", "--where", "raw=" + raw, data=data)), 1)

    def test_raw_filtering_never_uses_the_unfiltered_fast_path(self):
        first = '{"service":"api","level":"info"}'
        second = '{"service":"worker","level":"error"}'
        data = first + "\n  ignored\n" + second + "\n  kept\n"
        for workers in (1, 4):
            for grouping in ("off", "indent"):
                for flags in [("--min-level=error",), ("--where=service=worker",)]:
                    with self.subTest(workers=workers, grouping=grouping, flags=flags):
                        expected = second + ("\n  kept" if grouping == "indent" else "") + "\n"
                        self.assertEqual(run(f"--threads={workers}", "--output=raw", f"--multiline={grouping}",
                                             *flags, data=data).stdout, expected)

    def test_text_keeps_structural_newlines_but_escapes_message_controls(self):
        header = json.dumps({"level": "error", "message": "failure\nforged\u202e"})
        data = header + "\n  frame\x1b[2J\u202e\n"
        text = run("--multiline=indent", "--color=never", "--template={level}: {message}", data=data).stdout
        self.assertEqual(text, "ERROR: failure\\x0aforged\\xe2\\x80\\xae\n  frame\\x1b[2J\\xe2\\x80\\xae\n")
        raw_header = run("--multiline=indent", "--template={raw}", data=data).stdout
        self.assertEqual(raw_header.count("frame"), 1)

    def test_orphans_blank_lines_crlf_and_unterminated_records(self):
        grouped = rows("--multiline=indent", data="  orphan\r\nhead\r\n  frame\r\n\r\nlast\n  final")
        self.assertEqual([r["line"] for r in grouped], [1, 2, 4, 5])
        self.assertEqual([r["raw"] for r in grouped], ["  orphan", "head\n  frame", "", "last\n  final"])

    def test_records_do_not_cross_file_boundaries(self):
        with tempfile.TemporaryDirectory() as folder:
            first, second = Path(folder) / "first", Path(folder) / "second"
            first.write_text("head\n  first")
            second.write_text("  orphan\nnext\n")
            grouped = rows("--multiline=indent", first, second)
            self.assertEqual([r["raw"] for r in grouped], ["head\n  first", "  orphan", "next"])
            self.assertEqual([r["line"] for r in grouped], [1, 1, 2])
            self.assertEqual([r["file"] for r in grouped], [str(first), str(second), str(second)])

    def test_record_limit_rejects_whole_record_and_preserves_completed_prefix(self):
        self.assertEqual(run("--multiline=indent", "--max-record-bytes=8", "--output=raw",
                             data="head\n xx\n").stdout, "head\n xx\n")
        failed = run("--multiline=indent", "--max-record-bytes=7", "--output=raw", data="head\n xx\n", code=1)
        self.assertEqual(failed.stdout, "")
        self.assertIn("record starting at line 1", failed.stderr)
        oversized_header = run("--multiline=indent", "--max-record-bytes=3", "--output=raw",
                               data="head\n", code=1)
        self.assertEqual(oversized_header.stdout, "")
        with tempfile.TemporaryDirectory() as folder:
            first, second = Path(folder) / "first", Path(folder) / "second"
            first.write_text("ok\nbad\n  too long\n")
            second.write_text("last\n")
            failed = run("--multiline=indent", "--max-record-bytes=8", "--output=raw", first, second, code=1)
            self.assertEqual(failed.stdout, "ok\nlast\n")

    def test_physical_line_error_discards_incomplete_logical_record(self):
        failed = run("--multiline=indent", "--max-line-bytes=8", "--output=raw",
                     data="ok\nbad\n  123456789\n", code=1)
        self.assertEqual(failed.stdout, "ok\n")
        self.assertIn("max-line-bytes", failed.stderr)

    def test_parallel_records_cross_batches_and_keep_order(self):
        records = [json.dumps({"level": "error" if i % 3 else "info", "seq": i}) + f"\n  frame {i}"
                   for i in range(1600)]
        records[9] += "\n  " + "x" * 300000
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "records.log"
            source.write_text("\n".join(records))
            for mode in ("raw", "text", "json"):
                flags = ["--multiline=indent", "--output", mode, "--color=never", str(source)]
                self.assertEqual(run("--threads=1", *flags).stdout, run("--threads=8", *flags).stdout)
            grouped = rows("--multiline=indent", source)
            self.assertEqual(len(grouped), 1600)
            self.assertEqual([r["fields"]["seq"] for r in grouped], list(map(str, range(1600))))
            self.assertEqual(grouped[10]["line"], 22)

    def test_live_pipe_flushes_without_eof_and_late_lines_start_new_record(self):
        process = subprocess.Popen([BINARY, "--multiline=indent", "--multiline-timeout-ms=80",
                                    "--output=json", "--threads=4"], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(b'{"level":"error"}\n  frame\n')
            process.stdin.flush()
            self.assertTrue(select.select([process.stdout], [], [], 5 * SCALE)[0], "record held until EOF")
            first = json.loads(process.stdout.readline())
            self.assertEqual(first["continuation"], "  frame")
            process.stdin.write(b"  late\n")
            process.stdin.flush()
            self.assertTrue(select.select([process.stdout], [], [], 5 * SCALE)[0], "late record held")
            second = json.loads(process.stdout.readline())
            self.assertEqual((second["raw"], second["line"]), ("  late", 3))
            process.stdin.close()
            process.stdin = None
            _, error = process.communicate(timeout=5 * SCALE)
            self.assertEqual((process.returncode, error), (0, b""))
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5 * SCALE)

    def test_follow_flushes_idle_records_and_restarts_line_numbers_after_rotation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "follow.log"
            path.write_text('{"level":"error"}\n  frame\n')
            process = subprocess.Popen([BINARY, "--follow", "--multiline=indent",
                                        "--multiline-timeout-ms=80", "--output=json", str(path)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertTrue(select.select([process.stdout], [], [], 5 * SCALE)[0])
                first = json.loads(process.stdout.readline())
                self.assertEqual((first["line"], first["continuation"]), (1, "  frame"))
                path.rename(path.with_suffix(".old"))
                path.write_text("  orphan\n")
                self.assertTrue(select.select([process.stdout], [], [], 5 * SCALE)[0])
                second = json.loads(process.stdout.readline())
                self.assertEqual((second["line"], second["raw"]), (1, "  orphan"))
                # No further output is pending, so no write can observe EPIPE.
                # This test verifies idle framing/rotation, then ends follow.
                process.terminate()
                process.wait(timeout=5 * SCALE)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5 * SCALE)

    def test_closed_output_cancels_a_pending_multiline_record(self):
        for workers in (1, 4):
            process = subprocess.Popen([BINARY, f"--threads={workers}", "--multiline=indent"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            try:
                process.stdout.close()
                try:
                    process.stdin.write(b'{"level":"error"}\n  frame\n')
                    process.stdin.flush()
                except BrokenPipeError:
                    pass
                self.assertEqual(process.wait(timeout=5 * SCALE), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5 * SCALE)

    def test_invalid_arguments_and_metadata_write_failures(self):
        for args in [("--where=oops",), ("--where==value",), ("--min-level=unknown",),
                     ("--min-level=oops",), ("--multiline=regex",), ("--max-record-bytes=0",),
                     ("--multiline-timeout-ms=0",), ("--multiline-timeout-ms=60001",), ("--where",)]:
            with self.subTest(args=args):
                run(*args, code=2)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "read-only"
            path.write_text("input")
            for flag in ("--help", "--version", "--list-modules"):
                with path.open("rb") as sink:
                    result = subprocess.run([BINARY, flag], stdout=sink, stderr=subprocess.PIPE, timeout=5 * SCALE)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(b"stdout", result.stderr)


if __name__ == "__main__":
    unittest.main()
