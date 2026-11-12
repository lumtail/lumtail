# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Agent output, bounded queries, compiled filters and cancellation contracts."""

import json
from decimal import Decimal
from itertools import product
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())
SCALE = float(os.environ.get("LUMTAIL_TEST_TIMEOUT_SCALE", "1"))


def run(*args, data="", code=0):
    result = subprocess.run([BINARY, *map(str, args)], input=data, text=True,
                            capture_output=True, timeout=15 * SCALE)
    if result.returncode != code:
        raise AssertionError(f"exit {result.returncode}, expected {code}: {result.stderr}")
    return result


def rows(*args, data=""):
    return [json.loads(line) for line in run("--agent", *args, data=data).stdout.splitlines()]


class AgentContracts(unittest.TestCase):
    def test_truncation_failure_retains_source_provenance(self):
        for workers in (1, 4):
            with self.subTest(workers=workers):
                failed = run("--agent", "--fail-on-truncation", f"--threads={workers}",
                             "--max-message-bytes=4", data="ok\nlonger\n", code=1)
                self.assertIn("-:2:", failed.stderr)
                self.assertNotIn("\x1b", failed.stderr)
                # The failed record is never published; a valid prefix may exist.
                self.assertTrue(all(not json.loads(line).get("truncated", False)
                                    for line in failed.stdout.splitlines()))

    def test_limit_ignores_truncation_in_later_batches(self):
        first = json.dumps({"message": "first", "padding": "a" * 900000})
        clipped = json.dumps({"message": "x" * 200})
        for workers, multiline in product((1, 2, 4, 16), ("off", "indent")):
            for prefix in ((first,), (first, json.dumps({"message": "second"}))):
                with self.subTest(workers=workers, multiline=multiline, limit=len(prefix)):
                    selected = run("--agent", "--fail-on-truncation", "--max-message-bytes=128",
                                   f"--threads={workers}", f"--multiline={multiline}",
                                   f"--limit={len(prefix)}",
                                   data="\n".join((*prefix, clipped)) + "\n")
                    self.assertEqual(selected.stderr, "")
                    records = list(map(json.loads, selected.stdout.splitlines()))
                    self.assertEqual([record["message"] for record in records],
                                     ["first", "second"][:len(prefix)])
                    self.assertEqual([record["line"] for record in records],
                                     list(range(1, len(prefix) + 1)))
                    self.assertTrue(all(not record.get("truncated", False) for record in records))

    def test_truncation_inside_limit_preserves_completed_prefix(self):
        data = "\n".join(map(json.dumps, (
            {"message": "first", "padding": "a" * 900000},
            {"message": "second"}, {"message": "x" * 200}))) + "\n"
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir="/tmp") as source:
            source.write(data)
            source.flush()
            for workers, multiline in product((1, 2, 4, 16), ("off", "indent")):
                with self.subTest(workers=workers, multiline=multiline):
                    failed = run("--agent", "--fail-on-truncation", "--max-message-bytes=128",
                                 f"--threads={workers}", f"--multiline={multiline}",
                                 "--limit=3", "--stats", source.name, code=1)
                    self.assertEqual([json.loads(line)["message"] for line in failed.stdout.splitlines()],
                                     ["first", "second"])
                    diagnostic, statistics = failed.stderr.splitlines()
                    self.assertIn(f"{source.name}:3:", diagnostic)
                    statistics = json.loads(statistics)
                    self.assertEqual(statistics["records"], 2)
                    self.assertFalse(statistics["complete"])

    def test_truncation_errors_follow_source_order(self):
        data = "\n".join(map(json.dumps, (
            {"message": "x" * 200, "padding": "a" * 900000},
            {"message": "y" * 200}))) + "\n"
        for workers, multiline in product((1, 2, 4, 16), ("off", "indent")):
            with self.subTest(workers=workers, multiline=multiline):
                failed = run("--agent", "--fail-on-truncation", "--max-message-bytes=128",
                             f"--threads={workers}", f"--multiline={multiline}",
                             "--limit=2", data=data, code=1)
                self.assertEqual(failed.stdout, "")
                self.assertIn("-:1:", failed.stderr)
                self.assertNotIn("-:2:", failed.stderr)

    def test_numeric_filters_match_an_independent_decimal_oracle(self):
        random_source = random.Random(0xDEC1A1)
        values = ["0", "-0", "1e1000000", "1e-1000000", "-1e-1000000", "-1e1000000",
                  "0.10000000000000001", "9007199254740993", "18446744073709551615",
                  "9" * 128, "1" + "0" * 127]
        for _ in range(100):
            sign = random_source.choice(("", "-"))
            whole = str(random_source.randrange(10 ** random_source.randrange(1, 35)))
            fraction = "." + "".join(str(random_source.randrange(10))
                                    for _ in range(random_source.randrange(1, 35)))
            values.append(f"{sign}{whole}{fraction}e{random_source.randrange(-200, 200)}")
        data = "\n".join(json.dumps({"message": str(i), "value": value})
                         for i, value in enumerate(values))
        comparisons = {"<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
                       ">": lambda a, b: a > b, ">=": lambda a, b: a >= b}
        thresholds = ["0", "-0.1", "0.1", "9007199254740992", "1e1000000",
                      "1e-1000000", "9" * 128, *values[-4:]]
        for index, threshold in enumerate(thresholds):
            for op, compare in comparisons.items():
                with self.subTest(threshold=threshold, op=op):
                    selected = rows("--filter", f"value{op}{threshold}", "--limit", len(values),
                                    "--threads", 1 if index % 2 else 4, data=data)
                    expected = [str(i) for i, value in enumerate(values)
                                if compare(Decimal(value), Decimal(threshold))]
                    self.assertEqual([row["message"] for row in selected], expected)

    def test_numeric_filters_preserve_missing_invalid_and_exact_semantics(self):
        invalid = [None, "", "NaN", "Infinity", "01", "+1", ".1", "1.", " 1", "1ms",
                   "1e1000001", "1e-1000001", "9" * 129]
        records = [{"message": str(i), **({"value": v} if v is not None else {})}
                   for i, v in enumerate(invalid)]
        data = "\n".join(map(json.dumps, records))
        self.assertEqual(rows("--filter=value>=0", data=data), [])
        self.assertEqual(len(rows("--filter=NOT value>=0", data=data)), len(records))
        for value in invalid[1:]:
            result = run("--filter", "value>" + json.dumps(value), "/missing-input", code=2)
            self.assertEqual(result.stdout, "")
            self.assertNotIn("open", result.stderr)
        data = '\n'.join(json.dumps({"message": str(i), "value": value})
                         for i, value in enumerate(("1", "1.0", "1e0", "a<b>=c")))
        self.assertEqual([r["message"] for r in rows("--filter=value=1.0", data=data)], ["1"])
        self.assertEqual([r["message"] for r in rows("--filter=value=a<b>=c", data=data)], ["3"])
        self.assertEqual([r["message"] for r in rows("--filter=value>=1 AND value<=1", data=data)],
                         ["0", "1", "2"])

    def test_compact_default_snapshot_schema_and_legacy_output(self):
        data = "\n".join(json.dumps({"message": f"event {i}", "level": "w", "extra": "evidence"})
                         for i in range(150))
        output = run("--agent", "--color=always", data=data)
        self.assertEqual(output.stderr, "")
        self.assertNotIn("\x1b", output.stdout)
        selected = list(map(json.loads, output.stdout.splitlines()))
        self.assertEqual(len(selected), 100)
        self.assertEqual(list(selected[0]), ["timestamp", "level", "message", "file", "line", "format"])
        self.assertEqual(selected[0], {"timestamp": None, "level": "WARN", "message": "event 0",
                                      "file": "-", "line": 1, "format": "json"})
        self.assertEqual([r["line"] for r in selected], list(range(1, 101)))
        self.assertEqual(run("--output=agent", data=data).stdout, output.stdout)
        full = list(map(json.loads, run("--output=json", data=data).stdout.splitlines()))
        self.assertEqual(len(full), 150)
        self.assertEqual(full[0]["fields"]["extra"], "evidence")
        self.assertIn("raw", full[0])

    def test_agent_compact_matches_agent_records_without_repeated_names(self):
        def invoke(folder, *args, code=0):
            result = subprocess.run([BINARY, *map(str, args)], cwd=folder, text=True,
                                    capture_output=True, timeout=15 * SCALE)
            self.assertEqual(result.returncode, code, result.stderr)
            return result

        def expected(agent_lines, fields):
            lines, current = [], None
            for row in map(json.loads, agent_lines):
                if row["file"] != current:
                    current = row["file"]
                    lines.append({"file": current})
                record = [row["timestamp"], row["level"], row["message"], row["line"],
                          row["format"], *(row.get("fields", {}).get(name) for name in fields)]
                clipped = [name for name in row.get("truncated_fields", []) if name != "file"]
                if clipped:
                    record.append({"truncated": clipped})
                lines.append(record)
            return lines

        with tempfile.TemporaryDirectory() as folder:
            padding = "p" * 180
            for name, count in (("a.log", 900), ("quiet.log", 3), ("b.log", 700)):
                (Path(folder) / name).write_text("".join(
                    json.dumps({"message": f"{name} {index} {padding}", "user": f"u{index % 3}",
                                "level": "error" if name != "quiet.log" else "info"}) + "\n"
                    for index in range(count)))
            files = ("a.log", "quiet.log", "b.log")
            for workers, limit, bytes_, fields in product(
                    (1, 4), (2000, 1000, 3), (2048, 12), ((), ("user", "missing"))):
                selection = (f"--agent-fields={','.join(fields)}",) if fields else ()
                common = (f"--threads={workers}", f"--limit={limit}", "--min-level=error",
                          f"--max-message-bytes={bytes_}", *selection, *files)
                with self.subTest(workers=workers, limit=limit, bytes=bytes_, fields=fields):
                    agent = invoke(folder, "--output=agent", *common).stdout.splitlines()
                    compact = invoke(folder, "--output=agent-compact", *common).stdout
                    header, *body = map(json.loads, compact.splitlines())
                    self.assertEqual(header, {"schema": "urn:lumtail:agent-compact:v1",
                                              "columns": ["timestamp", "level", "message",
                                                          "line", "format", *fields]})
                    self.assertEqual(body, expected(agent, fields))
                    self.assertNotIn({"file": "quiet.log"}, body)
                    self.assertLess(len(compact), sum(map(len, agent)))
            (Path(folder) / "huge.log").write_text(
                json.dumps({"message": "h" * 150000}) + "\n" + json.dumps({"message": "t"}) + "\n")
            for workers in (1, 4):
                with self.subTest(huge=workers):
                    common = (f"--threads={workers}", "--max-message-bytes=200000", "huge.log",
                              "b.log", "--limit=3")
                    agent = invoke(folder, "--output=agent", *common).stdout.splitlines()
                    compact = invoke(folder, "--output=agent-compact", *common).stdout
                    self.assertEqual(list(map(json.loads, compact.splitlines()[1:])),
                                     expected(agent, ()))
            self.assertEqual(invoke(folder, "--output=agent-compact", "--where=user=none",
                                    *files).stdout, "")
            both = invoke(folder, "--agent", "--output=agent-compact", "--limit=1", "b.log")
            self.assertEqual(both.stdout.splitlines()[1:],
                             ['{"file":"b.log"}', f'[null,"ERROR","b.log 0 {padding}",1,"json"]'])
            failed = invoke(folder, "--output=agent-compact", "--fail-on-truncation",
                            "--max-message-bytes=4", "a.log", code=1)
            self.assertIn("a.log:1:", failed.stderr)
            self.assertEqual(failed.stdout, "")
            odd = 'we"ird\n\x1b‮name' + "x" * 200 + ".log"
            (Path(folder) / odd).write_text(json.dumps({"message": "m"}) + "\n")
            header, file_line, record = invoke(folder, "--output=agent-compact",
                                               "--max-message-bytes=8", odd).stdout.splitlines()
            self.assertNotIn("\x1b", file_line)
            self.assertEqual(json.loads(file_line), {"file": odd})
            self.assertEqual(json.loads(record), [None, "UNKNOWN", "m", 1, "json"])
            stats = invoke(folder, "--output=agent-compact", "--stats-version=2", "--limit=1",
                           "a.log").stderr.splitlines()[-1]
            self.assertEqual(json.loads(stats)["stop_reason"], "limit")
        tricky = run("--output=agent-compact", "--", "-", data='{"message":"x"}\n').stdout
        self.assertEqual(tricky.splitlines()[1], '{"file":"-"}')
        for flags in (("--agent", "--output=json"), ("--output=agent-compact", "--output=text",
                                                     "--agent")):
            run(*flags, code=2)
        run("--output=json", "--agent-fields=user", code=2)

    def test_substring_filter_matches_a_python_oracle(self):
        generator = random.Random(20261112)
        values = ["".join(generator.choice("ab") for _ in range(generator.randrange(0, 24)))
                  for _ in range(400)]
        data = "".join(json.dumps({"message": "m", "v": value}) + "\n" for value in values)
        for _ in range(40):
            needle = "".join(generator.choice("ab") for _ in range(generator.randrange(1, 7)))
            with self.subTest(needle=needle):
                selected = run("--output=json", "--threads=2", "--filter", f"v~*{needle}*",
                               data=data).stdout.splitlines()
                self.assertEqual([json.loads(line)["fields"]["v"] for line in selected],
                                 [value for value in values if needle in value])

    def test_agent_compact_schema_describes_every_line_kind(self):
        schema = json.loads(run("--output=agent-compact", "--agent-schema",
                                "/missing-input").stdout)
        self.assertEqual(schema["$id"], "urn:lumtail:agent-compact:v1")
        header, file_line, record = schema["oneOf"]
        self.assertEqual(header["properties"]["schema"]["const"], schema["$id"])
        self.assertEqual(file_line["required"], ["file"])
        self.assertEqual(record["maxItems"], 5 + 16 + 1)
        self.assertEqual(json.loads(run("--agent-schema").stdout)["$id"], "urn:lumtail:agent:v1")

    def test_schema_does_not_open_input_or_rules(self):
        result = run("--agent-schema", "--follow", "--rules", "missing-rules", "missing-input")
        schema = json.loads(result.stdout)
        self.assertEqual(schema["$id"], "urn:lumtail:agent:v1")
        self.assertEqual(schema["required"], ["timestamp", "level", "message", "file", "line", "format"])
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(result.stderr, "")

    def test_clipping_counts_encoded_bytes_and_preserves_source_for_filters(self):
        message = "☀\x00\"\\\n" * 20
        data = json.dumps({"message": message, "timestamp": "t" * 80})
        for budget in (1, 2, 3, 4, 5, 6, 8, 16, 31):
            with self.subTest(budget=budget):
                event, = rows("--max-message-bytes", budget, "--filter",
                              "message=" + json.dumps(message, ensure_ascii=False), data=data)
                for field in ("message", "timestamp", "file"):
                    encoded = json.dumps(event[field], ensure_ascii=False, separators=(",", ":")).encode()
                    self.assertLessEqual(len(encoded) - 2, budget)
                self.assertTrue(event["truncated"])
                self.assertIn("message", event["truncated_fields"])
                self.assertIn("timestamp", event["truncated_fields"])
        original, = map(json.loads, run("--output=json", data=data).stdout.splitlines())
        self.assertEqual(original["fields"]["message"], message)

    def test_multiline_clipping_keeps_provenance_and_reports_omission(self):
        data = '{"level":"error","message":"failure\\ninside"}\n  frame 1\n  frame 2\nnext\n'
        first, second = rows("--multiline=indent", "--max-lines-per-record=3", data=data)
        self.assertEqual(first["message"], "failure\ninside\n  frame 1")
        self.assertEqual(first["line"], 1)
        self.assertEqual(first["truncated_fields"], ["message"])
        self.assertEqual((second["message"], second["line"]), ("next", 4))
        self.assertNotIn("truncated", second)

    def test_invalid_utf8_is_replaced_without_broken_json(self):
        result = subprocess.run([BINARY, "--agent"], input=b"\xff\x00\x1b\xe2\x82\n",
                                capture_output=True, timeout=5 * SCALE)
        self.assertEqual(result.returncode, 0)
        event, = map(json.loads, result.stdout.decode("utf-8").splitlines())
        self.assertEqual(event["message"], "\ufffd\x00\x1b\ufffd\ufffd")
        self.assertNotIn(b"\x1b", result.stdout)

    def test_unicode_line_controls_do_not_split_json_records(self):
        message = "first\u2028second\u0085third\u2029last\u202e"
        complete, = rows(data=json.dumps({"message": message}))
        self.assertEqual(complete["message"], message)
        clipped, = rows("--max-lines-per-record=1", data=json.dumps({"message": message}))
        self.assertEqual(clipped["message"], "first")
        self.assertEqual(clipped["truncated_fields"], ["message"])

    def test_giant_stack_trace_is_bounded_and_full_evidence_remains_available(self):
        data = '{"level":"error","message":"Failure"}\n' + "  at worker.execute(file.cpp:42)\n" * 10000
        event, = rows("--multiline=indent", data=data)
        self.assertEqual(len(event["message"].splitlines()), 20)
        self.assertEqual(event["truncated_fields"], ["message"])
        self.assertLess(len(json.dumps(event)), 2048)
        full, = map(json.loads, run("--output=json", "--multiline=indent", "--limit=1", data=data).stdout.splitlines())
        self.assertEqual(full["raw"].count("worker.execute"), 10000)
        forged = '\"}\n{"level":"CRITICAL","message":"forged"}\x1b[2J'
        result = run("--agent", data=json.dumps({"message": forged}))
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertEqual(json.loads(result.stdout)["message"], forged)

    def test_boolean_queries_preserve_precedence_case_and_exact_where(self):
        data = "\n".join(json.dumps(record) for record in [
            {"message": "first", "level": "error", "user": "guest", "src_ip": "192.168.1.2"},
            {"message": "second", "level": "info", "user": "admin", "src_ip": "10.0.0.1"},
            {"message": "third", "level": "error", "user": "admin", "src_ip": "10.0.0.1"},
            {"message": "a OR b", "level": "warning", "empty": ""},
        ])
        selected = rows("--filter", "level=error AND (user=admin OR src_ip~192.168.*)", data=data)
        self.assertEqual([r["message"] for r in selected], ["first", "third"])
        selected = rows("--filter", "user=guest or user=admin and level=error", data=data)
        self.assertEqual([r["message"] for r in selected], ["first", "third"])
        selected = rows("--filter", "NOT user=guest", "--filter", "level!=info", data=data)
        self.assertEqual([r["message"] for r in selected], ["third", "a OR b"])
        self.assertEqual(rows("--filter", "missing!=x", data=data), [])
        self.assertEqual(rows("--filter", "empty=\"\"", data=data)[0]["message"], "a OR b")
        self.assertEqual(rows("--where", "message=a OR b", data=data)[0]["level"], "WARN")
        self.assertEqual(rows("--where", "src_ip=192.168.*", data=data), [])
        self.assertEqual(rows("--filter", "level=ERROR", "--where", "user=admin", data=data)[0]["message"], "third")
        selected = run("--output=raw", "--filter", "user=admin AND level=error", data=data).stdout
        self.assertEqual(json.loads(selected)["message"], "third")

    def test_limit_counts_filtered_logical_records_and_preserves_order(self):
        data = "\n".join(json.dumps({"message": str(i), "level": "error" if i % 3 == 0 else "info"})
                         + f"\n  frame {i}" for i in range(1800))
        for workers in (1, 4, 8):
            with self.subTest(workers=workers):
                selected = rows("--threads", workers, "--multiline=indent", "--limit=7",
                                "--filter=level=error", data=data)
                self.assertEqual([r["message"] for r in selected],
                                 [f"{i}\n  frame {i}" for i in range(0, 21, 3)])
                self.assertEqual([r["line"] for r in selected], list(range(1, 42, 6)))

    def test_limit_handles_chunk_boundaries_and_empty_records(self):
        data = "x" * (256 * 1024 - 1) + "\ntail\n"
        for workers in (1, 4):
            for mode in ("text", "raw", "json"):
                with self.subTest(workers=workers, mode=mode):
                    result = run("--threads", workers, "--output", mode, "--limit=1", data=data).stdout
                    if mode == "json":
                        self.assertEqual(len(result.splitlines()), 1)
                        self.assertEqual(json.loads(result)["line"], 1)
                    else:
                        self.assertEqual(result, data[:256 * 1024])
            empty = run("--threads", workers, "--limit=1025", data="\n" * 1500).stdout
            self.assertEqual(empty, "\n" * 1025)

    def test_limit_is_global_and_preserves_errors_before_the_selected_prefix(self):
        with tempfile.TemporaryDirectory() as folder:
            first, second, missing = (Path(folder) / name for name in ("first", "second", "missing"))
            first.write_text("a\nb\n")
            second.write_text("c\nd\n")
            for workers in (1, 4):
                flags = ("--threads", workers, "--limit=3", "--output=raw")
                self.assertEqual(run(*flags, first, second, missing).stdout, "a\nb\nc\n")
                failed = run(*flags, missing, first, second, code=1)
                self.assertEqual(failed.stdout, "a\nb\nc\n")
                self.assertIn("open", failed.stderr)
                # A read-ahead line-size failure after the selected prefix is irrelevant.
                first.write_text("a\n" + "x" * 200 + "\n")
                selected = run("--threads", workers, "--limit=1", "--max-line-bytes=100", first)
                self.assertEqual((selected.stdout, selected.stderr), ("a\n", ""))
                first.write_text("a\nb\n")

    def test_limit_cancels_a_pipe_without_waiting_for_eof(self):
        for workers in (1, 4):
            process = subprocess.Popen([BINARY, "--agent", "--limit=1", f"--threads={workers}"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                process.stdin.write(b'{"message":"live"}\n')
                process.stdin.flush()
                self.assertEqual(process.wait(timeout=5 * SCALE), 0)
                self.assertEqual(json.loads(process.stdout.read())["message"], "live")
                self.assertEqual(process.stderr.read(), b"")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                process.stdin.close()
                process.stdout.close()
                process.stderr.close()

    def test_duration_ends_idle_input_and_does_not_open_later_files(self):
        process = subprocess.Popen([BINARY, "--agent", "--duration-ms=40", "-", "/missing-later-file"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(b'{"message":"unfinished"}')
            process.stdin.flush()
            self.assertEqual(process.wait(timeout=5 * SCALE), 0)
            self.assertEqual(process.stdout.read(), b"")
            self.assertEqual(process.stderr.read(), b"")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "follow"
            path.write_text('{"message":"head"}\n  complete\n  partial')
            selected = rows("--follow", "--duration-ms=40", "--multiline=indent", path)
            self.assertEqual(selected[0]["message"], "head\n  complete")

    def test_invalid_queries_and_limits_fail_before_input(self):
        for flags in (("--limit=0",), ("--limit=-1",), ("--duration-ms=0",),
                      ("--duration-ms=86400001",), ("--max-message-bytes=0",),
                      ("--max-lines-per-record=0",), ("--agent", "--output=text"),
                      ("--output=json", "--agent"), ("--filter=message",),
                      ("--filter=level=unknown-label",), ("--filter=message~*x",)):
            with self.subTest(flags=flags):
                result = run(*flags, "/missing-input", code=2)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("open", result.stderr)
        run("--max-message-bytes=10", code=2)
        run("--max-lines-per-record=2", code=2)

    def test_selected_fields_are_ordered_bounded_and_preserve_filtering(self):
        data = json.dumps({"message": "ok", "service": "api", "user": "alice", "empty": ""})
        for workers in (1, 4):
            selected, = rows("--threads", workers, "--agent-fields=service,user,empty,missing",
                             "--max-message-bytes=5", "--where=user=alice", data=data)
            self.assertEqual(list(selected["fields"]), ["service", "user", "empty", "missing"])
            self.assertEqual(selected["fields"],
                             {"service": "api", "user": "al", "empty": "", "missing": None})
            self.assertIn("fields.user", selected["truncated_fields"])
            self.assertNotIn("raw", selected)
        complete, = rows("--agent-fields=service,user,empty,missing", data=data)
        self.assertEqual(complete["fields"]["user"], "alice")
        self.assertNotIn("truncated", complete)
        replaced, = rows("--agent-fields=service", "--agent-fields=user", data=data)
        self.assertEqual(replaced["fields"], {"user": "alice"})
        self.assertNotIn("fields", rows(data=data)[0])

    def test_selected_strings_count_escapes_unicode_and_line_breaks(self):
        data = json.dumps({"message": "ok", "first": "\u0000☀", "second": "☀z",
                           "third": "keep\u2028hidden"})
        selected, = rows("--agent-fields=first,second,third", "--max-message-bytes=8", data=data)
        self.assertEqual(selected["fields"], {"first": "\u0000", "second": "", "third": "ke"})
        self.assertEqual(sum(len(json.dumps(v, ensure_ascii=False).encode()) - 2
                             for v in selected["fields"].values()), 8)
        for name in ("first", "second", "third"):
            self.assertIn("fields." + name, selected["truncated_fields"])
        selected, = rows("--agent-fields=third,second", "--max-lines-per-record=1", data=data)
        self.assertEqual(selected["fields"], {"third": "keep", "second": "☀z"})
        self.assertEqual(selected["truncated_fields"], ["fields.third"])

    def test_invalid_field_selection_fails_before_input(self):
        for selection in ("", "user,", "user,user", "user,,service", "bad name", "x" * 129,
                          ",".join(f"field{i}" for i in range(17)), "x" * 4097):
            with self.subTest(selection=selection):
                result = run("--agent", "--agent-fields", selection, "/missing-input", code=2)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("open", result.stderr)
        run("--agent-fields=user", "/missing-input", code=2)


if __name__ == "__main__":
    unittest.main()
