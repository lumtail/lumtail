# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Public CLI contracts, parser dispatch, custom rules and streamed I/O."""

import errno
import json
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import termios
import threading
import time
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())
ROOT = Path(__file__).resolve().parents[1]
BUILTIN_MODULES = ["json", "cef", "leef", "fail2ban", "bind.query", "unbound.log", "cri.log",
                   "syslog", "web-error", "access", "haproxy.http", "ids.fast", "aws.vpc-flow",
                   "squid.native", "glog.text", "osquery.status", "fortigate.kv", "auditd.raw",
                   "logfmt.kv", "plain"]
TIMEOUT_SCALE = float(os.environ.get("LUMTAIL_TEST_TIMEOUT_SCALE", "1"))
STATS_SIZE = r"(?:\d+ B|\d+\.\d (?:KiB|MiB|GiB|TiB))"
STATS_TEXT = re.compile(
    rf"lumtail: stats: read (?P<bytes>{STATS_SIZE}), wrote (?P<records>\d+) records?, "
    rf"\d+\.\d{{3}} s, (?:n/a|{STATS_SIZE}/s), (?P<workers>\d+) workers?, "
    rf"CPU (?:n/a|\d+\.\d{{3}} s user \+ \d+\.\d{{3}} s system), "
    rf"peak RSS (?:n/a|{STATS_SIZE})(?P<incomplete>, incomplete)?\n")


def iec_size(size):
    """Independent copy of the --stats size rounding: one decimal, half up."""
    if size < 1024:
        return f"{size} B"
    unit = 1
    while unit < 4 and size >= 1024 ** (unit + 1):
        unit += 1
    while True:
        scale = 1024 ** unit
        tenths = (20 * size + scale) // (2 * scale)
        if tenths < 10240 or unit == 4:
            return f"{tenths // 10}.{tenths % 10} {('KiB', 'MiB', 'GiB', 'TiB')[unit - 1]}"
        unit += 1


def run(*args, data="", code=0):
    result = subprocess.run(
        [BINARY, *map(str, args)], input=data, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30 * TIMEOUT_SCALE,
    )
    if result.returncode != code:
        raise AssertionError(f"exit {result.returncode}, expected {code}: {result.stderr}")
    return result


def events(*args, data=""):
    return [json.loads(line) for line in run("--output", "json", *args, data=data).stdout.splitlines()]


def terminal(*args, data=None, env=None, drain_after_exit=False):
    """Exercise a real terminal, including input detection and automatic color."""
    master, slave = os.openpty()
    process = None
    try:
        settings = termios.tcgetattr(slave)
        # Capture the CLI's bytes directly. Terminal newline postprocessing
        # must not change the output used by the exact-equality assertions.
        settings[1] &= ~termios.OPOST
        settings[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, settings)
        child_env = dict(os.environ, TERM="xterm-256color")
        child_env.pop("NO_COLOR", None)
        child_env.update(env or {})
        process = subprocess.Popen([BINARY, *map(str, args)], stdin=slave, stdout=slave,
                                   stderr=subprocess.PIPE, env=child_env)
        # Like a real parent shell, retain a slave reference until the output
        # is drained. Darwin can discard queued output on the last slave close.
        if data is not None:
            os.write(master, data.encode() + b"\x04")
        if drain_after_exit:
            # Only for short-output cases that fit the terminal queue. This
            # deliberately exercises a reader scheduled after child exit.
            process.wait(timeout=5 * TIMEOUT_SCALE)
        output = bytearray()
        deadline = time.monotonic() + 10 * TIMEOUT_SCALE
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("terminal command did not finish")
            if process.poll() is not None:
                if not select.select([master], [], [], 0)[0]:
                    break
            elif not select.select([master], [], [], min(remaining, 0.05))[0]:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                break
            if not chunk:
                break
            output.extend(chunk)
        process.wait(timeout=5 * TIMEOUT_SCALE)
        return subprocess.CompletedProcess(
            process.args, process.returncode,
            output.decode(), process.stderr.read().decode(),
        )
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stderr.close()
        os.close(master)
        if slave >= 0:
            os.close(slave)


class LumtailTests(unittest.TestCase):
    def test_explicit_inherited_descriptors_for_input_and_rules(self):
        for root in ("/dev/fd", "/proc/self/fd"):
            if not Path(root).is_dir():
                continue
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, b"hello\n")
                os.close(write_fd)
                write_fd = None
                path = f"{root}/{read_fd}"
                result = subprocess.run([BINARY, "--output=json", path], pass_fds=(read_fd,),
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                event = json.loads(result.stdout)
                self.assertEqual((event["raw"], event["file"], event["line"]), ("hello", path, 1))
            finally:
                os.close(read_fd)
                if write_fd is not None:
                    os.close(write_fd)
            with open(ROOT / "examples/modules.json", "rb") as rules:
                result = subprocess.run(
                    [BINARY, "--rules", f"{root}/{rules.fileno()}", "--output=json"],
                    pass_fds=(rules.fileno(),), input=b"now [FAIL] app: failed\n",
                    capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["format"], "application")
        self.assertEqual(run("--output=raw", "/dev/stdin", data="stdin\n").stdout, "stdin\n")
        with tempfile.TemporaryDirectory() as folder:
            alias = Path(folder) / "stdin"
            alias.symlink_to("/dev/stdin")
            self.assertEqual(run("--output=raw", alias, data="aliased pipe\n").stdout,
                             "aliased pipe\n")
            source = Path(folder) / "input"
            source.write_bytes(b"file\n")
            with open(source, "rb") as stream:
                result = subprocess.run([BINARY, "--output=raw", "/dev/stdin", "/dev/stdin"],
                                        stdin=stream, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"file\nfile\n" if sys.platform.startswith("linux") else b"file\n")

    def test_rsyslog_file_timestamps_and_level_initials(self):
        for timestamp in ("2026-11-08T01:02:03.123456+01:00", "2024-02-29T23:59:60Z",
                          "2026-11-08T01:02:03-03:30"):
            source = timestamp + " host sshd[42]: Failed password for alice from 192.0.2.1 port 22 ssh2"
            event = events(data=source)[0]
            self.assertEqual(event["format"], "syslog")
            self.assertEqual(event["fields"]["timestamp"], timestamp)
            self.assertEqual(event["fields"]["source"], "sshd")
            self.assertEqual(event["fields"]["pid"], "42")
            self.assertEqual(event["fields"]["syslog_format"], "rsyslog")
        for timestamp in ("2026-02-29T01:02:03Z", "2026-11-08T24:00:00Z",
                          "2026-11-08T01:02:03+99:00", "2026-11-08T01:02:03.Z"):
            self.assertEqual(events(data=timestamp + " host app: hello")[0]["format"], "plain")
        for label, level in (("d", "DEBUG"), ("i", "INFO"), ("w", "WARN"),
                             ("e", "ERROR"), ("f", "CRITICAL")):
            self.assertEqual(events(data=json.dumps({"level": label}))[0]["level"], level)
        source = '<013>01 - host app - - - hello'
        event = events(data=source)[0]
        self.assertEqual(event["format"], "syslog")
        self.assertEqual(event["fields"]["version"], "01")
        self.assertEqual(event["fields"]["timestamp"], "-")
        self.assertEqual(event["fields"]["message"], "hello")

    def test_process_substitution_rules_wait_for_delayed_bytes(self):
        for nonblocking in (False, True):
            read_fd, write_fd = os.pipe()
            os.set_blocking(read_fd, not nonblocking)
            document = (ROOT / "examples/modules.json").read_bytes()
            process = subprocess.Popen(
                [BINARY, "--rules", f"/dev/fd/{read_fd}", "--output=json"],
                pass_fds=(read_fd,), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            os.close(read_fd)
            errors = []
            def write_rules():
                try:
                    time.sleep(0.1)
                    self.assertEqual(os.write(write_fd, document), len(document))
                except (OSError, AssertionError) as error:
                    errors.append(error)
                finally:
                    os.close(write_fd)
            writer = threading.Thread(target=write_rules)
            writer.start()
            try:
                output, error = process.communicate(b"now [FAIL] app: failed\n", timeout=5 * TIMEOUT_SCALE)
                self.assertEqual((process.returncode, error, errors), (0, b"", []))
                self.assertEqual(json.loads(output)["format"], "application")
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
                writer.join(timeout=5)
                self.assertFalse(writer.is_alive())

    def test_json_preserves_large_integer_tokens(self):
        for number in ("18446744073709551616", "-9223372036854775809",
                       "123456789012345678901234567890", "9" * 400):
            with self.subTest(number=number):
                source = '{"id":' + number + ',"nested": [ ' + number + ', {"text":"1234"} ]}'
                event = events(data=source + "\n")[0]
                self.assertEqual(event["format"], "json")
                self.assertEqual(event["fields"]["id"], number)
                self.assertEqual(json.loads(event["fields"]["nested"]),
                                 [int(number), {"text": "1234"}])
                self.assertEqual(event["raw"], source)
        for malformed in ('{"id":012345678901234567890}',
                          '{"id":123456789012345678901234567890x}',
                          '{"id":--123456789012345678901234567890}'):
            self.assertEqual(events(data=malformed)[0]["format"], "plain")
        source = '{"id":123456789012345678901234567890,"id":7,"text":"98765432109876543210"}'
        fields = events(data=source)[0]["fields"]
        self.assertEqual(fields["id"], "7")
        self.assertEqual(fields["text"], "98765432109876543210")
        number = "9" * 400
        source = '{"event_type":"dns","dns":{"version":2,"answers":[{"id":' + number + '}]}}'
        fields = events(data=source)[0]["fields"]
        self.assertEqual(json.loads(fields["dns_answers"]), [{"id": int(number)}])
        self.assertEqual(json.loads(fields["dns"])["answers"], [{"id": int(number)}])

    def test_json_escapes_unicode_controls_in_all_strings(self):
        controls = ''.join(map(chr, [*range(0x80, 0xa0), 0x61c, 0x200e, 0x200f,
                                    *range(0x2028, 0x202f), *range(0x2066, 0x206a)]))
        for prefix in (b"", b"\xff"):
            result = subprocess.run([BINARY, "--output=json"],
                                    input=prefix + controls.encode() + b"\n",
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["raw"],
                             ("\ufffd" if prefix else "") + controls)
            for char in controls:
                self.assertNotIn(char.encode(), result.stdout)
                self.assertIn(f"\\u{ord(char):04x}".encode(), result.stdout)

    def test_apache_without_module_and_malformed_access_requests(self):
        source = "[Sat Nov 07 18:30:00 2026] [:error] [pid 42] PHP Fatal error: failed"
        event = events("--errors-only", data=source)[0]
        self.assertEqual((event["format"], event["level"]), ("web-error", "ERROR"))
        for request in ('\\x16\\x03\\x01', '', 'GET /old', 'too many request words here'):
            with self.subTest(request=request):
                source = f'192.0.2.1 - - [08/Nov/2026:01:02:03 +0000] "{request}" 400 0'
                event = events("--min-level=warn", data=source)[0]
                self.assertEqual((event["format"], event["level"]), ("access", "WARN"))
                self.assertEqual(event["fields"]["request"], request)
                self.assertEqual(event["raw"], source)
                for field in ("method", "path", "protocol"):
                    self.assertNotIn(field, event["fields"])

    def test_eve_alert_validates_destination_aliases(self):
        for address, port, valid in (("not-an-ip", 99999, False),
                                     ("192.0.2.1", 65535, True),
                                     ("2001:db8::1", 0, True),
                                     ("192.0.2.999", -1, False)):
            source = json.dumps({"event_type": "alert", "dest_ip": address,
                                 "dest_port": port, "alert": {"severity": 2}})
            event = events(data=source)[0]
            fields = event["fields"]
            self.assertEqual(fields["dest_ip"], address)
            self.assertEqual(fields["dest_port"], str(port))
            self.assertEqual("dst_ip" in fields, valid)
            self.assertEqual("dst_port" in fields, valid)
            self.assertEqual(event["level"], "ERROR")

    def test_auditd_raw_profiles_keep_fields_outcomes_and_order(self):
        source = ROOT / "examples/auditd-raw.log"
        baseline = events(source)
        self.assertEqual(len(baseline), 7)
        self.assertTrue(all(row["format"] == "auditd.raw" for row in baseline))
        for workers in (1, 4):
            self.assertEqual(events("--threads", workers, source), baseline)
            self.assertEqual(events("--threads", workers, "--module", "auditd.raw", source), baseline)
        self.assertEqual(baseline[0]["fields"]["syscall"], "59")
        self.assertEqual(baseline[0]["level"], "UNKNOWN")
        self.assertEqual(baseline[1]["fields"]["auditd.fields.a0"], '\"/usr/bin/id\"')
        self.assertEqual(baseline[2]["fields"]["path"], "/usr/bin/id")
        self.assertNotIn("command", baseline[3]["fields"])
        self.assertEqual(baseline[5]["fields"]["user"], "alice")
        self.assertEqual(baseline[5]["fields"]["auditd.msg.acct"], "616c696365")
        self.assertEqual(baseline[5]["fields"]["src_ip"], "192.0.2.10")
        self.assertEqual([row["level"] for row in baseline[5:]], ["ERROR", "INFO"])
        failed = events("--auth-failures", source)
        self.assertEqual([row["line"] for row in failed], [6])
        self.assertEqual(events("--errors-only", source), failed)
        self.assertEqual(events("--where", "auditd.serial=42", source), baseline[:5])
        self.assertEqual(run("--output=raw", source).stdout, source.read_text())
        mixed = events(data='{"message":"json"}\n' + source.read_text() + "ordinary text\n")
        self.assertEqual([row["format"] for row in mixed], ["json"] + ["auditd.raw"] * 7 + ["plain"])
        agent = [json.loads(line) for line in run("--agent", "--auth-failures", "--agent-fields",
                                               "user,auditd.serial", source).stdout.splitlines()]
        self.assertEqual(agent[0]["fields"], {"user": "alice", "auditd.serial": "43"})

    def test_audit_parser_preserves_v1_custom_names_precedence_and_capacity(self):
        with tempfile.TemporaryDirectory() as temporary:
            rules = Path(temporary) / "rules.json"
            modules = [{"name": "auditd", "priority": -999,
                        "pattern": "type={kind} msg=audit({message}"}]
            modules += [{"name": "compat" + str(index), "priority": -999,
                         "pattern": "not-matching-" + str(index) + ":{message}"} for index in range(119)]
            rules.write_text(json.dumps({"version": 1, "modules": modules}))
            listed = run("--rules", rules, "--list-modules").stdout.splitlines()
            self.assertEqual(len(listed), len(BUILTIN_MODULES) + 120)
            source = "type=USER_AUTH msg=audit(1.001:2): acct=\"alice\" res=failed\n"
            rows = events("--rules", rules, data=source)
            self.assertEqual(rows[0]["format"], "auditd")
            self.assertNotIn("auditd.type", rows[0]["fields"])
            self.assertEqual(events("--rules", rules, "--module=auditd", data=source), rows)
            modules.append({"name": "too-many", "pattern": "never:{message}"})
            rules.write_text(json.dumps({"version": 1, "modules": modules}))
            self.assertIn("registry exceeds", run("--rules", rules, code=2).stderr)

    def test_numeric_filters_work_in_all_output_modes_and_preserve_record_order(self):
        records = [{"message": str(i), "duration_ms": str(i), "padding": "x" * 160}
                   for i in range(1800)]
        data = "\n".join(map(json.dumps, records)) + "\n"
        expected = [str(i) for i in range(1700, 1800)]
        for workers in (1, 4):
            flags = ("--threads", workers, "--filter", "duration_ms>=1700 AND duration_ms<1800")
            self.assertEqual([r["fields"]["message"] for r in events(*flags, data=data)], expected)
            raw = run(*flags, "--output=raw", data=data).stdout
            self.assertEqual([json.loads(line)["message"] for line in raw.splitlines()], expected)
            text = run(*flags, "--template={message}", data=data).stdout
            self.assertEqual(text.splitlines(), expected)
        data = "\n".join(json.dumps({"message": str(value), "counter": value})
                         for value in (9007199254740992, 9007199254740993))
        selected = events("--filter=counter>=9007199254740993", data=data)
        self.assertEqual([r["fields"]["message"] for r in selected], ["9007199254740993"])

    def test_rule_file_reads_keep_byte_limits_and_chunk_boundaries(self):
        baseline = run("--list-modules").stdout
        document = b'{"version":1,"modules":[]}'
        with tempfile.TemporaryDirectory() as folder:
            rules = Path(folder) / "rules.json"
            for size in (4095, 4096, 4097, 8192, 1048576):
                with self.subTest(size=size):
                    rules.write_bytes(document + b" " * (size - len(document)))
                    self.assertEqual(run("--rules", rules, "--list-modules").stdout, baseline)
            rules.write_bytes(document + b" " * (1048577 - len(document)))
            self.assertIn("rules file exceeds 1 MiB", run("--rules", rules, code=2).stderr)
            rules.write_bytes(b"")
            self.assertIn("invalid JSON", run("--rules", rules, code=2).stderr)
            rules.write_bytes(document + b" " * (4096 - len(document)) + b"!")
            self.assertIn("invalid JSON", run("--rules", rules, code=2).stderr)

    def test_authentication_ip_literals_have_a_portable_unambiguous_policy(self):
        valid = ("192.0.2.10", "2001:db8::10", "::ffff:192.0.2.10")
        invalid = ("192.000.2.10", "0x7f.0.0.1", "127.1", "::ffff:192.000.2.10", "fe80::1%lo0",
                   "2130706433", "0x7f000001", "0")
        addresses = (*valid, *invalid)
        lines = [f"<86>Nov  7 18:30:00 host sshd[42]: Failed password for alice from {address} port 54000 ssh2"
                 for address in addresses]
        for threads in (1, 4):
            rows = events("--threads", threads, data="\n".join(lines))
            self.assertEqual([row["raw"] for row in rows], lines)
            for address, row in zip(addresses, rows):
                with self.subTest(threads=threads, address=address):
                    self.assertEqual(row["format"], "syslog")
                    if address in valid:
                        self.assertEqual(row["fields"]["src_ip"], address)
                        self.assertEqual(row["fields"]["outcome"], "failure")
                        self.assertEqual(row["level"], "ERROR")
                    else:
                        self.assertNotIn("src_ip", row["fields"])
                        self.assertNotIn("outcome", row["fields"])
                        self.assertEqual(row["level"], "INFO")

    def test_first_launch_guides_terminal_users_and_keeps_stdin_explicit(self):
        result = terminal(drain_after_exit=True)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith("Lumtail\n"))
        self.assertIn("lumtail --follow app.log", result.stdout)
        self.assertIn("lumtail --errors-only app.log", result.stdout)
        self.assertIn("lumtail --help", result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertEqual(run().stdout, "")
        self.assertEqual(run(data="piped record\n").stdout, "piped record\n")
        typed = terminal("-", data="typed record\n")
        self.assertEqual(typed.returncode, 0)
        self.assertEqual(typed.stdout, "typed record\n")

    def test_help_prioritizes_common_tasks_and_works_without_a_follow_file(self):
        help_text = run("--help", "--follow").stdout
        self.assertIn("Start here", help_text)
        self.assertIn("Everyday options", help_text)
        self.assertIn("--errors-only --where service=api app.log", help_text)
        self.assertIn("--help-all", help_text)
        self.assertNotIn("--threads", help_text)
        self.assertNotIn("--max-line-bytes", help_text)
        self.assertLessEqual(len(help_text.splitlines()), 32)
        self.assertTrue(all(len(line) <= 80 for line in help_text.splitlines()))
        self.assertEqual(run("-h").stdout, help_text)
        self.assertEqual(run("--version", "--follow").stdout, "lumtail 0.1.0\n")

    def test_full_help_exposes_controls_without_loading_input_or_rules(self):
        result = run("--help-all", "--follow", "--rules", "missing-rules.json")
        self.assertEqual(result.stderr, "")
        self.assertTrue(result.stdout.startswith(run("--help").stdout))
        self.assertIn("Filters keep the entire record", result.stdout)
        for flag in ("--template", "--color", "--list-modules", "--rules", "--module",
                     "--threads", "--line-buffered", "--max-line-bytes", "--max-record-bytes",
                     "--multiline-timeout-ms", "--preset", "--alerts-only", "--auth-failures",
                     "--high-severity"):
            with self.subTest(flag=flag):
                self.assertIn(flag, result.stdout)
        self.assertTrue(all(len(line) <= 80 for line in result.stdout.splitlines()))
        for flags in (("--help", "--help-all"), ("--help-all", "--help")):
            self.assertEqual(run(*flags).stdout, result.stdout)
        self.assertEqual(terminal("--help-all").stdout, result.stdout)
        self.assertIn("unexpected value", run("--help-all=yes", code=2).stderr)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "read-only"
            path.write_text("input")
            with path.open("rb") as sink:
                failed = subprocess.run([BINARY, "--help-all"], stdout=sink,
                                        stderr=subprocess.PIPE, timeout=5 * TIMEOUT_SCALE)
            self.assertEqual(failed.returncode, 1)
            self.assertIn(b"stdout", failed.stderr)

    def test_cli_api_selection_and_contract_are_metadata_without_input_reads(self):
        for flag in ("--api-version=1",):
            self.assertEqual(run(flag, data="plain\n").stdout, run(data="plain\n").stdout)
        contract = run("--cli-contract", "--rules", "missing.json", "missing.log")
        self.assertEqual(contract.stderr, "")
        self.assertEqual(json.loads(contract.stdout)["api_version"], 1)
        for value in ("0", "2", "invalid", "01"):
            rejected = run("--api-version", value, "missing.log", code=2)
            self.assertEqual(rejected.stdout, "")
            self.assertIn("unsupported CLI API version", rejected.stderr)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "read-only"
            path.write_text("input")
            with path.open("rb") as sink:
                failed = subprocess.run([BINARY, "--cli-contract"], stdout=sink,
                                        stderr=subprocess.PIPE, timeout=5 * TIMEOUT_SCALE)
            self.assertEqual(failed.returncode, 1)
            self.assertIn(b"stdout", failed.stderr)

    def test_runtime_protections_report_the_actual_build(self):
        result = run("--sandbox-status", "--follow", "--rules", "missing-rules.json")
        self.assertEqual(result.stderr, "")
        self.assertTrue(result.stdout.startswith("Runtime protections\n"))
        self.assertIn("Filesystem:", result.stdout)
        self.assertIn("System calls:", result.stdout)
        self.assertIn("Core dumps: disabled", result.stdout)
        self.assertIn("Instrumentation exceptions:", result.stdout)
        self.assertIn("Required confinement:", result.stdout)
        self.assertIn("--sandbox-status", run("--help-all").stdout)
        self.assertIn("unexpected value", run("--sandbox-status=yes", code=2).stderr)

    @unittest.skipUnless(sys.platform == "darwin", "macOS deployment entitlements")
    def test_macos_sandbox_status_rejects_false_and_nonboolean_entitlements(self):
        for value in ("<false/>", "<string>disabled</string>"):
            with self.subTest(entitlement=value), tempfile.TemporaryDirectory() as folder:
                binary = Path(folder) / "lumtail"
                shutil.copy2(BINARY, binary)
                entitlements = Path(folder) / "entitlements.plist"
                entitlements.write_text(
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<plist version="1.0"><dict>'
                    '<key>com.apple.security.app-sandbox</key>' + value + '</dict></plist>\n')
                subprocess.run(
                    ["/usr/bin/codesign", "--force", "--sign", "-", "--entitlements",
                     str(entitlements), "--timestamp=none", str(binary)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=30 * TIMEOUT_SCALE, check=True)
                status = subprocess.run(
                    [str(binary), "--sandbox-status"], capture_output=True, text=True,
                    timeout=30 * TIMEOUT_SCALE)
                self.assertEqual(status.returncode, 0, status.stderr)
                self.assertEqual(status.stderr, "")
                self.assertIn("Filesystem: unavailable\n", status.stdout)
                self.assertIn("System calls: unavailable\n", status.stdout)
                self.assertIn("Core dumps: disabled\n", status.stdout)
                self.assertIn("Required confinement: unavailable\n", status.stdout)

    def test_required_confinement_status_and_discovery(self):
        status = run("--sandbox-status").stdout
        ready = "  Required confinement: available\n" in status
        result = run("--require-sandbox", "--sandbox-status", "--follow",
                     "--rules", "missing-rules.json", code=0 if ready else 1)
        self.assertEqual(result.stdout, status)
        self.assertEqual(result.stderr == "", ready)
        if not ready:
            self.assertIn("--require-sandbox:", result.stderr)
        for flag in ("--help", "--help-all", "--version", "--agent-schema"):
            with self.subTest(flag=flag):
                discovery = run("--require-sandbox", flag, "--rules", "missing-rules.json")
                self.assertEqual(discovery.stderr, "")
                self.assertEqual(discovery.stdout, run(flag).stdout)
        self.assertIn("--require-sandbox", run("--help-all").stdout)
        self.assertIn("unexpected value", run("--require-sandbox=no", code=2).stderr)

    def test_required_confinement_controls_reading(self):
        ready = "  Required confinement: available\n" in run("--sandbox-status").stdout
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.log"
            path.write_text("selected input\n")
            flags = ("--output=raw", "--rules", ROOT / "examples/modules.json", path, "-")
            result = run("--require-sandbox", *flags, data="stdin record\n",
                         code=0 if ready else 1)
            if ready:
                self.assertEqual(result.stdout, run(*flags, data="stdin record\n").stdout)
                self.assertEqual(result.stderr, "")
            else:
                self.assertEqual(result.stdout, "")
                self.assertIn("--require-sandbox:", result.stderr)
                # Keep stdin open and provide unwritten FIFOs. Rejection must
                # precede a blocking rule load or input read.
                rules, logs = Path(folder) / "rules.fifo", Path(folder) / "logs.fifo"
                os.mkfifo(rules)
                os.mkfifo(logs)
                process = subprocess.Popen([BINARY, "--require-sandbox", "--rules", str(rules),
                                            str(logs)], stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    self.assertEqual(process.wait(timeout=5 * TIMEOUT_SCALE), 1)
                    stdout, stderr = process.communicate(timeout=5 * TIMEOUT_SCALE)
                    self.assertEqual(stdout, b"")
                    self.assertIn(b"--require-sandbox:", stderr)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=5 * TIMEOUT_SCALE)

    def test_argument_errors_offer_a_next_step(self):
        result = run("--output", "invalid", code=2)
        self.assertEqual(result.stdout, "")
        self.assertIn("--output expects", result.stderr)
        self.assertIn("lumtail --help", result.stderr)
        self.assertIn("lumtail --list-modules", run("--module", "missing", code=2).stderr)

    def test_focused_example_keeps_the_selected_failure_and_its_context(self):
        path = ROOT / "examples/traces.log"
        flags = ("--errors-only", "--where", "service=api", "--multiline", "indent")
        continuation = (
            "  java.lang.IllegalStateException: payment rejected\n"
            "    at example.PaymentService.charge(PaymentService.java:42)\n"
            "    at example.Api.handle(Api.java:17)"
        )
        text = run(*flags, "--template", "{file}:{line} [{level}] {message}", path)
        self.assertEqual(text.stdout, f"{path}:1 [ERROR] Request failed\n{continuation}\n")
        self.assertEqual(text.stderr, "")
        selected = events(*flags, path)
        self.assertEqual(len(selected), 1)
        event = selected[0]
        self.assertEqual((event["file"], event["line"], event["format"], event["level"]),
                         (str(path), 1, "json", "ERROR"))
        self.assertEqual(event["fields"]["service"], "api")
        self.assertEqual(event["fields"]["message"], "Request failed")
        self.assertEqual(event["continuation"], continuation)
        self.assertEqual(event["raw"], path.read_text().splitlines()[0] + "\n" + continuation)

    def test_format_listing_is_readable_in_a_terminal_and_stable_in_pipes(self):
        args = ("--rules", ROOT / "examples/modules.json", "--list-modules")
        result = terminal(*args)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith("Formats\n"))
        self.assertIn("JSON Lines", result.stdout)
        self.assertIn("Custom rules", result.stdout)
        self.assertLess(result.stdout.index("application"), result.stdout.index("json"))
        rows = [line.split("\t") for line in run(*args).stdout.splitlines()]
        self.assertEqual([name for name, _ in rows],
                         ["application", "worker", *BUILTIN_MODULES])
        self.assertEqual([int(priority) for _, priority in rows][:2], [100, 90])
        priorities = [int(priority) for _, priority in rows[2:]]
        self.assertEqual(priorities, sorted(priorities, reverse=True))
        self.assertEqual(priorities[-1], -1000)
        listed = [line.split() for line in result.stdout.splitlines() if line.startswith("  ")]
        for name in BUILTIN_MODULES:
            with self.subTest(module=name):
                row = next(words for words in listed if words[0] == name)
                self.assertNotEqual(row[1:], ["Custom", "rules"])
        self.assertIn("Common Event Format (CEF)", result.stdout)
        self.assertIn("Fail2ban logs", result.stdout)

    def test_color_highlights_the_severity_field_and_keeps_content_safe(self):
        data = json.dumps({"level": "error", "message": "ERROR \x1b[2J"}) + "\n"
        result = run("--color=always", "--template", "ERROR [{level}] {message}", data=data)
        self.assertEqual(result.stdout,
                         "ERROR [\x1b[31mERROR\x1b[0m] ERROR \\x1b[2J\n")
        self.assertEqual(run("--color=always", "--template", "{message}", data=data).stdout,
                         "ERROR \\x1b[2J\n")
        self.assertEqual(run("--color=always", "--template", "{message} [{level}]", data=data).stdout,
                         "ERROR \\x1b[2J [\x1b[31mERROR\x1b[0m]\n")

    def test_terminal_color_respects_the_environment(self):
        data = '{"level":"error","message":"Failed"}\n'
        args = ("--threads=1", "--template", "[{level}] {message}")
        colored = terminal(*args, data=data)
        self.assertEqual(colored.returncode, 0)
        self.assertEqual(colored.stdout, "[\x1b[31mERROR\x1b[0m] Failed\n")
        for env in ({"NO_COLOR": ""}, {"TERM": "dumb"}):
            with self.subTest(env=env):
                result = terminal(*args, data=data, env=env)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "[ERROR] Failed\n")
        forced = terminal(*args, "--color=always", data=data, env={"NO_COLOR": "1"})
        self.assertEqual(forced.returncode, 0)
        self.assertEqual(forced.stdout, colored.stdout)

    def test_parallel_output_matches_sequential_in_order(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "mixed.log"
            samples = (ROOT / "examples/mixed.log").read_text().splitlines()
            lines = [json.dumps({"level": "error" if i % 3 else "info", "message": "x" * (i % 300), "seq": i})
                     if i % 2 else samples[i % len(samples)] for i in range(20000)]
            lines.insert(0, json.dumps({"message": "first " + "x" * 800000, "level": "error"}))
            path.write_text("\n".join(lines))
            for mode in ("text", "json", "raw"):
                for filters in ((), ("--errors-only",)):
                    with self.subTest(mode=mode, filters=filters):
                        args = ("--rules", ROOT / "examples/modules.json", "--output", mode, *filters, path)
                        expected = run("--threads=1", *args).stdout
                        actual = run("--threads=8", *args).stdout
                        self.assertEqual(actual, expected)

    def test_parallel_writer_failure_does_not_deadlock(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "large.log"
            path.write_text('{"message":"output","level":"error"}\n' * 50000)
            with open(os.devnull, "rb") as readonly:
                result = subprocess.run([BINARY, "--threads=4", str(path)], stdout=readonly,
                                        stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"write stdout", result.stderr)

    def test_closed_downstream_cancels_idle_input_pipe(self):
        for threads in (1, 4):
            with self.subTest(threads=threads):
                process = subprocess.Popen([BINARY, "--threads", str(threads)], stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    process.stdout.close()
                    process.stdin.write(b'{"level":"info","message":"live"}\n')
                    process.stdin.flush()
                    self.assertEqual(process.wait(timeout=3), 0)
                    self.assertEqual(process.stderr.read(), b"")
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.stdin.close()
                    process.stderr.close()
                    process.wait()

    def test_parallel_file_errors_preserve_valid_records(self):
        with tempfile.TemporaryDirectory() as folder:
            first, last = Path(folder) / "first.log", Path(folder) / "last.log"
            first.write_text("before\n" + "x" * 200 + "\n")
            last.write_text("after\n")
            result = run("--threads=4", "--max-line-bytes=100", first, last, code=1)
            self.assertEqual(result.stdout, "before\nafter\n")
            self.assertIn("line 2 exceeds", result.stderr)

    def test_thread_count_validation(self):
        for value in ("0", "-1", "257", "invalid", "9999999999999999999999999999"):
            with self.subTest(value=value):
                self.assertIn("--threads expects", run("--threads", value, code=2).stderr)
        self.assertEqual(run("-j", "1", data="hello\n").stdout, "hello\n")
        self.assertEqual(run("--threads=auto", data="hello\n").stdout, "hello\n")

    def test_deep_rules_fail_without_crashing(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "deep.json"
            path.write_text('[' * 50000 + '0' + ']' * 50000)
            self.assertIn("64 levels", run("--rules", path, code=2).stderr)

    def test_follow_rejects_fifo_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.fifo"
            os.mkfifo(path)
            self.assertIn("regular file", run("--follow", path, code=1).stderr)

    def test_diagnostics_escape_terminal_controls(self):
        result = run("--module", "bad\x1b[2J\nname", code=2)
        self.assertNotIn("\x1b", result.stderr)
        self.assertIn("bad\\x1b[2J\\x0aname", result.stderr)

    def test_text_escapes_invalid_utf8_and_unicode_controls(self):
        result = subprocess.run([BINARY], input=b"\xff\xc2\x9b\xe2\x80\xae\n", capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"\\xff\\xc2\\x9b\\xe2\\x80\\xae\n")

    def test_json_preserves_byte_order_and_utf8_replacement(self):
        source = b'prefix "\\\x00\t\xe1\x80A\xf0\x90\x80B\xed\xa0\x80\xe2\x80\xa8'
        # Replacement consumes a maximal valid prefix, leaving the following
        # ASCII byte intact. A surrogate's invalid continuation is reprocessed.
        message = 'prefix "\\\x00\t\ufffdA\ufffdB\ufffd\ufffd\ufffd\u2028'
        for threads in (1, 4):
            result = subprocess.run(
                [BINARY, "--output=json", f"--threads={threads}"], input=source + b"\n",
                capture_output=True, timeout=10 * TIMEOUT_SCALE,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b"")
            event = json.loads(result.stdout)
            self.assertEqual(event["raw"], message)
            self.assertEqual(event["fields"]["message"], message)
            expected = json.dumps(event, sort_keys=True, ensure_ascii=False,
                                  separators=(",", ":")).replace("\u2028", "\\u2028").encode() + b"\n"
            self.assertEqual(result.stdout, expected)

    @unittest.skipUnless(Path("/dev/full").exists(), "requires /dev/full")
    def test_output_failure_is_reported(self):
        with open("/dev/full", "wb") as output:
            result = subprocess.run([BINARY], input=b"record\n", stdout=output, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertTrue(result.stderr)

    def test_mixed_formats_and_custom_rules(self):
        rows = events("--rules", ROOT / "examples/modules.json", ROOT / "examples/mixed.log")
        self.assertEqual([r["format"] for r in rows], ["json", "syslog", "access", "access", "application", "worker", "plain"])
        self.assertEqual([r["level"] for r in rows], ["INFO", "ERROR", "INFO", "ERROR", "ERROR", "WARN", "UNKNOWN"])
        self.assertEqual(rows[2]["fields"]["user"], "alice")
        self.assertEqual(rows[3]["fields"]["access_format"], "combined")
        self.assertEqual(rows[4]["fields"]["original_level"], "FAIL")
        self.assertEqual(rows[5]["fields"]["worker"], "7")

    def test_json_aliases_and_escaped_values(self):
        source = {"time": "now", "severity": "fatal", "logger": "api", "msg": "hello\nworld ☀", "extra": {"a": 1}}
        event, = events(data=json.dumps(source) + "\n")
        self.assertEqual(event["level"], "CRITICAL")
        self.assertEqual(event["fields"]["message"], "hello\nworld ☀")
        self.assertEqual(event["fields"]["source"], "api")
        self.assertEqual(event["fields"]["extra"], '{"a":1}')
        self.assertEqual(len(run(data=json.dumps(source) + "\n").stdout.splitlines()), 1)

    def test_numeric_pino_level_and_alias_precedence(self):
        event, = events(data='{"level":50,"severity":"info","message":"primary","msg":"other"}\n')
        self.assertEqual(event["level"], "ERROR")
        self.assertEqual(event["fields"]["message"], "primary")

    def test_security_shortcuts_require_exact_labels_and_combine_with_and(self):
        records = [
            {"event_type": "alert", "level": "warn", "message": "low alert"},
            {"event_type": "alert", "level": "critical", "message": "high alert"},
            {"event_type": "authentication", "outcome": "failure", "level": "error", "user": "alice"},
            {"event_type": "authentication", "outcome": "success", "level": "critical"},
            {"event_type": "Alert", "level": "error"},
            {"event_type": "authentication", "outcome": "Failure", "level": "error"},
            {"level": "error", "message": "alert: authentication failure"},
            {"event_type": "alert", "level": "unmapped", "message": "unknown severity"},
            {"event_type": ["alert"], "level": "critical"},
            {"event_type": "authentication", "level": "critical"},
        ]
        data = "\n".join(json.dumps(record) for record in records)
        rows = events(data=data)
        self.assertEqual(events("--alerts-only", data=data), [rows[0], rows[1], rows[7]])
        self.assertEqual(events("--auth-failures", data=data), [rows[2]])
        self.assertEqual(events("--auth-failures", "--where=user=other", data=data), [])
        self.assertEqual(events("--alerts-only", "--high-severity", data=data), [rows[1]])
        for flags in (("--high-severity", "--min-level=warn"),
                      ("--min-level=warn", "--high-severity")):
            self.assertEqual(events(*flags, data=data), events("--errors-only", data=data))
        for flags in (("--high-severity", "--min-level=critical"),
                      ("--min-level=critical", "--high-severity")):
            self.assertEqual(events("--alerts-only", *flags, data=data), [rows[1]])
        for flags in (("--alerts-only", "--auth-failures"), ("--auth-failures", "--alerts-only")):
            self.assertEqual(events(*flags, data=data), [])
        self.assertEqual(events("--alerts-only", "--alerts-only", data=data),
                         events("--alerts-only", data=data))
        self.assertEqual(events("--auth-failures", "--auth-failures", data=data), [rows[2]])
        # High CEF severity and Fail2ban bans do not supply an alert event_type.
        for fixture in ("cef.log", "fail2ban.log"):
            self.assertEqual(events("--alerts-only", ROOT / "examples" / fixture), [])

    def test_security_shortcuts_match_existing_filters_across_modes_and_workers(self):
        data = "".join((ROOT / "examples" / name).read_text()
                       for name in ("suricata-eve.log", "unix-auth.log", "cef.log", "fail2ban.log")) * 80
        shortcuts = [
            (("--alerts-only",), ("--where=event_type=alert",)),
            (("--auth-failures",), ("--where=event_type=authentication", "--where=outcome=failure")),
            (("--high-severity",), ("--errors-only",)),
        ]
        for workers in (1, 4):
            for mode in ("text", "json", "raw"):
                for shortcut, explicit in shortcuts:
                    with self.subTest(workers=workers, mode=mode, shortcut=shortcut):
                        flags = (f"--threads={workers}", f"--output={mode}", "--preset=network")
                        self.assertEqual(run(*flags, *shortcut, data=data).stdout,
                                         run(*flags, *explicit, data=data).stdout)

    def test_security_presets_format_text_and_preserve_json_and_raw(self):
        record = {"timestamp": "now", "level": "error", "source": "sensor", "user": "alice",
                  "src_ip": "2001:db8::10", "dst_ip": "198.51.100.20", "outcome": "failure",
                  "message": "alarm\n\x1b[2J"}
        data = json.dumps(record) + "\n"
        safe_message = "alarm\\x0a\\x1b[2J"
        expected = {
            "security": f"now [ERROR] sensor | {safe_message}\n",
            "network": f"now [ERROR] 2001:db8::10 → 198.51.100.20 | {safe_message}\n",
            "auth": f"now [ERROR] sensor user=alice remote=2001:db8::10 outcome=failure | {safe_message}\n",
        }
        baseline = events(data=data)
        for preset, output in expected.items():
            with self.subTest(preset=preset):
                self.assertEqual(run("--preset", preset, "--color=never", data=data).stdout, output)
                colored = run(f"--preset={preset}", "--color=always", data=data).stdout
                self.assertEqual(colored, output.replace("[ERROR]", "[\x1b[31mERROR\x1b[0m]"))
                self.assertEqual(events(f"--preset={preset}", data=data), baseline)
                self.assertEqual(run(f"--preset={preset}", "--output=raw", data=data).stdout, data)
        self.assertEqual(run("--preset=auth", "--preset=network", data=data).stdout, expected["network"])
        self.assertEqual(run("--preset=security", data="plain\n").stdout, "- [UNKNOWN] - | plain\n")
        self.assertEqual(run("--preset=auth", data='{"user":"","message":"present"}\n').stdout,
                         "- [UNKNOWN] - user= remote=- outcome=- | present\n")
        custom = run("--rules", ROOT / "examples/modules.json", "--preset=security",
                     data="worker=9 level=warn message=busy\n")
        self.assertEqual(custom.stdout, "- [WARN] - | busy\n")

    def test_security_presets_explicit_template_precedence_and_validation(self):
        data = '{"level":"error","message":"failure"}\n'
        for flags in (("--preset=network", "--template={level}: {message}"),
                      ("--template={level}: {message}", "--preset=network"),
                      ("--preset=auth", "--template={level}: {message}", "--preset=security")):
            self.assertEqual(run(*flags, data=data).stdout, "ERROR: failure\n")
        for value in ("", "missing", "Security", "{message}"):
            result = run(f"--preset={value}", data=data, code=2)
            self.assertEqual(result.stdout, "")
            self.assertIn("--preset", result.stderr)
        self.assertIn("needs a value", run("--preset", code=2).stderr)
        self.assertIn("--preset expects", run("--preset=missing", "--template=explicit", code=2).stderr)
        for flag in ("--alerts-only", "--auth-failures", "--high-severity"):
            self.assertIn("unexpected value", run(flag + "=yes", code=2).stderr)

    def test_security_shortcuts_keep_multiline_metadata_and_emit_live_input(self):
        failure, _, success, *_ = (ROOT / "examples/unix-auth.log").read_text().splitlines()
        data = failure + "\n  failure context\n" + success + "\n  success context\n"
        for workers in (1, 4):
            with self.subTest(workers=workers):
                row, = events(f"--threads={workers}", "--auth-failures", "--multiline=indent",
                              "--preset=auth", data=data)
                self.assertEqual(row["raw"], failure + "\n  failure context")
                self.assertEqual(row["line"], 1)
                self.assertEqual(row["continuation"], "  failure context")
                raw = run(f"--threads={workers}", "--auth-failures", "--multiline=indent",
                          "--preset=auth", "--output=raw", data=data).stdout
                self.assertEqual(raw, failure + "\n  failure context\n")
        process = subprocess.Popen([BINARY, "--threads=4", "--alerts-only", "--preset=network"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            records = [{"event_type": "flow", "message": "ignored"},
                       {"event_type": "alert", "level": "error", "src_ip": "192.0.2.1",
                        "dst_ip": "198.51.100.2", "message": "live alert"}]
            process.stdin.write(("\n".join(json.dumps(record) for record in records) + "\n").encode())
            process.stdin.flush()
            self.assertTrue(select.select([process.stdout], [], [], 5 * TIMEOUT_SCALE)[0],
                            "security-filtered input waited for EOF")
            self.assertEqual(process.stdout.readline(),
                             b"- [ERROR] 192.0.2.1 \xe2\x86\x92 198.51.100.2 | live alert\n")
        finally:
            remaining, errors = process.communicate(timeout=5 * TIMEOUT_SCALE)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(remaining, b"")
        self.assertEqual(errors, b"")

    def test_suricata_eve_fields_templates_and_raw(self):
        path = ROOT / "examples/suricata-eve.log"
        data = path.read_text()
        inputs = [json.loads(line) for line in data.splitlines()]
        rows = events(path)
        self.assertEqual([row["format"] for row in rows], ["json"] * 4)
        self.assertEqual([row["level"] for row in rows], ["CRITICAL", "ERROR", "WARN", "UNKNOWN"])
        fields = rows[0]["fields"]
        for key in ("timestamp", "src_ip", "src_port", "dest_ip", "dest_port", "event_type"):
            self.assertEqual(fields[key], str(inputs[0][key]))
        for key in ("signature", "signature_id", "category", "action"):
            self.assertEqual(fields[key], str(inputs[0]["alert"][key]))
        self.assertEqual(fields["dst_ip"], inputs[0]["dest_ip"])
        self.assertEqual(fields["dst_port"], str(inputs[0]["dest_port"]))
        self.assertEqual(fields["alert_severity"], "1")
        self.assertEqual(fields["original_level"], "1")
        self.assertEqual(fields["source"], "suricata")
        self.assertEqual(fields["message"], inputs[0]["alert"]["signature"])
        self.assertEqual(json.loads(fields["alert"]), inputs[0]["alert"])
        self.assertEqual([row["raw"] for row in rows], data.splitlines())
        self.assertTrue(all(isinstance(value, str) for value in fields.values()))
        template = "{timestamp} [{level}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | {signature}"
        expected = (f'{fields["timestamp"]} [CRITICAL] {fields["src_ip"]}:{fields["src_port"]}'
                    f' → {fields["dst_ip"]}:{fields["dst_port"]} | {fields["signature"]}\n')
        self.assertEqual(run("--color=never", "--where=alert_severity=1", "--template", template,
                             path).stdout, expected)
        self.assertEqual(run("--output=raw", path).stdout, data)
        self.assertEqual(events("--module=json", path), rows)

    def test_suricata_eve_filters_and_parallel_output(self):
        path = ROOT / "examples/suricata-eve.log"
        rows = events(path)
        self.assertEqual(events("--errors-only", path), rows[:2])
        self.assertEqual(events("--min-level=error", "--where=event_type=alert", path), rows[:2])
        self.assertEqual(events("--where=event_type=alert", path), rows[:3])
        self.assertEqual(events("--where=signature_id=1000002", path), [rows[1]])
        self.assertEqual(events("--where=dst_ip=2001:db8::20", path), [rows[2]])
        raw = run("--output=raw", "--errors-only", path).stdout
        self.assertEqual(raw, "\n".join(row["raw"] for row in rows[:2]) + "\n")
        data = path.read_text() * 400
        for mode in ("text", "json", "raw"):
            with self.subTest(mode=mode):
                args = (f"--output={mode}", "--where=event_type=alert", "--min-level=warn")
                self.assertEqual(run("--threads=4", *args, data=data).stdout,
                                 run("--threads=1", *args, data=data).stdout)

    def test_zeek_json_profiles_fields_provenance_and_filters(self):
        path = ROOT / "examples/zeek-json.log"
        rows = events(path)
        types = ["conn", "notice", "weird", "dns", "http", "ssl", "files"]
        self.assertEqual([row["format"] for row in rows], ["json"] * 7)
        self.assertEqual([row["level"] for row in rows], ["UNKNOWN"] * 7)
        self.assertEqual([row["fields"]["zeek_log_type"] for row in rows], types)
        self.assertEqual([row["fields"]["event_type"] for row in rows], types)
        self.assertEqual([row["line"] for row in rows], list(range(1, 8)))
        self.assertTrue(all(row["file"] == str(path) for row in rows))
        self.assertEqual([row["raw"] for row in rows], path.read_text().splitlines())
        self.assertEqual(rows[0]["fields"]["flow_id"], "CExample")
        self.assertEqual(rows[3]["fields"]["dns_rrname"], "example.test")
        self.assertEqual(json.loads(rows[3]["fields"]["dns_answers"]), ["2001:db8::30", "2001:db8::31"])
        self.assertEqual(rows[4]["fields"]["http_status"], "503")
        self.assertEqual(rows[5]["fields"]["tls_sni"], "example.test")
        self.assertEqual(rows[6]["fields"]["file_id"], "FExample")
        self.assertEqual(rows[6]["fields"]["source"], "HTTP")
        self.assertNotIn("src_port", rows[6]["fields"])
        self.assertEqual(events("--module=json", path), rows)
        self.assertEqual(events("--where=zeek_log_type=dns", path), [rows[3]])
        self.assertEqual(events("--filter=http_status>=500 AND user=alice", path), [rows[4]])
        self.assertEqual(events("--errors-only", path), [])
        self.assertEqual(events("--alerts-only", path), [])
        self.assertEqual(run("--where=zeek_log_type=http", "--color=never", "--template",
                             "{level}|{http_method}|{http_status}", path).stdout, "UNKNOWN|GET|503\n")
        self.assertEqual(run("--output=raw", path).stdout, path.read_text())
        agent = [json.loads(line) for line in run("--agent", "--limit=1", "--where=zeek_log_type=dns",
                                                 "--agent-fields=flow_id,dns_rrname", path).stdout.splitlines()]
        self.assertEqual(agent[0]["fields"], {"flow_id": "CExample", "dns_rrname": "example.test"})

    def test_security_json_profiles_fields_and_filters(self):
        path = ROOT / "examples/security-profiles.jsonl"
        rows = events(path)
        markers = ["gelf_profile", "journald_profile", "falco_profile", "osquery_profile",
                   "okta_profile", "gcp_profile", "osquery_profile", "okta_profile"]
        self.assertEqual([row["format"] for row in rows], ["json"] * 8)
        self.assertTrue(all(marker in row["fields"] for marker, row in zip(markers, rows)))
        self.assertEqual([row["level"] for row in rows],
                         ["ERROR", "WARN", "WARN", "UNKNOWN", "WARN", "ERROR", "UNKNOWN", "INFO"])
        self.assertEqual([row["raw"] for row in rows], path.read_text().splitlines())
        self.assertEqual(events("--module=json", path), rows)
        self.assertEqual(events("--where=okta_result=FAILURE", path), [rows[4]])
        self.assertEqual(events("--where=gcp_profile=audit", "--where=outcome=failure", path), [rows[5]])
        self.assertEqual(run("--where=falco_profile=alert", "--color=never", "--template",
                             "{level}|{user}|{command}", path).stdout, "WARN|root|bash -i\n")
        self.assertEqual(run("--where=journald_profile=json", "--color=never", "--template",
                             "{source}|{pid}|{message}", path).stdout,
                         "sshd|2210|Invalid user deploy from 203.0.113.9\n")
        self.assertEqual(run("--output=raw", path).stdout, path.read_text())
        ordinary = '{"short_message":"x","version":"1.0","host":"h"}\n'
        row, = events(data=ordinary)
        self.assertNotIn("gelf_profile", row["fields"])

    def test_logfmt_records_fields_and_fallback(self):
        path = ROOT / "examples/logfmt.log"
        rows = events(path)
        self.assertEqual([row["format"] for row in rows], ["logfmt.kv"] * 4 + ["plain"])
        self.assertEqual([row["level"] for row in rows], ["INFO", "ERROR", "WARN", "UNKNOWN", "UNKNOWN"])
        self.assertEqual([row["raw"] for row in rows], path.read_text().splitlines())
        self.assertEqual(rows[1]["fields"]["message"], 'upstream refused "checkout"')
        self.assertEqual(rows[2]["fields"]["timestamp"], "2026-11-11T08:00:02Z")
        self.assertEqual(rows[2]["fields"]["source"], "db")
        self.assertEqual(events("--module=logfmt.kv", path), rows)
        for threads in ("1", "4"):
            self.assertEqual(events("--threads", threads, path), rows)
        self.assertEqual(events("--where=user=alice", path), [rows[1]])
        self.assertEqual(events("--errors-only", path), [rows[1]])
        self.assertEqual(events("--filter", "status>=400", path), [rows[3]])
        self.assertEqual(run("--output=raw", path).stdout, path.read_text())
        row, = events("--module=logfmt.kv", data="plain words only\n")
        self.assertEqual(row["format"], "plain")
        row, = events(data='a=1 b="x\\u0000"\n')
        self.assertEqual(row["format"], "plain")

    def test_cloud_json_profiles_fields_and_filters(self):
        path = ROOT / "examples/cloud-profiles.jsonl"
        rows = events(path)
        markers = ("snort_profile", "docker_profile", "cloudtrail_profile", "waf_profile",
                   "traefik_profile")
        self.assertEqual([row["format"] for row in rows], ["json"] * 10)
        self.assertEqual([next(m for m in markers if m in row["fields"]) for row in rows],
                         [m for m in markers for _ in range(2)])
        self.assertEqual([row["level"] for row in rows],
                         ["UNKNOWN", "ERROR"] + ["UNKNOWN"] * 6 + ["INFO", "ERROR"])
        self.assertEqual([row["raw"] for row in rows], path.read_text().splitlines())
        self.assertEqual(events("--module=json", path), rows)
        for threads in ("1", "4"):
            self.assertEqual(events("--threads", threads, path), rows)
        self.assertEqual(events("--where=outcome=failure", path), [rows[5]])
        self.assertEqual(events("--where=waf_profile=aws", "--where=action=BLOCK", path), [rows[7]])
        self.assertEqual(events("--where=docker_stream=stderr", path), [rows[3]])
        self.assertEqual(events("--filter", "http_status>=500", path), [rows[9]])
        self.assertEqual(rows[5]["fields"]["src_ip"], "2001:db8::25")
        self.assertEqual(rows[9]["fields"]["src_ip"], "2001:db8::10")
        self.assertEqual(rows[9]["fields"]["original_level"], "info")
        self.assertEqual(rows[2]["fields"]["message"], rows[2]["fields"]["log"][:-1])

    def test_dns_mail_and_container_lines(self):
        cases = (("examples/cri.log", ["cri.log"] * 5, ["UNKNOWN"] * 5),
                 ("examples/dns-query.log",
                  ["bind.query"] * 2 + ["unbound.log"] * 2 + ["syslog", "unbound.log"],
                  ["INFO"] * 5 + ["ERROR"]),
                 ("examples/postfix.log", ["syslog"] * 7, ["UNKNOWN"] * 7))
        for name, formats, levels in cases:
            with self.subTest(sample=name):
                path = ROOT / name
                rows = events(path)
                self.assertEqual([row["format"] for row in rows], formats)
                self.assertEqual([row["level"] for row in rows], levels)
                self.assertEqual([row["raw"] for row in rows], path.read_text().splitlines())
                for threads in ("1", "4"):
                    self.assertEqual(events("--threads", threads, path), rows)
        cri = ROOT / "examples/cri.log"
        self.assertEqual(len(events("--where=cri_partial=true", cri)), 1)
        self.assertEqual(run("--template", "{message}", cri).stdout.splitlines()[2],
                         "first chunk of a long line ")
        dns = ROOT / "examples/dns-query.log"
        self.assertEqual([row["fields"]["src_ip"] for row in events("--where=event_type=dns", dns)],
                         ["192.0.2.10", "192.0.2.12", "198.51.100.7", "198.51.100.7", "2001:db8::10"])
        row, = events("--where=dns_rcode=NXDOMAIN", dns)
        self.assertEqual((row["fields"]["dst_port"], row["fields"]["dns_duration"]), ("53", "0.104210"))
        self.assertEqual(len(events("--errors-only", dns)), 1)
        mail = ROOT / "examples/postfix.log"
        self.assertEqual(run("--where=postfix_queue_id=1E240100019", "--template", "{postfix_service}",
                             mail).stdout.split(), ["smtpd", "qmgr", "smtp"])
        self.assertEqual([row["fields"]["mail_to"] for row in events("--where=outcome=failure", mail)],
                         ["carol@example.test", "user@relay.example.test"])
        row, = events("--where=action=reject", mail)
        self.assertEqual((row["fields"]["src_ip"], row["fields"]["smtp_code"]), ("198.51.100.77", "554"))
        row, = events("--module=cri.log", data="Nov 11 08:00:00 host app: text\n")
        self.assertEqual(row["format"], "plain")

    def test_firewall_proxy_and_osquery_lines(self):
        cases = (("examples/filterlog.log", ["syslog"] * 6, ["INFO"] * 6),
                 ("examples/haproxy.log", ["syslog"] + ["haproxy.http"] * 5,
                  ["INFO"] + ["UNKNOWN"] * 5),
                 ("examples/osquery-status.log", ["glog.text"] * 4 + ["osquery.status", "json"],
                  ["INFO", "WARN", "ERROR", "CRITICAL", "WARN", "ERROR"]))
        for name, formats, levels in cases:
            with self.subTest(sample=name):
                path = ROOT / name
                rows = events(path)
                self.assertEqual([row["format"] for row in rows], formats)
                self.assertEqual([row["level"] for row in rows], levels)
                self.assertEqual([row["raw"] for row in rows], path.read_text().splitlines())
                for threads in ("1", "4"):
                    self.assertEqual(events("--threads", threads, path), rows)
        firewall = ROOT / "examples/filterlog.log"
        rows = events("--where=action=block", firewall)
        self.assertEqual([row["fields"]["src_ip"] for row in rows],
                         ["192.0.2.10", "2001:db8::10", "203.0.113.9"])
        self.assertNotIn("host", rows[0]["fields"])
        self.assertEqual(run("--where=protocol=udp", "--template", "{src_port}>{dst_port}",
                             firewall).stdout, "53>40000\n")
        proxy = ROOT / "examples/haproxy.log"
        self.assertEqual(run("--filter", "http_status>=500", "--template",
                             "{haproxy_server}|{haproxy_termination}|{duration_ms}", proxy).stdout,
                         "<NOSRV>|sQ--|30001\n")
        self.assertEqual(len(events("--where=haproxy_tls=true", proxy)), 2)
        status = ROOT / "examples/osquery-status.log"
        self.assertEqual(run("--errors-only", "--template", "{code_file}", status).stdout.split(),
                         ["scheduler.cpp", "main.cpp", "tls.cpp"])

    def test_vendor_firewall_and_waf_records(self):
        firewall = ROOT / "examples/firewall-vendors.log"
        rows = events(firewall)
        self.assertEqual([row["format"] for row in rows], ["fortigate.kv"] * 3 + ["syslog"] * 4)
        self.assertEqual([row["level"] for row in rows],
                         ["INFO", "INFO", "INFO", "CRITICAL", "INFO", "CRITICAL", "INFO"])
        self.assertEqual([row["raw"] for row in rows], firewall.read_text().splitlines())
        for threads in ("1", "4"):
            self.assertEqual(events("--threads", threads, firewall), rows)
        self.assertEqual(run("--where=action=deny", "--template", "{src_ip}>{dst_ip}:{dst_port}",
                             firewall).stdout, "10.1.100.160>198.51.100.25:22\n")
        self.assertEqual(run("--where=event_type=firewall", "--template", "{source}|{src_ip}",
                             firewall).stdout.split(),
                         ["fortigate|10.1.100.155", "fortigate|10.1.100.160",
                          "pan-os|192.0.2.10"])
        threat = events("--where=pan_type=THREAT", firewall)
        self.assertEqual(threat[0]["fields"]["signature_id"], "33337")
        self.assertEqual(threat[0]["fields"]["pan_misc"], "/cgi-bin/x.cgi?a=1,2")
        system = events("--where=pan_type=SYSTEM", firewall)
        self.assertEqual(system[0]["fields"]["message"],
                         'User admin logged in via Web from 198.51.100.7 using https, "SSO"')
        waf = ROOT / "examples/waf-profiles.jsonl"
        rows = events(waf)
        self.assertEqual([row["format"] for row in rows], ["json"] * 5)
        self.assertEqual([row["level"] for row in rows],
                         ["CRITICAL", "CRITICAL", "WARN", "INFO", "UNKNOWN"])
        self.assertEqual(run("--where=event_type=waf", "--template", "{source}|{signature_id}",
                             waf).stdout.split(),
                         ["modsecurity|942100", "modsecurity|1001", "cloudflare|c0ffee"])
        self.assertEqual(run("--filter", "http_status>=400", "--template", "{src_ip}",
                             waf).stdout.split(),
                         ["192.0.2.10", "203.0.113.7", "203.0.113.9", "2001:db8::7"])
        self.assertEqual(len(events("--where=modsec_interrupted=true", waf)), 2)

    def test_network_text_modules_fields_and_filters(self):
        cases = (("examples/ids-fast.log", "ids.fast", ["WARN", "ERROR", "UNKNOWN", "CRITICAL"]),
                 ("examples/aws-vpc-flow.log", "aws.vpc-flow", ["UNKNOWN"] * 3),
                 ("examples/squid-access.log", "squid.native", ["INFO", "INFO", "WARN"]))
        for name, module, levels in cases:
            with self.subTest(module=module):
                path = ROOT / name
                rows = events(path)
                self.assertEqual([row["format"] for row in rows], [module] * len(levels))
                self.assertEqual([row["level"] for row in rows], levels)
                self.assertEqual([row["raw"] for row in rows], path.read_text().splitlines())
                self.assertEqual(events(f"--module={module}", path), rows)
                self.assertEqual(run("--output=raw", path).stdout, path.read_text())
        fast = ROOT / "examples/ids-fast.log"
        self.assertEqual(run("--where=source=suricata", "--color=never", "--template",
                             "{signature_id}|{icmp_type}|{icmp_code}|{action}", fast).stdout,
                         "3000019|8|0|Drop\n")
        self.assertEqual(len(events("--alerts-only", fast)), 4)
        flow = ROOT / "examples/aws-vpc-flow.log"
        self.assertEqual(run("--where=action=REJECT", "--color=never", "--template",
                             "{src_ip}|{protocol}|{vpc_bytes}", flow).stdout,
                         "2001:db8:a::15|ipv6-icmp|216\n")
        squid = ROOT / "examples/squid-access.log"
        self.assertEqual(run("--filter=http_status>=400", "--color=never", "--template",
                             "{squid_result}|{http_url}", squid).stdout,
                         "TCP_DENIED|http://blocked.example.com/\n")
        data = "".join((ROOT / name).read_text() for name, _, _ in cases) * 200
        for mode in ("text", "json", "raw"):
            baseline = run("--threads=1", f"--output={mode}", data=data).stdout
            self.assertEqual(run("--threads=4", f"--output={mode}", data=data).stdout, baseline)

    def test_zeek_mixed_workers_and_multiline_preserve_order(self):
        data = ((ROOT / "examples/zeek-json.log").read_text() + '{"message":"ordinary JSON"}\n'
                + 'An unstructured message\n') * 300
        for mode in ("text", "json", "raw", "agent"):
            args = (f"--output={mode}", "--color=never")
            baseline = run("--threads=1", *args, data=data).stdout
            for workers in (2, 4):
                self.assertEqual(run(f"--threads={workers}", *args, data=data).stdout, baseline)
        first = (ROOT / "examples/zeek-json.log").read_text().splitlines()[0]
        row, = events("--multiline=indent", data=first + "\n continuation\n")
        self.assertEqual((row["line"], row["fields"]["zeek_log_type"]), (1, "conn"))
        self.assertEqual(row["raw"], first + "\n continuation")
        self.assertEqual(row["continuation"], " continuation")

    def test_zeek_required_fields_types_paths_and_ambiguity(self):
        originals = [json.loads(line) for line in (ROOT / "examples/zeek-json.log").read_text().splitlines()]
        required = [
            ["uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "conn_state", "missed_bytes"],
            ["note", "actions"], ["name", "notice", "peer"],
            ["uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "trans_id", "query"],
            ["uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "trans_depth", "request_body_len", "response_body_len"],
            ["uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "resumed", "established", "ssl_history"],
            ["fuid", "depth", "seen_bytes", "missing_bytes"],
        ]
        for fallback in ("", ',"large_number":18446744073709551616'):
            cases = []
            for original, keys in zip(originals, required):
                for key in ["ts", *keys]:
                    cases.append({k: v for k, v in original.items() if k != key})
                    cases.append({**original, key: None})
                for path in ("unrecognized", "tls", 1, None):
                    cases.append({**original, "_path": path})
            cases += [{**originals[0], "id.orig_h": "host.invalid"},
                      {**originals[0], "id.resp_h": "fe80::1%lo0"},
                      {**originals[0], "id.orig_p": 65536},
                      {**originals[1], "actions": ["Notice::ACTION_LOG", False]},
                      {**originals[0], "name": "weird", "notice": False, "peer": "worker"}]
            data = "\n".join(json.dumps(row)[:-1] + fallback + "}" for row in cases)
            for original, row in zip(cases, events(data=data)):
                with self.subTest(original=original, fallback=fallback):
                    self.assertEqual(row["format"], "json")
                    self.assertNotIn("zeek_log_type", row["fields"])
                    self.assertNotIn("flow_id", row["fields"])
            for original, profile in zip(originals, ("conn", "notice", "weird", "dns", "http", "ssl", "files")):
                data = json.dumps({**original, "_path": profile})[:-1] + fallback + "}"
                self.assertEqual(events(data=data)[0]["fields"]["zeek_log_type"], profile)

    def test_zeek_optional_alias_types_duplicates_and_native_collisions(self):
        sources = [json.loads(line) for line in (ROOT / "examples/zeek-json.log").read_text().splitlines()]
        for suffix in ("", ',"large_number":18446744073709551616'):
            base = json.dumps(sources[4])[:-1]
            for value in ("100", "599", "0", "600", "-1", "503.0", '"503"', "true", "null"):
                row, = events(data=base + ',"status_code":' + value + suffix + "}")
                self.assertEqual(row["fields"].get("http_status"), value if value in ("100", "599") else None)
            row, = events(data=json.dumps({**sources[4], "http_status": "", "user": "", "message": "",
                                           "level": "warn", "file": "forged", "line": 999, "raw": "forged"})[:-1]
                          + suffix + "}")
            self.assertEqual(row["fields"]["http_status"], "")
            self.assertEqual(row["fields"]["user"], "")
            self.assertEqual(row["fields"]["message"], "")
            self.assertEqual((row["file"], row["line"], row["level"]), ("-", 1, "WARN"))
            self.assertNotEqual(row["raw"], "forged")
            for value in ('[]', '["first","second"]', '["first",1]', 'null', '{}'):
                base = json.dumps(sources[3])[:-1]
                row, = events(data=base + ',"answers":' + value + suffix + "}")
                self.assertEqual(row["fields"].get("dns_answers"), value if value in ('[]', '["first","second"]') else None)
            for value in ("0", "18446744073709551615", "18446744073709551616", "1.0", "-1", '"1"', "true"):
                base = json.dumps(sources[6])[:-1]
                row, = events(data=base + ',"total_bytes":' + value + suffix + "}")
                self.assertEqual(row["fields"].get("file_size"), value if value in ("0", "18446744073709551615") else None)
        source = {**sources[1], "msg": "literal\x1b[2J\n☀\u202e", "src": "not-an-ip"}
        row, = events(data=json.dumps(source))
        self.assertEqual(row["fields"]["message"], source["msg"])
        self.assertNotIn("src_ip", row["fields"])
        text = run("--color=never", "--template={message}", data=json.dumps(source)).stdout
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        for original in sources[4:6]:
            for protocol in ("icmp", "unknown", "", False, None, []):
                row, = events(data=json.dumps({**original, "proto": protocol}))
                self.assertIn("zeek_log_type", row["fields"])
                self.assertNotIn("src_port", row["fields"])
                self.assertNotIn("dst_port", row["fields"])
        for kind in ("alert", "flow", "http", "dns", "tls", "fileinfo", "anomaly"):
            row, = events(data=json.dumps({**sources[0], "event_type": kind, kind: {}}))
            self.assertNotIn("zeek_log_type", row["fields"])

    def test_kubernetes_audit_profiles_keep_stages_roles_and_policy_levels(self):
        path = ROOT / "examples/kubernetes-audit.jsonl"
        rows = events(path)
        self.assertEqual(len(rows), 6)
        self.assertEqual([row["format"] for row in rows], ["json"] * 6)
        self.assertEqual([row["level"] for row in rows], ["UNKNOWN"] * 6)
        self.assertEqual([row["fields"]["audit_level"] for row in rows],
                         ["Metadata", "RequestResponse", "Metadata", "Request", "Request", "None"])
        self.assertEqual([row["fields"]["audit_stage"] for row in rows],
                         ["RequestReceived", "ResponseComplete", "ResponseStarted", "ResponseComplete", "Panic", "ResponseComplete"])
        self.assertEqual([row["fields"]["audit_id"] for row in rows[:2]], ["synthetic-request-1"] * 2)
        self.assertEqual([row["line"] for row in rows], list(range(1, 7)))
        self.assertTrue(all(row["file"] == str(path) for row in rows))
        self.assertEqual([row["raw"] for row in rows], path.read_text().splitlines())
        for row in rows:
            self.assertNotIn("event_id", row["fields"])
            self.assertNotIn("src_ip", row["fields"])
            self.assertEqual(row["fields"]["event_type"], "kubernetes_audit")
        self.assertNotIn("outcome", rows[0]["fields"])
        self.assertEqual(rows[1]["fields"]["outcome"], "failure")
        self.assertNotIn("body-only-context", rows[1]["fields"]["message"])
        self.assertEqual(json.loads(rows[1]["fields"]["requestObject"])["syntheticBody"], "body-only-context")
        self.assertEqual(rows[2]["fields"]["actor"], "carol")
        self.assertEqual(rows[2]["fields"]["target_user"], "bob")
        self.assertEqual(json.loads(rows[2]["fields"]["user"])["username"], "carol")
        self.assertNotIn("outcome", rows[5]["fields"])
        self.assertEqual(rows[5]["fields"]["timestamp"], "")
        self.assertEqual(events("--module=json", path), rows)
        self.assertEqual(events("--where=audit_id=synthetic-request-1", path), rows[:2])
        self.assertEqual(events("--where=outcome=failure", path), [rows[1], rows[4]])
        self.assertEqual(events("--alerts-only", path), [])
        self.assertEqual(events("--errors-only", path), [])
        self.assertEqual(run("--where=actor=alice", "--where=audit_stage=ResponseComplete", "--color=never",
                             "--template={action}|{k8s_resource}|{http_status}|{level}", path).stdout,
                         "create|pods|403|UNKNOWN\n")
        self.assertEqual(run("--output=raw", path).stdout, path.read_text())
        selected = [json.loads(line) for line in run("--agent", "--limit=1", "--where=target_user=bob",
                                                    "--agent-fields=actor,target_user,audit_stage", path).stdout.splitlines()]
        self.assertEqual(selected[0]["fields"], {"actor": "carol", "target_user": "bob", "audit_stage": "ResponseStarted"})

    def test_kubernetes_mixed_parallel_raw_and_multiline(self):
        source = (ROOT / "examples/kubernetes-audit.jsonl").read_text()
        data = (source + (ROOT / "examples/zeek-json.log").read_text() + '{"message":"generic"}\nplain\n') * 120
        for mode in ("text", "json", "raw", "agent"):
            args = (f"--output={mode}", "--color=never")
            baseline = run("--threads=1", *args, data=data).stdout
            self.assertEqual(run("--threads=4", *args, data=data).stdout, baseline)
        first = source.splitlines()[0]
        row, = events("--multiline=indent", data=first + "\n continuation\n")
        self.assertEqual(row["fields"]["audit_stage"], "RequestReceived")
        self.assertEqual(row["line"], 1)
        self.assertEqual(row["raw"], first + "\n continuation")

    def test_kubernetes_required_fields_duplicate_types_and_fallback_backend(self):
        original = json.loads((ROOT / "examples/kubernetes-audit.jsonl").read_text().splitlines()[1])
        for extra in ("", ',"large_number":18446744073709551616'):
            cases = []
            for key in ("apiVersion", "kind", "auditID", "stage", "verb", "requestURI", "user", "level"):
                cases.append({k: v for k, v in original.items() if k != key})
                cases.append({**original, key: None})
            cases.extend(({**original, "apiVersion": "audit.k8s.io/v1beta1"},
                          {**original, "kind": "EventList"}, {**original, "level": "error"},
                          {**original, "stage": "Unknown"}, {**original, "user": []}))
            for row in events(data="\n".join(json.dumps(case)[:-1] + extra + "}" for case in cases)):
                self.assertNotIn("k8s_profile", row["fields"])
                self.assertNotIn("actor", row["fields"])
                self.assertNotIn("audit_stage", row["fields"])
            base = json.dumps(original)[:-1]
            row, = events(data=base + ',"user":{"username":"first","username":null},'
                          '"responseStatus":{"code":200,"code":false,"status":"Failure"}' + extra + "}")
            self.assertEqual(row["fields"]["k8s_profile"], "audit/v1")
            self.assertNotIn("actor", row["fields"])
            self.assertNotIn("http_status", row["fields"])
            self.assertNotIn("outcome", row["fields"])
            row, = events(data=base + ',"level":"error"' + extra + "}")
            self.assertNotIn("k8s_profile", row["fields"])
            self.assertEqual(row["level"], "ERROR")
            row, = events(data=json.dumps({**original, "actor": "", "message": "", "source": "", "file": "forged", "line": 999,
                                          "raw": "forged", "format": "forged"})[:-1]
                          + extra + "}")
            self.assertEqual((row["file"], row["line"]), ("-", 1))
            self.assertEqual(row["format"], "json")
            self.assertNotEqual(row["raw"], "forged")
            self.assertEqual(row["fields"]["raw"], "forged")
            self.assertEqual(row["fields"]["format"], "forged")
            self.assertEqual(row["fields"]["actor"], "")
            self.assertEqual(row["fields"]["message"], "")
            self.assertEqual(row["fields"]["source"], "")
        original["user"]["username"] = "alice\x1b[2J\u202e☀"
        row, = events(data=json.dumps(original))
        self.assertEqual(row["fields"]["actor"], original["user"]["username"])
        text = run("--color=never", "--template={actor}", data=json.dumps(original)).stdout
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)

    def test_kubernetes_http_integer_limits_and_timestamp_presence(self):
        source = json.loads((ROOT / "examples/kubernetes-audit.jsonl").read_text().splitlines()[1])
        values = ("100", "200", "299", "300", "599", "600", "0", "-1", "18446744073709551615",
                  "18446744073709551616", "403.0", '"403"', "true", "null", "{}", "[]")
        for extra in ("", ',"large_number":18446744073709551616'):
            base = json.dumps(source)[:-1]
            data = "\n".join(base + ',"responseStatus":{"status":"Failure","code":' + value + '}' + extra + '}'
                             for value in values)
            rows = events(data=data)
            self.assertEqual(len(rows), len(values))
            for value, row in zip(values, rows):
                expected = value if value in ("100", "200", "299", "300", "599") else None
                self.assertEqual(row["fields"].get("http_status"), expected)
                self.assertEqual(row["fields"].get("outcome"),
                                 "failure" if expected and expected not in ("200", "299") else None)
        for value in ("", "supplied-clock-text", None, 0, False, []):
            row, = events(data=json.dumps({**source, "stageTimestamp": value}))
            self.assertEqual(row["fields"].get("timestamp"), value if isinstance(value, str) else None)
        source["requestURI"] = "/" + "synthetic/" * 8000
        source["requestObject"] = {"payload": "body-only-context" * 4000}
        row, = events(data=json.dumps(source))
        self.assertEqual(row["fields"]["message"], source["verb"] + " " + source["requestURI"])
        self.assertLess(len(row["fields"]["message"].encode()), len(row["raw"].encode()))
        self.assertNotIn("body-only-context", row["fields"]["message"])

    def test_suricata_eve_unknown_severity_and_field_types(self):
        severities = [None, 0, 4, 50, 255, 18446744073709551615, -1, 1.0, "1", True, [], {}]
        for extra in ({}, {"large_number": 18446744073709551616}):
            sources = [{"event_type": "alert", "level": 60,
                        "alert": {"severity": severity, "signature": [], "signature_id": "123",
                                  "category": None, "action": False}, **extra}
                       for severity in severities]
            rows = events(data="\n".join(json.dumps(source) for source in sources))
            self.assertEqual(len(rows), len(sources))
            for severity, source, row in zip(severities, sources, rows):
                with self.subTest(severity=severity, extra=extra):
                    self.assertEqual(row["format"], "json")
                    self.assertEqual(row["level"], "UNKNOWN")
                    self.assertEqual(row["fields"]["message"], row["raw"])
                    self.assertEqual(json.loads(row["fields"]["alert"]), source["alert"])
                    for key in ("signature", "signature_id", "category", "action", "dst_ip", "dst_port"):
                        self.assertNotIn(key, row["fields"])
                    if type(severity) is int and severity >= 0:
                        self.assertEqual(row["fields"]["original_level"], str(severity))
                        self.assertEqual(row["fields"]["alert_severity"], str(severity))
                    else:
                        self.assertNotIn("original_level", row["fields"])
                        self.assertNotIn("alert_severity", row["fields"])
        row, = events(data='{"event_type":"alert","alert":{}}')
        self.assertEqual(row["level"], "UNKNOWN")
        self.assertEqual(row["fields"]["message"], row["raw"])

    def test_suricata_eve_signature_ids_keep_integer_precision(self):
        ids = [0, 1000001, 9223372036854775808, 18446744073709551615,
               -1, 18446744073709551616, 1.0, "123", True, None, {}, []]
        for extra in ({}, {"large_number": 18446744073709551616}):
            data = "\n".join(json.dumps({"event_type": "alert", "alert": {
                "severity": 1, "signature_id": value}, **extra}) for value in ids)
            rows = events(data=data)
            self.assertEqual(len(rows), len(ids))
            for value, row in zip(ids, rows):
                with self.subTest(value=value, extra=extra):
                    self.assertEqual(row["level"], "CRITICAL")
                    if type(value) is int and 0 <= value <= 18446744073709551615:
                        self.assertEqual(row["fields"]["signature_id"], str(value))
                    else:
                        self.assertNotIn("signature_id", row["fields"])

    def test_json_large_integers_keep_exact_digits(self):
        values = [str(value) for value in (-(2 ** 63) - 1, -(2 ** 63), 2 ** 64 - 1,
                                          2 ** 64, 123456789012345678901234567890)]
        values += ["9" * 2048, "-" + "9" * 2048]
        data = "\n".join('{"n":' + value + ',"nested":{"n":' + value +
                         '},"array":[' + value + ',"digits"],"message":"count"}'
                         for value in values)
        for threads in (1, 4):
            rows = events("--threads", threads, data=data)
            self.assertEqual(len(rows), len(values))
            for value, line, row in zip(values, data.splitlines(), rows):
                self.assertEqual(row["format"], "json")
                self.assertEqual(row["fields"]["n"], value)
                self.assertEqual(row["fields"]["nested"], '{"n":' + value + '}')
                self.assertEqual(row["fields"]["array"], '[' + value + ',"digits"]')
                self.assertEqual(row["raw"], line)
            self.assertEqual(run("--threads", threads, "--output=raw", data=data).stdout,
                             data + "\n")
        row, = events(data='{"n":1,"\\u006e":123456789012345678901234567890}')
        self.assertEqual(row["fields"]["n"], values[4])
        for depth in (63, 64, 65):
            nested = '[' * (depth - 1) + values[4] + ']' * (depth - 1)
            line = '{"n":' + nested + '}'
            row, = events(data=line)
            self.assertEqual(row["format"], "json" if depth <= 64 else "plain")
            if depth <= 64:
                self.assertEqual(row["fields"]["n"], nested)
            self.assertEqual(row["raw"], line)
        for value in ("01", "+1", "--1", "9" * 30 + "x"):
            row, = events(data='{"n":' + value + '}')
            self.assertEqual(row["format"], "plain")

    def test_suricata_alert_destination_aliases_are_validated(self):
        addresses = ["192.0.2.1", "2001:db8::1", "not-an-ip", "192.0.2.999",
                     "192.00.2.1", "fe80::1%en0", "192.0.2.1\0", "", 123, [], None]
        ports = [0, 65535, 65536, 99999, -1, 2 ** 64, "443", 443.0, True, None, {}]
        for extra in ({}, {"large_number": 123456789012345678901234567890}):
            sources = [{"event_type": "alert", "dest_ip": address, "dest_port": port,
                        "alert": {"severity": 2, "signature": "test"}, **extra}
                       for address in addresses for port in ports]
            rows = events(data="\n".join(json.dumps(source) for source in sources))
            self.assertEqual(len(rows), len(sources))
            for source, row in zip(sources, rows):
                self.assertEqual(row["format"], "json")
                self.assertEqual(row["level"], "ERROR")
                fields = row["fields"]
                if source["dest_ip"] in addresses[:2]:
                    self.assertEqual(fields["dst_ip"], source["dest_ip"])
                else:
                    self.assertNotIn("dst_ip", fields)
                if type(source["dest_port"]) is int and 0 <= source["dest_port"] <= 65535:
                    self.assertEqual(fields["dst_port"], str(source["dest_port"]))
                else:
                    self.assertNotIn("dst_port", fields)
                self.assertEqual(json.loads(row["raw"]), source)
                for key in ("dest_ip", "dest_port"):
                    if isinstance(source[key], str):
                        self.assertEqual(fields[key], source[key])
                    else:
                        self.assertEqual(json.loads(fields[key]), source[key])

    def test_suricata_eve_only_specializes_alert_objects(self):
        sources = [
            {"event_type": "flow", "alert": {"severity": 1, "signature": "unused"}},
            {"event_type": "Alert", "alert": {"severity": 1}},
            {"alert": {"severity": 1}},
            {"event_type": "alert"},
            *({"event_type": "alert", "alert": value}
              for value in [None, "alert", [], 1, True]),
        ]
        for source in sources:
            source.update(level=50, message="application", dest_ip="192.0.2.2")
        rows = events(data="\n".join(json.dumps(source) for source in sources))
        for row in rows:
            self.assertEqual(row["format"], "json")
            self.assertEqual(row["level"], "ERROR")
            self.assertEqual(row["fields"]["message"], "application")
            self.assertEqual(row["fields"]["original_level"], "50")
            for key in ("source", "signature", "alert_severity", "dst_ip"):
                self.assertNotIn(key, row["fields"])

    def test_suricata_eve_alias_precedence_and_compatibility_parser(self):
        source = {
            "event_type": "alert", "level": 60, "logger": "sensor-1", "msg": "explicit message",
            "signature": "top-level", "signature_id": 1, "category": "top-level", "action": "drop",
            "dest_ip": "192.0.2.2", "dst_ip": "other", "dest_port": 443, "dst_port": 80,
            "alert": {"severity": 2, "signature": "EVE signature", "signature_id": 123,
                      "category": "EVE category", "action": "allowed"},
        }
        for extra in ({}, {"large_number": 18446744073709551616}):
            with self.subTest(extra=extra):
                row, = events(data=json.dumps(source | extra))
                fields = row["fields"]
                self.assertEqual(row["format"], "json")
                self.assertEqual(row["level"], "ERROR")
                self.assertEqual(fields["original_level"], "2")
                self.assertEqual(fields["alert_severity"], "2")
                self.assertEqual(fields["source"], "sensor-1")
                self.assertEqual(fields["message"], "explicit message")
                for key in ("signature", "category", "action"):
                    self.assertEqual(fields[key], source["alert"][key])
                self.assertEqual(fields["signature_id"], "123")
                self.assertEqual(fields["dst_ip"], "192.0.2.2")
                self.assertEqual(fields["dst_port"], "443")

    def test_suricata_eve_duplicate_keys_use_last_value_in_both_parsers(self):
        for extra in ("", ',"large_number":18446744073709551616'):
            with self.subTest(extra=extra):
                data = ('{"event_type":"flow","event_type":"alert","alert":null,'
                        '"alert":{"severity":1,"severity":3,"signature":"first","signature":"last"}'
                        + extra + '}')
                row, = events(data=data)
                self.assertEqual(row["level"], "WARN")
                self.assertEqual(row["fields"]["signature"], "last")
                self.assertEqual(row["fields"]["message"], "last")
                data = ('{"event_type":"alert","level":50,"alert":{"severity":1},"alert":null'
                        + extra + '}')
                row, = events(data=data)
                self.assertEqual(row["level"], "ERROR")
                self.assertNotIn("alert_severity", row["fields"])

    def test_leef_versions_native_fields_and_envelopes(self):
        path = ROOT / "examples/leef.log"
        rows = events(path)
        self.assertEqual([row["format"] for row in rows], ["leef"] * 6)
        self.assertEqual([row["level"] for row in rows], ["UNKNOWN"] * 6)
        self.assertEqual([row["raw"] for row in rows], path.read_text().splitlines())
        self.assertEqual(events("--module=leef", path), rows)
        self.assertEqual(rows[0]["fields"]["leef_version"], "1.0")
        self.assertEqual(rows[0]["fields"]["user"], "alice")
        self.assertEqual(rows[0]["fields"]["original_level"], "8")
        self.assertEqual(rows[1]["fields"]["src_port"], "0")
        self.assertEqual(rows[1]["fields"]["dst_ip"], "2001:db8::21")
        self.assertEqual(rows[2]["fields"]["message"], "")
        self.assertEqual(rows[2]["fields"]["leef_ext_note"], "literal a=b \\n")
        self.assertEqual(rows[3]["fields"]["leef_delimiter"], "¦")
        self.assertEqual(rows[4]["fields"]["syslog_level"], "CRITICAL")
        self.assertEqual(rows[5]["fields"]["timestamp"], "1794076201000")
        self.assertEqual(rows[5]["fields"]["syslog_timestamp"], "2026-11-07T18:30:01Z")
        self.assertEqual(rows[5]["fields"]["syslog_sd.meta.x"], "kept")

    def test_leef_filters_templates_parallel_raw_and_multiline(self):
        path = ROOT / "examples/leef.log"
        self.assertEqual(len(events("--where", "format=leef", "--where", "user=alice", path)), 2)
        self.assertEqual(len(events("--filter", "leef_ext_cat=authentication", path)), 1)
        self.assertEqual(events("--min-level", "error", path), [])
        text = run("--color=never", "--where", "user=alice", "--template",
                   "{level}|{event_code}|{user}", path).stdout
        self.assertEqual(text, "UNKNOWN|login-denied|alice\nUNKNOWN|device-clock|alice\n")
        data = path.read_text() * 500
        self.assertEqual(run("--output=raw", "--threads=4", data=data).stdout, data)
        self.assertEqual(run("--output=json", "--threads=4", data=data).stdout,
                         run("--output=json", "--threads=1", data=data).stdout)
        first = path.read_text().splitlines()[0]
        row, = events("--multiline", "indent", data=first + "\n continuation\n")
        self.assertEqual(row["format"], "leef")
        self.assertEqual(row["raw"], first + "\n continuation")
        self.assertEqual(row["line"], 1)

    def test_leef_rejection_collisions_and_typed_attributes(self):
        prefix = "LEEF:2.0|V|P|1|id|^|"
        row, = events(data=prefix + "level=critical^source=forged^raw=forged^"
                      "leef_event_id=forged^syslog_sd.meta.x=forged^usrName=alice^usrName=^"
                      "src=192.0.2.1^src=host.example^dst=fe80::1%lo0^srcPort=65536^sev=")
        self.assertEqual(row["format"], "leef")
        self.assertEqual(row["fields"]["source"], "P")
        self.assertEqual(row["fields"]["message"], "id")
        self.assertEqual(row["fields"]["leef_event_id"], "id")
        self.assertEqual(row["fields"]["leef_ext_level"], "critical")
        self.assertEqual(row["fields"]["leef_ext_syslog_sd.meta.x"], "forged")
        self.assertEqual(row["fields"]["user"], "")
        self.assertEqual(row["fields"]["original_level"], "")
        for field in ("src_ip", "dst_ip", "src_port", "raw", "syslog_sd.meta.x"):
            self.assertNotIn(field, row["fields"])
        malformed = ["LEEF:", "LEEF:3.0|V|P|1|id|", prefix + "broken",
                     "LEEF:2.0|V|P|1|id|x10000|a=b", "LEEF:2.0|V|P|1|id|xd800|a=b",
                     "LEEF:1.0|V|P|1|id|a=b\t\t", "LEEF:1.0|V|P|1|id|bad key=value"]
        for flags in ((), ("--module=leef",)):
            rows = events(*flags, data="\n".join(malformed))
            self.assertEqual([row["format"] for row in rows], ["plain"] * len(malformed))
            self.assertEqual([row["raw"] for row in rows], malformed)
        maximum = prefix + "^".join("key=value" for _ in range(1024))
        self.assertEqual(events(data=maximum)[0]["format"], "leef")
        self.assertEqual(events(data=maximum + "^extra=value")[0]["format"], "plain")
        wrapped = "<2>Nov  7 18:30:00 host " + prefix + "msg=kept"
        self.assertEqual(events(data=wrapped)[0]["format"], "leef")
        forced, = events("--module=syslog", data=wrapped)
        self.assertEqual(forced["format"], "syslog")
        self.assertEqual(forced["fields"]["source"], "LEEF")
        self.assertNotIn("leef_version", forced["fields"])
        for data in ("ordinary " + prefix + "msg=mention",
                     "<13>Nov  7 18:30:00 host app: ordinary " + prefix + "msg=mention"):
            self.assertNotEqual(events(data=data)[0]["format"], "leef")

    def test_cef_fields_and_syslog_envelopes(self):
        path = ROOT / "examples/cef.log"
        rows = events(path)
        self.assertEqual([row["format"] for row in rows], ["cef"] * 6)
        self.assertEqual([row["level"] for row in rows], ["ERROR", "INFO", "CRITICAL", "WARN", "INFO", "UNKNOWN"])
        self.assertEqual([row["raw"] for row in rows], path.read_text().splitlines())
        self.assertEqual(events("--module=cef", path), rows)
        fields = rows[0]["fields"]
        for key, value in {"cef_version": "0", "cef_device_vendor": "Example",
                           "cef_device_product": "Firewall", "cef_device_version": "1.0",
                           "cef_event_class_id": "100", "event_code": "100", "signature_id": "100",
                           "signature": "Login failed", "source": "Firewall", "message": "Login failed",
                           "original_level": "8", "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20",
                           "src_port": "54000", "dst_port": "443", "user": "alice", "actor": "alice",
                           "target_user": "root", "action": "denied", "category": "authentication",
                           "protocol": "TCP", "timestamp": "1794072600000"}.items():
            self.assertEqual(fields[key], value)
        self.assertEqual(fields["src"], fields["cef_ext_src"])
        self.assertEqual(rows[1]["fields"]["src_ip"], "2001:db8::10")
        self.assertNotIn("event_type", rows[1]["fields"])
        self.assertEqual(rows[2]["fields"]["host"], "gateway")
        self.assertEqual(rows[2]["fields"]["priority"], "134")
        self.assertEqual(rows[2]["fields"]["syslog_level"], "INFO")
        self.assertNotIn("syslog_source", rows[2]["fields"])
        escaped = rows[3]["fields"]
        self.assertEqual(escaped["cef_name"], "Policy | rule")
        self.assertEqual(escaped["message"], "Rule a=b fired\nInspect C:\\temp | next")
        self.assertEqual(escaped["cs1Label"], "Policy name")
        self.assertEqual(escaped["cef_ext_cs1"], "Edge policy")
        self.assertEqual(escaped["syslog_source"], "relay")
        self.assertEqual(escaped["pid"], "42")
        modern = rows[4]["fields"]
        self.assertEqual(modern["timestamp"], "2026-11-07T18:30:04+01:00")
        self.assertEqual(modern["syslog_timestamp"], modern["timestamp"])
        self.assertEqual(modern["cef_ext_rt"], "1794072604000")
        self.assertEqual(modern["syslog_level"], "CRITICAL")
        self.assertEqual(modern["version"], "1")
        self.assertEqual(modern["msgid"], "ID47")
        self.assertEqual(modern["structured_data"], '[meta a="x]y"][other x="1"]')
        self.assertTrue(modern["syslog_message"].startswith("CEF:1|"))
        self.assertNotIn("timestamp", rows[5]["fields"])
        self.assertTrue(all(isinstance(value, str) for row in rows for value in row["fields"].values()))

    def test_cef_filters_templates_raw_and_mixed_input(self):
        path = ROOT / "examples/cef.log"
        rows = events(path)
        self.assertEqual(events("--errors-only", path), [rows[0], rows[2]])
        self.assertEqual(events("--min-level=warn", path), [rows[0], rows[2], rows[3]])
        self.assertEqual(events("--where=user=alice", "--where=action=denied", path), [rows[0]])
        self.assertEqual(events("--where=cs1=Edge policy", path), [rows[3]])
        text = run("--where=src_ip=192.0.2.10", "--color=never", "--template",
                   "[{level}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | {signature}", path).stdout
        self.assertEqual(text, "[ERROR] 192.0.2.10:54000 → 198.51.100.20:443 | Login failed\n")
        self.assertEqual(run("--output=raw", path).stdout, path.read_text())
        raw = run("--output=raw", "--where=event_code=100", path).stdout
        self.assertEqual(raw, rows[0]["raw"] + "\n")
        escaped = run("--where=event_code=202", "--template={message}", path).stdout
        self.assertEqual(escaped, "Rule a=b fired\\x0aInspect C:\\temp | next\n")
        data = (path.read_text() + '{"level":"error","message":"application"}\n'
                'Nov  7 18:30:00 host app: ordinary\nplain\n')
        self.assertEqual([row["format"] for row in events(data=data)], ["cef"] * 6 + ["json", "syslog", "plain"])

    def test_cef_extension_duplicates_spaces_and_collision_policy(self):
        prefix = "CEF:1|V|P|1|id|Header|7|"
        extension = ("src=192.0.2.1 src=192.0.2.2 msg=first msg=last  extra=value "
                     "empty= last=tail   ")
        row, = events(data=prefix + extension)
        fields = row["fields"]
        self.assertEqual(fields["src_ip"], "192.0.2.2")
        self.assertEqual(fields["message"], "last ")
        self.assertEqual(fields["extra"], "value")
        self.assertEqual(fields["empty"], "")
        self.assertEqual(fields["last"], "tail")
        native = {
            "level": "CRITICAL", "source": "forged", "timestamp": "forged", "message": "forged",
            "signature": "forged", "signature_id": "forged", "event_code": "forged",
            "raw": "forged", "format": "forged", "file": "forged", "line": "9",
            "priority": "0", "host": "forged", "pid": "0", "version": "9", "msgid": "forged",
            "structured_data": "forged", "syslog_level": "forged", "cef_name": "forged",
            "cef_severity": "0", "cef_ext_src": "forged", "src_ip": "forged", "user": "forged",
        }
        extension = "src=192.0.2.1 " + " ".join(f"{key}={value}" for key, value in native.items())
        data = '<134>1 - host relay 42 ID [meta x="1"] ' + prefix + extension
        row, = events(data=data)
        fields = row["fields"]
        self.assertEqual((row["format"], row["file"], row["line"], row["level"]), ("cef", "-", 1, "ERROR"))
        self.assertEqual(row["raw"], data)
        self.assertEqual(fields["cef_name"], "Header")
        self.assertEqual(fields["message"], "Header")
        self.assertEqual(fields["source"], "P")
        self.assertEqual(fields["timestamp"], "-")
        self.assertEqual(fields["priority"], "134")
        self.assertEqual(fields["syslog_level"], "INFO")
        self.assertEqual(fields["host"], "host")
        self.assertEqual(fields["pid"], "42")
        self.assertEqual(fields["version"], "1")
        self.assertEqual(fields["src_ip"], "192.0.2.1")
        self.assertNotIn("user", fields)
        for key, value in native.items():
            self.assertEqual(fields["cef_ext_" + key], value)

    def test_cef_missing_empty_and_invalid_typed_extensions(self):
        for extension in ("", "   ", "msg=", "msg= suser= duser= src= dst= spt= dpt= rt="):
            with self.subTest(extension=extension):
                row, = events(data="CEF:0|||||Name||" + extension)
                self.assertEqual(row["format"], "cef")
                self.assertEqual(row["level"], "UNKNOWN")
                self.assertEqual(row["fields"]["source"], "cef")
                self.assertEqual(row["fields"]["message"], "" if extension.startswith("msg=") else "Name")
        values = ["bad", "-1", "65536", "1.0", "18446744073709551616", ""]
        data = "\n".join("CEF:0|V|P|1|id|Name|8|src=host.example dst=fe80::1%eth0 "
                         f"spt={value} dpt={value}" for value in values)
        for row in events(data=data):
            for key in ("src_ip", "dst_ip", "src_port", "dst_port"):
                self.assertNotIn(key, row["fields"])
            self.assertIn("cef_ext_src", row["fields"])
        row, = events(data="CEF:1|V|P|1|id|Name|9|src=192.0.2.1 src=bad spt=0 dpt=65535")
        self.assertNotIn("src_ip", row["fields"])
        self.assertEqual(row["fields"]["src_port"], "0")
        self.assertEqual(row["fields"]["dst_port"], "65535")
        row, = events(data="CEF:1|V|P|1|id|Name|Low|duser=bob")
        self.assertEqual(row["fields"]["user"], "bob")
        self.assertNotIn("actor", row["fields"])

    def test_cef_malformed_records_and_forced_syslog_compatibility(self):
        malformed = ["CEF:", "CEF:2|V|P|1|id|Name|7|", "CEF:01|V|P|1|id|Name|7|",
                     "CEF:0|V|P|1|id|Name|7", "CEF:0|V|P|1|id|Name|7|broken",
                     "CEF:0|V|P|1|id|Name|7|msg=a=b", "CEF:0|V|P|1|id|Name|7|msg=bad\\q",
                     "CEF:0|V|P|1|id|Name|7|msg=bad\\", "CEF:0|V\\q|P|1|id|Name|7|",
                     "CEF:0|V|P|1|id|Name|7|bad key=value", "CEF:0|V|P|1|id|Name|7|=value"]
        data = "\n".join(malformed)
        for flags in ((), ("--module=cef",)):
            rows = events(*flags, data=data)
            self.assertEqual([row["format"] for row in rows], ["plain"] * len(malformed))
            self.assertEqual([row["raw"] for row in rows], malformed)
        payload = "CEF:0|V|P|1|id|Name|7|src=192.0.2.1"
        for prefix in ("Nov  7 18:30:00 host ", "Nov  7 18:30:00 host app[42]: ",
                       '<134>1 - host app 42 ID [meta x="CEF:bogus"] '):
            row, = events(data=prefix + payload)
            self.assertEqual(row["format"], "cef")
            forced, = events("--module=syslog", data=prefix + payload)
            self.assertEqual(forced["format"], "syslog")
            self.assertNotIn("cef_version", forced["fields"])
            fallback, = events(data=prefix + malformed[1])
            self.assertEqual(fallback["format"], "syslog")
            self.assertEqual(fallback["raw"], prefix + malformed[1])
        messages = [f'Nov  7 18:30:00 host app: log mentions {payload}',
                    f'{{"message":{json.dumps(payload)}}}',
                    '<134>1 - host app 42 ID [meta x="CEF:bogus"] ordinary']
        self.assertEqual([row["format"] for row in events(data="\n".join(messages))], ["syslog", "json", "syslog"])

    def test_cef_parallel_multiline_and_record_limits(self):
        data = (ROOT / "examples/cef.log").read_text() * 500
        for mode in ("text", "json", "raw"):
            with self.subTest(mode=mode):
                args = (f"--output={mode}", "--min-level=warn")
                self.assertEqual(run("--threads=4", *args, data=data).stdout,
                                 run("--threads=1", *args, data=data).stdout)
        first = (ROOT / "examples/cef.log").read_text().splitlines()[0]
        row, = events("--multiline=indent", "--errors-only", data=first + "\n  context\nplain\n")
        self.assertEqual(row["raw"], first + "\n  context")
        self.assertEqual(row["continuation"], "  context")
        self.assertEqual(row["line"], 1)
        self.assertEqual(row["fields"]["message"], "Login failed")
        prefix = "CEF:0|V|P|1|id|Name|7|"
        data = prefix + " ".join(f"key{i}=value" for i in range(1024))
        self.assertEqual(events(data=data)[0]["format"], "cef")
        excessive = data + " overflow=value"
        row, = events(data=excessive)
        self.assertEqual(row["format"], "plain")
        self.assertEqual(row["raw"], excessive)
        result = run(f"--max-line-bytes={len(first) - 1}", data=first, code=1)
        self.assertIn("exceeds", result.stderr)

    def test_unix_authentication_fields_and_filters(self):
        path = ROOT / "examples/unix-auth.log"
        rows = events(path)
        self.assertEqual([row["format"] for row in rows], ["syslog"] * 9)
        self.assertEqual([row["level"] for row in rows],
                         ["ERROR", "ERROR", "INFO", "ERROR", "ERROR", "ERROR", "ERROR", "INFO", "UNKNOWN"])
        self.assertEqual([row["raw"] for row in rows], path.read_text().splitlines())
        ssh = rows[0]["fields"]
        for key, value in {"event_type": "authentication", "action": "login", "outcome": "failure",
                           "user": "root", "src_ip": "192.0.2.10", "src_port": "54000",
                           "auth_method": "password", "priority": "86", "pid": "400",
                           "source": "sshd", "reason": "authentication_failure"}.items():
            self.assertEqual(ssh[key], value)
        self.assertEqual(rows[1]["fields"]["reason"], "invalid_user")
        self.assertEqual(rows[1]["fields"]["src_ip"], "2001:db8::10")
        self.assertNotIn("auth_method", rows[1]["fields"])
        self.assertEqual(rows[2]["fields"]["auth_method"], "publickey")
        self.assertEqual(rows[2]["fields"]["outcome"], "success")
        self.assertEqual(rows[2]["fields"]["syslog_format"], "rfc5424")
        self.assertEqual(rows[3]["fields"]["auth_method"], "pam")
        self.assertEqual(rows[3]["fields"]["actor"], "alice")
        self.assertNotIn("src_ip", rows[3]["fields"])
        self.assertEqual(rows[4]["fields"]["user"], "alice")
        self.assertEqual(rows[4]["fields"]["target_user"], "root")
        self.assertEqual(rows[4]["fields"]["command"], "/usr/bin/id")
        self.assertEqual(rows[5]["fields"]["reason"], "not_in_sudoers")
        self.assertEqual(rows[6]["fields"]["action"], "su")
        self.assertEqual(rows[6]["fields"]["remote_host"], "client.example")
        self.assertNotIn("src_ip", rows[6]["fields"])
        self.assertEqual(rows[7]["fields"]["outcome"], "success")
        self.assertEqual(rows[7]["fields"]["target_user"], "root")
        self.assertEqual(rows[7]["fields"]["command"], "/bin/echo ready; USER=other")
        self.assertNotIn("event_type", rows[8]["fields"])
        selected = [rows[index] for index in (0, 1, 3, 4, 5, 6)]
        self.assertEqual(events("--where=event_type=authentication", "--where=outcome=failure", path), selected)
        self.assertEqual(events("--errors-only", path), selected)
        self.assertEqual(events("--module=syslog", path), rows)
        self.assertEqual(run("--output=raw", path).stdout, path.read_text())
        rendered = run("--color=never", "--where=src_ip=192.0.2.10", "--template",
                       "[{level}] {user} {src_ip}:{src_port} {outcome}", path)
        self.assertEqual(rendered.stdout, "[ERROR] root 192.0.2.10:54000 failure\n")

    def test_ssh_authentication_methods_and_higher_syslog_severity(self):
        for source in ("sshd", "sshd-session"):
            for method in ("password", "publickey", "keyboard-interactive/pam", "hostbased"):
                for outcome, level in (("Failed", "ERROR"), ("Accepted", "INFO")):
                    with self.subTest(source=source, method=method, outcome=outcome):
                        message = f"{outcome} {method} for alice from 2001:db8::1 port 65535 ssh2"
                        row, = events(data=f"<86>1 - host {source} 42 ID - {message}")
                        self.assertEqual(row["level"], level)
                        self.assertEqual(row["fields"]["auth_method"], method)
                        self.assertEqual(row["fields"]["user"], "alice")
                        self.assertEqual(row["fields"]["message"], message)
        message = "Failed password for invalid user guest from 192.0.2.1 port 1 ssh2 [preauth]"
        for priority, level in ((86, "ERROR"), (82, "CRITICAL")):
            row, = events(data=f"<{priority}>Nov  7 18:30:00 host sshd[42]: {message}")
            self.assertEqual(row["level"], level)
            self.assertEqual(row["fields"]["reason"], "invalid_user")

    def test_authentication_rejects_incomplete_or_unrelated_messages(self):
        messages = [
            "Failed password for alice from 192.0.2.1 port 22",
            "Failed password for alice from 192.0.2.1 port 22 ssh2fake",
            "Failed password for alice from 192.0.2.1 port 22 ssh2 extra",
            "Failed password for alice from 192.0.2.1 port 0 ssh2",
            "Failed password for alice from 192.0.2.1 port 65536 ssh2",
            "Failed password for alice from 192.0.2.1 port -1 ssh2",
            "Failed password for alice from 192.0.2.1 port 18446744073709551616 ssh2",
            "Failed password for alice from 999.2.3.4 port 22 ssh2",
            "Failed password for alice from client.example port 22 ssh2",
            "Failed password for alice from fe80::1%eth0 port 22 ssh2",
            "Failed password for alice from 192.0.2.1\0ignored port 22 ssh2",
            "Accepted password for invalid user alice from 192.0.2.1 port 22 ssh2",
            "Invalid user guest from 192.0.2.1 port 22 trailing",
            "pam_unix(sudo:auth): authentication failure; user=alice",
            "pam_unix(sshd:session): authentication failure; user=alice",
            "pam_sss(sshd:auth): authentication failure; user=alice",
            "pam_unix(sshd:auth): authentication failure;forged",
            "notice: Failed password for alice from 192.0.2.1 port 22 ssh2",
        ]
        data = "\n".join(f"Nov  7 18:30:00 host sshd[42]: {message}" for message in messages)
        rows = events(data=data)
        self.assertEqual(len(rows), len(messages))
        for message, row in zip(messages, rows):
            with self.subTest(message=message):
                self.assertEqual(row["format"], "syslog")
                self.assertEqual(row["level"], "UNKNOWN")
                self.assertEqual(row["fields"]["message"], message)
                for key in ("event_type", "outcome", "src_ip", "user", "reason"):
                    self.assertNotIn(key, row["fields"])

    def test_pam_and_sudo_failure_details(self):
        for source, service in (("sshd", "sshd"), ("sshd-session", "sshd"),
                                ("sudo", "sudo"), ("su-l", "su-l"), ("login", "login")):
            with self.subTest(source=source):
                message = (f"pam_unix({service}:auth): authentication failure; logname=alice "
                           "ruser= rhost=2001:db8::1 tty=pts/0 user=root")
                row, = events(data=f"Nov  7 18:30:00 host {source}[42]: {message}")
                self.assertEqual(row["level"], "ERROR")
                self.assertEqual(row["fields"]["user"], "root")
                self.assertEqual(row["fields"]["actor"], "alice")
                self.assertEqual(row["fields"]["src_ip"], "2001:db8::1")
                self.assertEqual(row["fields"]["tty"], "pts/0")
        for reason, normalized in (("1 incorrect password attempt", "authentication_failure"),
                                   ("command not allowed", "command_not_allowed"),
                                   ("user NOT authorized on host", "not_authorized")):
            row, = events(data=f"Nov  7 18:30:00 host sudo[42]: alice : {reason}")
            self.assertEqual(row["level"], "ERROR")
            self.assertEqual(row["fields"]["reason"], normalized)
        for message in ("alice : 0 incorrect password attempts", "alice : TTY=pts/0 ; USER=root",
                        "alice : TTY=pts/0 ; COMMAND=/usr/bin/id", "alice : unknown failure"):
            row, = events(data=f"Nov  7 18:30:00 host sudo[42]: {message}")
            self.assertEqual(row["level"], "UNKNOWN")
            self.assertNotIn("event_type", row["fields"])

    def test_authentication_keeps_large_messages_and_trailing_whitespace(self):
        pam = ("pam_unix(sshd:auth): authentication failure; user=root " + "extra=x " * 10000 +
               "rhost=192.0.2.1" + " " * 200000)
        sudo = ("alice : command not allowed ; " + "EXTRA=x ; " * 10000 + "USER=root" + " " * 200000)
        data = f"Nov  7 18:30:00 host sshd[42]: {pam}\nNov  7 18:30:00 host sudo[42]: {sudo}\n"
        rows = events("--threads=1", data=data)
        self.assertEqual([row["level"] for row in rows], ["ERROR", "ERROR"])
        self.assertEqual(rows[0]["fields"]["src_ip"], "192.0.2.1")
        self.assertEqual(rows[1]["fields"]["target_user"], "root")
        self.assertEqual([row["fields"]["message"] for row in rows], [pam, sudo])

    def test_fail2ban_fields_and_filters(self):
        path = ROOT / "examples/fail2ban.log"
        rows = events(path)
        self.assertEqual([row["format"] for row in rows], ["fail2ban"] * 3 + ["syslog", "fail2ban"])
        self.assertEqual([row["level"] for row in rows], ["WARN", "ERROR", "INFO", "ERROR", "INFO"])
        self.assertEqual([row["raw"] for row in rows], path.read_text().splitlines())
        for index, action in enumerate(("found", "ban", "unban", "ban")):
            self.assertEqual(rows[index]["fields"]["action"], action)
            self.assertEqual(rows[index]["fields"]["event_type"], "fail2ban")
            self.assertEqual(rows[index]["fields"]["jail"], "sshd")
        self.assertEqual(rows[1]["fields"]["timestamp"], "2026-11-07 18:30:01,456")
        self.assertEqual(rows[1]["fields"]["original_level"], "NOTICE")
        self.assertEqual(rows[1]["fields"]["pid"], "500")
        self.assertEqual(rows[2]["fields"]["src_ip"], "2001:db8::10")
        self.assertNotIn("event_type", rows[4]["fields"])
        self.assertEqual(events("--where=action=ban", "--where=jail=sshd", path), [rows[1], rows[3]])
        self.assertEqual(events("--errors-only", path), [rows[1], rows[3]])
        forced = events("--module=fail2ban", path)
        self.assertEqual(forced[:3], rows[:3])
        self.assertEqual(forced[3]["format"], "plain")
        self.assertEqual(forced[4], rows[4])
        self.assertEqual(run("--output=raw", path).stdout, path.read_text())
        self.assertIn("[ERROR] sshd ban 192.0.2.10", run(
            "--where=action=ban", "--template=[{level}] {jail} {action} {src_ip}", path).stdout)

    def test_fail2ban_rejects_malformed_headers_and_actions(self):
        prefix = "2026-11-07 18:30:00,123 fail2ban.actions [500]: NOTICE "
        messages = ("[sshd] Ban invalid", "[sshd] Ban 192.0.2.1 extra", "[] Ban 192.0.2.1",
                    "[bad jail] Ban 192.0.2.1", "[sshd] Ban 192.0.2.1\0ignored", "[sshd] Ban",
                    "[sshd] Found 192.0.2.1 -", "[sshd] Found 192.0.2.1 garbage",
                    "[sshd] Reban 192.0.2.1", "[sshd] Ban 192.0.2.0/24")
        rows = events(data="\n".join(prefix + message for message in messages))
        self.assertEqual(len(rows), len(messages))
        for row in rows:
            self.assertEqual(row["format"], "fail2ban")
            self.assertEqual(row["level"], "INFO")
            for key in ("event_type", "jail", "action", "src_ip"):
                self.assertNotIn(key, row["fields"])
        headers = [prefix.replace("11-07", "13-07"), prefix.replace("18:30", "24:30"),
                   prefix.replace(",123", ",12"), prefix.replace("[500]:", "[pid]:"),
                   prefix.replace("[500]:", "[500]"), prefix.replace("NOTICE", "MISSING"),
                   prefix.replace("fail2ban.actions", "application.actions")]
        data = "\n".join(header + "[sshd] Ban 192.0.2.1" for header in headers)
        rows = events(data=data)
        self.assertEqual([row["format"] for row in rows], ["plain"] * len(headers))
        self.assertEqual([row["raw"] for row in rows], data.splitlines())
        message = "[sshd] Ban 192.0.2.1"
        for source in ("fail2ban", "fail2ban-server", "fail2ban.actions", "app"):
            row, = events(data=f"Nov  7 18:30:00 host {source}[42]: {message}")
            self.assertEqual(row["level"], "UNKNOWN" if source == "app" else "ERROR")

    def test_unix_security_parallel_and_multiline_output(self):
        data = ((ROOT / "examples/unix-auth.log").read_text() +
                (ROOT / "examples/fail2ban.log").read_text()) * 400
        for mode in ("text", "json", "raw"):
            with self.subTest(mode=mode):
                args = (f"--output={mode}", "--min-level=error")
                self.assertEqual(run("--threads=4", *args, data=data).stdout,
                                 run("--threads=1", *args, data=data).stdout)
        first = (ROOT / "examples/unix-auth.log").read_text().splitlines()[0]
        data = first + "\n  context\nNov  7 18:30:01 host sshd[42]: unrelated\n"
        row, = events("--multiline=indent", "--where=outcome=failure", data=data)
        self.assertEqual(row["raw"], first + "\n  context")
        self.assertEqual(row["continuation"], "  context")
        self.assertEqual(row["line"], 1)

    def test_syslog_5424_structured_data(self):
        data = '<165>1 2026-11-07T18:00:00Z host app 42 ID47 [meta a="x]y" b="a\\\"b"][other x="1"] hello\n'
        row, = events(data=data)
        self.assertEqual(row["format"], "syslog")
        self.assertEqual(row["level"], "INFO")
        self.assertEqual(row["fields"]["message"], "hello")
        self.assertEqual(row["fields"]["pid"], "42")
        self.assertIn('[other x="1"]', row["fields"]["structured_data"])

    def test_syslog_structured_data_filtering_and_namespace(self):
        data = '<165>1 - host app 42 ID [auth@32473 user="alice" outcome="failure" empty=""][flags] failed\n'
        for threads in (1, 4):
            with self.subTest(threads=threads):
                row, = events("--threads", threads, "--where=syslog_sd.auth@32473.user=alice", data=data)
                self.assertEqual(row["fields"]["syslog_sd_status"], "ok")
                self.assertEqual(events("--filter=syslog_sd.auth@32473.user=alice", data=data), [row])
                self.assertEqual(row["fields"]["syslog_sd.auth@32473.empty"], "")
                self.assertEqual(row["fields"]["syslog_sd.flags"], "")
                self.assertEqual(row["raw"], data.rstrip("\n"))
                self.assertEqual(row["line"], 1)
                self.assertEqual(events("--where=syslog_sd.auth@32473.missing=", data=data), [])
                self.assertEqual(run("--output=raw", "--threads", threads, data=data).stdout, data)
                self.assertEqual(run("--template={syslog_sd.auth@32473.user}", data=data).stdout, "alice\n")
                self.assertEqual(events("--module=syslog", data=data), events(data=data))
        indented = data + "  continuation\n"
        row, = events("--multiline=indent", "--where=syslog_sd.auth@32473.outcome=failure", data=indented)
        self.assertEqual(row["raw"], indented.rstrip("\n"))
        self.assertEqual(row["fields"]["syslog_sd.auth@32473.user"], "alice")

    def test_syslog_structured_data_envelope_and_fallback(self):
        prefix = '<11>1 - host app 42 ID '
        payload = 'CEF:0|Vendor|Product|1|id|Name|2|syslog_sd_status=forged syslog_sd.meta.x=forged'
        row, = events(data=prefix + '[meta x="value"] ' + payload)
        self.assertEqual(row["format"], "cef")
        self.assertEqual(row["fields"]["syslog_sd.meta.x"], "value")
        self.assertEqual(row["fields"]["syslog_sd_status"], "ok")
        self.assertEqual(row["fields"]["cef_ext_syslog_sd.meta.x"], "forged")
        self.assertEqual(row["fields"]["syslog_level"], "ERROR")
        self.assertEqual(row["level"], "INFO")
        malformed = prefix + '[good x="v"][bad x="unescaped]value"] visible'
        row, = events(data=malformed)
        self.assertEqual(row["format"], "syslog")
        self.assertEqual(row["raw"], malformed)
        self.assertEqual(row["fields"]["message"], "visible")
        self.assertEqual(row["fields"]["syslog_sd_status"], "invalid")
        self.assertNotIn("syslog_sd.good.x", row["fields"])
        row, = events(data=prefix + '[unclosed x="value"')
        self.assertEqual(row["format"], "plain")

    def test_syslog_without_priority_and_nil_data(self):
        rows = events(data='Nov  7 18:30:01 host app: hello\n<11>1 - host app - - - failed\n')
        self.assertEqual([r["level"] for r in rows], ["UNKNOWN", "ERROR"])
        self.assertEqual(rows[1]["fields"]["message"], "failed")

    def test_suricata_observation_profiles_and_preservation(self):
        path = ROOT / "examples/suricata-observations.jsonl"
        rows = events(path)
        self.assertEqual(len(rows), 7)
        self.assertEqual({row["format"] for row in rows}, {"json"})
        self.assertEqual({row["level"] for row in rows}, {"UNKNOWN"})
        self.assertTrue(all(row["fields"]["source"] == "suricata" for row in rows))
        self.assertTrue(all(row["fields"]["dst_ip"] == "2001:db8::53" for row in rows))
        self.assertTrue(all(row["fields"]["protocol"] == "TCP" for row in rows))
        self.assertTrue(all(row["fields"]["flow_id"] == "18446744073709551615" for row in rows))
        self.assertEqual(rows[0]["fields"]["http_status"], "200")
        self.assertEqual(rows[2]["fields"]["dns_rrname"], "example.test")
        self.assertEqual(json.loads(rows[2]["fields"]["dns_queries"])[0]["rrtype"], "AAAA")
        self.assertEqual(rows[3]["fields"]["tls_ja3"], "0123456789abcdef")
        self.assertEqual(rows[4]["fields"]["file_stored"], "false")
        self.assertEqual(rows[5]["fields"]["anomaly_event"], "UNEXPECTED_MESSAGE")
        self.assertEqual(rows[6]["fields"]["flow_alerted"], "true")
        self.assertEqual(events("--alerts-only", path), [])
        self.assertEqual(events("--errors-only", path), [])
        self.assertEqual(events("--module=json", path), rows)
        for row, native in zip(rows, map(json.loads, path.read_text().splitlines())):
            kind = native["event_type"]
            self.assertEqual(json.loads(row["fields"][kind]), native[kind])
            self.assertEqual(json.loads(row["raw"]), native)
        for mode in ("text", "json", "raw"):
            self.assertEqual(run("--threads=1", "--output", mode, path).stdout,
                             run("--threads=4", "--output", mode, path).stdout)
        self.assertEqual(run("--output=raw", path).stdout, path.read_text())
        self.assertEqual(len(events("--where=http_method=GET", path)), 1)

    def test_suricata_observation_recognition_types_and_collisions(self):
        inputs = [
            {"event_type": "unknown", "http": {}, "dest_ip": "192.0.2.1"},
            {"event_type": "http", "http": [], "dest_ip": "192.0.2.1"},
            {"event_type": "http", "http": {"http_method": 42, "status": "invalid", "length": -1},
             "dest_ip": "example.test", "dest_port": 65536},
            {"event_type": "http", "source": "", "message": "", "level": "warn", "http_method": "old",
             "http": {"http_method": "POST", "status": 503, "length": 0}, "dest_port": 0},
            {"event_type": "dns", "dns": {"queries": [{"rrname": "one"}, {"rrname": "two"}]}},
            {"event_type": "fileinfo", "fileinfo": {"size": "42", "stored": 1}},
        ]
        rows = events(data="\n".join(map(json.dumps, inputs)))
        for row in rows[:2]:
            self.assertNotIn("source", row["fields"])
            self.assertNotIn("dst_ip", row["fields"])
        self.assertNotIn("http_method", rows[2]["fields"])
        self.assertNotIn("http_status", rows[2]["fields"])
        self.assertNotIn("http_length", rows[2]["fields"])
        self.assertNotIn("dst_ip", rows[2]["fields"])
        self.assertNotIn("dst_port", rows[2]["fields"])
        self.assertEqual(rows[3]["fields"]["http_method"], "POST")
        self.assertEqual(rows[3]["fields"]["source"], "")
        self.assertEqual(rows[3]["fields"]["message"], "")
        self.assertEqual(rows[3]["fields"]["dst_port"], "0")
        self.assertEqual(rows[3]["level"], "WARN")
        self.assertNotIn("dns_rrname", rows[4]["fields"])
        self.assertNotIn("file_size", rows[5]["fields"])
        self.assertNotIn("file_stored", rows[5]["fields"])
        for version in (4, "3", -1, None):
            unknown = {"event_type": "dns", "dns": {"version": version, "rrname": "example.test"}}
            row, = events(data=json.dumps(unknown))
            self.assertNotIn("dns_rrname", row["fields"])
            self.assertNotIn("source", row["fields"])
        duplicate = '{"event_type":"http","http":{"http_method":"GET","http_method":42}}'
        row, = events(data=duplicate)
        self.assertNotIn("http_method", row["fields"])
        duplicate = '{"event_type":"http","http":{"http_method":"GET"},"http":[]}'
        row, = events(data=duplicate)
        self.assertNotIn("source", row["fields"])
        self.assertNotIn("http_method", row["fields"])
        path = ROOT / "examples/suricata-observations.jsonl"
        for line in path.read_text().splitlines():
            normal, = events(data=line)
            compatibility, = events(data=line[:-1] + ',"large":18446744073709551616}')
            compatibility["fields"].pop("large")
            self.assertEqual(normal["fields"]["message"], normal["raw"])
            self.assertEqual(compatibility["fields"]["message"], compatibility["raw"])
            normal["fields"].pop("message")
            compatibility["fields"].pop("message")
            kind = normal["fields"]["event_type"]
            for key in (kind, "dns_queries", "dns_answers", "dns_grouped"):
                if key in normal["fields"]:
                    normal["fields"][key] = json.loads(normal["fields"][key])
                    compatibility["fields"][key] = json.loads(compatibility["fields"][key])
            self.assertEqual(normal["fields"], compatibility["fields"])

    def test_web_error_profiles_filters_and_worker_equivalence(self):
        path = ROOT / "examples/web-error.log"
        rows = events(path)
        self.assertEqual([row["format"] for row in rows], ["web-error"] * 4)
        self.assertEqual([row["level"] for row in rows], ["ERROR", "INFO", "ERROR", "WARN"])
        self.assertEqual([row["fields"]["source"] for row in rows], ["apache", "apache", "nginx", "nginx"])
        self.assertEqual(rows[0]["fields"]["event_code"], "AH00124")
        self.assertEqual(rows[0]["fields"]["src_port"], "443")
        self.assertEqual(rows[2]["fields"]["src_ip"], "2001:db8::10")
        self.assertEqual(rows[2]["fields"]["request"], "GET /login HTTP/1.1")
        self.assertEqual(events("--module=web-error", path), rows)
        self.assertEqual(len(events("--errors-only", path)), 2)
        self.assertEqual(len(events("--where=source=apache", path)), 2)
        for mode in ("text", "json", "raw"):
            args = ["--output", mode, path]
            self.assertEqual(run("--threads=1", *args).stdout, run("--threads=4", *args).stdout)
        self.assertEqual(run("--output=raw", path).stdout, path.read_text())
        first = path.read_text().splitlines()[0]
        data = first + "\n  context\nordinary\n"
        row, = events("--multiline=indent", "--where=source=apache", data=data)
        self.assertEqual(row["raw"], first + "\n  context")
        self.assertEqual(row["line"], 1)
        row, = events("--module=web-error", data="unrelated error text")
        self.assertEqual(row["format"], "plain")

    def test_access_escaped_quotes_and_missing_request(self):
        data = '127.0.0.1 - - [07/Nov/2026:18:30:03 +0100] "GET / HTTP/1.1" 404 - "-" "a\\\"b"\n'
        data += '127.0.0.1 - - [07/Nov/2026:18:30:03 +0100] "-" 400 0\n'
        rows = events(data=data)
        self.assertEqual([r["format"] for r in rows], ["access", "access"])
        self.assertEqual([r["level"] for r in rows], ["WARN", "WARN"])

    def test_apache_empty_module_keeps_error_severity(self):
        line = '[Sat Nov 07 18:30:00.123456 2026] [:error] [pid 42] AH00124: failed'
        for args in ((), ("--errors-only",), ("--module=web-error",)):
            row, = events(*args, data=line)
            self.assertEqual(row["format"], "web-error")
            self.assertEqual(row["level"], "ERROR")
            self.assertEqual(row["fields"]["apache_module"], "")
            self.assertEqual(row["fields"]["original_level"], "error")
            self.assertEqual(row["raw"], line)

    def test_access_rejected_requests_keep_status_and_context(self):
        requests = ["", "-", "GET", "GET /", "GET / HTTP/1.1 extra", "bad\\\"request"]
        prefix = '127.0.0.1 - alice [07/Nov/2026:18:30:02 +0100] '
        for suffix in ("", ' "https://example.test/" "client\\\"1"'):
            for status, level in ((400, "WARN"), (503, "ERROR")):
                lines = [prefix + '"' + request + '" ' + str(status) + ' 12' + suffix
                         for request in requests]
                data = "\n".join(lines)
                for threads in (1, 4):
                    rows = events("--threads", threads, data=data)
                    self.assertEqual(len(rows), len(lines))
                    for request, line, row in zip(requests, lines, rows):
                        self.assertEqual(row["format"], "access")
                        self.assertEqual(row["level"], level)
                        fields = row["fields"]
                        self.assertEqual(fields["request"], request)
                        self.assertEqual(fields["message"], request)
                        self.assertEqual(fields["status"], str(status))
                        self.assertEqual(fields["bytes"], "12")
                        self.assertEqual(fields["user"], "alice")
                        for key in ("method", "path", "protocol"):
                            self.assertNotIn(key, fields)
                        self.assertEqual(row["raw"], line)
                    self.assertEqual(events("--threads", threads, "--where=status=" + str(status),
                                            data=data), rows)
                    self.assertEqual(events("--threads", threads, "--errors-only", data=data),
                                     rows if status >= 500 else [])
                    self.assertEqual(run("--threads", threads, "--output=raw", data=data).stdout,
                                     data + "\n")

    def test_render_limit_is_an_explicit_failure_in_each_execution_mode(self):
        data = "x" * 20000 + "\n"
        template = "{raw}" * 1024
        for threads in (1, 4):
            with self.subTest(threads=threads):
                result = run("--threads", threads, "--template", template, data=data, code=1)
                self.assertIn("rendered line exceeds 16 MiB", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_malformed_input_is_preserved(self):
        lines = ['{"bad":', '{"message":"unterminated}', '[1,2]', '<999>bad', '<11>1 - h a - - [broken', 'Nov 99 99:99:99 nonsense']
        rows = events(data="\n".join(lines))
        self.assertEqual([r["format"] for r in rows], ["plain"] * len(lines))
        self.assertEqual([r["raw"] for r in rows], lines)

    def test_late_parser_rejections_preserve_the_entire_record(self):
        access = '127.0.0.1 - alice [07/Nov/2026:18:30:02 +0100] '
        lines = [
            'ordinary log line with several words',
            '<11>1 - host app 42 ID [meta x="unterminated]',
            '<11>Nov  7 18:30:01 ',
            access + '"GET / HTTP/1.1" 200 12 "-"',
            access + '"GET / HTTP/1.1" 200 12 "-" "agent" extra',
            access + '"GET / HTTP/1.1" 200 twelve',
            access + '"GET / HTTP/1.1 400 0',
            access + '"GET /" 999 12',
        ]
        for threads in (1, 4):
            with self.subTest(threads=threads):
                rows = events("--threads", threads, data="\n".join(lines))
                self.assertEqual([r["format"] for r in rows], ["plain"] * len(lines))
                self.assertEqual([r["fields"]["message"] for r in rows], lines)
                self.assertEqual([r["raw"] for r in rows], lines)

    def test_access_fields_survive_validation_and_keep_whitespace(self):
        common = '\t127.0.0.1\t- alice [07/Nov/2026:18:30:02 +0100] "GET /health HTTP/1.1" 503 12  '
        combined = common.rstrip() + ' "https://example.test/" "client\\\"1"'
        rows = events(data=common + "\n" + combined + "\n")
        for row in rows:
            self.assertEqual(row["format"], "access")
            self.assertEqual(row["level"], "ERROR")
            for key, value in {"remote_addr": "127.0.0.1", "source": "127.0.0.1",
                               "ident": "-", "user": "alice", "method": "GET",
                               "path": "/health", "protocol": "HTTP/1.1",
                               "status": "503", "bytes": "12"}.items():
                self.assertEqual(row["fields"][key], value)
        self.assertEqual(rows[0]["raw"], common)
        self.assertEqual(rows[0]["fields"]["access_format"], "common")
        self.assertNotIn("referer", rows[0]["fields"])
        self.assertEqual(rows[1]["fields"]["access_format"], "combined")
        self.assertEqual(rows[1]["fields"]["referer"], "https://example.test/")
        self.assertEqual(rows[1]["fields"]["user_agent"], 'client\\"1')

    def test_deep_json_falls_back(self):
        row, = events(data='{"a":' + '[' * 65 + '0' + ']' * 65 + '}\n')
        self.assertEqual(row["format"], "plain")

    def test_forced_module_and_unknown_module(self):
        self.assertEqual(events("--module", "plain", data='{"level":"error"}\n')[0]["format"], "plain")
        self.assertEqual(events("--module", "json", data="unstructured\n")[0]["format"], "plain")
        self.assertIn("unknown module", run("--module", "missing", code=2).stderr)

    def test_filter_raw_and_json_never_contains_ansi(self):
        data = '{"level":"warn"}\n{"level":"error"}\n{"level":"fatal"}\ntext\n'
        rows = events("--errors-only", "--color=always", data=data)
        self.assertEqual([r["level"] for r in rows], ["ERROR", "CRITICAL"])
        self.assertNotIn("\x1b", run("--output=raw", "--color=always", data=data).stdout)
        self.assertEqual(run("--output=raw", data=data).stdout, data)

    def test_template_and_terminal_control_escaping(self):
        data = json.dumps({"level": "error", "message": "\x1b[2J\nhello\tworld"}) + "\n"
        text = run("--template", "{{{level}}} {message} {missing} {file}:{line}", data=data).stdout
        self.assertEqual(text, "{ERROR} \\x1b[2J\\x0ahello\\x09world - -:1\n")
        self.assertIn("\x1b[31m", run("--color=always", data=data).stdout)

    def test_custom_layout(self):
        out = run("--rules", ROOT / "examples/modules.json", data="worker=9 level=warn message=busy\n").stdout
        self.assertEqual(out, "[WARN] worker 9 → busy\n")

    def test_empty_lines_and_message_whitespace(self):
        self.assertEqual(run(data="\n\n").stdout, "\n\n")
        rows = events(data="<11>1 - host app - - - message  \n<11>Nov  7 18:30:01 host app: message  \n")
        self.assertEqual([r["fields"]["message"] for r in rows], ["message  ", "message  "])

    def test_files_stdin_crlf_and_final_line(self):
        with tempfile.TemporaryDirectory() as folder:
            first, second = Path(folder) / "a.log", Path(folder) / "b.log"
            first.write_bytes(b"one\r\n\r\ntwo")
            second.write_text("last\n")
            rows = events(first, "-", second, data="middle\n")
            self.assertEqual([r["raw"] for r in rows], ["one", "", "two", "middle", "last"])
            self.assertEqual([r["line"] for r in rows], [1, 2, 3, 1, 1])
            self.assertEqual([r["file"] for r in rows], [str(first)] * 3 + ["-", str(second)])

    def test_buffer_boundaries(self):
        lines = ["a" * 65535, "b" * 65536, "c" * 65537, "final"]
        self.assertEqual([r["raw"] for r in events(data="\n".join(lines))], lines)

    def test_line_limit_and_missing_file(self):
        self.assertEqual(run("--max-line-bytes=3", data="abc\n").stdout, "abc\n")
        self.assertIn("exceeds", run("--max-line-bytes=3", data="abcd\n", code=1).stderr)
        self.assertIn("exceeds", run("--max-line-bytes=65536", data="x" * 65537, code=1).stderr)
        self.assertIn("open", run("/does/not/exist/lumtail.log", code=1).stderr)

    def test_invalid_rules_and_patterns(self):
        invalid = [
            "{", [], {"version": 2, "modules": []},
            {"version": 1, "modules": [{"name": "x", "pattern": "{a}{b}"}]},
            {"version": 1, "modules": [{"name": "x", "pattern": "{a} {a}"}]},
            {"version": 1, "modules": [{"name": "plain", "pattern": "{message}"}]},
            {"version": 1, "modules": [{"name": "x", "pattern": "{raw}"}]},
            {"version": 1, "modules": [{"name": "x", "pattern": "{message}", "priority": -1000}]},
            {"version": 1, "modules": [{"name": "x", "pattern": "{message}", "display": {"color": "pink"}}]},
            {"version": 1, "modules": [{"name": "x", "pattern": "{message}", "display": {"template": "{oops"}}]},
            {"version": 1, "modules": [{"name": "x", "pattern": "{message}", "levels": {"bad": "garbage"}}]},
            {"version": 1, "modules": [{"name": "x", "pattern": "{message}", "typo": True}]},
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rules.json"
            for value in invalid:
                with self.subTest(value=value):
                    path.write_text(value if isinstance(value, str) else json.dumps(value))
                    self.assertEqual(run("--rules", path, code=2).stdout, "")

    def test_priority_and_stable_ties(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rules.json"
            path.write_text(json.dumps({"version": 1, "modules": [
                {"name": "first", "pattern": "{message}", "priority": 81},
                {"name": "second", "pattern": "{message}", "priority": 81},
            ]}))
            self.assertEqual(events("--rules", path, data='{"message":"hi"}\n')[0]["format"], "first")
            self.assertIn("duplicate module", run("--rules", path, "--rules", path, code=2).stderr)

    def test_patterns_are_anchored_and_escape_braces(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rules.json"
            path.write_text(json.dumps({"version": 1, "modules": [{
                "name": "tagged", "pattern": "BEGIN {{ {level} | {message} }} END",
                "display": {"template": "{{{level}}}: {message}"},
            }]}))
            valid = "BEGIN { warn | hello } END"
            lines = [valid, valid + " extra", "extra " + valid, "BEGIN { warn | a } END b } END"]
            rows = events("--rules", path, data="\n".join(lines))
            self.assertEqual([r["format"] for r in rows], ["tagged", "plain", "plain", "plain"])
            self.assertEqual(run("--rules", path, data=valid).stdout, "{WARN}: hello\n")

    def test_downstream_pipe_closure(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "large.log"
            path.write_text("unstructured\n" * 100000)
            with subprocess.Popen([BINARY, str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
                self.assertEqual(process.stdout.readline(), b"unstructured\n")
                process.stdout.close()
                self.assertEqual(process.wait(timeout=5), 0)
                self.assertEqual(process.stderr.read(), b"")

    def test_cli_validation_and_listing(self):
        for args in [("--wat",), ("--output", "bad"), ("--max-line-bytes", "0"), ("--follow",), ("--color", "bad"), ("--template", "{"), ("--rules",)]:
            with self.subTest(args=args):
                run(*args, code=2)
        self.assertTrue(run("--help").stdout.startswith("Lumtail"))
        self.assertEqual(run("--version").stdout, "lumtail 0.1.0\n")
        names = [line.split()[0] for line in run("--rules", ROOT / "examples/modules.json", "--list-modules").stdout.splitlines()]
        self.assertEqual(names, ["application", "worker", *BUILTIN_MODULES])

    def test_live_pipe_is_not_held_until_eof(self):
        process = subprocess.Popen([BINARY, "--output=raw"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(b"live\n")
            process.stdin.flush()
            self.assertTrue(select.select([process.stdout], [], [], 3)[0], "live record was buffered")
            self.assertEqual(os.read(process.stdout.fileno(), 4096), b"live\n")
        finally:
            process.communicate(timeout=3)
        self.assertEqual(process.returncode, 0)

    def test_follow_append_truncation_and_rotation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "live.log"
            path.write_text("initial\n")
            process = subprocess.Popen([BINARY, "--follow", "--output=raw", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            def expect(text):
                expected = text.encode()
                received = bytearray()
                deadline = time.monotonic() + 3
                while len(received) < len(expected):
                    remaining = max(0, deadline - time.monotonic())
                    self.assertTrue(select.select([process.stdout], [], [], remaining)[0], f"no follow output for {text!r}")
                    chunk = os.read(process.stdout.fileno(), len(expected) - len(received))
                    self.assertTrue(chunk, "follow output closed early")
                    received.extend(chunk)
                self.assertEqual(received, expected)
            try:
                expect("initial\n")
                with path.open("a") as out:
                    out.write("partial")
                    out.flush()
                    self.assertFalse(select.select([process.stdout], [], [], 0.2)[0])
                    out.write(" done\n")
                expect("partial done\n")
                path.write_text("")
                time.sleep(0.3)
                with path.open("a") as out:
                    out.write("truncated\n")
                expect("truncated\n")
                with path.open("a") as old_writer:
                    path.rename(path.with_suffix(".old"))
                    old_writer.write("old writer tail\n")
                    old_writer.flush()
                    path.write_text("rotated\n")
                    expect("old writer tail\nrotated\n")
            finally:
                process.terminate()
                process.communicate(timeout=3)

    def stats_run(self, *args, data=b"", env=None):
        result = subprocess.run([BINARY, *map(str, args)], input=data, capture_output=True,
                                env=env, timeout=60 * TIMEOUT_SCALE)
        lines = result.stderr.splitlines(keepends=True)
        self.assertTrue(lines and lines[-1].endswith(b"\n"), result.stderr)
        last = lines[-1].decode()
        if last.startswith("{"):
            stats = json.loads(last)
        else:
            match = STATS_TEXT.fullmatch(last)
            self.assertIsNotNone(match, last)
            stats = {"records": int(match["records"]), "workers": int(match["workers"]),
                     "complete": match["incomplete"] is None, "read": match["bytes"],
                     "text": last}
        return result, b"".join(lines[:-1]), stats

    def assert_bytes_read(self, stats, expected):
        if "bytes_read" in stats:
            self.assertEqual(stats["bytes_read"], expected)
        else:
            self.assertEqual(stats["read"], iec_size(expected))

    def test_stats_keeps_stdout_and_counts_written_records(self):
        with tempfile.TemporaryDirectory() as directory:
            # 64-byte records end exactly on 256 KiB output chunk boundaries.
            aligned = Path(directory) / "aligned.log"
            aligned.write_bytes(b"".join(b"%063d\n" % number for number in range(12000)))
            mixed = Path(directory) / "mixed.log"
            mixed.write_bytes(b"".join(
                (b'{"level":"error","n":%d,"pad":"%s"}\n' if number % 7 == 0 else
                 b'{"level":"info","n":%d,"pad":"%s"}\n') % (number, b"x" * (number % 97))
                for number in range(9000)))
            cases = [
                (aligned, ["--output=raw"]),
                (aligned, ["--output=raw", "--limit=4096"]),
                (aligned, ["--output=raw", "--limit=8193"]),
                (aligned, ["--output=raw", "--line-buffered"]),
                (aligned, ["--output=raw", "--filter=line>=1"]),
                (mixed, ["--output=json"]),
                (mixed, ["--output=json", "--where=level=ERROR"]),
                (mixed, ["--output=json", "--limit=777"]),
                (mixed, ["--color=never"]),
                (mixed, ["--agent", "--limit=5000"]),
            ]
            for path, args in cases:
                for threads in ("1", "4"):
                    with self.subTest(path=path.name, args=args, threads=threads):
                        call = [*args, f"--threads={threads}", path]
                        plain = subprocess.run([BINARY, *call], capture_output=True,
                                               timeout=60 * TIMEOUT_SCALE)
                        result, diagnostics, stats = self.stats_run("--stats", *call)
                        self.assertEqual(result.returncode, plain.returncode)
                        self.assertEqual(result.stdout, plain.stdout)
                        self.assertEqual(diagnostics, plain.stderr)
                        self.assertTrue(stats["complete"])
                        self.assertEqual(stats["records"], len(result.stdout.splitlines()))
                        if not any(arg.startswith("--limit") for arg in args):
                            self.assert_bytes_read(stats, path.stat().st_size)
                        # Unfiltered raw output bypasses parsing and the worker pool.
                        bypass = args[0] == "--output=raw" and not any(
                            arg.startswith("--filter") for arg in args)
                        parallel = threads == "4" and not bypass
                        self.assertEqual(stats["workers"], 4 if parallel else 1)

    def test_stats_counts_bytes_from_every_input(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.log"
            second = Path(directory) / "second.log"
            first.write_bytes(b"a\r\nb\n")
            second.write_bytes(b"c" * 70000)
            result, _, stats = self.stats_run("--stats", "--output=json", "--threads=1",
                                              first, "-", second, data=b"stdin\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(stats["bytes_read"], 5 + 6 + 70000)
            self.assertEqual(stats["records"], 4)
            self.assertEqual(stats["stats_version"], 1)
            self.assertEqual(list(stats), sorted(stats))
            follow = Path(directory) / "follow.log"
            follow.write_bytes(b"one\ntwo\n")
            result, _, stats = self.stats_run("--stats", "--follow", "--duration-ms=300",
                                              "--output=raw", follow)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_bytes_read(stats, 8)
            self.assertEqual(stats["records"], 2)
            self.assertTrue(stats["complete"])

    def test_stats_is_opt_in_and_last_on_stderr(self):
        environment = dict(os.environ, LUMTAIL_STATS="1")
        quiet = subprocess.run([BINARY, "--output=raw"], input=b"a\n", capture_output=True,
                               env=environment, timeout=10 * TIMEOUT_SCALE)
        self.assertEqual((quiet.returncode, quiet.stdout, quiet.stderr), (0, b"a\n", b""))
        missing = "/nonexistent/lumtail-stats.log"
        result, diagnostics, stats = self.stats_run("--stats", "-", missing, data=b"a\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn(missing.encode(), diagnostics)
        self.assert_bytes_read(stats, 2)
        self.assertEqual(stats["records"], 1)
        self.assertFalse(stats["complete"])
        self.assertTrue(stats["text"].endswith(", incomplete\n"))
        for args in (["--stats=json"], ["--stats", "--max-line-bytes=0"]):
            with self.subTest(args=args):
                usage = run(*args, code=2)
                self.assertNotIn("lumtail: stats:", usage.stderr)

    def stop_reason(self, *args, data=b""):
        result, _, stats = self.stats_run("--stats-version=2", "--output=json", *args, data=data)
        self.assertEqual(stats["stats_version"], 2)
        self.assertEqual(stats["complete"], stats["stop_reason"] != "error")
        return result, stats

    def test_stats_version_two_reports_why_processing_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.log"
            first.write_bytes(b"a\nb\n")
            for threads in ("1", "4"):
                with self.subTest(threads=threads):
                    common = [f"--threads={threads}", "--filter=line>=1"]
                    _, stats = self.stop_reason(*common, first, "-", data=b"c\n")
                    self.assertEqual((stats["stop_reason"], stats["records"]), ("eof", 3))
                    _, stats = self.stop_reason(*common, "--limit=3", first, "-", data=b"c\n")
                    self.assertEqual((stats["stop_reason"], stats["records"]), ("limit", 3))
                    _, stats = self.stop_reason(*common, "--limit=4", first, "-", data=b"c\n")
                    self.assertEqual(stats["stop_reason"], "eof")
                    _, stats = self.stop_reason(*common, "--multiline=indent", "--limit=1",
                                                data=b"x\n  y\nz\n")
                    self.assertEqual((stats["stop_reason"], stats["records"]), ("limit", 1))
                    result, stats = self.stop_reason(*common, first, "/nonexistent/stop.log")
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual((stats["stop_reason"], stats["records"]), ("error", 2))
                    result, stats = self.stop_reason(*common, "--max-line-bytes=4",
                                                     data=b"ok\ntoo long\n")
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(stats["stop_reason"], "error")

            follow = Path(directory) / "follow.log"
            follow.write_bytes(b"one\n")
            _, stats = self.stop_reason("--follow", "--duration-ms=200", follow)
            self.assertEqual((stats["stop_reason"], stats["records"]), ("duration", 1))
            # A pipe that stays open ends only at the deadline.
            process = subprocess.Popen([BINARY, "--stats-version=2", "--output=json",
                                        "--duration-ms=300", "-"], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                process.stdin.write(b"open\n")
                process.stdin.flush()
                process.wait(timeout=30 * TIMEOUT_SCALE)
                stdout, stderr = process.stdout.read(), process.stderr.read()
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()
            stats = json.loads(stderr.splitlines()[-1])
            self.assertEqual(len(stdout.splitlines()), 1)
            self.assertEqual((stats["stop_reason"], stats["records"]), ("duration", 1))

        data = b"".join(b"%d\n" % number for number in range(400000))
        for args in (["--output=raw"], ["--output=json", "--threads=4"]):
            with self.subTest(closure=args):
                process = subprocess.Popen([BINARY, "--stats-version=2", *args],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
                feeder = threading.Thread(target=self.feed_ignoring_closure,
                                          args=(process.stdin, data))
                feeder.start()
                process.stdout.readline()
                process.stdout.close()
                _, stderr = process.communicate(timeout=60 * TIMEOUT_SCALE)
                feeder.join()
                self.assertEqual(process.returncode, 0, stderr)
                self.assertTrue(stderr.endswith(b", stop: output_closed\n") or
                                b'"stop_reason":"output_closed"' in stderr, stderr)

        _, _, stats = self.stats_run("--stats", "--output=json", data=b"a\n")
        self.assertNotIn("stop_reason", stats)
        self.assertEqual(stats["stats_version"], 1)

    @staticmethod
    def feed_ignoring_closure(stream, data):
        try:
            stream.write(data)
            stream.close()
        except BrokenPipeError:
            pass


    def test_format_acceptance_targets_match_catalog(self):
        catalog = (ROOT / "docs/features/security-formats.md").read_text()
        section = catalog.split("\n## Acceptance targets\n", 1)[1].split("\n## ", 1)[0]
        pairs = re.findall(r"```sh\n(.*?)```\n\n```text\n(.*?)```", section, re.S)
        self.assertEqual(len(pairs), 15)
        for command, expected in pairs:
            with self.subTest(command=command):
                # Join shell line continuations as sh would.
                args = shlex.split(command.replace("\\\n", " "))
                self.assertEqual(args[0], "lumtail")
                result = subprocess.run([BINARY, *args[1:]], cwd=ROOT, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=30 * TIMEOUT_SCALE)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.decode(), expected)

    def test_documented_samples_exist(self):
        pages = [ROOT / "README.md", ROOT / "examples/README.md",
                 *(ROOT / "docs").rglob("*.md"), *(ROOT / "man").iterdir()]
        for page in pages:
            for sample in sorted(set(re.findall(r"examples/[A-Za-z0-9_.-]+\.[a-z]+", page.read_text()))):
                with self.subTest(page=page.name, sample=sample):
                    self.assertTrue((ROOT / sample).is_file())


if __name__ == "__main__":
    unittest.main()
