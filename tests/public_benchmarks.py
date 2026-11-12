# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Check public-log selection, downloads and cleanup using local fixtures."""

from contextlib import redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv.pop(1)).resolve()
SCALE = float(os.environ.get("LUMTAIL_TEST_TIMEOUT_SCALE", "1"))
sys.path.insert(0, str(ROOT / "benchmarks"))
import public_logs as public
import public_report


def fixtures():
    records = [
        dict(eventName="DeleteNetworkAcl", readOnly=False, eventSource="ec2.amazonaws.com", eventVersion="1.08",
             awsRegion="us-east-2", userAgent="Boto3/1.10", sourceIPAddress="192.0.2.1"),
        dict(eventName="CreateNetworkAcl", readOnly=False, eventSource="ec2.amazonaws.com", eventVersion="1.08",
             awsRegion="us-west-2", userAgent="aws-sdk-go/1.0", sourceIPAddress="192.0.2.2"),
        dict(eventName="DescribeInstances", readOnly=True, eventSource="ec2.amazonaws.com", eventVersion="1.08",
             awsRegion="us-west-2", userAgent="eks.amazonaws.com", sourceIPAddress="192.0.2.3"),
        dict(eventName="DescribeNetworkAcls", readOnly=True, eventSource="ec2.amazonaws.com", eventVersion="1.08",
             awsRegion="us-east-2", userAgent="Boto3/1.10", sourceIPAddress="192.0.2.4"),
    ]
    return {
        "json": b"".join((json.dumps(row) + "\n").encode() for row in records),
        "syslog": (b'<35>1 2026-04-26T07:03:02Z host1.example.com sshd 42 - [meta severity="ERROR"]'
                   b'[auth user="admin" src_ip="192.0.2.1" result="failure"] Failed password for admin from 192.0.2.1\n'
                   b'<30>1 2026-04-26T07:03:03Z host2.example.com kernel 43 - [net dst_port="443" action="DROP"] Connection DROP\n'
                   b'<14>1 2026-04-26T07:03:04Z host3.example.com nginx 44 - [http status="200" method="GET" path="/"] GET / 200\n'),
    }


class PublicBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lumtail-public-test-")
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)

    def local_download(self, source, destination):
        destination.write_bytes(fixtures()[source["name"]])

    def test_queries_match_independent_raw_counts_and_bytes(self):
        for name, raw in fixtures().items():
            with self.subTest(corpus=name):
                source = {"name": name}
                folder = self.folder / name
                folder.mkdir()
                with mock.patch.object(public, "download", side_effect=self.local_download):
                    base, path, info = public.prepare(name, source, folder, 0)
                expected = {"json": (4, 2, 2), "syslog": (3, 1, 3)}[name]
                self.assertEqual(tuple(q["matches"] for q in info["queries"][:3]), expected)
                self.assertEqual(info["queries"][3]["matches"], 0)
                self.assertEqual(info["normalized_records"], 0)
                for query in info["queries"]:
                    result = subprocess.run(public.command(BINARY, path, query, "raw", "2", info["input_records"], False),
                                            capture_output=True, timeout=20 * SCALE)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.count(b"\n"), query["matches"])
                    self.assertEqual(hashlib.sha256(result.stdout).hexdigest(), query["source_raw_sha256"])

    def test_amplification_keeps_complete_passes_and_range_tail_is_removed(self):
        raw = fixtures()["syslog"]
        tail = b"<31>1 partial"
        with mock.patch.object(public, "download", side_effect=lambda source, path: path.write_bytes(raw + tail)):
            base, path, info = public.prepare("syslog", {"total_bytes": len(raw) + len(tail)}, self.folder, len(raw) * 2 + 1)
        self.assertEqual(info["passes"], 3)
        self.assertEqual(path.read_bytes(), raw * 3)
        self.assertEqual(base.read_bytes(), raw)
        self.assertEqual(info["dropped_range_tail_bytes"], len(tail))
        self.assertEqual(info["input_records"], 9)

    def test_download_pins_size_hash_and_http_range(self):
        data = b"download fixture\n"
        source = {"url": "https://example.invalid/log", "title": "fixture", "bytes": len(data),
                  "total_bytes": len(data) * 2, "sha256": hashlib.sha256(data).hexdigest()}
        def response(status=206, content=data, total=None):
            stream = io.BytesIO(content)
            stream.status = status
            stream.headers = {"Content-Range": f'bytes 0-{len(data) - 1}/{total or len(data) * 2}'}
            return stream
        with mock.patch.object(public.urllib.request, "urlopen", return_value=response()) as opened:
            public.download(source, self.folder / "valid")
        self.assertEqual(opened.call_args.args[0].get_header("Range"), f"bytes=0-{len(data) - 1}")
        for stream in (response(200), response(content=data[:-1]), response(content=data + b"x"),
                       response(content=b"X" + data[1:]), response(total=1)):
            with self.subTest(stream=stream), mock.patch.object(public.urllib.request, "urlopen", return_value=stream):
                with self.assertRaises(ValueError):
                    public.download(source, self.folder / "invalid")

    def test_archive_reads_only_named_member(self):
        archive = self.folder / "source.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("syslog.log", fixtures()["syslog"])
            output.writestr("../../outside", b"unused")
        with mock.patch.object(public, "download", side_effect=lambda source, path: shutil.copyfile(archive, path)):
            base, path, info = public.prepare("syslog", {"member": "syslog.log", "member_bytes": len(fixtures()["syslog"])},
                                              self.folder, 0)
        self.assertEqual(info["source_records"], 3)
        self.assertFalse((self.folder.parent / "outside").exists())

    def test_manual_run_produces_report_and_cleans_only_its_own_cache(self):
        directory = self.folder / "cache"
        directory.mkdir()
        marker = directory / "unrelated"
        marker.write_text("keep")
        output = self.folder / "report.json"
        argv = ["public_logs.py", str(BINARY), "--corpus", "json", "--threads", "1", "2",
                "--mode", "json", "agent", "--target-mib", "1", "--warmups", "0", "--repetitions", "1",
                "--timeout", str(20 * SCALE), "--directory", str(directory), "--output", str(output)]
        with mock.patch.object(sys, "argv", argv), mock.patch.dict(public.SOURCES, {"json": {**public.SOURCES["json"], "name": "json"}}), \
                mock.patch.object(public, "download", side_effect=self.local_download), redirect_stderr(io.StringIO()):
            self.assertEqual(public.main(), 0)
        report = json.loads(output.read_text())
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(report["results"]), 16)
        self.assertEqual(list(directory.iterdir()), [marker])
        self.assertTrue(all(row["removed"] for row in report["cleanup"]))
        self.assertGreater(report["corpora"]["json"]["input_records"], 100)
        self.assertTrue(all(row["samples"][0]["stats"]["complete"] for row in report["results"]))
        public_report.validate(report)
        report["corpora"]["json"]["source"]["title"] = "JSON <content> & filters"
        svg = public_report.infographic(report)
        ET.fromstring(svg)
        self.assertIn("JSON &lt;content&gt; &amp; filters", svg)
        rendered = public_report.markdown(report, output, self.folder / "chart.svg", self.folder / "report.md")
        self.assertIn("[Raw samples, commands, hashes and cleanup](report.json)", rendered)
        for query in report["corpora"]["json"]["queries"]:
            if query["filter"]:
                self.assertIn(query["filter"], rendered)

    def test_report_rejects_failed_runs_and_incomplete_cleanup(self):
        for data in ({"status": "failed"}, {"status": "complete", "results": [{}], "cleanup": []},
                     {"status": "complete", "results": [{}], "cleanup": [{"removed": False}]}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                public_report.validate(data)

    def test_failure_and_interrupt_remove_partial_download_and_save_status(self):
        for failure, expected, code in ((ValueError("hash mismatch"), "failed", 1), (KeyboardInterrupt(), "interrupted", 130)):
            with self.subTest(status=expected):
                directory = self.folder / "cache"
                output = self.folder / "failed.json"
                argv = ["public_logs.py", str(BINARY), "--corpus", "json", "--directory", str(directory), "--output", str(output)]
                def failed(source, path):
                    path.write_bytes(b"partial download")
                    raise failure
                with mock.patch.object(sys, "argv", argv), mock.patch.object(public, "download", side_effect=failed), \
                        redirect_stderr(io.StringIO()):
                    self.assertEqual(public.main(), code)
                report = json.loads(output.read_text())
                self.assertEqual(report["status"], expected)
                self.assertTrue(report["cleanup"][0]["removed"])
                self.assertEqual(list(directory.iterdir()), [])

    def test_revision_is_recorded_when_another_user_owns_the_checkout(self):
        # BSD CI copies the checkout into a VM as another user.
        with mock.patch.dict(os.environ, {"GIT_TEST_ASSUME_DIFFERENT_OWNER": "1"}):
            host = public.host_metadata(BINARY)
        revision = subprocess.check_output(["git", "-c", f"safe.directory={ROOT}", "rev-parse", "HEAD"],
                                           text=True, cwd=ROOT).strip()
        self.assertEqual(host["revision"], revision)

    def test_incomplete_or_wrong_counts_are_rejected(self):
        for stats in ({"stats_version": 1, "complete": False, "bytes_read": 100, "records": 2},
                      {"stats_version": 1, "complete": True, "bytes_read": 99, "records": 2},
                      {"stats_version": 1, "complete": True, "bytes_read": 100, "records": 1}):
            with self.subTest(stats=stats), self.assertRaises(ValueError):
                public.validate_sample({"stats": stats}, {"input_bytes": 100}, {"matches": 2})

    def test_hash_worker_streams_output_and_bounds_blocked_children(self):
        data = b"hash sample\n" * 100000
        path = self.folder / "hash.log"
        path.write_bytes(data)
        result = public.invoke_worker({"command": [str(BINARY), "--output=raw", str(path)], "kind": "hash", "timeout": 20 * SCALE})
        self.assertEqual(result["output_bytes"], len(data))
        self.assertEqual(result["output_records"], 100000)
        self.assertEqual(result["output_sha256"], hashlib.sha256(data).hexdigest())
        with self.assertRaises(RuntimeError):
            public.invoke_worker({"command": [sys.executable, "-c", "import time;time.sleep(10)"],
                                  "kind": "hash", "timeout": 0.05})


if __name__ == "__main__":
    unittest.main()
