#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Check how tools/profile.py reads xctrace exports, disassembly and hardware counts, and
stages a workload."""

import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("profile_tool", ROOT / "tools/profile.py")
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)

# Two lumtail samples (one reusing the first one's backtrace by ref) and one sample of
# another process, in the shape xctrace export writes for the CPU Profiler.
EXPORT = f"""<?xml version="1.0"?>
<trace-query-result><node>
<row><process id="1" fmt="lumtail (42)"/><thread-state id="2">Running</thread-state>
<cycle-weight id="3">300</cycle-weight>
<tagged-backtrace id="4">
<frame id="5" name="memchr" addr="0x1a05"><binary id="6" name="libsystem_platform.dylib"
load-addr="0x1000"/></frame>
<frame id="7" name="std::find" addr="0x2"><source line="12"><path id="8">/sdk/find.h</path>
</source></frame>
<frame id="9" name="lumtail::scan" addr="0x3"><source line="40"><path id="10">{ROOT}/src/scan.cpp</path>
</source></frame>
<frame id="11" name="main" addr="0x4"><source line="7"><path id="12">{ROOT}/src/main.cpp</path>
</source></frame>
</tagged-backtrace></row>
<row><process ref="1"/><thread-state ref="2"/><cycle-weight id="13">100</cycle-weight>
<tagged-backtrace ref="4"/></row>
<row><process id="14" fmt="other (7)"/><thread-state ref="2"/><cycle-weight ref="3"/>
<tagged-backtrace ref="4"/></row>
<row><process ref="1"/><thread-state ref="2"/><cycle-weight id="15">600</cycle-weight>
<tagged-backtrace id="16"><frame ref="11"/></tagged-backtrace></row>
<row><process ref="1"/><thread-state ref="2"/><cycle-weight id="17">0</cycle-weight><sentinel/></row>
</node></trace-query-result>
"""


class ProfileTool(unittest.TestCase):
    def test_aggregates_lumtail_cycles_by_function_line_and_owner(self):
        with TemporaryDirectory() as folder:
            export = Path(folder) / "run-0.xml"
            export.write_text(EXPORT)
            result = profile.aggregate([export])
        self.assertEqual((result["samples"], result["cycles"]), (4, 1000))
        self.assertEqual(result["self_function"], {"memchr": 400, "main": 600,
                                                   "(no backtrace)": 0})
        self.assertEqual(result["self_line"][("main", "src/main.cpp:7")], 600)
        self.assertEqual(result["self_file"]["libsystem_platform.dylib"], 400)
        # memchr time belongs to the nearest lumtail frame, skipping the inlined std::find.
        self.assertEqual(result["owned"], {"lumtail::scan": 400, "main": 600,
                                           "(outside lumtail)": 0})
        self.assertEqual(result["owned_line"][("lumtail::scan", "src/scan.cpp:40")], 400)
        self.assertEqual(result["inclusive"], {"lumtail::scan": 400, "main": 1000})
        self.assertEqual(result["callers"]["memchr"], {"lumtail::scan": 400})
        # Only the first sample's leaf names its binary; its address drops the low marker bits.
        self.assertEqual(result["instructions"], {("libsystem_platform.dylib", 0xa04): 400})
        self.assertEqual(profile.share(400, result), (40.0, 100 * (0.4 * 0.6 / 4) ** 0.5))

    def test_disassembly_maps_addresses_to_symbol_instruction_and_line(self):
        listing = f"""
0000000100000010 <lumtail::scan(std::string_view)>:
; lumtail::scan(std::string_view)():
; {ROOT}/src/scan.cpp:40
100000010:     \tldrb\tw8, [x0]
100000014:     \tb.ne\t0x100000010 <lumtail::scan(std::string_view)+0x0>

0000000100000018 <main>:
100000018:     \tret
""".splitlines()
        found = profile.parse_disassembly(listing, {0x100000014, 0x100000018, 0x100000099})
        self.assertEqual(found, {
            0x100000014: ("lumtail::scan(std::string_view)", "b.ne 0x100000010", "src/scan.cpp:40"),
            0x100000018: ("main", "ret", "?")})

    def test_bottlenecks_weight_lumtail_threads_by_run_time(self):
        export = """<?xml version="1.0"?>
<trace-query-result><node>
<row><duration id="1">1</duration><process id="2" fmt="lumtail (42)"/>
<uint64-array id="3">1000 2000 3000 4000</uint64-array></row>
<row><duration id="4">3</duration><process ref="2"/>
<uint64-array id="5">5000 1000 2000 1000</uint64-array></row>
<row><duration ref="4"/><process id="6" fmt="other (7)"/><uint64-array ref="3"/></row>
</node></trace-query-result>
"""
        with TemporaryDirectory() as folder:
            path = Path(folder) / "run-0.counters.xml"
            path.write_text(export)
            self.assertEqual(profile.bottlenecks(path), [40.0, 12.5, 22.5, 17.5])

    def test_time_counts_read_hardware_lines(self):
        text = ("        3.27 real         3.10 user         0.10 sys\n"
                "         19318000000  instructions retired\n"
                "          6804000000  cycles elapsed\n"
                "             3047832  peak memory footprint\n")
        self.assertEqual(profile.time_counts(text), {
            "instructions": 19318000000, "cycles": 6804000000, "peak_footprint_bytes": 3047832})

    def test_stage_copies_binary_symbols_and_file_arguments(self):
        with TemporaryDirectory() as folder:
            folder = Path(folder)
            build = folder / "build"
            (build / "lumtail.dSYM").mkdir(parents=True)
            (build / "lumtail").write_text("binary")
            data = folder / "app.log"
            data.write_text("line\n")
            staging = folder / "staging"
            staging.mkdir()
            command = profile.stage(build / "lumtail", ["--threads", "1", str(data), "-"],
                                    staging)
            self.assertEqual(command, [staging / "lumtail", "--threads", "1",
                                       str(staging / "inputs/2-app.log"), "-"])
            self.assertEqual((staging / "inputs/2-app.log").read_text(), "line\n")
            self.assertTrue((staging / "lumtail.dSYM").is_dir())


if __name__ == "__main__":
    unittest.main()
