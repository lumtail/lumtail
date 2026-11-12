#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Check how tools/profile.py reads xctrace exports and stages a workload."""

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
<frame id="5" name="memchr" addr="0x1"><binary id="6" name="libsystem_platform.dylib"/></frame>
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
        self.assertEqual(profile.share(400, result), (40.0, 100 * (0.4 * 0.6 / 4) ** 0.5))

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
