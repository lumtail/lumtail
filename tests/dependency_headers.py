# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Reject dependency header shadowing using the real CMake compiler search order.

Run against a build configured with fetched nlohmann_json, simdjson and Highway.
A shared package prefix containing stale simdjson/Highway headers must not win
against the selected isolated dependencies. No dependency sources are modified.
"""

import argparse
import json
from pathlib import Path
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    args = parser.parse_args()
    database = json.loads((args.build / "compile_commands.json").read_text())
    entry = next(row for row in database if Path(row["file"]).name == "scan.cpp")
    command = shlex.split(entry["command"])
    includes = [Path(command[index + 1]) for index, value in enumerate(command[:-1])
                if value == "-isystem"]
    json_root = next(path for path in includes if (path / "nlohmann/json.hpp").is_file())
    if (json_root / "simdjson.h").exists() or (json_root / "hwy/highway.h").exists():
        parser.error("this regression requires isolated fetched dependency headers")
    with tempfile.TemporaryDirectory(prefix="lumtail-header-isolation-") as temporary:
        prefix = Path(temporary)
        (prefix / "nlohmann").symlink_to(json_root / "nlohmann", target_is_directory=True)
        (prefix / "simdjson.h").write_text('#error "stale simdjson header shadowed selected dependency"\n')
        (prefix / "hwy").mkdir()
        (prefix / "hwy/highway.h").write_text('#error "stale Highway header shadowed selected dependency"\n')
        probe = prefix / "probe.cpp"
        probe.write_text("#include <simdjson.h>\n#include <hwy/highway.h>\n#include <nlohmann/json.hpp>\n")
        flags = []
        index = 0
        while index < len(command):
            value = command[index]
            if value == "-o":
                index += 2
                continue
            if value == "-c" or value == entry["file"]:
                index += 1
                continue
            flags.append(str(prefix) if value == str(json_root) else value)
            index += 1
        subprocess.run([*flags, "-fsyntax-only", str(probe)], cwd=entry["directory"], check=True)
    print("Selected dependency headers precede conflicting shared-prefix headers.")


if __name__ == "__main__":
    main()
