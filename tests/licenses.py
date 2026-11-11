# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Check that installation carries the complete reviewed license material."""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "highway-1.4.0.txt": "Copyright (c) The Highway Project Authors. All rights reserved.",
    "Apache-2.0.txt": "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
    "BSL-1.0.txt": "Boost Software License - Version 1.0",
    "simdjson-instruction-set-BSD-3-Clause.txt": "Neither the names of Facebook",
    "simdjson-fast_float-MIT.txt": "Copyright (c) 2021 The simdjson_fast_float authors",
}

COPYRIGHT = "SPDX-FileCopyrightText: 2026 lumtail contributors"
LICENSE_ID = "SPDX-License-Identifier: MIT"


def front_matter(lines):
    if not lines or lines[0] != "---":
        return {}, lines
    if "---" not in lines[1:]:
        raise AssertionError("Unterminated front matter")
    end = lines.index("---", 1)
    fields = dict(line.split(": ", 1) for line in lines[1:end] if ": " in line)
    return fields, lines[end + 1:]


def require_metadata(path):
    try:
        _, body = front_matter(path.read_text(encoding="utf-8").splitlines())
    except AssertionError as error:
        raise AssertionError(f"{error}: {path}") from None
    header = body[:6]
    identifiers = [line.strip() for line in header
                   if line.strip().startswith("SPDX-License-Identifier:")]
    if not any(line.strip() == COPYRIGHT for line in header) or identifiers != [LICENSE_ID]:
        raise AssertionError(f"Missing or conflicting project license metadata: {path}")


def review_project_materials(root):
    license_text = (root / "LICENSE").read_bytes()
    for directory in ("docs", "assets"):
        copy = root / directory / "LICENSE"
        if not copy.is_file() or copy.read_bytes() != license_text:
            raise AssertionError(f"Missing or changed directory license: {copy}")
    documents = set(root.glob("*.md")) - {root / "THIRD_PARTY_NOTICES.md"}
    for directory in ("docs", "assets", "examples", "benchmarks", ".github", "contracts"):
        documents.update((root / directory).rglob("*.md"))
    for skills in (".claude/skills", ".agents/skills"):
        directory = root / skills
        for entry in sorted(directory.iterdir()) if directory.is_dir() else []:
            if entry.is_symlink():
                # Codex reads .agents/skills and Claude reads .claude/skills; one folder serves both.
                target = Path(os.readlink(entry))
                if target.is_absolute() or root.resolve() not in entry.resolve().parents:
                    raise AssertionError(f"Skill link leaves the repository: {entry}")
            skill = entry / "SKILL.md"
            if not skill.is_file():
                raise AssertionError(f"Missing skill definition: {skill}")
            fields, _ = front_matter(skill.read_text(encoding="utf-8").splitlines())
            if fields.get("name") != entry.name or not fields.get("description"):
                raise AssertionError(f"Missing or conflicting skill name or description: {skill}")
            documents.update(path for path in entry.resolve().rglob("*.md"))
    for document in sorted(documents):
        require_metadata(document)
    for asset in sorted((root / "assets").rglob("*")):
        if not asset.is_file() or asset.name == "LICENSE" or asset.suffix == ".md":
            continue
        if asset.suffix == ".svg":
            require_metadata(asset)
            for element in ET.parse(asset).getroot().iter():
                tag = element.tag.rsplit("}", 1)[-1]
                if tag in {"image", "style", "font", "font-face", "script", "foreignObject"} or any(
                        key.rsplit("}", 1)[-1] == "href" and not value.startswith("#")
                        for key, value in element.attrib.items()):
                    raise AssertionError(f"Unreviewed embedded or external artwork resource: {asset}")
        elif asset.suffix in {".png", ".gif", ".cast"}:
            companion = asset.with_name(asset.name + ".license")
            if not companion.is_file():
                raise AssertionError(f"Missing artwork license companion: {companion}")
            require_metadata(companion)
            if asset.suffix != ".cast":
                source = asset.with_suffix(".svg" if asset.suffix == ".png" else ".cast")
                if not source.is_file() or f"Source: {source.name}" not in companion.read_text(
                        encoding="utf-8").splitlines():
                    raise AssertionError(f"Missing or conflicting artwork source: {companion}")
        elif asset.suffix == ".license" and asset.with_suffix("").suffix in {".png", ".gif", ".cast"}:
            if not asset.with_suffix("").is_file():
                raise AssertionError(f"Orphaned artwork license companion: {asset}")
        else:
            raise AssertionError(f"Unreviewed artwork file: {asset}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cmake", required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--doc-dir", type=Path, required=True)
    parser.add_argument("--contract-dir", type=Path, required=True)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    review_project_materials(ROOT)
    notices = " ".join((ROOT / "THIRD_PARTY_NOTICES.md").read_text().split())
    for author in ("Niels Lohmann", "Bjoern Hoehrmann", "Florian Loitsch", "Evan Nemerson",
                   "Junekey Jeon", "Martin Moene", "The Abseil Authors", "Eric Niebler",
                   "Google Fuchsia"):
        if author not in notices:
            raise AssertionError(f"Missing component attribution: {author}")
    for filename, marker in REQUIRED.items():
        if marker not in (ROOT / "LICENSES" / filename).read_text():
            raise AssertionError(f"Missing or incomplete license: {filename}")
        if f"LICENSES/{filename}" not in notices:
            raise AssertionError(f"Notice does not reference {filename}")

    with tempfile.TemporaryDirectory(prefix="lumtail-licenses-") as temporary:
        # DESTDIR also contains any absolute install destination configured by
        # a packager, so the check cannot write to their real installation.
        stage = Path(temporary)
        prefix = Path("/lumtail-license-check")
        environment = dict(os.environ, DESTDIR=str(stage))
        result = subprocess.run(
            [args.cmake, "--install", str(args.build_dir), "--config", args.config,
             "--prefix", str(prefix)],
            env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=45, check=False,
        )
        if result.returncode:
            raise AssertionError(f"Staged installation failed:\n{result.stdout}")
        destination = args.doc_dir if args.doc_dir.is_absolute() else prefix / args.doc_dir
        installed = stage / destination.relative_to(destination.anchor)
        expected = [ROOT / name for name in ("README.md", "CONTRIBUTING.md", "LICENSE",
                                            "LICENSING.md", "contributors.md", "THIRD_PARTY_NOTICES.md")]
        for directory in ("LICENSES", "assets", "docs", "examples"):
            expected.extend((ROOT / directory).rglob("*"))
        for source in expected:
            if source.is_file():
                copy = installed / source.relative_to(ROOT)
                if not copy.is_file() or copy.read_bytes() != source.read_bytes():
                    raise AssertionError(f"Missing or changed installed notice: {copy}")
        destination = args.contract_dir if args.contract_dir.is_absolute() else prefix / args.contract_dir
        installed_contracts = stage / destination.relative_to(destination.anchor)
        contract_root = ROOT / "contracts/cli"
        for source in contract_root.rglob("*"):
            if source.is_file():
                copy = installed_contracts / source.relative_to(contract_root)
                if not copy.is_file() or copy.read_bytes() != source.read_bytes():
                    raise AssertionError(f"Missing or changed installed CLI contract: {copy}")
    print("License notices and their staged installation passed.")


if __name__ == "__main__":
    main()
