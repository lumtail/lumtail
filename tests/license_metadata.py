# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Exercise the documentation and artwork licensing policy's failure paths."""

import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("license_checks", ROOT / "tests/licenses.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
HEADER = (f"<!--\n{checks.COPYRIGHT}\n{checks.LICENSE_ID}\n-->\n")
SKILL = "---\nname: demo\ndescription: Read demo logs.\n---\n\n" + HEADER + "# Demo\n"


class LicenseMetadataTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="lumtail-license-metadata-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for directory in ("docs", "assets/img"):
            (self.root / directory).mkdir(parents=True)
        for name in ("LICENSE", "docs/LICENSE", "assets/LICENSE"):
            (self.root / name).write_bytes((ROOT / "LICENSE").read_bytes())
        (self.root / "docs/guide.md").write_text(HEADER + "# Guide\n", encoding="utf-8")
        self.svg = self.root / "assets/img/mark.svg"
        self.svg.write_text(HEADER + '<svg xmlns="http://www.w3.org/2000/svg"/>\n', encoding="utf-8")
        (self.root / "assets/img/mark.png").write_bytes(b"image fixture")
        self.notice = self.root / "assets/img/mark.png.license"
        self.notice.write_text(f"{checks.COPYRIGHT}\n{checks.LICENSE_ID}\nSource: mark.svg\n",
                               encoding="utf-8")
        self.recording = self.root / "assets/img/demo.cast"
        self.recording.write_text('{"version":2}\n', encoding="utf-8")
        self.recording_notice = self.recording.with_name("demo.cast.license")
        self.recording_notice.write_text(f"{checks.COPYRIGHT}\n{checks.LICENSE_ID}\n",
                                         encoding="utf-8")
        self.animation = self.root / "assets/img/demo.gif"
        self.animation.write_bytes(b"animation fixture")
        self.animation_notice = self.animation.with_name("demo.gif.license")
        self.animation_notice.write_text(
            f"{checks.COPYRIGHT}\n{checks.LICENSE_ID}\nSource: demo.cast\n", encoding="utf-8")
        self.skill = self.root / ".claude/skills/demo/SKILL.md"
        self.skill.parent.mkdir(parents=True)
        self.skill.write_text(SKILL, encoding="utf-8")
        self.skill_link = self.root / ".agents/skills/demo"
        self.skill_link.parent.mkdir(parents=True)
        self.skill_link.symlink_to("../../.claude/skills/demo", target_is_directory=True)

    def rejected(self, message):
        with self.assertRaisesRegex(AssertionError, message):
            checks.review_project_materials(self.root)

    def test_complete_materials(self):
        checks.review_project_materials(self.root)

    def test_document_header_required(self):
        (self.root / "docs/guide.md").write_text("# Guide\n", encoding="utf-8")
        self.rejected("license metadata")

    def test_svg_header_required(self):
        self.svg.write_text('<svg xmlns="http://www.w3.org/2000/svg"/>\n', encoding="utf-8")
        self.rejected("license metadata")

    def test_conflicting_license_rejected(self):
        self.svg.write_text(HEADER.replace("-->\n", "SPDX-License-Identifier: CC0-1.0\n-->\n") +
                            '<svg xmlns="http://www.w3.org/2000/svg"/>\n', encoding="utf-8")
        self.rejected("license metadata")

    def test_png_notice_required(self):
        self.notice.unlink()
        self.rejected("license companion")

    def test_png_editable_source_required(self):
        self.svg.unlink()
        self.rejected("artwork source")

    def test_png_source_notice_matches_export(self):
        self.notice.write_text(f"{checks.COPYRIGHT}\n{checks.LICENSE_ID}\nSource: other.svg\n",
                               encoding="utf-8")
        self.rejected("artwork source")

    def test_orphaned_notice_rejected(self):
        (self.root / "assets/img/mark.png").unlink()
        self.rejected("Orphaned")

    def test_demo_notices_required(self):
        for notice in (self.recording_notice, self.animation_notice):
            with self.subTest(notice=notice.name):
                content = notice.read_bytes()
                notice.unlink()
                self.rejected("license companion")
                notice.write_bytes(content)

    def test_demo_license_metadata_required(self):
        for notice in (self.recording_notice, self.animation_notice):
            with self.subTest(notice=notice.name):
                content = notice.read_bytes()
                notice.write_text("No license metadata\n", encoding="utf-8")
                self.rejected("license metadata")
                notice.write_bytes(content)

    def test_animation_recording_required(self):
        self.recording.unlink()
        self.recording_notice.unlink()
        self.rejected("artwork source")

    def test_animation_source_notice_matches_export(self):
        self.animation_notice.write_text(
            f"{checks.COPYRIGHT}\n{checks.LICENSE_ID}\nSource: other.cast\n", encoding="utf-8")
        self.rejected("artwork source")

    def test_orphaned_demo_notices_rejected(self):
        for asset in (self.recording, self.animation):
            with self.subTest(asset=asset.name):
                content = asset.read_bytes()
                asset.unlink()
                self.rejected("Orphaned")
                asset.write_bytes(content)

    def test_directory_license_must_be_complete(self):
        (self.root / "docs/LICENSE").write_text("MIT\n", encoding="utf-8")
        self.rejected("directory license")

    def test_directory_license_must_exist(self):
        for directory in ("docs", "assets"):
            with self.subTest(directory=directory):
                license_file = self.root / directory / "LICENSE"
                original = license_file.read_bytes()
                license_file.unlink()
                self.rejected("directory license")
                license_file.write_bytes(original)

    def test_unreviewed_font_rejected(self):
        (self.root / "assets/img/downloaded.woff").write_bytes(b"font fixture")
        self.rejected("Unreviewed artwork file")

    def test_embedded_resource_rejected(self):
        self.svg.write_text(HEADER + '<svg xmlns="http://www.w3.org/2000/svg">'
                            '<image href="https://example.invalid/external.png"/></svg>\n',
                            encoding="utf-8")
        self.rejected("Unreviewed embedded or external")


    def test_skill_header_required_after_front_matter(self):
        self.skill.write_text(SKILL.replace(HEADER, ""), encoding="utf-8")
        self.rejected("license metadata")

    def test_skill_front_matter_must_end(self):
        self.skill.write_text("---\nname: demo\n" + HEADER, encoding="utf-8")
        self.rejected("Unterminated front matter")

    def test_skill_name_matches_folder(self):
        self.skill.write_text(SKILL.replace("name: demo", "name: other"), encoding="utf-8")
        self.rejected("skill name")

    def test_skill_description_required(self):
        self.skill.write_text(SKILL.replace("description: Read demo logs.\n", ""),
                              encoding="utf-8")
        self.rejected("skill name or description")

    def test_skill_link_stays_relative(self):
        self.skill_link.unlink()
        self.skill_link.symlink_to(self.skill.parent, target_is_directory=True)
        self.rejected("leaves the repository")

    def test_broken_skill_link_rejected(self):
        self.skill_link.unlink()
        self.skill_link.symlink_to("../../.claude/skills/missing", target_is_directory=True)
        self.rejected("Missing skill definition")


if __name__ == "__main__":
    unittest.main()
