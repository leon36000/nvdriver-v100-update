# SPDX-License-Identifier: MIT
"""Focused tests for portable-transfer Markdown link auditing."""

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from audit_transfer_document_links import (  # noqa: E402
    annotate_excluded_links,
    find_excluded_links,
)


class TransferDocumentLinkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "docs").mkdir()
        (self.root / "evidence").mkdir()
        (self.root / "docs/STATE.md").write_text(
            "[included](../evidence/receipt.json) "
            "[local log](../evidence/private.log) "
            "[web](https://example.test/report) [anchor](#state)\n"
            "```markdown\n[example](../evidence/example.json)\n```\n",
            encoding="utf-8",
        )
        (self.root / "evidence/receipt.json").write_text("{}\n", encoding="utf-8")
        self.tracked = {"docs/STATE.md", "evidence/receipt.json"}

    def test_finds_only_excluded_links_outside_fenced_code(self):
        result = find_excluded_links(self.root, self.tracked)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["target"], "evidence/private.log")
        self.assertEqual(result[0]["document"], "docs/STATE.md")

    def test_annotation_makes_excluded_artifact_reference_explicit(self):
        self.assertEqual(annotate_excluded_links(self.root, self.tracked), 1)
        text = (self.root / "docs/STATE.md").read_text(encoding="utf-8")
        self.assertIn(
            "local log (local-only artifact; excluded from GitLab transfer; "
            "source: `evidence/private.log`)",
            text,
        )
        self.assertEqual(find_excluded_links(self.root, self.tracked), [])


if __name__ == "__main__":
    unittest.main()
