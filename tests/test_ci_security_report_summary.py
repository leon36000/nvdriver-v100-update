import json
from pathlib import Path
import tempfile
import unittest

from tools.summarize_ci_security_reports import summarize_reports


class CiSecurityReportSummaryTests(unittest.TestCase):
    def test_summarizes_scanner_reports_without_secrets_or_full_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "gitleaks-report.json").write_text(json.dumps([
                {"RuleID": "aws-access-key", "File": "/build/private/a.py",
                 "Secret": "redacted-value-alpha", "Match": "redacted-value-alpha"},
                {"RuleID": "aws-access-key", "File": "/build/private/a.py",
                 "Secret": "redacted-value-beta"},
            ]), encoding="utf-8")
            (root / "semgrep-report.json").write_text(json.dumps({"results": [
                {"check_id": "python.lang.security.audit", "path": "/build/private/b.py",
                 "extra": {"severity": "ERROR", "message": "internal-message-alpha"}},
            ]}), encoding="utf-8")
            (root / "trivy-report.json").write_text(json.dumps({"Results": [
                {"Target": "/build/private/image.json", "Misconfigurations": [
                    {"ID": "AVD-TEST-0001", "Severity": "HIGH",
                     "Title": "internal-title-alpha"}
                ]}
            ]}), encoding="utf-8")

            result = summarize_reports(root)
            rendered = json.dumps(result, sort_keys=True)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["reports"]["gitleaks"]["finding_count"], 2)
        self.assertEqual(result["reports"]["semgrep"]["finding_count"], 1)
        self.assertEqual(result["reports"]["trivy"]["finding_count"], 1)
        self.assertFalse(result["raw_finding_values_retained"])
        self.assertFalse(result["full_paths_retained"])
        self.assertNotIn("redacted-value", rendered)
        self.assertNotIn("internal-", rendered)
        self.assertNotIn("/build/private", rendered)
        self.assertEqual(
            result["reports"]["gitleaks"]["top_groups"][0]["file"], "a.py")

    def test_missing_reports_are_reported_as_partial_not_clean(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = summarize_reports(Path(temporary))
        self.assertEqual(result["status"], "partial")
        self.assertEqual(set(result["missing_reports"]), {"gitleaks", "semgrep", "trivy"})
        self.assertIsNone(result["reports"]["gitleaks"]["finding_count"])

    def test_malformed_report_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary, "semgrep-report.json").write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Semgrep report"):
                summarize_reports(Path(temporary))


if __name__ == "__main__":
    unittest.main()
