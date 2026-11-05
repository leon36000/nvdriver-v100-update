from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.summarize_ci_security_reports import main, summarize_reports


class CiSecurityReportSummaryTests(unittest.TestCase):
    @staticmethod
    def _write_reports(root: Path) -> None:
        (root / "gitleaks-report.json").write_text(json.dumps([
            {
                "RuleID": "SECRET_RULE_MARKER",
                "File": "/private/path/API_KEY_FILENAME_MARKER.py",
                "StartLine": 5,
                "Secret": "GITLEAKS_VALUE_MARKER",
                "Match": "GITLEAKS_MATCH_MARKER",
            },
            {
                "RuleID": "SECRET_RULE_MARKER",
                "File": "/private/path/API_KEY_FILENAME_MARKER.py",
                "StartLine": 5,
                "Secret": "SECOND_GITLEAKS_VALUE_MARKER",
            },
            {
                "RuleID": "SECRET_RULE_MARKER",
                "File": "/private/path/API_KEY_FILENAME_MARKER.py",
                "Secret": "THIRD_GITLEAKS_VALUE_MARKER",
            },
        ]), encoding="utf-8")
        (root / "semgrep-report.json").write_text(json.dumps({
            "results": [{
                "check_id": "SEMGREP_RULE_MARKER",
                "path": "/private/SEMGREP_PATH_MARKER.py",
                "start": {"line": 22},
                "extra": {
                    "severity": "ERROR",
                    "message": "SEMGREP_MESSAGE_MARKER",
                },
            }],
            "errors": [],
            "paths": {
                "scanned": ["/private/SCANNED_PATH_MARKER.py"],
                "skipped": [],
            },
        }), encoding="utf-8")
        (root / "trivy-report.json").write_text(json.dumps({
            "SchemaVersion": 2,
            "Results": [{
                "Target": "/private/TRIVY_TARGET_MARKER.json",
                "Misconfigurations": [],
                "Vulnerabilities": [{
                    "VulnerabilityID": "TRIVY_RULE_MARKER",
                    "Severity": "HIGH",
                    "CauseMetadata": {"StartLine": 8},
                    "Title": "TRIVY_TITLE_MARKER",
                }],
                "Secrets": [],
            }],
        }), encoding="utf-8")

    def test_summary_omits_untrusted_values_paths_and_raw_report_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_reports(root)
            result = summarize_reports(root)
            rendered = json.dumps(result, sort_keys=True)

        self.assertEqual(result["status"], "reports_complete")
        self.assertEqual(result["reports"]["gitleaks"]["finding_count"], 3)
        self.assertEqual(result["reports"]["semgrep"]["finding_count"], 1)
        self.assertEqual(result["reports"]["trivy"]["finding_count"], 1)
        self.assertFalse(result["raw_finding_values_retained"])
        self.assertFalse(result["scanner_identifiers_retained"])
        self.assertFalse(result["file_paths_retained"])
        self.assertFalse(result["scanner_completion_verified"])
        self.assertEqual(
            result["status_scope"],
            "artifact_presence_schema_and_scanner_error_count",
        )
        self.assertEqual(result["scanner_error_count"], 0)
        for marker in (
            "SECRET_RULE_MARKER",
            "API_KEY_FILENAME_MARKER",
            "GITLEAKS_VALUE_MARKER",
            "GITLEAKS_MATCH_MARKER",
            "SEMGREP_RULE_MARKER",
            "SEMGREP_PATH_MARKER",
            "SEMGREP_MESSAGE_MARKER",
            "SCANNED_PATH_MARKER",
            "TRIVY_TARGET_MARKER",
            "TRIVY_RULE_MARKER",
            "TRIVY_TITLE_MARKER",
            "/private/path",
        ):
            self.assertNotIn(marker, rendered)
        self.assertNotIn("\"sha256\"", rendered)

        gitleaks_group = result["reports"]["gitleaks"]["top_groups"][0]
        self.assertEqual(gitleaks_group["start_line"], 5)
        self.assertEqual(gitleaks_group["count"], 2)
        self.assertRegex(gitleaks_group["group_id"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            result["reports"]["semgrep"]["top_groups"][0]["severity"], "ERROR")
        self.assertEqual(
            result["reports"]["trivy"]["top_groups"][0]["severity"], "HIGH")
        self.assertEqual(result["reports"]["trivy"]["top_groups"][0]["start_line"], 8)

        with tempfile.TemporaryDirectory() as temporary:
            second = Path(temporary)
            self._write_reports(second)
            second_result = summarize_reports(second)
        self.assertNotEqual(
            gitleaks_group["group_id"],
            second_result["reports"]["gitleaks"]["top_groups"][0]["group_id"],
        )

    def test_empty_but_well_formed_scanner_reports_are_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "gitleaks-report.json").write_text("[]", encoding="utf-8")
            (root / "semgrep-report.json").write_text(
                '{"results": [], "errors": [], "paths": {"scanned": [], "skipped": []}}',
                encoding="utf-8")
            (root / "trivy-report.json").write_text(
                '{"SchemaVersion": 2, "Results": []}', encoding="utf-8")
            result = summarize_reports(root)
        self.assertEqual(result["status"], "reports_complete")
        self.assertEqual(
            [result["reports"][name]["finding_count"]
             for name in ("gitleaks", "semgrep", "trivy")],
            [0, 0, 0],
        )

    def test_trivy_empty_results_may_be_omitted_from_versioned_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "gitleaks-report.json").write_text("[]", encoding="utf-8")
            (root / "semgrep-report.json").write_text(
                '{"results": [], "errors": [], "paths": {"scanned": [], "skipped": []}}',
                encoding="utf-8")
            (root / "trivy-report.json").write_text(json.dumps({
                "SchemaVersion": 2,
                "Trivy": {"Version": "0.76.1"},
                "CreatedAt": "2026-11-05T04:00:35Z",
                "ArtifactName": ".",
                "ArtifactType": "filesystem",
            }), encoding="utf-8")
            result = summarize_reports(root)

        self.assertEqual(result["status"], "reports_complete")
        self.assertEqual(result["reports"]["trivy"]["finding_count"], 0)

    def test_missing_reports_are_partial_and_cli_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = summarize_reports(root)
            output = io.StringIO()
            with patch("sys.argv", ["summarize", "--root", str(root)]), \
                    redirect_stdout(output):
                exit_code = main()
        self.assertEqual(result["status"], "reports_partial")
        self.assertEqual(set(result["missing_reports"]), {"gitleaks", "semgrep", "trivy"})
        self.assertIsNone(result["reports"]["gitleaks"]["finding_count"])
        self.assertEqual(exit_code, 2)
        self.assertIn('"status": "reports_partial"', output.getvalue())

    def test_semgrep_errors_are_counted_safely_and_keep_cli_failing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_reports(root)
            (root / "semgrep-report.json").write_text(json.dumps({
                "results": [],
                "errors": [
                    {
                        "type": "TimeoutError",
                        "path": "/private/TIMEOUT_PATH_MARKER.py",
                        "message": "TIMEOUT_SECRET_MARKER",
                    },
                    {
                        "code": "UNTRUSTED_SCANNER_CODE_MARKER",
                        "message": "SECOND_SCANNER_SECRET_MARKER",
                    },
                    "THIRD_SCANNER_SECRET_MARKER",
                ],
                "paths": {"scanned": [], "skipped": []},
            }), encoding="utf-8")
            output_path = root / "safe-summary.json"
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch("sys.argv", [
                    "summarize", "--root", str(root), "--output", str(output_path)
            ]), redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main()
            result = json.loads(output_path.read_text(encoding="utf-8"))
            rendered = stdout.getvalue() + output_path.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 2)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(result["status"], "reports_with_scanner_errors")
        self.assertEqual(result["scanner_error_count"], 3)
        semgrep = result["reports"]["semgrep"]
        self.assertEqual(semgrep["scanner_error_count"], 3)
        self.assertEqual(semgrep["scanner_error_categories"], {"other": 2, "timeout": 1})
        self.assertFalse(result["scanner_completion_verified"])
        for marker in (
            "TIMEOUT_PATH_MARKER",
            "TIMEOUT_SECRET_MARKER",
            "UNTRUSTED_SCANNER_CODE_MARKER",
            "SECOND_SCANNER_SECRET_MARKER",
            "THIRD_SCANNER_SECRET_MARKER",
        ):
            self.assertNotIn(marker, rendered)

    def test_invalid_trivy_report_writes_safe_summary_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "gitleaks-report.json").write_text("[]", encoding="utf-8")
            (root / "semgrep-report.json").write_text(
                '{"results": [], "errors": [], "paths": {"scanned": [], "skipped": []}}',
                encoding="utf-8")
            (root / "trivy-report.json").write_text(json.dumps({
                "SchemaVersion": "SCHEMA_VALUE_MARKER",
                "Results": False,
                "private": "REPORT_VALUE_MARKER",
            }), encoding="utf-8")
            output_path = root / "safe-summary.json"
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch("sys.argv", [
                    "summarize", "--root", str(root), "--output", str(output_path)
            ]), redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main()
            artifact = output_path.read_text(encoding="utf-8")
            result = json.loads(artifact)

        self.assertEqual(exit_code, 2)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(result["status"], "reports_invalid")
        self.assertEqual(result["invalid_reports"], ["trivy"])
        self.assertEqual(
            result["reports"]["trivy"]["schema_observation"],
            {"schema_version_type": "string", "results_type": "boolean"},
        )
        self.assertIsNone(result["reports"]["trivy"]["finding_count"])
        self.assertNotIn("SCHEMA_VALUE_MARKER", artifact)
        self.assertNotIn("REPORT_VALUE_MARKER", artifact)
        self.assertEqual(stdout.getvalue(), artifact)

    def test_invalid_or_incomplete_report_shapes_fail_closed(self):
        cases = (
            ("gitleaks-report.json", '{"findings": []}', "Gitleaks report"),
            ("semgrep-report.json", '{"results": [], "errors": false}', "Semgrep report"),
            (
                "semgrep-report.json",
                '{"results": [], "paths": {"scanned": []}}',
                "Semgrep report errors field",
            ),
            (
                "semgrep-report.json",
                '{"results": [], "errors": [], "paths": {"scanned": false}}',
                "Semgrep report must contain scanned paths",
            ),
            (
                "semgrep-report.json",
                (
                    '{"results": [], "errors": [], "paths": {"scanned": [], '
                    '"skipped": [{"path": "x"}]}}'
                ),
                "Semgrep report contains malformed skipped paths",
            ),
            ("trivy-report.json", "{}", "Trivy report must use schema version 2"),
            (
                "trivy-report.json",
                '{"SchemaVersion": 2, "Results": null}',
                "Trivy report Results field must be an array",
            ),
            (
                "trivy-report.json",
                '{"SchemaVersion": 2, "Results": false}',
                "Trivy report must use schema version 2",
            ),
            (
                "trivy-report.json",
                '{"SchemaVersion": 2, "Results": [{"Target": "x", "Secrets": false}]}',
                "Trivy Secrets must be an array",
            ),
            (
                "trivy-report.json",
                '{"SchemaVersion": 1, "Results": []}',
                "Trivy report must use schema version 2",
            ),
        )
        for filename, content, expected in cases:
            with self.subTest(filename=filename, expected=expected), \
                    tempfile.TemporaryDirectory() as temporary:
                Path(temporary, filename).write_text(content, encoding="utf-8")
                result = summarize_reports(Path(temporary))
                report_name = filename.removesuffix("-report.json")
                self.assertEqual(result["status"], "reports_invalid")
                self.assertEqual(result["invalid_reports"], [report_name])
                self.assertEqual(
                    result["reports"][report_name]["status"], "invalid_schema")
                self.assertIsNone(result["reports"][report_name]["finding_count"])

    def test_cli_suppresses_filesystem_error_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "gitleaks-report.json").write_text("[]", encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch("sys.argv", ["summarize", "--root", str(root)]), \
                    patch.object(Path, "read_bytes", side_effect=OSError("PRIVATE_PATH_MARKER")), \
                    redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main()
        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("PRIVATE_PATH_MARKER", stderr.getvalue())
        self.assertIn("details suppressed", stderr.getvalue())

    def test_cli_writes_safe_schema_error_without_scanner_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "gitleaks-report.json").write_text(
                '{"finding": "PRIVATE_CONTENT_MARKER"}', encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch("sys.argv", ["summarize", "--root", str(root)]), \
                    redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main()
        self.assertEqual(exit_code, 2)
        self.assertEqual(stderr.getvalue(), "")
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["status"], "reports_invalid")
        self.assertEqual(result["invalid_reports"], ["gitleaks"])
        self.assertNotIn("PRIVATE_CONTENT_MARKER", stdout.getvalue())
        self.assertNotIn(str(root), stdout.getvalue())

    def test_deeply_nested_json_is_classified_without_recursion_trace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "gitleaks-report.json").write_text("[]", encoding="utf-8")
            with patch(
                "tools.summarize_ci_security_reports.json.loads",
                side_effect=RecursionError("PRIVATE_CONTENT_MARKER"),
            ):
                result = summarize_reports(root)
        self.assertEqual(result["status"], "reports_invalid")
        self.assertEqual(result["invalid_reports"], ["gitleaks"])
        self.assertEqual(result["reports"]["gitleaks"]["status"], "invalid_json")


if __name__ == "__main__":
    unittest.main()
