#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU-only safety contracts for the compile-only V100 private-provider runner."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/run_pc3_v100_private_open580_build.py"
RUN_ID = "a" * 32
BUNDLE_SHA = "b" * 64


def load_tool():
    spec = importlib.util.spec_from_file_location("run_pc3_v100_private_open580_build", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_result(tool):
    payload = b"compile report\n"
    packed = io.BytesIO()
    with tarfile.open(fileobj=packed, mode="w:gz") as archive:
        info = tarfile.TarInfo("evidence/compile-report.json")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    packed_bytes = packed.getvalue()
    return {
        "schema": "nvidia-hybrid-pc3-v100-private-open580-build-result-v1",
        "status": "completed",
        "run_id": RUN_ID,
        "bundle_sha256": BUNDLE_SHA,
        "hostname": "pc3-v100",
        "kernel_release": "6.8.0-147-generic",
        "builder_exit_code": 0,
        "builder_stdout_sha256": "c" * 64,
        "builder_stderr_sha256": "d" * 64,
        "builder_output_bytes": 20,
        "builder_report": {"kernel_release": "6.8.0-147-generic",
                            "qualification": "compiled-native-private-open580-provider-only"},
        "builder_report_sha256": "e" * 64,
        "artifacts": [{"path": "evidence/compile-report.json", "bytes": len(payload),
                       "sha256": hashlib.sha256(payload).hexdigest()}],
        "artifact_archive_bytes": len(packed_bytes),
        "artifact_archive_sha256": hashlib.sha256(packed_bytes).hexdigest(),
        "artifact_archive_base64": base64.b64encode(packed_bytes).decode("ascii"),
        "module_installed": False,
        "module_loaded": False,
        "gpu_accessed": False,
        "cuda_execution_tested": False,
        "scratch_removed": True,
        "staged_bundle_removed": True,
    }


class PrivateOpen580RunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def validate(self, report):
        return self.tool.validate_guest_result(json.dumps(report).encode("utf-8"), RUN_ID, BUNDLE_SHA)

    def test_runner_exists(self):
        self.assertTrue(TOOL_PATH.is_file())

    def test_embedded_guest_declares_its_builder_output_bound(self):
        self.assertRegex(self.tool.GUEST_BUILD_SCRIPT, r"^import .*\bio,?json\b")
        self.assertRegex(self.tool.GUEST_BUILD_SCRIPT, r"(?m)^MAX_MAKE_OUTPUT_BYTES=16777216$")
        self.assertIn("len(stdout)+len(stderr)>MAX_MAKE_OUTPUT_BYTES", self.tool.GUEST_BUILD_SCRIPT)
        self.assertIn('"PATH":"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"',
                      self.tool.GUEST_BUILD_SCRIPT)
        self.assertGreaterEqual(self.tool.MAX_CAPTURED_ARTIFACT_BYTES, 34 * 1024 * 1024)
        self.assertIn('"hybrid580_open.ko"', self.tool.GUEST_BUILD_SCRIPT)
        self.assertNotIn('"nvidia.ko"', self.tool.GUEST_BUILD_SCRIPT)
        self.assertIn('"kernel-open","conftest")', self.tool.GUEST_BUILD_SCRIPT)
        self.assertIn('if name.endswith(".h")', self.tool.GUEST_BUILD_SCRIPT)

    def test_pc3_target_and_host_key_alias_are_fixed(self):
        self.tool.validate_pc3_transport_identity("pc3@pc3", "pc3")
        with self.assertRaisesRegex(ValueError, "pinned PC3"):
            self.tool.validate_pc3_transport_identity("attacker@elsewhere", "pc3")
        with self.assertRaisesRegex(ValueError, "pinned PC3"):
            self.tool.validate_pc3_transport_identity("pc3@pc3", "attacker")

    def test_known_hosts_entry_fingerprint_is_derived_and_pinnable(self):
        entry = (
            "# Host pc3 found: line 13\n"
            "|1|hash|salt ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAILxUWgtVV2wrWN6M4xKut3yY3xmEyNFVbpQzsh8BWMv+\n"
        )
        self.assertEqual(
            self.tool.known_hosts_fingerprints(entry),
            {"SHA256:04QMvstMuydvbUvYWq7HguzzjN1RzwG8zoqL4olbs5g"},
        )

    def test_root_transport_envelope_requires_verified_pc3_stage_cleanup(self):
        envelope = {
            "schema": "nvidia-hybrid-pc3-v100-private-open580-transport-v1",
            "guest_ssh_exit_code": 0,
            "guest_stdout_b64": "e30=",
            "guest_stderr_sha256": "c" * 64,
            "hostkey_fingerprint": self.tool.GUEST_HOSTKEY_FINGERPRINT,
            "pc3_bundle_removed": True,
        }
        accepted = self.tool.validate_pc3_root_envelope(envelope)
        self.assertTrue(accepted["pc3_bundle_removed"])
        envelope["pc3_bundle_removed"] = False
        with self.assertRaisesRegex(ValueError, "stage cleanup"):
            self.tool.validate_pc3_root_envelope(envelope)

    def test_root_transport_pins_known_hosts_file_to_root_owner(self):
        self.assertIn("known_st.st_uid!=0", self.tool.PC3_ROOT_RUN_SCRIPT)

    def test_accepts_pinned_compile_only_result_and_archive(self):
        report = self.validate(valid_result(self.tool))
        self.assertEqual(report["_artifact_archive_bytes"],
                         base64.b64decode(report["artifact_archive_base64"]))

    def test_rejects_result_that_claims_module_was_loaded(self):
        report = valid_result(self.tool)
        report["module_loaded"] = True
        with self.assertRaisesRegex(ValueError, "compile-only"):
            self.validate(report)

    def test_accepts_structured_early_guest_failure_with_bounded_detail(self):
        report = valid_result(self.tool)
        report["status"] = "failed"
        report["builder_report"] = None
        report["builder_report_sha256"] = None
        report["error"] = "ValueError: pinned target mismatch"
        accepted = self.validate(report)
        self.assertEqual(accepted["error"], "ValueError: pinned target mismatch")

    def test_rejects_failure_detail_on_completed_guest_result(self):
        report = valid_result(self.tool)
        report["error"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "fields differ"):
            self.validate(report)

    def test_rejects_unbounded_guest_failure_detail(self):
        report = valid_result(self.tool)
        report["status"] = "failed"
        report["builder_report"] = None
        report["builder_report_sha256"] = None
        report["error"] = "x" * 201
        with self.assertRaisesRegex(ValueError, "failure detail"):
            self.validate(report)

    def test_rejects_wrong_kernel_even_when_compile_claim_succeeds(self):
        report = valid_result(self.tool)
        report["kernel_release"] = "7.0.0-38-generic"
        with self.assertRaisesRegex(ValueError, "pinned V100 target"):
            self.validate(report)

    def test_rejects_guest_bundle_digest_that_differs_from_staged_input(self):
        report = valid_result(self.tool)
        report["bundle_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "bundle SHA-256"):
            self.validate(report)

    def test_rejects_artifact_path_escape(self):
        report = valid_result(self.tool)
        report["artifacts"][0]["path"] = "evidence/../../outside"
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.validate(report)

    def test_rejects_archive_hash_mismatch(self):
        report = valid_result(self.tool)
        report["artifact_archive_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest or size mismatch"):
            self.validate(report)


if __name__ == "__main__":
    unittest.main()
