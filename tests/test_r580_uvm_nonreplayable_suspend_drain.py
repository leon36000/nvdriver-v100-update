# SPDX-License-Identifier: MIT
"""Apply and audit the R580 non-replayable-fault suspend patch."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import audit_uvm_pm_lifecycle as audit

SOURCE_ROOT = ROOT / "build/experiments/r580-uvm-clean-v3-20261021/source/kernel-open"
PATCH = ROOT / "patches/r580.178.04/uvm/0001-suspend-drain-non-replayable-faults.patch"


class R580NonReplayableSuspendDrainTests(unittest.TestCase):
    def test_patch_applies_cleanly_and_closes_the_source_ordering_gap(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-drain-test-") as directory:
            tree = Path(directory)
            for relative in audit.RELATIVE_FILES:
                destination = tree / "kernel-open" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = SOURCE_ROOT / relative
                if relative == "nvidia-uvm/uvm_global.c":
                    shutil.copy2(source, destination)
                else:
                    destination.symlink_to(source)

            applied = subprocess.run(
                ["patch", "--batch", "--forward", "-p1", "-i", str(PATCH)],
                cwd=tree, check=False, capture_output=True, text=True)
            self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
            self.assertNotIn("offset", applied.stdout.lower() + applied.stderr.lower())
            self.assertNotIn("fuzz", applied.stdout.lower() + applied.stderr.lower())

            report = audit.audit_tree(tree / "kernel-open", "r580-non-replayable-suspend-drain")
            facts = report["uvm_suspend_quiescence"]
            self.assertTrue(facts["rm_get_fault_batches_synchronously_serviced_under_service_lock"])
            self.assertTrue(facts[
                "suspend_calls_rm_get_fault_service_after_bottom_half_before_kill_queue_flush"])
            self.assertFalse(facts["suspend_queries_rm_pending_fault_status"])
            self.assertFalse(facts["suspend_rescans_pending_faults_before_queue_flush"])
            self.assertTrue(facts["rm_hardware_fault_buffer_flush_is_not_present"])


if __name__ == "__main__":
    unittest.main()
