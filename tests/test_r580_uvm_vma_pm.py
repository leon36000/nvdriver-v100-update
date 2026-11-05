# SPDX-License-Identifier: MIT
"""Regression checks for the pinned R580 UVM VMA/PM source audit."""
import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "r580_uvm_vma_pm_audit", ROOT / "tools/audit_r580_uvm_vma_pm.py")
AUDIT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AUDIT)

OPEN_ROOT = ROOT / "build/experiments/r580-uvm-clean-v3-20261021/source/kernel-open"
PROPRIETARY_ROOT = ROOT / ".cache/vendor-proprietary/r580.178.04-ubuntu/usr/src/nvidia-580.178.04"


def copy_audit_inputs(source: Path, destination: Path) -> None:
    for relative in AUDIT.RELATIVE_FILES:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)


class R580UvmVmaPmTests(unittest.TestCase):
    def test_open_and_proprietary_sources_agree_on_vma_pm_contract(self):
        report = AUDIT.audit_tree(OPEN_ROOT, "open")
        legacy = AUDIT.audit_tree(PROPRIETARY_ROOT, "proprietary")
        self.assertFalse(report["managed_vma"]["open_close_take_global_pm_lock"])
        self.assertTrue(report["managed_vma"]["open_uses_va_space_write_lock"])
        self.assertTrue(report["managed_vma"]["close_uses_va_space_write_lock"])
        self.assertTrue(report["managed_vma"]["fault_pm_trylock_precedes_va_read_lock"])
        self.assertTrue(report["uvm_suspend"]["locks_all_va_spaces_for_write"])
        self.assertTrue(report["nv_vma_start_write"]["protects_kernel_vma_writer_sequence"])
        self.assertFalse(report["entry_wrapper"]["acquires_global_pm_lock"])
        for field in ("managed_vma", "special_vmas", "uvm_mmap", "uvm_suspend",
                      "nv_vma_start_write", "entry_wrapper"):
            left, right = dict(report[field]), dict(legacy[field])
            left.pop("source_lines", None)
            right.pop("source_lines", None)
            left.pop("source_line", None)
            right.pop("source_line", None)
            self.assertEqual(left, right)

    def test_rejects_managed_fault_without_pm_trylock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_audit_inputs(OPEN_ROOT, root)
            source = root / "nvidia-uvm/uvm_va_space.c"
            source.write_text(source.read_text().replace(
                "uvm_down_read_trylock_no_tracking(&g_uvm_global.pm.lock)",
                "uvm_down_read(&g_uvm_global.pm.lock)", 1))
            with self.assertRaisesRegex(ValueError, "managed CPU fault"):
                AUDIT.audit_tree(root, "mutated-fault")

    def test_rejects_uvm_suspend_without_va_space_exclusion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_audit_inputs(OPEN_ROOT, root)
            source = root / "nvidia-uvm/uvm_global.c"
            source.write_text(source.read_text().replace("uvm_va_space_down_write(va_space);", "", 1))
            with self.assertRaisesRegex(ValueError, "every VA-space write lock"):
                AUDIT.audit_tree(root, "mutated-suspend")

    def test_rejects_vma_flag_fallback_without_vma_writer_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_audit_inputs(OPEN_ROOT, root)
            source = root / "common/inc/nv-mm.h"
            source.write_text(source.read_text().replace("nv_vma_start_write(vma);", "", 1))
            with self.assertRaisesRegex(ValueError, "compatibility wrapper"):
                AUDIT.audit_tree(root, "mutated-vma-writer")


if __name__ == "__main__":
    unittest.main()
