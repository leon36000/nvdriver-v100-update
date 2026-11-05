# SPDX-License-Identifier: MIT
"""Pin and exercise NVIDIA's R595.112 large page-table allocation fix."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools import r595_large_page_table_host_harness as harness


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class R595LargePageTableBackportTests(unittest.TestCase):
    def test_backport_reproduces_the_pinned_upstream_nv_c_exactly(self):
        self.assertEqual(sha256(harness.R595_99), harness.R595_99_SHA256)
        self.assertEqual(sha256(harness.R595_112), harness.R595_112_SHA256)
        self.assertEqual(sha256(harness.R595_99_HEADER), harness.R595_99_HEADER_SHA256)
        self.assertEqual(sha256(harness.R595_112_HEADER), harness.R595_112_HEADER_SHA256)
        self.assertEqual(sha256(harness.R595_99_OS_INTERFACE),
                         harness.R595_99_OS_INTERFACE_SHA256)
        self.assertEqual(sha256(harness.R595_112_OS_INTERFACE),
                         harness.R595_112_OS_INTERFACE_SHA256)
        patch_text = harness.PATCH.read_text()
        with tempfile.TemporaryDirectory(prefix="r595-large-page-table-patch-") as tmp:
            temp_root = Path(tmp)
            source_map = (
                (harness.R595_99, "kernel-open/nvidia/nv.c"),
                (harness.R595_99_HEADER, "kernel-open/common/inc/nv-linux.h"),
                (harness.R595_99_OS_INTERFACE, "kernel-open/nvidia/os-interface.c"),
            )
            targets = {}
            for original, relative in source_map:
                target = temp_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, target)
                targets[relative] = target
            command = ["patch", "--batch", "--fuzz=0", "-p1"]
            dry = subprocess.run(command + ["--dry-run"], cwd=temp_root,
                                 input=patch_text, text=True,
                                 capture_output=True, check=False)
            self.assertEqual(dry.returncode, 0, dry.stdout + dry.stderr)
            self.assertNotRegex((dry.stdout + dry.stderr).lower(), r"\b(?:fuzz|offset)\b")
            applied = subprocess.run(command, cwd=temp_root, input=patch_text,
                                     text=True, capture_output=True, check=False)
            self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
            self.assertNotRegex((applied.stdout + applied.stderr).lower(),
                                r"\b(?:fuzz|offset)\b")
            self.assertEqual(targets["kernel-open/nvidia/nv.c"].read_bytes(),
                             harness.R595_112.read_bytes())
            upstream_header = harness.R595_112_HEADER.read_text()
            patched_header = targets["kernel-open/common/inc/nv-linux.h"].read_text()
            self.assertEqual(
                harness.extract_function(
                    patched_header, "nv_vmalloc(unsigned long size, gfp_t flags)"),
                harness.extract_function(
                    upstream_header, "nv_vmalloc(unsigned long size, gfp_t flags)"))
            upstream_os = harness.R595_112_OS_INTERFACE.read_text()
            patched_os = targets["kernel-open/nvidia/os-interface.c"].read_text()
            self.assertIn("*address = nv_vmalloc(alloc_size, GFP_KERNEL);", patched_os)
            self.assertIn("*address = nv_vmalloc(alloc_size, GFP_KERNEL);", upstream_os)

    def test_exact_production_functions_use_safe_allocator_pair_at_2gib(self):
        result = harness.run()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["qualification"],
                         "exact-patched-replay-source-host-cpu-execution")
        self.assertFalse(result["runtime_or_hardware_validated"])
        self.assertFalse(result["module_loaded_or_installed"])
        self.assertEqual(result["run_exit_code"], 0)
        self.assertEqual(result["output"], [
            "small_and_INT_MAX_boundary=pass",
            "oversized_vmalloc_zeroed_and_matching_vfree=pass",
            "overflow_count_bounds_alloc_failure_and_busy_free=pass",
        ])


if __name__ == "__main__":
    unittest.main()
