# SPDX-License-Identifier: MIT
"""Mutation tests for the conditional R595 PMM tracker-wait finding."""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from tools.audit_r595_pmm_tracker_wait_context import (
    SOURCE_FILES,
    SOURCE_ROOT,
    analyze_sources,
    audit_sources,
)


class R595PmmTrackerWaitContextTests(unittest.TestCase):
    def _copy_sources(self) -> Path:
        temp = tempfile.TemporaryDirectory(prefix="r595-pmm-wait-context-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / "nvidia-uvm"
        root.mkdir()
        for name in SOURCE_FILES:
            shutil.copyfile(SOURCE_ROOT / name, root / name)
        return root

    def test_hash_pinned_candidate_reports_conditional_wait_risk(self) -> None:
        report = audit_sources()
        result = report["result"]

        self.assertEqual(report["qualification"]["level"], "analyzed-statically")
        self.assertFalse(report["qualification"]["module_loaded_or_installed"])
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])
        self.assertEqual(result["status"], "conditional-lock-held-wait-risk")
        self.assertEqual(result["failed_checks"], [])
        self.assertEqual(result["source_sites"]["pmm_gpu_free_safe_merge_line"], 717)
        self.assertEqual(result["source_sites"]["block_population_free_line"], 2928)

    def test_mutation_removing_oom_wait_falsifies_the_risk(self) -> None:
        root = self._copy_sources()
        tracker = root / "uvm_tracker.c"
        source = tracker.read_text()
        start = source.index("NV_STATUS uvm_tracker_add_tracker_safe(")
        end = source.index("\nbool uvm_tracker_is_entry_completed(", start)
        body = source[start:end].replace(
            "status = uvm_tracker_wait(src);", "status = NV_OK;", 1
        )
        source = source[:start] + body + source[end:]
        tracker.write_text(source)

        result = analyze_sources(root)
        self.assertFalse(result["checks"]["safe_merge_waits_on_source_only_after_no_memory"])
        self.assertEqual(result["status"], "unresolved")

    def test_mutation_releasing_root_lock_before_merge_falsifies_the_risk(self) -> None:
        root = self._copy_sources()
        pmm = root / "uvm_pmm_gpu.c"
        source = pmm.read_text()
        start = source.index("void uvm_pmm_gpu_free(")
        end = source.index("\nstatic NvU32 num_subchunks(", start)
        body = source[start:end]
        body = body.replace(
            "root_chunk_lock(pmm, root_chunk);\n\n        // Remove any completed entries",
            "// Lock moved outside the modeled wait path for mutation testing.\n\n        // Remove any completed entries",
            1,
        )
        source = source[:start] + body + source[end:]
        pmm.write_text(source)

        result = analyze_sources(root)
        self.assertFalse(result["checks"]["pmm_free_merges_under_root_lock"])
        self.assertEqual(result["status"], "unresolved")

    def test_mutation_removing_block_lock_assertion_downgrades_caller_evidence(self) -> None:
        root = self._copy_sources()
        va_block = root / "uvm_va_block.c"
        source = va_block.read_text()
        start = source.index("static NV_STATUS block_populate_gpu_chunk(")
        end = source.index("\n// Populate all chunks", start)
        body = source[start:end].replace("uvm_assert_mutex_locked(&block->lock);", "", 1)
        source = source[:start] + body + source[end:]
        va_block.write_text(source)

        result = analyze_sources(root)
        self.assertFalse(result["checks"]["block_population_cleanup_calls_pmm_free_under_block_lock"])
        self.assertEqual(result["status"], "unresolved")


if __name__ == "__main__":
    unittest.main()
