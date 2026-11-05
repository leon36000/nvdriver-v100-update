#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contracts for the R595 mixed-provider UVM semaphore-registration audit."""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from tools.audit_r595_cross_provider_semaphore_init import (
    DEFAULT_FRONTEND_ROUTE,
    DEFAULT_R595_UVM,
    audit_sources,
)


class R595CrossProviderSemaphoreInitTests(unittest.TestCase):
    def test_audit_reports_the_conditional_second_provider_blocker(self):
        report = audit_sources(DEFAULT_R595_UVM, DEFAULT_FRONTEND_ROUTE)

        self.assertEqual(
            report["result"],
            "conditional_cross_provider_gpu_registration_blocker",
        )
        self.assertTrue(report["claims"]["first_gpu_eagerly_allocates_sysmem_semaphore_pages"])
        self.assertTrue(report["claims"]["second_gpu_maps_existing_pool_before_channel_manager"])
        self.assertTrue(report["claims"]["provider_mismatch_stops_before_backend_dispatch"])
        self.assertFalse(report["runtime_or_hardware_validated"])

    def test_audit_rejects_modified_source_before_classifying(self):
        with tempfile.TemporaryDirectory(prefix="r595-cross-provider-source-") as temp:
            root = Path(temp)
            shutil.copytree(DEFAULT_R595_UVM, root / "uvm")
            target = root / "uvm" / "uvm_rm_mem.c"
            target.write_bytes(target.read_bytes() + b"\n/* altered */\n")

            with self.assertRaisesRegex(ValueError, "source hash mismatch"):
                audit_sources(root / "uvm", DEFAULT_FRONTEND_ROUTE)


if __name__ == "__main__":
    unittest.main()
