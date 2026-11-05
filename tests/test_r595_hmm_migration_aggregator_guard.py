# SPDX-License-Identifier: MIT
"""Pin the outer R595 migration guard that must precede tracker aggregation."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PREIMAGE = ROOT / (
    "build/experiments/r595-hmm-isolated-cpu-fallback-v1-20261029/"
    "candidate/nvidia-uvm/uvm_migrate.c"
)
PATCH = ROOT / "patches/r595.99.02/0010-r595-hmm-migration-aggregate-guard.patch"
PREIMAGE_SHA256 = "d5c0e903f6795f6d786f68204a5855fd21d930ee85d4416d074f1d71927b2c56"


def _migration_body(source: str) -> str:
    start = source.index("NV_STATUS uvm_va_block_migrate_locked(")
    end = source.index("// Unmapping CPU pages", start)
    return source[start:end]


def _assert_guard(test: unittest.TestCase, source: str) -> None:
    body = _migration_body(source)
    guard = re.search(
        r"if \(uvm_va_block_is_hmm\(va_block\) &&\s*"
        r"uvm_push_isolated_gpu_execution_enabled\(\) &&\s*"
        r"UVM_ID_IS_GPU\(dest_id\) &&\s*"
        r"!uvm_hmm_must_use_sysmem\(va_block, va_block_context->hmm\.vma\)\)\s*"
        r"return NV_ERR_NOT_SUPPORTED;",
        body,
    )
    test.assertIsNotNone(guard, "isolated HMM GPU-residency rejection is missing")
    test.assertIn('#include "uvm_hmm.h"', source)
    guard_end = guard.end()
    test.assertLess(guard_end, body.index("uvm_hmm_va_block_migrate_locked("))
    test.assertLess(guard_end, body.index("if (out_tracker)"))
    test.assertIn("UVM_ASSERT(uvm_hmm_check_context_vma_is_valid", body[:guard.start()])


class R595HmmMigrationAggregatorGuardTests(unittest.TestCase):
    def _patched_source(self) -> str:
        self.assertTrue(PREIMAGE.is_file(), f"missing pinned migration source: {PREIMAGE}")
        self.assertTrue(PATCH.is_file(), f"missing migration-aggregate patch: {PATCH}")
        original = PREIMAGE.read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), PREIMAGE_SHA256)
        with tempfile.TemporaryDirectory(prefix="r595-hmm-migrate-aggregate-") as directory:
            root = Path(directory)
            target = root / "nvidia-uvm/uvm_migrate.c"
            target.parent.mkdir(parents=True)
            target.write_bytes(original)
            result = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotRegex(result.stdout, r"\b(?:offset|fuzz)\b")
            return target.read_text()

    def test_isolated_hmm_gpu_rejection_precedes_tracker_aggregation(self) -> None:
        _assert_guard(self, self._patched_source())

    def test_mutation_removing_aggregate_guard_fails(self) -> None:
        source = self._patched_source().replace(
            "    if (uvm_va_block_is_hmm(va_block) &&\n"
            "        uvm_push_isolated_gpu_execution_enabled() &&\n"
            "        UVM_ID_IS_GPU(dest_id) &&\n"
            "        !uvm_hmm_must_use_sysmem(va_block, va_block_context->hmm.vma))\n"
            "        return NV_ERR_NOT_SUPPORTED;\n",
            "",
            1,
        )
        with self.assertRaises((AssertionError, ValueError)):
            _assert_guard(self, source)

    def test_mutation_that_rejects_sysmem_fallback_fails(self) -> None:
        source = self._patched_source().replace(
            "        !uvm_hmm_must_use_sysmem(va_block, va_block_context->hmm.vma))",
            "        UVM_ID_IS_VALID(dest_id))",
            1,
        )
        with self.assertRaises((AssertionError, ValueError)):
            _assert_guard(self, source)


if __name__ == "__main__":
    unittest.main()
