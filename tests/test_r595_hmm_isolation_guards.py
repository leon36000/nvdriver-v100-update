# SPDX-License-Identifier: MIT
"""Source contracts for fail-closed R595 HMM behavior in isolated mode.

The patch preserves CPU HMM faulting and the existing sysmem fallback while
refusing HMM GPU residency in isolated-provider mode. A worker-time check also
prevents foreign-provider tracker work from reaching the lock-held map/merge
path. These are static contracts, not runtime or hardware proof.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PREIMAGE = ROOT / (
    "build/experiments/r595-provider-id-validation-v1-20261029/"
    "candidate/nvidia-uvm/uvm_hmm.c"
)
PATCH = ROOT / "patches/r595.99.02/0009-r595-hmm-isolated-mode-cpu-fallback.patch"
PREIMAGE_SHA256 = "9fb7477ee9c9058493a99847f9395a22959c04ceed33f1120849ec3f71e38d04"


def _function_body(source: str, signature: str, next_signature: str) -> str:
    start = source.index(signature)
    end = source.index(next_signature, start)
    return source[start:end]


def _assert_guard_contract(test: unittest.TestCase, source: str) -> None:
    service = _function_body(
        source,
        "NV_STATUS uvm_hmm_va_block_service_locked(",
        "static NV_STATUS uvm_hmm_migrate_alloc_and_copy(",
    )
    cpu_fault = service.index("return hmm_block_cpu_fault_locked(")
    isolated_fault = service.index("if (uvm_push_isolated_gpu_execution_enabled())")
    reject_fault = service.index("return NV_ERR_NOT_SUPPORTED;", isolated_fault)
    gpu_population = service.index("status = uvm_va_block_populate_pages_gpu(")
    test.assertLess(cpu_fault, isolated_fault)
    test.assertLess(isolated_fault, reject_fault)
    test.assertLess(reject_fault, gpu_population)

    migrate = _function_body(
        source,
        "NV_STATUS uvm_hmm_va_block_migrate_locked(",
        "NV_STATUS uvm_hmm_migrate_ranges(",
    )
    sysmem_fallback = migrate.index("if (UVM_ID_IS_GPU(dest_id) && uvm_hmm_must_use_sysmem(")
    cpu_return = migrate.index("return hmm_make_resident_cpu(", sysmem_fallback)
    isolated_migration = migrate.index("if (uvm_push_isolated_gpu_execution_enabled() && UVM_ID_IS_GPU(dest_id))")
    reject_migration = migrate.index("return NV_ERR_NOT_SUPPORTED;", isolated_migration)
    gpu_population = migrate.index("uvm_va_block_populate_pages_gpu(")
    test.assertLess(sysmem_fallback, cpu_return)
    test.assertLess(cpu_return, isolated_migration)
    test.assertLess(isolated_migration, reject_migration)
    test.assertLess(reject_migration, gpu_population)

    eviction = _function_body(
        source,
        "void uvm_hmm_block_add_eviction_mappings(",
        "const uvm_va_policy_t *uvm_hmm_find_policy_end(",
    )
    provider_guard = eviction.index(
        "if (uvm_push_isolated_gpu_execution_enabled() &&\n"
        "                    uvm_tracker_has_other_providers(&va_block->tracker, gpu))"
    )
    reject_worker = eviction.index("status = NV_ERR_NOT_SUPPORTED;", provider_guard)
    map_call = eviction.index("status = uvm_va_block_add_mappings(")
    merge_call = eviction.index("uvm_tracker_add_tracker_safe(&local_tracker, &va_block->tracker);")
    unlock = eviction.index("uvm_mutex_unlock(&va_block->lock);")
    wait = eviction.index("uvm_tracker_wait_deinit(&local_tracker);")
    test.assertLess(provider_guard, reject_worker)
    test.assertLess(reject_worker, map_call)
    test.assertLess(map_call, merge_call)
    test.assertLess(merge_call, unlock)
    test.assertLess(unlock, wait)
    test.assertIn("if (status != NV_OK)\n            break;", eviction)


class R595HmmIsolationGuardTests(unittest.TestCase):
    def _patched_source(self) -> str:
        self.assertTrue(PREIMAGE.is_file(), f"missing pinned R595 UVM source: {PREIMAGE}")
        self.assertTrue(PATCH.is_file(), f"missing R595 HMM isolation patch: {PATCH}")
        original = PREIMAGE.read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), PREIMAGE_SHA256)

        with tempfile.TemporaryDirectory(prefix="r595-hmm-isolation-") as directory:
            root = Path(directory)
            target = root / "nvidia-uvm/uvm_hmm.c"
            target.parent.mkdir(parents=True)
            target.write_bytes(original)
            result = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotRegex(result.stdout, r"\b(?:offset|fuzz)\b")
            return target.read_text()

    def test_patch_preserves_cpu_and_sysmem_paths_and_guards_gpu_hmm_paths(self) -> None:
        _assert_guard_contract(self, self._patched_source())

    def test_mutation_removing_isolated_gpu_fault_guard_fails(self) -> None:
        source = self._patched_source().replace(
            "    if (uvm_push_isolated_gpu_execution_enabled())\n"
            "        return NV_ERR_NOT_SUPPORTED;\n",
            "",
            1,
        )
        with self.assertRaises((AssertionError, ValueError)):
            _assert_guard_contract(self, source)

    def test_mutation_removing_isolated_gpu_migration_guard_fails(self) -> None:
        source = self._patched_source().replace(
            "    if (uvm_push_isolated_gpu_execution_enabled() && UVM_ID_IS_GPU(dest_id))\n"
            "        return NV_ERR_NOT_SUPPORTED;\n",
            "",
            1,
        )
        with self.assertRaises((AssertionError, ValueError)):
            _assert_guard_contract(self, source)

    def test_mutation_removing_worker_provider_guard_fails(self) -> None:
        source = self._patched_source().replace(
            "                if (uvm_push_isolated_gpu_execution_enabled() &&\n"
            "                    uvm_tracker_has_other_providers(&va_block->tracker, gpu)) {\n"
            "                    status = NV_ERR_NOT_SUPPORTED;\n"
            "                    break;\n"
            "                }\n",
            "",
            1,
        )
        with self.assertRaises((AssertionError, ValueError)):
            _assert_guard_contract(self, source)


if __name__ == "__main__":
    unittest.main()
