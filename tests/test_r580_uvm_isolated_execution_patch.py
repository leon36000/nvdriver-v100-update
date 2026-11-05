# SPDX-License-Identifier: MIT
"""Patch-application contract for isolated same-process GPU execution mode."""
from pathlib import Path
import importlib
import shutil
import subprocess
import tempfile
import unittest

from tools.audit_hybrid_uvm_abi import c_function_definition

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches/r580.178.04/uvm/0002-hybrid-isolated-gpu-execution.patch"
SOURCE_FILES = (
    "nvidia-uvm/uvm_gpu.c",
    "nvidia-uvm/uvm_gpu_semaphore.c",
    "nvidia-uvm/uvm_push.c",
    "nvidia-uvm/uvm_migrate_pageable.c",
    "nvidia-uvm/uvm_channel_test.c",
)


class R580UvmIsolatedExecutionPatchTests(unittest.TestCase):
    def _patch_source_tree(self, root, audit):
        self.assertTrue(PATCH.is_file(), "the isolated-execution source patch is missing")
        patch_binary = shutil.which("patch")
        self.assertIsNotNone(patch_binary, "GNU patch is required for the source-overlay contract")

        for relative in SOURCE_FILES:
            source = audit.SOURCE_ROOT / relative
            expected_label = relative.rsplit("/", 1)[-1]
            expected_hash = audit.EXPECTED_SOURCE_SHA256[expected_label]
            self.assertEqual(audit.sha256_file(source), expected_hash)
            target = root / "kernel-open" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

        result = subprocess.run(
            [patch_binary, "--batch", "--fuzz=0", "--forward", "-p1", "-i", str(PATCH)],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_patch_applies_exactly_and_gates_only_cross_gpu_semaphore_paths(self):
        audit = importlib.import_module("tools.audit_uvm_owner_isolation_architecture")

        with tempfile.TemporaryDirectory(prefix="r580-uvm-isolation-") as temporary:
            root = Path(temporary)
            self._patch_source_tree(root, audit)

            push = (root / "kernel-open/nvidia-uvm/uvm_push.c").read_text()
            self.assertIn("static bool uvm_hybrid_isolated_gpu_execution = false;", push)
            self.assertIn("module_param(uvm_hybrid_isolated_gpu_execution, bool, 0444);", push)
            self.assertIn(
                "return !g_uvm_global.conf_computing_enabled && !uvm_hybrid_isolated_gpu_execution;",
                push,
            )

            gpu = (root / "kernel-open/nvidia-uvm/uvm_gpu.c").read_text()
            self.assertIn(
                "if (!uvm_push_allow_dependencies_across_gpus())\n        return NV_OK;",
                gpu,
            )
            self.assertIn(
                "if (g_uvm_global.conf_computing_enabled || uvm_push_allow_dependencies_across_gpus()) {",
                gpu,
            )

            semaphore = (root / "kernel-open/nvidia-uvm/uvm_gpu_semaphore.c").read_text()
            self.assertIn(
                "if (!g_uvm_global.conf_computing_enabled &&\n            !uvm_push_allow_dependencies_across_gpus())\n            return uvm_rm_mem_alloc_and_map_cpu(",
                semaphore,
            )
            self.assertIn("return uvm_rm_mem_alloc_and_map_all(", semaphore)

            migrate = (root / "kernel-open/nvidia-uvm/uvm_migrate_pageable.c").read_text()
            wait = migrate.index("uvm_tracker_wait_for_other_gpus(&zero_tracker, copying_gpu)")
            copy_push = migrate.index("migrate_vma_copy_begin_push(va_space, copying_gpu")
            acquire = migrate.index("uvm_push_acquire_tracker(&push, &zero_tracker)")
            self.assertLess(wait, copy_push)
            self.assertLess(copy_push, acquire)
            self.assertIn(
                "if (!uvm_push_allow_dependencies_across_gpus()) {\n"
                "        status = uvm_tracker_wait_for_other_gpus(&zero_tracker, copying_gpu);\n"
                "        if (status != NV_OK) {\n"
                "            uvm_tracker_wait_deinit(&zero_tracker);\n"
                "            return status;\n"
                "        }\n"
                "    }",
                migrate,
            )

            channel_test = (root / "kernel-open/nvidia-uvm/uvm_channel_test.c").read_text()
            guarded_acquire = (
                "if ((random_stream->push.gpu == gpu) || uvm_push_allow_dependencies_across_gpus()) {\n"
                "                    uvm_push_acquire_tracker(&stream->push, &random_stream->tracker);"
            )
            self.assertIn(guarded_acquire, channel_test)

    def test_isolated_mode_prevents_cross_provider_semaphore_duplication(self):
        audit = importlib.import_module("tools.audit_uvm_owner_isolation_architecture")

        with tempfile.TemporaryDirectory(prefix="r580-uvm-admission-") as temporary:
            root = Path(temporary)
            self._patch_source_tree(root, audit)
            uvm_root = root / "kernel-open/nvidia-uvm"

            init_pools = c_function_definition(uvm_root / "uvm_gpu.c", "init_semaphore_pools")
            cc_secure_pool = init_pools.index("if (g_uvm_global.conf_computing_enabled)")
            isolated_return = init_pools.index("if (!uvm_push_allow_dependencies_across_gpus())")
            mapping_loop = init_pools.index("for_each_gpu(other_gpu)")
            cross_provider_dup_call = init_pools.index(
                "uvm_gpu_semaphore_pool_map_gpu(other_gpu->semaphore_pool, gpu)"
            )
            self.assertLess(cc_secure_pool, isolated_return)
            self.assertLess(isolated_return, mapping_loop)
            self.assertLess(mapping_loop, cross_provider_dup_call)

            page_allocation = c_function_definition(
                uvm_root / "uvm_gpu_semaphore.c", "pool_page_alloc_buffers"
            )
            isolated_cpu_map = page_allocation.index("uvm_rm_mem_alloc_and_map_cpu(")
            default_all_gpu_map = page_allocation.index("uvm_rm_mem_alloc_and_map_all(")
            self.assertLess(isolated_cpu_map, default_all_gpu_map)
            self.assertIn("!g_uvm_global.conf_computing_enabled", page_allocation)
            self.assertIn("!uvm_push_allow_dependencies_across_gpus()", page_allocation)
            self.assertIn("return uvm_rm_mem_alloc_and_map_cpu(", page_allocation)

            unmap = c_function_definition(uvm_root / "uvm_gpu.c", "deinit_semaphore_pools")
            unmap_guard = unmap.index(
                "if (g_uvm_global.conf_computing_enabled || uvm_push_allow_dependencies_across_gpus())"
            )
            unmap_loop = unmap.index("for_each_gpu(other_gpu)")
            self.assertLess(unmap_guard, unmap_loop)


if __name__ == "__main__":
    unittest.main()
