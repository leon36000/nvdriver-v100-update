#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contracts for the clean full-source R595/Linux 6.8 provider build."""

import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.build_r595_open_linux68_full import (  # noqa: E402
    EXPECTED_PROVIDER_SYMVERS_SEMANTIC_SHA256,
    KERNEL_RELEASE,
    LARGE_TABLE_POSTIMAGE_SHA256,
    LARGE_TABLE_HEADER_PATH,
    LARGE_TABLE_HEADER_POSTIMAGE_SHA256,
    LARGE_TABLE_OS_INTERFACE_PATH,
    LARGE_TABLE_OS_INTERFACE_POSTIMAGE_SHA256,
    LARGE_TABLE_PATH,
    DMABUF_UNMAP_PATH,
    DMABUF_UNMAP_POSTIMAGE_SHA256,
    MMAP_READONLY_PATH,
    MMAP_READONLY_POSTIMAGE_SHA256,
    VM_RSS_COUNTER_PATH,
    VM_RSS_COUNTER_POSTIMAGE_SHA256,
    PAGE_POOL_PROTOTYPES_FILES,
    apply_dmabuf_unmap_overlay,
    apply_mmap_readonly_overlay,
    apply_vm_rss_counter_overlay,
    apply_large_page_table_overlay,
    apply_page_pool_prototypes_overlay,
    apply_pfn_guard_overlay,
    build_command,
    provider_symvers_semantic_digest,
    validate_module_metadata,
    validate_provider_symvers,
)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class R595Linux68FullBuildTests(unittest.TestCase):
    def copy_large_table_replay_inputs(self, destination):
        replay = ROOT / "build/experiments/r595-syncboost-replay-v5/source"
        for relative in (LARGE_TABLE_HEADER_PATH, LARGE_TABLE_OS_INTERFACE_PATH,
                         LARGE_TABLE_PATH, "kernel-open/nvidia/nv-vm.c"):
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(replay / relative, target)

    def test_build_command_pins_target_headers_frontend_symvers_and_gcc13(self):
        command = build_command(
            Path("/tmp/replay/source"),
            Path("/tmp/kernel-headers"),
            Path("/project/frontend/Module.symvers"),
            Path("/tmp/gcc-13"),
            2,
        )
        self.assertEqual(command[:3], ["make", "-C", "/tmp/replay/source/kernel-open"])
        self.assertIn("KERNEL_UNAME=" + KERNEL_RELEASE, command)
        self.assertIn("SYSSRC=/tmp/kernel-headers", command)
        self.assertIn("NV_KERNEL_MODULES=nvidia nvidia-uvm", command)
        self.assertIn("KBUILD_EXTRA_SYMBOLS=/project/frontend/Module.symvers", command)
        self.assertIn("CC=/tmp/gcc-13", command)
        self.assertIn("-j2", command)
        self.assertEqual(command[-1], "modules")

    def test_pfn_overlay_reproduces_the_pinned_r595112_file_without_fuzz(self):
        original = ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
        original /= "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia/os-mlock.c"
        expected = ROOT / "build/research/open-gpu-kernel-modules-595.112.07/source/"
        expected /= "open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2/kernel-open/nvidia/os-mlock.c"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            target = source / "kernel-open/nvidia/os-mlock.c"
            target.parent.mkdir(parents=True)
            shutil.copyfile(original, target)
            receipt = apply_pfn_guard_overlay(source)
            self.assertEqual(target.read_bytes(), expected.read_bytes())
            self.assertEqual(receipt["postimage_sha256"], digest(expected))
            self.assertFalse(receipt["fuzz_used"])
            self.assertFalse(receipt["offset_used"])

    def test_pfn_overlay_refuses_modified_preimage(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            target = source / "kernel-open/nvidia/os-mlock.c"
            target.parent.mkdir(parents=True)
            target.write_text("modified source\n")
            with self.assertRaisesRegex(ValueError, "PFN guard preimage hash mismatch"):
                apply_pfn_guard_overlay(source)

    def test_large_page_table_overlay_reproduces_the_pinned_r595112_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            self.copy_large_table_replay_inputs(source)
            receipt = apply_large_page_table_overlay(source)
            self.assertEqual(digest(source / LARGE_TABLE_PATH), LARGE_TABLE_POSTIMAGE_SHA256)
            self.assertEqual(digest(source / LARGE_TABLE_HEADER_PATH),
                             LARGE_TABLE_HEADER_POSTIMAGE_SHA256)
            self.assertEqual(digest(source / LARGE_TABLE_OS_INTERFACE_PATH),
                             LARGE_TABLE_OS_INTERFACE_POSTIMAGE_SHA256)
            self.assertEqual(receipt["expected_replay_line_offset"], 56)
            self.assertEqual(receipt["offset_lines"], 56)
            self.assertEqual(receipt["patched_paths"], [
                LARGE_TABLE_HEADER_PATH, LARGE_TABLE_OS_INTERFACE_PATH, LARGE_TABLE_PATH,
            ])
            self.assertFalse(receipt["fuzz_used"])

    def test_large_page_table_overlay_refuses_modified_preimage(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            self.copy_large_table_replay_inputs(source)
            target = source / LARGE_TABLE_PATH
            target.write_text("modified replayed source\n")
            with self.assertRaisesRegex(ValueError, "before large page-table fix hash mismatch"):
                apply_large_page_table_overlay(source)

    def test_large_page_table_overlay_refuses_modified_wrapper_preimages(self):
        for relative, label in ((LARGE_TABLE_HEADER_PATH, "nv_vmalloc wrapper preimage"),
                                (LARGE_TABLE_OS_INTERFACE_PATH, "vmalloc callsite preimage")):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as tmp:
                source = Path(tmp) / "source"
                self.copy_large_table_replay_inputs(source)
                target = source / relative
                target.write_text("modified replayed source\n")
                with self.assertRaisesRegex(ValueError, label):
                    apply_large_page_table_overlay(source)

    def test_page_pool_prototype_overlay_is_exact_and_internalizes_helpers(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            self.copy_large_table_replay_inputs(source)
            apply_large_page_table_overlay(source)
            receipt = apply_page_pool_prototypes_overlay(source)
            for relative, (_, expected) in PAGE_POOL_PROTOTYPES_FILES.items():
                self.assertEqual(digest(source / relative), expected)
            self.assertFalse(receipt["fuzz_used"])
            self.assertFalse(receipt["offset_used"])
            self.assertEqual(receipt["patched_paths"], list(PAGE_POOL_PROTOTYPES_FILES))
            vm = (source / "kernel-open/nvidia/nv-vm.c").read_text()
            for name in ("nv_mem_pool_alloc_pages", "nv_mem_pool_destroy",
                         "nv_mem_pool_init", "nv_mem_pool_free_pages"):
                self.assertIn("static ", vm[vm.index(name) - 40:vm.index(name)])
            linux_header = (source / "kernel-open/common/inc/nv-linux.h").read_text()
            self.assertIn("NV_STATUS nv_init_page_pools(void);", linux_header)
            self.assertIn("void nv_destroy_page_pools(void);", linux_header)

    def test_page_pool_prototype_overlay_refuses_any_modified_preimage(self):
        for relative, (before, _) in PAGE_POOL_PROTOTYPES_FILES.items():
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as tmp:
                source = Path(tmp) / "source"
                self.copy_large_table_replay_inputs(source)
                apply_large_page_table_overlay(source)
                target = source / relative
                self.assertEqual(digest(target), before)
                target.write_text("modified source\n")
                with self.assertRaisesRegex(
                    ValueError, "page-pool prototype preimage .* hash mismatch"
                ):
                    apply_page_pool_prototypes_overlay(source)

    def test_dmabuf_unmap_overlay_matches_the_pinned_r595112_fix_exactly(self):
        replay = ROOT / "build/experiments/r595-syncboost-replay-v5/source"
        upstream = ROOT / "build/research/open-gpu-kernel-modules-595.112.07/source/"
        upstream /= "open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2/"
        upstream /= DMABUF_UNMAP_PATH
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            target = source / DMABUF_UNMAP_PATH
            target.parent.mkdir(parents=True)
            shutil.copyfile(replay / DMABUF_UNMAP_PATH, target)
            receipt = apply_dmabuf_unmap_overlay(source)
            patched = target.read_text()
            upstream_text = upstream.read_text()
            self.assertEqual(digest(target), DMABUF_UNMAP_POSTIMAGE_SHA256)
            self.assertIn(
                "dma_unmap_sg_attrs(dev, sgt->sgl, sgt->orig_nents,\n"
                "                       DMA_BIDIRECTIONAL, DMA_ATTR_SKIP_CPU_SYNC);",
                patched,
            )
            self.assertIn(
                "dma_unmap_sg_attrs(dev, sgt->sgl, sgt->orig_nents,\n"
                "                       DMA_BIDIRECTIONAL, DMA_ATTR_SKIP_CPU_SYNC);",
                upstream_text,
            )
            self.assertNotIn(
                "dma_unmap_sg_attrs(dev, sgt->sgl, sgt->nents, DMA_BIDIRECTIONAL",
                patched,
            )
            self.assertEqual(receipt["patched_paths"], [DMABUF_UNMAP_PATH])
            self.assertFalse(receipt["fuzz_used"])
            self.assertFalse(receipt["offset_used"])

    def test_dmabuf_unmap_overlay_refuses_modified_preimage(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            target = source / DMABUF_UNMAP_PATH
            target.parent.mkdir(parents=True)
            target.write_text("modified replayed source\n")
            with self.assertRaisesRegex(ValueError, "dma-buf unmap preimage hash mismatch"):
                apply_dmabuf_unmap_overlay(source)

    def test_dmabuf_mapping_and_unmapping_preserve_original_scatterlist_count(self):
        replay = ROOT / "build/experiments/r595-syncboost-replay-v5/source"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            target = source / DMABUF_UNMAP_PATH
            target.parent.mkdir(parents=True)
            shutil.copyfile(replay / DMABUF_UNMAP_PATH, target)
            apply_dmabuf_unmap_overlay(source)
            text = target.read_text()
            map_at = text.index("dma_map_sg_attrs(dev, sgt->sgl, sgt->orig_nents,")
            self.assertGreater(text.index("sgt->nents = rc;", map_at), map_at)
            unmap_at = text.index("nv_dma_buf_unmap_pages(")
            unmap_end = text.index("static void\nnv_dma_buf_unmap_pfns", unmap_at)
            unmap_body = text[unmap_at:unmap_end]
            self.assertIn("sgt->orig_nents", unmap_body)
            self.assertNotIn("sgt->nents", unmap_body)

    def test_mmap_readonly_protection_precedes_pte_installation_and_preserves_pm_guard(self):
        replay = ROOT / "build/experiments/r595-syncboost-replay-v5/source"
        upstream = ROOT / "build/research/open-gpu-kernel-modules-595.112.07/source/"
        upstream /= "open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2/"
        upstream /= MMAP_READONLY_PATH
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            target = source / MMAP_READONLY_PATH
            target.parent.mkdir(parents=True)
            shutil.copyfile(replay / MMAP_READONLY_PATH, target)
            receipt = apply_mmap_readonly_overlay(source)
            text = target.read_text()
            helper = text[text.index("int nvidia_mmap_helper("):]
            protection = helper.index("NV_PGPROT_READ_ONLY(vma->vm_page_prot)")
            prot_assignment = helper.index("prot = mmap_context->prot;")
            clear_write = helper.index("nv_vm_flags_clear(vma, VM_WRITE);")
            clear_maywrite = helper.index("nv_vm_flags_clear(vma, VM_MAYWRITE);")
            mapping = helper.index("Nvidia device node(nvidia#) maps device's BAR memory")
            peer_map = helper.index("nvidia_mmap_peer_io(vma, at, page_index, pages)")
            sysmem_map = helper.index("nvidia_mmap_sysmem(vma, at, page_index, pages)")
            finish = helper.index("vma->vm_ops = &nv_vm_ops;")
            self.assertLess(prot_assignment, protection)
            self.assertLess(protection, mapping)
            self.assertLess(protection, peer_map)
            self.assertLess(protection, sysmem_map)
            for protection_change in (clear_write, clear_maywrite):
                self.assertLess(protection_change, mapping)
                self.assertLess(protection_change, peer_map)
                self.assertLess(protection_change, sysmem_map)
            self.assertLess(peer_map, finish)
            self.assertLess(sysmem_map, finish)
            self.assertEqual(helper.count("NV_PGPROT_READ_ONLY(vma->vm_page_prot)"), 1)
            self.assertIn("nvidia_vma_access_unlocked", text)
            self.assertIn("down_read_trylock(&nv_system_pm_lock)", text)
            upstream_text = upstream.read_text()
            self.assertLess(
                upstream_text.index("NV_PGPROT_READ_ONLY(vma->vm_page_prot)"),
                upstream_text.index("Nvidia device node(nvidia#) maps device's BAR memory"),
            )
            self.assertEqual(digest(target), MMAP_READONLY_POSTIMAGE_SHA256)
            self.assertEqual(receipt["patched_paths"], [MMAP_READONLY_PATH])
            self.assertFalse(receipt["fuzz_used"])
            self.assertFalse(receipt["offset_used"])

    def test_mmap_readonly_overlay_refuses_modified_preimage(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            target = source / MMAP_READONLY_PATH
            target.parent.mkdir(parents=True)
            target.write_text("modified replayed source\n")
            with self.assertRaisesRegex(ValueError, "mmap read-only preimage hash mismatch"):
                apply_mmap_readonly_overlay(source)

    def test_vm_rss_counter_guard_returns_before_allocation_and_counter_access(self):
        upstream = ROOT / "build/research/open-gpu-kernel-modules-595.112.07/source/"
        upstream /= "open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2/"
        upstream /= VM_RSS_COUNTER_PATH
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            self.copy_large_table_replay_inputs(source)
            apply_large_page_table_overlay(source)
            apply_page_pool_prototypes_overlay(source)
            receipt = apply_vm_rss_counter_overlay(source)
            text = (source / VM_RSS_COUNTER_PATH).read_text()
            start = text.index("static nv_linux_mm_free_work_t *nv_account_mm_alloc")
            end = text.index("static void nv_account_mm_free(", start)
            function = text[start:end]
            null_counters = function.index("mm->rss_stat[MM_SHMEMPAGES].counters == NULL")
            allocation = function.index("NV_KMALLOC(mm_work, sizeof(*mm_work));")
            accounting = function.index("percpu_counter_add(&mm->rss_stat[MM_SHMEMPAGES], numPages);")
            self.assertLess(null_counters, allocation)
            self.assertLess(null_counters, accounting)
            self.assertIn("#if defined(NV_PERCPU_MM_COUNTER)", function)
            upstream_text = upstream.read_text()
            upstream_start = upstream_text.index(
                "static nv_linux_mm_free_work_t *nv_account_mm_alloc"
            )
            upstream_end = upstream_text.index("static void nv_account_mm_free(", upstream_start)
            self.assertEqual(function, upstream_text[upstream_start:upstream_end])
            self.assertEqual(digest(source / VM_RSS_COUNTER_PATH),
                             VM_RSS_COUNTER_POSTIMAGE_SHA256)
            self.assertEqual(receipt["patched_paths"], [VM_RSS_COUNTER_PATH])
            self.assertFalse(receipt["fuzz_used"])
            self.assertFalse(receipt["offset_used"])

    def test_vm_rss_counter_overlay_refuses_modified_preimage(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            self.copy_large_table_replay_inputs(source)
            apply_large_page_table_overlay(source)
            apply_page_pool_prototypes_overlay(source)
            target = source / VM_RSS_COUNTER_PATH
            target.write_text("modified replayed source\n")
            with self.assertRaisesRegex(ValueError, "mm RSS-counter preimage hash mismatch"):
                apply_vm_rss_counter_overlay(source)

    def test_provider_module_identity_requires_exact_target_and_kmod_metadata(self):
        metadata = {
            "name": "hybrid580_open",
            "version": "595.99.02",
            "license": "Dual MIT/GPL",
            "vermagic": KERNEL_RELEASE + " SMP preempt mod_unload modversions",
            "depends": "ecc",
            "softdep": "pre: ecdh_generic ecdsa_generic",
        }
        validate_module_metadata(metadata)
        metadata["softdep"] = "pre: ecdh_generic,ecdsa_generic"
        with self.assertRaisesRegex(ValueError, "soft dependency metadata differs"):
            validate_module_metadata(metadata)

    def test_provider_symvers_abi_hash_is_pinned_independent_of_build_root(self):
        path = ROOT / "build/experiments/r595-open-softdep-linux68-gcc13-v2/Module.symvers"
        semantic = validate_provider_symvers(path)
        self.assertEqual(semantic, EXPECTED_PROVIDER_SYMVERS_SEMANTIC_SHA256)
        with tempfile.TemporaryDirectory() as tmp:
            moved = Path(tmp) / "Module.symvers"
            rows = path.read_text().splitlines()
            moved.write_text("\n".join(
                " ".join([*line.split()[:2], "/different/replay/root/hybrid580_open",
                          *line.split()[3:]]) for line in rows
            ) + "\n")
            self.assertEqual(provider_symvers_semantic_digest(moved), semantic)
            self.assertNotEqual(digest(moved), digest(path))

    def test_provider_symvers_rejects_crc_change_and_duplicate_symbol(self):
        path = ROOT / "build/experiments/r595-open-softdep-linux68-gcc13-v2/Module.symvers"
        rows = path.read_text().splitlines()
        with tempfile.TemporaryDirectory() as tmp:
            altered = Path(tmp) / "Module.symvers"
            fields = rows[0].split()
            fields[0] = "0x00000000" if fields[0] != "0x00000000" else "0x00000001"
            altered.write_text(" ".join(fields) + "\n" + "\n".join(rows[1:]) + "\n")
            with self.assertRaisesRegex(ValueError, "ABI mismatch"):
                validate_provider_symvers(altered)
            altered.write_text("\n".join([rows[0], rows[0], *rows[1:]]) + "\n")
            with self.assertRaisesRegex(ValueError, "duplicate provider symbol"):
                provider_symvers_semantic_digest(altered)

    def test_provider_symvers_rejects_unexpected_module_provider_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            altered = Path(tmp) / "Module.symvers"
            altered.write_text("0x12345678 example_symbol /tmp/nvidia.ko EXPORT_SYMBOL\n")
            with self.assertRaisesRegex(ValueError, "unexpected provider module"):
                provider_symvers_semantic_digest(altered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
