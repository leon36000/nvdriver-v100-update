#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the isolated R580 Volta UVM source overlay preparation."""

from pathlib import Path
import hashlib
from contextlib import redirect_stdout
from io import StringIO
import struct
import sys
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.probe_volta_uvm_port import (  # noqa: E402
    VOLTA_OBJECT_SOURCES,
    adapt_maxwell_mmu_callback_tables,
    _verify_r580_volta_mmu_64k_contract,
    build_overlay,
    prepare_overlay,
)
from tools import probe_volta_uvm_port as uvm_port  # noqa: E402


ARCHIVE_PREFIX = "NVIDIA-kernel-module-source-580.178.04"
CALLBACK_ANCESTRY_SOURCES = (
    "uvm_maxwell.c",
    "uvm_maxwell_access_counter_buffer.c",
    "uvm_maxwell_ce.c",
    "uvm_maxwell_fault_buffer.c",
    "uvm_maxwell_host.c",
    "uvm_maxwell_mmu.c",
    "uvm_maxwell_sec2.c",
    "uvm_pascal.c",
    "uvm_pascal_ce.c",
    "uvm_pascal_host.c",
    "uvm_pascal_fault_buffer.c",
)
CALLBACK_ANCESTRY_DEPENDENCIES = (
    "cla16f.h", "clb06f.h", "clb0b5.h", "clc0b5.h", "clc06f.h",
    "uvm_pascal_fault_buffer.h",
    "hwref/pascal/gp100/dev_fault.h", "hwref/pascal/gp100/dev_fb.h",
    "hwref/pascal/gp100/dev_mmu.h",
    "hwref/maxwell/gm107/dev_mmu.h",
)
LEGACY_CALLBACK_SUBCHANNELS = (
    "#define UVM_SUBCHANNEL_A16F UVM_SUBCHANNEL_HOST",
    "#define UVM_SUBCHANNEL_B06F UVM_SUBCHANNEL_HOST",
    "#define UVM_SUBCHANNEL_B0B5 UVM_SUBCHANNEL_CE",
    "#define UVM_SUBCHANNEL_C06F UVM_SUBCHANNEL_HOST",
    "#define UVM_SUBCHANNEL_C0B5 UVM_SUBCHANNEL_CE",
)
HAL_DISPATCH_LINEAGES = {
    "ce_table": (
        "MAXWELL_DMA_COPY_A", "PASCAL_DMA_COPY_A",
        "PASCAL_DMA_COPY_B", "VOLTA_DMA_COPY_A",
    ),
    "host_table": (
        "KEPLER_CHANNEL_GPFIFO_B", "MAXWELL_CHANNEL_GPFIFO_A",
        "PASCAL_CHANNEL_GPFIFO_A", "VOLTA_CHANNEL_GPFIFO_A",
    ),
    "arch_table": (
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM200",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    ),
    "fault_buffer_table": (
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM200",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    ),
    "access_counter_buffer_table": (
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM200",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    ),
    "sec2_table": (
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM200",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    ),
}
REMOVED_VOLTA_ASSIGNMENTS = (
    "parent_gpu->tlb_batch.va_invalidate_supported = true;",
    "parent_gpu->tlb_batch.va_range_invalidate_supported = true;",
    "parent_gpu->can_map_sysmem_with_large_pages = true;",
    "parent_gpu->prefetch_fault_supported = true;",
    "parent_gpu->gpfifo_in_vidmem_supported = true;",
    "parent_gpu->replayable_faults_supported = true;",
    "parent_gpu->non_replayable_faults_supported = true;",
    "parent_gpu->fault_cancel_va_supported = true;",
    "parent_gpu->scoped_atomics_supported = true;",
    "parent_gpu->sparse_mappings_supported = true;",
    "parent_gpu->plc_supported = false;",
)


class VoltaUvmOverlayTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hybrid-uvm-overlay-test-")
        self.root = Path(self.temporary.name)
        self.archive = self.root / "r580-source.tar.gz"
        self.r595 = self.root / "r595"
        (self.r595 / "nvidia-uvm").mkdir(parents=True)
        (self.r595 / "common/inc").mkdir(parents=True)
        (self.r595 / "common/inc/nv_uvm_interface.h").write_text(
            "/* R615 interface fixture: preserve modern declarations. */\n"
            "NV_STATUS nvUvmInterfaceRegisterUvmEvents(void *events);\n"
            "void nvUvmInterfaceDeRegisterUvmEvents(void);\n"
            "NV_STATUS nvUvmInterfaceAccessBitsBufAlloc(void *device, void *info);\n"
            "NV_STATUS nvUvmInterfaceAccessBitsDump(void *device, void *info, int mode);\n"
            "NV_STATUS nvUvmInterfaceAccessBitsBufFree(void *device, void *info);\n"
        )
        (self.r595 / "nvidia-uvm/nvidia-uvm-sources.Kbuild").write_text(
            "NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_tracker.c\n"
            "NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_turing.c\n"
        )
        (self.r595 / "nvidia-uvm/uvm_push_macros.h").write_text(
            "#define UVM_SUBCHANNEL_SEC2 NVA06F_SUBCHANNEL_COMPUTE\n"
            "#define UVM_SUBCHANNEL_C46F UVM_SUBCHANNEL_HOST\n"
        )
        (self.r595 / "nvidia-uvm/uvm_hal.h").write_text(
            "uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_turing(void);\n"
            "void uvm_hal_turing_fault_buffer_entry_clear_valid("
            "uvm_parent_gpu_t *parent_gpu, NvU32 index);\n"
        )
        (self.r595 / "nvidia-uvm/uvm_hal.c").write_text(
            self._fixture_r615_hal_source()
        )
        (self.r595 / "nvidia-uvm/ctrl2080mc.h").write_text(
            "/* target-owned R615 control IDs; must not be replaced */\n"
            "#define NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100 (0x00000140)\n"
        )
        self._write_archive()
        self.fixture_archive_sha256 = self._sha256(self.archive)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def _sha256(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _write_archive(self, archive_path=None, *, archive_prefix=ARCHIVE_PREFIX,
                       copying=None):
        archive_path = archive_path or self.archive
        uvm_prefix = archive_prefix + "/kernel-open/nvidia-uvm/"
        files = {
            archive_prefix + "/COPYING": copying or (
                b"Except where noted otherwise, individual files are licensed as MIT.\n"
            ),
            uvm_prefix + "nvidia-uvm-sources.Kbuild": (
                b"NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_volta.c\n"
            ),
            uvm_prefix + "uvm_push_macros.h": (
                b"#define UVM_SUBCHANNEL_C36F UVM_SUBCHANNEL_HOST\n"
                b"#define UVM_SUBCHANNEL_C3B5 UVM_SUBCHANNEL_CE\n"
                b"#define UVM_SUBCHANNEL_A16F UVM_SUBCHANNEL_HOST\n"
                b"#define UVM_SUBCHANNEL_B06F UVM_SUBCHANNEL_HOST\n"
                b"#define UVM_SUBCHANNEL_B0B5 UVM_SUBCHANNEL_CE\n"
                b"#define UVM_SUBCHANNEL_C06F UVM_SUBCHANNEL_HOST\n"
                b"#define UVM_SUBCHANNEL_C0B5 UVM_SUBCHANNEL_CE\n"
            ),
            uvm_prefix + "uvm_volta.c": (
                ("void uvm_hal_volta_arch_init_properties(void) {\n" +
                 "\n".join(REMOVED_VOLTA_ASSIGNMENTS) +
                 "\nparent_gpu->tlb_batch.max_ranges = 8;\n}\n").encode()
            ),
            uvm_prefix + "uvm_pascal_mmu.c": (
                b"static NvU64 unmapped_pte_pascal(NvU64 page_size) { return page_size; }\n"
                b"static NvU64 make_pte_pascal(void) { return 0; }\n"
                b"static NvU64 poisoned_pte_pascal(void) { return 0; }\n"
                b"static uvm_mmu_mode_hal_t pascal_mmu_mode_hal;\n"
                b"uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_pascal(NvU64 page_size) { return &pascal_mmu_mode_hal; }\n"
                b"static void mmu_set_prefetch_faults(uvm_parent_gpu_t *parent_gpu, bool enable) {}\n"
                b"void uvm_hal_pascal_mmu_enable_prefetch_faults(uvm_parent_gpu_t *parent_gpu) {\n"
                b"UVM_ASSERT(parent_gpu->prefetch_fault_supported);\n}\n"
                b"void uvm_hal_pascal_mmu_disable_prefetch_faults(uvm_parent_gpu_t *parent_gpu) {}\n"
            ),
            uvm_prefix + "uvm_pascal_fault_buffer.h": b"/* fixture */\n",
            uvm_prefix + "hwref/pascal/gp100/dev_fault.h": b"/* fixture */\n",
            uvm_prefix + "hwref/pascal/gp100/dev_fb.h": b"/* fixture */\n",
            uvm_prefix + "hwref/pascal/gp100/dev_mmu.h": b"/* fixture */\n",
        }
        files[archive_prefix + "/kernel-open/common/inc/nv_uvm_interface.h"] = (
            b"/* common UVM interface fixture */\n"
        )
        files[uvm_prefix + "uvm_hal.c"] = self._fixture_r580_hal_source().encode()
        files[uvm_prefix + "ctrl2080mc.h"] = (
            b"#define NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000 (0x00000110)\n"
            b"#define NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM200 (0x00000120)\n"
            b"#define NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100 (0x00000130)\n"
            b"#define NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100 (0x00000140)\n"
        )
        files[uvm_prefix + "uvm_hal.h"] = (
            b"/* compile-probe prototype fixture */\n"
            b"void uvm_hal_maxwell_ce_init(uvm_push_t *push);\n"
            b"void uvm_hal_maxwell_arch_init_properties(uvm_parent_gpu_t *parent_gpu);\n"
            b"void uvm_hal_pascal_arch_init_properties(uvm_parent_gpu_t *parent_gpu);\n"
            b"void uvm_hal_volta_arch_init_properties(uvm_parent_gpu_t *parent_gpu);\n"
            b"uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_maxwell(NvU64 big_page_size);\n"
            b"uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_pascal(NvU64 big_page_size);\n"
            b"uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_volta(NvU64 big_page_size);\n"
        )
        for relative in (
            "uvm_volta.c", "uvm_volta_ce.c", "uvm_volta_fault_buffer.c",
            "uvm_volta_fault_buffer.h", "uvm_volta_host.c", "uvm_volta_mmu.c",
            "clc3b5.h", "clc36f.h", "hwref/volta/gv100/dev_fault.h",
            "hwref/volta/gv100/dev_fb.h", "hwref/volta/gv100/dev_mmu.h",
        ):
            if relative == "uvm_volta_mmu.c":
                files[uvm_prefix + relative] = (
                    b"uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_volta(NvU64 big_page_size) {\n"
                    b"UVM_ASSERT(big_page_size == UVM_PAGE_SIZE_64K || "
                    b"big_page_size == UVM_PAGE_SIZE_128K);\n"
                    b"if (big_page_size == UVM_PAGE_SIZE_128K)\n"
                    b"        return NULL;\n"
                    b"return uvm_hal_mmu_mode_pascal(big_page_size);\n}\n"
                )
            elif relative != "uvm_volta.c":
                files[uvm_prefix + relative] = ("fixture:" + relative + "\n").encode()
        for relative in CALLBACK_ANCESTRY_SOURCES + CALLBACK_ANCESTRY_DEPENDENCIES:
            if relative in {"uvm_pascal_fault_buffer.h", "nv_uvm_interface.h"}:
                continue
            if relative == "uvm_maxwell.c":
                files[uvm_prefix + relative] = (
                    b"void uvm_hal_maxwell_arch_init_properties(uvm_parent_gpu_t *parent_gpu) {\n"
                    b"    /* legacy fields {removed by R615} */\n"
                    b"    parent_gpu->can_map_sysmem_with_large_pages = false;\n"
                    b"}\n"
                )
                continue
            if relative == "uvm_pascal.c":
                files[uvm_prefix + relative] = (
                    b"void uvm_hal_pascal_arch_init_properties(uvm_parent_gpu_t *parent_gpu) {\n"
                    b"    parent_gpu->prefetch_fault_supported = false;\n"
                    b"}\n"
                )
                continue
            if relative == "uvm_maxwell_mmu.c":
                files[uvm_prefix + relative] = (
                    b"static NvU64 unmapped_pte_maxwell(NvU64 page_size) {\n"
                    b"    if (page_size == UVM_PAGE_SIZE_4K) return 0;\n"
                    b"    return 1;\n"
                    b"}\n"
                    b"static NvU64 poisoned_pte_maxwell(void) {\n"
                    b"    return make_pte_maxwell(UVM_APERTURE_VID, 0, UVM_PROT_READ_ONLY, 0);\n"
                    b"}\n"
                    b"static uvm_mmu_mode_hal_t maxwell_64_mmu_mode_hal = {\n"
                    b"    .unmapped_pte = unmapped_pte_maxwell,\n"
                    b"    .poisoned_pte = poisoned_pte_maxwell,\n"
                    b"};\n"
                    b"static uvm_mmu_mode_hal_t maxwell_128_mmu_mode_hal = {\n"
                    b"    .unmapped_pte = unmapped_pte_maxwell,\n"
                    b"    .poisoned_pte = poisoned_pte_maxwell,\n"
                    b"};\n"
                )
                continue
            if relative == "uvm_maxwell_host.c":
                files[uvm_prefix + relative] = (
                    b"uvm_access_counter_clear_op_t probe(void) { "
                    b"return UVM_ACCESS_COUNTER_CLEAR_OP_NONE; }\n"
                )
                continue
            files.setdefault(uvm_prefix + relative,
                             ("fixture:" + relative + "\n").encode())
        legacy_class_ids = {
            "cla16f.h": "#define KEPLER_CHANNEL_GPFIFO_B (0x0000A16F)\n",
            "clb06f.h": "#define MAXWELL_CHANNEL_GPFIFO_A (0x0000B06F)\n",
            "clb0b5.h": "#define MAXWELL_DMA_COPY_A (0x0000B0B5)\n",
            "clc06f.h": "#define PASCAL_CHANNEL_GPFIFO_A (0x0000C06F)\n",
            "clc0b5.h": "#define PASCAL_DMA_COPY_A (0x0000C0B5)\n",
            "clc1b5.h": "#define PASCAL_DMA_COPY_B (0x0000C1B5)\n",
            "clc36f.h": "#define VOLTA_CHANNEL_GPFIFO_A (0x0000C36F)\n",
            "clc3b5.h": "#define VOLTA_DMA_COPY_A (0x0000C3B5)\n",
        }
        for relative, declaration in legacy_class_ids.items():
            files[uvm_prefix + relative] = declaration.encode()
        with tarfile.open(archive_path, "w:gz") as tar:
            for name, content in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                import io
                tar.addfile(info, io.BytesIO(content))

    @staticmethod
    def _fixture_r580_hal_source():
        union_for_table = {
            "ce_table": "ce_ops",
            "host_table": "host_ops",
            "arch_table": "arch_ops",
            "fault_buffer_table": "fault_buffer_ops",
            "access_counter_buffer_table": "access_counter_buffer_ops",
            "sec2_table": "sec2_ops",
        }
        parent_ids = {
            "MAXWELL_DMA_COPY_A": None,
            "PASCAL_DMA_COPY_A": "MAXWELL_DMA_COPY_A",
            "PASCAL_DMA_COPY_B": "PASCAL_DMA_COPY_A",
            "VOLTA_DMA_COPY_A": "PASCAL_DMA_COPY_B",
            "KEPLER_CHANNEL_GPFIFO_B": None,
            "MAXWELL_CHANNEL_GPFIFO_A": "KEPLER_CHANNEL_GPFIFO_B",
            "PASCAL_CHANNEL_GPFIFO_A": "MAXWELL_CHANNEL_GPFIFO_A",
            "VOLTA_CHANNEL_GPFIFO_A": "PASCAL_CHANNEL_GPFIFO_A",
            "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000": None,
            "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM200": "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000",
            "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100": "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM200",
            "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100": "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100",
        }
        lines = []
        for table, lineage in HAL_DISPATCH_LINEAGES.items():
            lines.append(f"static uvm_hal_class_ops_t {table}[] = {{")
            for class_id in lineage:
                parent = parent_ids[class_id]
                parent_field = f".parent_id = {parent}, " if parent else ""
                callback_field = (
                    ".init = uvm_hal_maxwell_ce_init, "
                    if table == "ce_table" and class_id == "MAXWELL_DMA_COPY_A"
                    else ""
                )
                if table == "arch_table":
                    callback_field = {
                        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000": (
                            ".init_properties = uvm_hal_maxwell_arch_init_properties, "
                            ".mmu_mode_hal = uvm_hal_mmu_mode_maxwell, "
                        ),
                        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100": (
                            ".init_properties = uvm_hal_pascal_arch_init_properties, "
                            ".mmu_mode_hal = uvm_hal_mmu_mode_pascal, "
                        ),
                        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100": (
                            ".init_properties = uvm_hal_volta_arch_init_properties, "
                            ".mmu_mode_hal = uvm_hal_mmu_mode_volta, "
                        ),
                    }.get(class_id, "")
                lines.append(
                    f"    {{ .id = {class_id}, {parent_field}.u.{union_for_table[table]} = "
                    f"{{ {callback_field}}} }},"
                )
            lines.append("};")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _fixture_r615_hal_source():
        union_for_table = {
            "ce_table": "ce_ops",
            "host_table": "host_ops",
            "arch_table": "arch_ops",
            "fault_buffer_table": "fault_buffer_ops",
            "access_counter_buffer_table": "access_counter_buffer_ops",
            "sec2_table": "sec2_ops",
        }
        lines = ['#include "ctrl2080mc.h"']
        for table, union in union_for_table.items():
            class_id = (
                "TURING_DMA_COPY_A" if table == "ce_table" else
                "TURING_CHANNEL_GPFIFO_A" if table == "host_table" else
                "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_TU100"
            )
            lines.extend((
                f"static uvm_hal_class_ops_t {table}[] = {{",
                f"    {{ .id = {class_id}, .u.{union} = {{}} }},",
                "};",
            ))
        return "\n".join(lines) + "\n"

    def test_overlay_copies_source_and_restores_only_required_class_mappings(self):
        scratch = self.root / "scratch"
        report = prepare_overlay(
            self.archive, self.r595, scratch,
            expected_archive_sha256=self.fixture_archive_sha256,
        )
        sources = scratch / "nvidia-uvm/nvidia-uvm-sources.Kbuild"
        push = scratch / "nvidia-uvm/uvm_push_macros.h"
        source_list = sources.read_text()
        mappings = push.read_text()
        self.assertIn("NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_volta_fault_buffer.c", source_list)
        self.assertIn("NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_volta_mmu.c", source_list)
        self.assertEqual(mappings.count("UVM_SUBCHANNEL_C36F"), 1)
        self.assertEqual(mappings.count("UVM_SUBCHANNEL_C3B5"), 1)
        self.assertEqual(
            (scratch / "nvidia-uvm/uvm_volta_ce.c").read_text(),
            "fixture:uvm_volta_ce.c\n",
        )
        self.assertEqual(report["copied_volta_source_count"], 6)
        self.assertTrue(report["license_text_detected"])
        self.assertEqual(report["r580_archive_sha256"], self.fixture_archive_sha256)
        self.assertEqual(
            report["expected_r580_archive_sha256"], self.fixture_archive_sha256
        )
        self.assertTrue(report["archive_sha256_matches_expected"])
        self.assertNotIn("mit_source_confirmed", report)

    def test_overlay_excludes_prebuilt_kernel_outputs_from_the_scratch_tree(self):
        (self.r595 / "conftest/compile-tests").mkdir(parents=True)
        (self.r595 / "conftest/functions.h").write_text("stale conftest results\n")
        (self.r595 / "conftest/compile-tests/ktime_get_raw_ts64.h").write_text(
            "stale conftest probe\n"
        )
        (self.r595 / "nvidia-uvm/uvm_volta.o").write_bytes(b"stale object")
        (self.r595 / "nvidia-uvm/uvm_volta.mod").write_text("stale module metadata\n")
        (self.r595 / "nvidia-uvm/uvm_volta.mod.c").write_text("stale generated source\n")
        (self.r595 / "nvidia-uvm/uvm_volta.mod.o").write_bytes(b"stale module object")
        (self.r595 / "nvidia-uvm.ko").write_bytes(b"stale module")
        (self.r595 / "Module.symvers").write_text("stale symbol owners\n")
        (self.r595 / "modules.order").write_text("stale module order\n")
        (self.r595 / ".nvidia-uvm.ko.cmd").write_text("stale link command\n")
        (self.r595 / "nvidia-uvm/.uvm_volta.o.cmd").write_text("stale compile command\n")
        (self.r595 / "nvidia-uvm/.uvm_volta.o.d").write_text("stale dependency file\n")
        (self.r595 / "nvidia-uvm/.uvm_hal.d").write_text("stale dependency file\n")
        (self.r595 / ".tmp_versions").mkdir()
        (self.r595 / ".tmp_versions/nvidia-uvm.mod").write_text("stale metadata\n")
        (self.r595 / "nv-kernel.o_binary").write_bytes(b"source binary object")
        scratch = self.root / "scratch-clean"

        prepare_overlay(
            self.archive, self.r595, scratch,
            expected_archive_sha256=self.fixture_archive_sha256,
        )

        for relative in (
            "conftest",
            "nvidia-uvm/uvm_volta.o",
            "nvidia-uvm/uvm_volta.mod",
            "nvidia-uvm/uvm_volta.mod.c",
            "nvidia-uvm/uvm_volta.mod.o",
            "nvidia-uvm.ko",
            "Module.symvers",
            "modules.order",
            ".nvidia-uvm.ko.cmd",
            "nvidia-uvm/.uvm_volta.o.cmd",
            "nvidia-uvm/.uvm_volta.o.d",
            "nvidia-uvm/.uvm_hal.d",
            ".tmp_versions",
        ):
            self.assertFalse((scratch / relative).exists(), relative)
        self.assertEqual((scratch / "nv-kernel.o_binary").read_bytes(), b"source binary object")

    def test_dispatch_ancestor_restore_injects_pinned_rows_and_preserves_target_header(self):
        scratch = self.root / "dispatch-scratch"
        target_control_header = self.r595 / "nvidia-uvm/ctrl2080mc.h"
        target_header_before = target_control_header.read_bytes()
        report = prepare_overlay(
            self.archive, self.r595, scratch,
            expected_archive_sha256=self.fixture_archive_sha256,
            compile_probe_adapter=True,
            restore_callback_ancestors=True,
            restore_dispatch_ancestors=True,
        )
        hal = (scratch / "nvidia-uvm/uvm_hal.c").read_text()
        for table, lineage in HAL_DISPATCH_LINEAGES.items():
            table_start = hal.index(f"static uvm_hal_class_ops_t {table}[]")
            table_end = hal.index("};", table_start)
            table_text = hal[table_start:table_end]
            positions = [table_text.index(class_id) for class_id in lineage]
            self.assertEqual(positions, sorted(positions), table)
            self.assertIn(f".id = {lineage[-1]}", table_text)
        self.assertIn("#ifndef VOLTA_DMA_COPY_A", hal)
        self.assertIn("#elif VOLTA_DMA_COPY_A != 0x0000C3B5", hal)
        arch_table_start = hal.index("static uvm_hal_class_ops_t arch_table[]")
        arch_table_end = hal.index("};", arch_table_start)
        arch_table = hal[arch_table_start:arch_table_end]
        self.assertIn(
            ".mmu_mode_hal = uvm_hal_mmu_mode_maxwell_compile_probe_only,",
            arch_table,
        )
        self.assertIn(
            ".mmu_mode_hal = uvm_hal_mmu_mode_pascal_compile_probe_only,",
            arch_table,
        )
        self.assertIn(
            ".mmu_mode_hal = uvm_hal_mmu_mode_volta_compile_probe_only,",
            arch_table,
        )
        gv100_start = arch_table.index(
            ".id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100"
        )
        gv100_end = arch_table.index("\n", gv100_start)
        gv100_row = arch_table[gv100_start:gv100_end]
        self.assertIn(
            ".init_properties = uvm_hal_volta_arch_init_properties,", gv100_row
        )
        self.assertIn(
            ".parent_id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100,",
            gv100_row,
        )
        self.assertNotIn(".mmu_mode_hal = uvm_hal_mmu_mode_maxwell,", arch_table)
        self.assertNotIn(".mmu_mode_hal = uvm_hal_mmu_mode_pascal,", arch_table)
        self.assertNotIn(".mmu_mode_hal = uvm_hal_mmu_mode_volta,", arch_table)
        self.assertIn(
            "static uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_volta_compile_probe_only(void)",
            hal,
        )
        self.assertIn("return uvm_hal_mmu_mode_volta(UVM_PAGE_SIZE_64K);", hal)
        self.assertIn("return uvm_hal_mmu_mode_pascal(UVM_PAGE_SIZE_64K);", hal)
        self.assertIn("uvm_hal_mmu_mode_maxwell_compile_probe_only(void)", hal)
        self.assertIn("return NULL;", hal)
        self.assertIn(
            "void uvm_hal_maxwell_ce_init(uvm_push_t *push);", hal
        )
        self.assertEqual(target_control_header.read_bytes(), target_header_before)
        self.assertEqual(
            report["restored_dispatch_ancestor_rows"],
            {table: list(lineage) for table, lineage in HAL_DISPATCH_LINEAGES.items()},
        )
        self.assertNotEqual(
            report["restored_dispatch_ancestor_row_sha256"]["arch_table"],
            report["restored_dispatch_ancestor_compile_row_sha256"]["arch_table"],
        )
        self.assertEqual(
            report["restored_dispatch_ancestor_row_sha256"]["ce_table"],
            report["restored_dispatch_ancestor_compile_row_sha256"]["ce_table"],
        )
        self.assertTrue(report["dispatch_ancestors_compile_probe_only"])
        self.assertEqual(
            report["restored_dispatch_callback_prototypes"]["added_symbols"],
            [
                "uvm_hal_maxwell_arch_init_properties",
                "uvm_hal_maxwell_ce_init",
                "uvm_hal_mmu_mode_volta",
                "uvm_hal_pascal_arch_init_properties",
                "uvm_hal_volta_arch_init_properties",
            ],
        )
        self.assertTrue(
            report["restored_dispatch_callback_prototypes"]["compile_probe_only"]
        )
        self.assertEqual(
            report["dispatch_arch_mmu_mode_adaptations"],
            {
                "compile_probe_only": True,
                "row_adaptations": {
                    "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000": {
                        "legacy_symbol": "uvm_hal_mmu_mode_maxwell",
                        "compile_probe_symbol": "uvm_hal_mmu_mode_maxwell_compile_probe_only",
                    },
                    "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100": {
                        "legacy_symbol": "uvm_hal_mmu_mode_pascal",
                        "compile_probe_symbol": "uvm_hal_mmu_mode_pascal_compile_probe_only",
                    },
                    "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100": {
                        "legacy_symbol": "uvm_hal_mmu_mode_volta",
                        "compile_probe_symbol": "uvm_hal_mmu_mode_volta_compile_probe_only",
                    },
                },
                "maxwell": "unsupported callback returns NULL",
                "pascal": "legacy callback fixed to UVM_PAGE_SIZE_64K",
                "volta": "legacy callback fixed to UVM_PAGE_SIZE_64K",
                "volta_128k_supported": False,
                "volta_128k_rejection_source_verified": True,
            },
        )
        self.assertFalse(report["runtime_semantics_validated"])
        self.assertFalse(report["loaded_or_installed"])

    def test_volta_mmu_adapter_requires_the_pinned_64k_only_contract(self):
        with tarfile.open(self.archive, "r:*") as archive:
            member = next(
                name for name in archive.getnames()
                if name.endswith("/kernel-open/nvidia-uvm/uvm_volta_mmu.c")
            )
            source = archive.extractfile(member).read().decode("utf-8")
        _verify_r580_volta_mmu_64k_contract(source)
        changed = source.replace("return NULL;", "return &volta_mmu_mode_hal;", 1)
        with self.assertRaisesRegex(ValueError, "no longer rejects 128 KiB"):
            _verify_r580_volta_mmu_64k_contract(changed)

    def test_overlay_refuses_to_overwrite_an_existing_scratch_tree(self):
        scratch = self.root / "existing"
        scratch.mkdir()
        sentinel = scratch / "keep.txt"
        sentinel.write_text("preserve")
        with self.assertRaises(FileExistsError):
            prepare_overlay(
                self.archive, self.r595, scratch,
                expected_archive_sha256=self.fixture_archive_sha256,
            )
        self.assertEqual(sentinel.read_text(), "preserve")

    def test_overlay_rejects_an_archive_without_mit_license_text(self):
        bad_archive = self.root / "bad.tar.gz"
        self._write_archive(bad_archive, copying=b"no license text\n")
        with self.assertRaisesRegex(ValueError, "MIT license text marker"):
            prepare_overlay(
                bad_archive, self.r595, self.root / "bad-scratch",
                expected_archive_sha256=self._sha256(bad_archive),
            )

    def test_overlay_rejects_archive_hash_mismatch_before_preparation(self):
        scratch = self.root / "wrong-hash"
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            prepare_overlay(
                self.archive, self.r595, scratch,
                expected_archive_sha256="0" * 64,
            )
        self.assertFalse(scratch.exists())

    def test_overlay_rejects_a_root_that_does_not_match_r580_178_04(self):
        wrong_root_archive = self.root / "wrong-root.tar.gz"
        self._write_archive(
            wrong_root_archive,
            archive_prefix="NVIDIA-kernel-module-source-580.178.04-fixture",
        )
        with self.assertRaisesRegex(ValueError, "unexpected source root"):
            prepare_overlay(
                wrong_root_archive, self.r595, self.root / "wrong-root-scratch",
                expected_archive_sha256=self._sha256(wrong_root_archive),
            )

    def test_compile_probe_adapter_is_explicit_and_keeps_the_pascal_mmu_base(self):
        scratch = self.root / "compatibility-probe"
        report = prepare_overlay(
            self.archive, self.r595, scratch,
            expected_archive_sha256=self.fixture_archive_sha256,
            compile_probe_adapter=True,
        )
        volta = (scratch / "nvidia-uvm/uvm_volta.c").read_text()
        for assignment in REMOVED_VOLTA_ASSIGNMENTS:
            self.assertNotIn(assignment, volta)
        self.assertIn("parent_gpu->tlb_batch.max_ranges = 8;", volta)

        source_list = (scratch / "nvidia-uvm/nvidia-uvm-sources.Kbuild").read_text()
        self.assertIn("NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_pascal_mmu.c", source_list)
        pascal_mmu = (scratch / "nvidia-uvm/uvm_pascal_mmu.c").read_text()
        self.assertIn("uvm_hal_mmu_mode_pascal", pascal_mmu)
        self.assertNotIn("mmu_set_prefetch_faults", pascal_mmu)
        self.assertIn("unmapped_pte_pascal(void)", pascal_mmu)
        self.assertIn("poisoned_pte_pascal(uvm_page_tree_t *tree)", pascal_mmu)
        hal = (scratch / "nvidia-uvm/uvm_hal.h").read_text()
        self.assertIn("uvm_hal_mmu_mode_pascal(NvU64 big_page_size);", hal)
        self.assertTrue(report["compile_probe_adapter"])
        self.assertEqual(
            report["compatibility_pruned_assignments"],
            list(REMOVED_VOLTA_ASSIGNMENTS),
        )
        self.assertEqual(
            report["compile_probe_signature_adaptations"],
            [
                "unmapped_pte_pascal(NvU64 page_size) -> unmapped_pte_pascal(void)",
                "poisoned_pte_pascal(void) -> poisoned_pte_pascal(uvm_page_tree_t *tree)",
            ],
        )

    def test_callback_ancestry_probe_restores_missing_maxwell_pascal_sources(self):
        scratch = self.root / "callback-ancestry-probe"
        report = prepare_overlay(
            self.archive, self.r595, scratch,
            expected_archive_sha256=self.fixture_archive_sha256,
            compile_probe_adapter=True,
            restore_callback_ancestors=True,
        )

        expected_sources = {
            "uvm_maxwell.c",
            "uvm_maxwell_access_counter_buffer.c",
            "uvm_maxwell_ce.c",
            "uvm_maxwell_fault_buffer.c",
            "uvm_maxwell_host.c",
            "uvm_maxwell_mmu.c",
            "uvm_maxwell_sec2.c",
            "uvm_pascal.c",
            "uvm_pascal_ce.c",
            "uvm_pascal_host.c",
            "uvm_pascal_fault_buffer.c",
        }
        source_list = (scratch / "nvidia-uvm/nvidia-uvm-sources.Kbuild").read_text()
        for source in expected_sources:
            self.assertIn(f"NVIDIA_UVM_SOURCES += nvidia-uvm/{source}", source_list)
        pascal_mmu = (scratch / "nvidia-uvm/uvm_pascal_mmu.c").read_text()
        self.assertIn("uvm_hal_pascal_mmu_enable_prefetch_faults", pascal_mmu)
        self.assertNotIn("prefetch_fault_supported", pascal_mmu)
        self.assertTrue(report["callback_ancestry_compile_probe_only"])
        self.assertEqual(
            set(report["added_callback_ancestor_sources"]), expected_sources
        )
        self.assertEqual(
            set(report["copied_callback_ancestor_dependencies"]),
            set(CALLBACK_ANCESTRY_DEPENDENCIES),
        )
        modern_interface = scratch / "common/inc/nv_uvm_interface.h"
        self.assertIn("R615 interface fixture", modern_interface.read_text())
        self.assertFalse((scratch / "nvidia-uvm/nv_uvm_interface.h").exists())
        self.assertEqual(
            report["preserved_target_interface_headers"][0]["path"],
            "common/inc/nv_uvm_interface.h",
        )
        self.assertEqual(
            report["preserved_target_interface_headers"][0]["sha256"],
            self._sha256(modern_interface),
        )
        push_macros = (scratch / "nvidia-uvm/uvm_push_macros.h").read_text()
        for mapping in LEGACY_CALLBACK_SUBCHANNELS:
            self.assertIn(mapping, push_macros)
        hal = (scratch / "nvidia-uvm/uvm_hal.h").read_text()
        self.assertIn(
            "void uvm_hal_pascal_fault_buffer_entry_clear_valid("
            "uvm_parent_gpu_t *parent_gpu, NvU32 index);",
            hal,
        )
        maxwell_host = (scratch / "nvidia-uvm/uvm_maxwell_host.c").read_text()
        self.assertNotIn("UVM_ACCESS_COUNTER_CLEAR_OP_NONE", maxwell_host)
        self.assertIn("(uvm_access_counter_clear_op_t)0", maxwell_host)
        for source in ("uvm_maxwell.c", "uvm_pascal.c"):
            text = (scratch / "nvidia-uvm" / source).read_text()
            self.assertIn(
                'UVM_ASSERT_MSG(0, "compile-probe-only: unsupported R580 ancestor callback")',
                text,
            )
        self.assertEqual(
            {entry["source"] for entry in report["stubbed_callback_parent_properties"]},
            {"uvm_maxwell.c", "uvm_pascal.c"},
        )
        maxwell_mmu = (scratch / "nvidia-uvm/uvm_maxwell_mmu.c").read_text()
        self.assertIn("unmapped_pte_maxwell(NvU64 page_size)", maxwell_mmu)
        self.assertIn("poisoned_pte_maxwell(void)", maxwell_mmu)
        self.assertIn(
            ".unmapped_pte = unmapped_pte_maxwell_compile_probe_only,", maxwell_mmu
        )
        self.assertIn(
            ".poisoned_pte = poisoned_pte_maxwell_compile_probe_only,", maxwell_mmu
        )
        self.assertEqual(
            {entry["symbol"] for entry in report["stubbed_maxwell_mmu_callbacks"]},
            {"unmapped_pte_maxwell", "poisoned_pte_maxwell"},
        )
        self.assertTrue(report["callback_ancestor_compile_adaptations"])

    def test_callback_ancestor_adapter_refuses_missing_r615_interface_api(self):
        (self.r595 / "common/inc/nv_uvm_interface.h").write_text(
            "/* deliberately incomplete R615 interface fixture */\n"
            "NV_STATUS nvUvmInterfaceRegisterUvmEvents(void *events);\n"
        )
        scratch = self.root / "missing-r615-api"
        with self.assertRaisesRegex(ValueError, "missing required declarations"):
            prepare_overlay(
                self.archive, self.r595, scratch,
                expected_archive_sha256=self.fixture_archive_sha256,
                compile_probe_adapter=True,
                restore_callback_ancestors=True,
            )
        self.assertFalse(scratch.exists())

    def test_maxwell_mmu_dispatch_adapter_fails_closed_on_source_drift(self):
        source = (
            "static NvU64 unmapped_pte_maxwell(NvU64 page_size) {\n"
            "    if (page_size == UVM_PAGE_SIZE_4K) return 0;\n"
            "    return page_size;\n"
            "}\n"
            "static NvU64 poisoned_pte_maxwell(void) { return 1; }\n"
            "static uvm_mmu_mode_hal_t mode = {\n"
            "    .unmapped_pte = unmapped_pte_maxwell,\n"
            "    .poisoned_pte = poisoned_pte_maxwell,\n"
            "};\n"
        )
        changed = source.replace(
            ".unmapped_pte = unmapped_pte_maxwell,",
            ".unmapped_pte = changed_callback,",
        )
        with self.assertRaisesRegex(ValueError, "exactly two unmapped_pte_maxwell"):
            adapt_maxwell_mmu_callback_tables(changed)

    @staticmethod
    def _valid_relocatable_elf64():
        ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
        header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            ident, 1, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, 1, 0,
        )
        return header + bytes(64)

    def _successful_link_log(self, sources=VOLTA_OBJECT_SOURCES):
        lines = [f"  CC [M] nvidia-uvm/{source[:-2]}.o" for source in sources]
        lines.append("  LD [M] nvidia-uvm.ko")
        return "\n".join(lines) + "\n"

    def test_external_frontend_symvers_builds_only_uvm_and_is_hash_pinned(self):
        scratch = self.root / "frontend-bound-build"
        scratch.mkdir()
        self._write_frontend_conftest_fixture(scratch)
        kernel_source = self.root / "target-kernel-source"
        kernel_source.mkdir()
        kernel_compiler_target = self.root / "target-gcc-real"
        kernel_compiler_target.write_text("#!/bin/sh\nexit 0\n")
        kernel_compiler_target.chmod(0o700)
        kernel_compiler = self.root / "target-gcc"
        kernel_compiler.symlink_to(kernel_compiler_target.name)
        symvers = self.root / "frontend-Module.symvers"
        symvers.write_text("0x12345678\tnvUvmInterfaceRegisterUvmEvents\tnvidia\tEXPORT_SYMBOL\n")
        expected = hashlib.sha256(symvers.read_bytes()).hexdigest()

        def fake_make(command, **kwargs):
            (scratch / "nvidia-uvm.ko").write_bytes(self._valid_relocatable_elf64())
            self.assertIn("NV_KERNEL_MODULES=nvidia-uvm", command)
            self.assertIn(f"KBUILD_EXTRA_SYMBOLS={symvers.resolve()}", command)
            self.assertIn(
                f"NV_KERNEL_EXTRA_CONFTEST_KBUILD={scratch / 'nvidia-conftest-only.Kbuild'}",
                command,
            )
            self.assertNotIn("NV_KERNEL_MODULES=nvidia nvidia-uvm", command)
            self.assertIn("KERNEL_UNAME=6.8.0-147-generic", command)
            self.assertIn(f"SYSSRC={kernel_source.resolve()}", command)
            self.assertIn(f"CC={kernel_compiler.absolute()}", command)
            fragment = (scratch / "nvidia-conftest-only.Kbuild").read_text()
            self.assertIn("NV_CONFTEST_FUNCTION_COMPILE_TESTS += ktime_get_raw_ts64", fragment)
            self.assertIn("NV_CONFTEST_FUNCTION_COMPILE_TESTS += vm_flags_set", fragment)
            self.assertIn("NV_CONFTEST_TYPE_COMPILE_TESTS += mm_has_mmap_lock", fragment)
            self.assertNotIn("obj-m", fragment)
            self.assertIn("include $(NV_KERNEL_EXTRA_CONFTEST_KBUILD)",
                          (scratch / "Kbuild").read_text())
            return subprocess.CompletedProcess(
                command, 0,
                self._successful_link_log((*VOLTA_OBJECT_SOURCES, "uvm_pascal_mmu.c"))
                + "  LD [M] nvidia-uvm.o\n"
                + "  CC [M] nvidia-uvm.mod.o\n"
                + "  CC [M] .module-common.o\n",
                None,
            )

        with patch("tools.probe_volta_uvm_port.subprocess.run", side_effect=fake_make):
            report = build_overlay(
                scratch, jobs=1, compile_probe_adapter=True,
                frontend_module_symvers=symvers,
                expected_frontend_symvers_sha256=expected,
                kernel_uname="6.8.0-147-generic",
                kernel_source=kernel_source,
                kernel_compiler=kernel_compiler,
            )

        self.assertTrue(report["module_linked_this_run"])
        self.assertEqual(report["frontend_module_symvers"], {
            "path": str(symvers.resolve()),
            "expected_sha256": expected,
            "sha256_before": expected,
            "sha256_after": expected,
            "unchanged": True,
        })
        self.assertEqual(report["supplemental_frontend_conftests"]["test_count"], 3)
        self.assertTrue(report["supplemental_frontend_conftests"]["kbuild_include_injected"])
        self.assertEqual(report["kernel_target"], {
            "release": "6.8.0-147-generic",
            "source": str(kernel_source.resolve()),
            "compiler": str(kernel_compiler.absolute()),
        })

    def test_absolute_kbuild_paths_are_normalized_for_module_closure(self):
        scratch = self.root / "absolute-kbuild-paths"
        scratch.mkdir()
        self._write_frontend_conftest_fixture(scratch)
        symvers = self.root / "absolute-paths-Module.symvers"
        symvers.write_text("0x12345678\tnvUvmInterfaceRegisterUvmEvents\tnvidia\tEXPORT_SYMBOL\n")
        expected = hashlib.sha256(symvers.read_bytes()).hexdigest()
        absolute_log = "\n".join(
            [f"  CC [M] {scratch}/nvidia-uvm/{source[:-2]}.o"
             for source in VOLTA_OBJECT_SOURCES]
            + [f"  LD [M] {scratch}/nvidia-uvm.ko"]
        ) + "\n"

        def fake_make(command, **kwargs):
            (scratch / "nvidia-uvm.ko").write_bytes(self._valid_relocatable_elf64())
            return subprocess.CompletedProcess(command, 0, absolute_log, None)

        with patch("tools.probe_volta_uvm_port.subprocess.run", side_effect=fake_make):
            report = build_overlay(
                scratch, jobs=1,
                frontend_module_symvers=symvers,
                expected_frontend_symvers_sha256=expected,
            )

        self.assertTrue(report["module_linked_this_run"])
        self.assertEqual(report["compiled_volta_objects"], [
            f"nvidia-uvm/{source[:-2]}.o" for source in VOLTA_OBJECT_SOURCES
        ])
        self.assertEqual(report["unexpected_module_actions"], [])

    def test_external_frontend_symvers_fails_closed_when_nvidia_conftest_contract_drifts(self):
        scratch = self.root / "frontend-bound-drift-build"
        scratch.mkdir()
        self._write_frontend_conftest_fixture(scratch, malformed=True)
        symvers = self.root / "frontend-drift-Module.symvers"
        symvers.write_text("0x12345678\tnvUvmInterfaceRegisterUvmEvents\tnvidia\tEXPORT_SYMBOL\n")
        expected = hashlib.sha256(symvers.read_bytes()).hexdigest()

        with patch("tools.probe_volta_uvm_port.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "unsupported nvidia conftest declaration"):
                build_overlay(
                    scratch, jobs=1, frontend_module_symvers=symvers,
                    expected_frontend_symvers_sha256=expected,
                )
        run.assert_not_called()

    def test_external_frontend_symvers_rejects_unexpected_backend_build_or_link_steps(self):
        scratch = self.root / "frontend-bound-unexpected-module-build"
        scratch.mkdir()
        self._write_frontend_conftest_fixture(scratch)
        symvers = self.root / "frontend-unexpected-Module.symvers"
        symvers.write_text("0x12345678\tnvUvmInterfaceRegisterUvmEvents\tnvidia\tEXPORT_SYMBOL\n")
        expected = hashlib.sha256(symvers.read_bytes()).hexdigest()
        log = (
            self._successful_link_log((*VOLTA_OBJECT_SOURCES, "uvm_pascal_mmu.c"))
            + "  CC [M] nvidia/nv.o\n"
            + "  LD [M] hybrid580_open.ko\n"
        )

        def fake_make(command, **kwargs):
            (scratch / "nvidia-uvm.ko").write_bytes(self._valid_relocatable_elf64())
            return subprocess.CompletedProcess(command, 0, log, None)

        with patch("tools.probe_volta_uvm_port.subprocess.run", side_effect=fake_make):
            report = build_overlay(
                scratch, jobs=1, compile_probe_adapter=True,
                frontend_module_symvers=symvers,
                expected_frontend_symvers_sha256=expected,
            )

        self.assertTrue(report["build_command_succeeded"])
        self.assertFalse(report["module_linked_this_run"])
        self.assertEqual(report["unexpected_module_actions"], [
            "CC [M] nvidia/nv.o",
            "LD [M] hybrid580_open.ko",
        ])

    def test_build_warning_lines_are_preserved_in_the_report(self):
        scratch = self.root / "warning-report-build"
        scratch.mkdir()
        warning = "nvidia-uvm/uvm_hal.c:1: warning: synthetic compile warning"
        log = self._successful_link_log() + "\n" + warning + "\n"

        def fake_make(command, **kwargs):
            (scratch / "nvidia-uvm.ko").write_bytes(self._valid_relocatable_elf64())
            return subprocess.CompletedProcess(command, 0, log, None)

        with patch("tools.probe_volta_uvm_port.subprocess.run", side_effect=fake_make):
            report = build_overlay(scratch, jobs=1)

        self.assertTrue(report["module_linked_this_run"])
        self.assertEqual(report["build_warnings"], [warning])

    def _write_frontend_conftest_fixture(self, scratch, *, malformed=False):
        nvidia = scratch / "nvidia"
        nvidia.mkdir()
        declarations = (
            "NV_CONFTEST_FUNCTION_COMPILE_TESTS += ktime_get_raw_ts64\n"
            "NV_CONFTEST_FUNCTION_COMPILE_TESTS += vm_flags_set\n"
            "NV_CONFTEST_TYPE_COMPILE_TESTS += mm_has_mmap_lock\n"
        )
        if malformed:
            declarations += "NV_CONFTEST_UNKNOWN_COMPILE_TESTS += unexpected\n"
        (nvidia / "nvidia.Kbuild").write_text(
            "obj-m += hybrid580_open.o\n"
            "# Register the conftests needed by nvidia.ko\n"
            "NV_OBJECTS_DEPEND_ON_CONFTEST += $(NVIDIA_OBJECTS)\n"
            + declarations
        )
        (scratch / "Kbuild").write_text(
            "$(foreach _module, $(NV_KERNEL_MODULES), \\\n"
            " $(eval include $(src)/$(_module)/$(_module).Kbuild))\n"
        )

    def test_external_frontend_symvers_requires_exact_pinned_hash_before_build(self):
        scratch = self.root / "frontend-bound-invalid-build"
        scratch.mkdir()
        symvers = self.root / "frontend-Module.symvers"
        symvers.write_text("pinned input\n")
        with patch("tools.probe_volta_uvm_port.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "frontend Module.symvers SHA-256 mismatch"):
                build_overlay(
                    scratch, jobs=1, frontend_module_symvers=symvers,
                    expected_frontend_symvers_sha256="0" * 64,
                )
        run.assert_not_called()

    def test_external_frontend_symvers_refuses_a_dangling_fragment_symlink(self):
        scratch = self.root / "frontend-bound-symlink-build"
        scratch.mkdir()
        self._write_frontend_conftest_fixture(scratch)
        symvers = self.root / "frontend-symlink-Module.symvers"
        symvers.write_text("0x12345678\tnvUvmInterfaceRegisterUvmEvents\tnvidia\tEXPORT_SYMBOL\n")
        expected = hashlib.sha256(symvers.read_bytes()).hexdigest()
        outside = self.root / "outside"
        outside.mkdir()
        target = outside / "created-if-followed"
        (scratch / "nvidia-conftest-only.Kbuild").symlink_to(target)

        with patch("tools.probe_volta_uvm_port.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "staged NVIDIA conftest fragment"):
                build_overlay(
                    scratch, jobs=1, frontend_module_symvers=symvers,
                    expected_frontend_symvers_sha256=expected,
                )

        run.assert_not_called()
        self.assertFalse(target.exists())

    def test_fresh_link_requires_every_callback_ancestor_object(self):
        scratch = self.root / "callback-ancestor-build"
        scratch.mkdir()
        sources = (
            *VOLTA_OBJECT_SOURCES,
            "uvm_pascal_mmu.c",
            *CALLBACK_ANCESTRY_SOURCES,
        )

        def fake_make(command, **kwargs):
            (scratch / "nvidia-uvm.ko").write_bytes(self._valid_relocatable_elf64())
            return subprocess.CompletedProcess(
                command, 0, self._successful_link_log(sources), None
            )

        with patch("tools.probe_volta_uvm_port.subprocess.run", side_effect=fake_make):
            report = build_overlay(
                scratch,
                jobs=1,
                compile_probe_adapter=True,
                callback_ancestor_sources=CALLBACK_ANCESTRY_SOURCES,
            )

        self.assertTrue(report["build_command_succeeded"])
        self.assertTrue(report["expected_port_sources_compiled_this_run"])
        self.assertEqual(set(report["expected_port_sources_compiled"]), set(sources))

    def test_stale_module_is_not_reported_linked_after_successful_noop_make(self):
        scratch = self.root / "noop-build"
        scratch.mkdir()
        module = scratch / "nvidia-uvm.ko"
        module.write_bytes(self._valid_relocatable_elf64())
        with patch("tools.probe_volta_uvm_port.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, "", None)
            report = build_overlay(scratch, jobs=1)

        self.assertTrue(report["build_command_succeeded"])
        self.assertFalse(report["module_linked_this_run"])
        self.assertFalse(report["module_linked"])
        self.assertTrue(report["module_exists"])
        self.assertTrue(report["module_elf_valid"])

    def test_fresh_link_with_invalid_elf_is_not_reported_linked(self):
        scratch = self.root / "invalid-elf-build"
        scratch.mkdir()

        def fake_make(command, **kwargs):
            (scratch / "nvidia-uvm.ko").write_bytes(b"not an ELF file")
            return subprocess.CompletedProcess(command, 0, self._successful_link_log(), None)

        with patch("tools.probe_volta_uvm_port.subprocess.run", side_effect=fake_make):
            report = build_overlay(scratch, jobs=1)

        self.assertTrue(report["build_command_succeeded"])
        self.assertTrue(report["linkage_trace_found"])
        self.assertFalse(report["module_elf_valid"])
        self.assertFalse(report["module_linked_this_run"])

    def test_fresh_link_requires_link_trace_and_valid_elf(self):
        scratch = self.root / "valid-link-build"
        scratch.mkdir()

        def fake_make(command, **kwargs):
            (scratch / "nvidia-uvm.ko").write_bytes(self._valid_relocatable_elf64())
            return subprocess.CompletedProcess(command, 0, self._successful_link_log(), None)

        with patch("tools.probe_volta_uvm_port.subprocess.run", side_effect=fake_make):
            report = build_overlay(scratch, jobs=1)

        self.assertTrue(report["module_linked_this_run"])
        self.assertTrue(report["module_linked"])
        self.assertTrue(report["module_elf_valid"])
        self.assertTrue(report["build_log_sha256"])
        self.assertEqual(report["module_sha256"], self._sha256(scratch / "nvidia-uvm.ko"))

    def test_linker_failure_is_kept_in_general_build_diagnostics(self):
        scratch = self.root / "linker-failure-build"
        scratch.mkdir()
        log = (
            "ld.lld: error: undefined symbol: missing_uvm_symbol\n"
            "make[3]: *** [scripts/Makefile.modfinal:...] Error 1\n"
        )
        with patch("tools.probe_volta_uvm_port.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 2, log, None)
            report = build_overlay(scratch, jobs=1)

        self.assertFalse(report["build_command_succeeded"])
        self.assertFalse(report["module_linked_this_run"])
        self.assertTrue(any("undefined symbol" in line for line in report["build_diagnostics"]))
        self.assertTrue(any("Error 1" in line for line in report["build_diagnostics"]))
        self.assertEqual(report["build_log_sha256"], self._sha256(scratch / "uvm-port-build.log"))

    def test_cli_pins_external_frontend_symvers_and_writes_private_report(self):
        archive = self.root / "r580.tar.xz"
        scratch = self.root / "cli-frontend-bound"
        symvers = self.root / "frontend-Module.symvers"
        symvers.write_text("0x12345678\tnvUvmInterfaceRegisterUvmEvents\tnvidia\tEXPORT_SYMBOL\n")
        expected = hashlib.sha256(symvers.read_bytes()).hexdigest()
        kernel_source = self.root / "cli-kernel-source"
        kernel_source.mkdir()
        kernel_compiler = self.root / "cli-kernel-gcc"
        kernel_compiler.write_text("#!/bin/sh\nexit 0\n")
        kernel_compiler.chmod(0o700)
        report_path = self.root / "uvm-report.json"
        argv = [
            "probe_volta_uvm_port.py",
            "--r580-archive", str(archive),
            "--scratch", str(scratch),
            "--frontend-module-symvers", str(symvers),
            "--expected-frontend-symvers-sha256", expected,
            "--kernel-uname", "6.8.0-147-generic",
            "--kernel-source", str(kernel_source),
            "--kernel-compiler", str(kernel_compiler),
            "--report", str(report_path),
        ]

        with patch.object(sys, "argv", argv), \
                patch.object(uvm_port, "prepare_overlay", return_value={"prepared": True}), \
                patch.object(uvm_port, "build_overlay", return_value={
                    "build_command_succeeded": True,
                    "module_linked_this_run": True,
                }) as build:
            with redirect_stdout(StringIO()):
                self.assertEqual(uvm_port.main(), 0)

        build.assert_called_once_with(
            scratch.resolve(), 4,
            compile_probe_adapter=False,
            callback_ancestor_sources=(),
            frontend_module_symvers=symvers,
            expected_frontend_symvers_sha256=expected,
            kernel_uname="6.8.0-147-generic",
            kernel_source=kernel_source,
            kernel_compiler=kernel_compiler,
        )
        self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)

    def test_cli_requires_external_frontend_symvers_path_and_hash_together(self):
        symvers = self.root / "frontend-Module.symvers"
        base_argv = [
            "probe_volta_uvm_port.py",
            "--r580-archive", str(self.archive),
            "--scratch", str(self.root / "cli-pair-check"),
        ]

        for extra in (
            ["--frontend-module-symvers", str(symvers)],
            ["--expected-frontend-symvers-sha256", "0" * 64],
            ["--kernel-uname", "6.8.0-147-generic"],
        ):
            with self.subTest(extra=extra), \
                    patch.object(sys, "argv", [*base_argv, *extra]), \
                    patch.object(uvm_port, "prepare_overlay") as prepare:
                with redirect_stdout(StringIO()), self.assertRaises(SystemExit) as raised:
                    uvm_port.main()
                self.assertEqual(raised.exception.code, 2)
                prepare.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
