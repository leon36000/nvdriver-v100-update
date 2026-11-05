# SPDX-License-Identifier: MIT
"""Compile the pinned R580/R595 UVM layouts and exercise the bridge adapters."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
R595_INC = ROOT / "build/experiments/r595-r580-open-fullbuild-v3-20261023/source/kernel-open/common/inc"
R580_INC = ROOT / "build/experiments/r580-private-proprietary-build-v2-20261023/nvidia-580.178.04/common/inc"
BRIDGE = ROOT / "src/hybrid580_uvm_callback_bridge.c"
R580_CURRENT_ROOT = ROOT / "build/experiments/r58019607-sync-boost-legacy-build-v2/source"
R595_CURRENT_ROOT = ROOT / "build/experiments/r595-syncboost-open-build-v2/source/kernel-open"
R595112_CURRENT_SOURCE = ROOT / (
    "build/experiments/r595112-hybrid-open-source-core-rethunk-build-v1-20261102/source")
R595112_CURRENT_ROOT = R595112_CURRENT_SOURCE / "kernel-open"
R580_GPU_INFO_HEADER_SHA256 = {
    "nvidia-uvm/ctrl2080mc.h":
        "436710b6cc1f656c6f00c9b857f0f5b4931b43ccce22fa7129ccd9b30a00721a",
    "nvidia-uvm/clc36f.h":
        "56cbabbaf8c63cb2e2c0200dec3c18371d46772b0fcf903ab230d0de3b36c70b",
    "nvidia-uvm/clc3b5.h":
        "c6321efb3a6581d384495ac735bb80e8c0b1472d73e9043fefc973e25f2d5744",
    "hybrid-sdk/common/sdk/nvidia/inc/class/clc3c0.h":
        "3cfaff3faa703b105817cbc00c73ac620cdba11b75ca549ab9b3741737360e32",
}
R595112_GPU_INFO_HEADER_SHA256 = {
    "version.mk":
        "10fd21cb82f0444b73501ce2f0728b1b61bf477fbe019ecc9431458efc3a1baa",
    "kernel-open/nvidia-uvm/ctrl2080mc.h":
        "e7044317cefd8a86de3f53c702e4ce734497e5da5458fc0f10a6ed2517e4729e",
    "src/common/sdk/nvidia/inc/class/clc36f.h":
        "56cbabbaf8c63cb2e2c0200dec3c18371d46772b0fcf903ab230d0de3b36c70b",
    "src/common/sdk/nvidia/inc/class/clc3b5.h":
        "c6321efb3a6581d384495ac735bb80e8c0b1472d73e9043fefc973e25f2d5744",
    "src/common/sdk/nvidia/inc/class/clc3c0.h":
        "3cfaff3faa703b105817cbc00c73ac620cdba11b75ca549ab9b3741737360e32",
}


class Hybrid580UvmAbiCompatTests(unittest.TestCase):
    def _compile_and_run(self, source, include_dir, define=None, extra_include_dirs=()):
        with tempfile.TemporaryDirectory(prefix="hybrid580-uvm-abi-") as directory:
            binary = Path(directory) / "abi-test"
            command = ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                       "-fsanitize=undefined", "-fno-sanitize-recover=all",
                       "-I", str(include_dir)]
            for extra_include_dir in extra_include_dirs:
                command.extend(["-I", str(extra_include_dir)])
            command.extend([str(source), "-o", str(binary)])
            if define:
                command.insert(1, f"-D{define}")
            build = subprocess.run(command, capture_output=True, text=True,
                                   timeout=30, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            return run.stdout

    def test_audit_report_persists_gpu_registration_abi_evidence(self):
        with tempfile.TemporaryDirectory(prefix="hybrid580-uvm-report-") as directory:
            report_path = Path(directory) / "abi-report.json"
            run = subprocess.run(
                [sys.executable, str(ROOT / "tools/audit_hybrid_uvm_abi.py"),
                 "--report", str(report_path)], capture_output=True, text=True,
                timeout=60, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            report = json.loads(report_path.read_text())

        self.assertEqual(report["schema"], "hybrid-uvm-branch-abi-audit-v8")
        registration = report["gpu_registration_abi"]
        self.assertEqual(registration["classification"],
                         "pinned-header-and-host-compiler-layout")
        self.assertTrue(registration["gpu_info"]["size_and_offsets_equal"])
        self.assertEqual(registration["gpu_info"]["field_count"], 35)
        self.assertTrue(registration["gpu_platform_info"]["declaration_identical"])
        self.assertEqual(registration["gpu_platform_info"]["fields"], [
            "pci_dev", "dma_addressable_start", "dma_addressable_limit"])
        self.assertFalse(registration["hardware_validated"])
        memory = report["gpu_memory_abi"]
        self.assertEqual(memory["classification"],
                         "pinned-layout-and-UVM-field-access-census")
        self.assertTrue(memory["fb_info"]["size_and_offsets_equal"])
        self.assertEqual(memory["fb_info"]["field_count"], 10)
        self.assertTrue(memory["fb_info"]["api_signature_identical"])
        self.assertEqual(memory["fb_info"]["fields_read_by_r580_and_r595"], [
            "bStaticBar1WriteCombined", "bZeroFb", "heapSize",
            "heapStart", "maxAllocatableAddress", "maxVidmemPageSize",
            "reservedHeapSize", "staticBar1Size", "staticBar1StartOffset"])
        self.assertEqual(memory["fb_info"]["fields_not_read_by_either_uvm_source"],
                         ["bStaticBar1Enabled"])
        pma = memory["pma_allocation"]
        self.assertEqual(pma["field_count"], 8)
        self.assertEqual((pma["r580_size"], pma["r595_size"]), (56, 56))
        self.assertTrue(pma["size_and_offsets_equal"])
        self.assertTrue(pma["api_signature_identical"])
        self.assertEqual(pma["normalized_api_signature"],
                         "NV_STATUS nvUvmInterfacePmaAllocPages(void *pPma, "
                         "NvLength pageCount, NvU64 pageSize, "
                         "UvmPmaAllocationOptions *pPmaAllocOptions, NvU64 *pPages);")
        self.assertEqual(pma["fields_accessed_by_r580_and_r595_uvm"], [
            "flags", "numPagesAllocated", "physBegin", "physEnd", "resultFlags"])
        self.assertEqual(pma["fields_not_explicitly_accessed_by_either_uvm_source"], [
            "alignment", "minimumSpeed", "regionId"])
        self.assertEqual(pma["allocation_flag_values"], {
            "ALLOCATE_ALLOW_PARTIAL": 4096,
            "ALLOCATE_CONTIGUOUS": 64,
            "ALLOCATE_DONT_EVICT": 1,
            "ALLOCATE_NO_ZERO": 1024,
            "ALLOCATE_PINNED": 2,
            "ALLOCATE_PROTECTED_REGION": 256,
            "ALLOCATE_RESULT_IS_ZERO": 1,
            "ALLOCATE_SPECIFY_ADDRESS_RANGE": 8,
        })
        faults = report["faults_abi"]
        self.assertEqual(faults["classification"],
                         "pinned-header-host-compiler-layout-and-UVM-source-access-census")
        self.assertTrue(faults["gpu_fault_info"]["size_and_offsets_equal"])
        self.assertEqual((faults["gpu_fault_info"]["r580_size"],
                          faults["gpu_fault_info"]["r595_size"]), (184, 184))
        self.assertEqual(faults["gpu_fault_info"]["top_level_offsets"], {
            "replayable": 0, "nonReplayable": 104,
            "faultBufferHandle": 168, "pDevice": 176,
        })
        self.assertEqual(faults["gpu_fault_info"]["replayable_offsets"], {
            "pFaultBufferGet": 0, "pFaultBufferPut": 8,
            "pFaultBufferInfo": 16, "pPmcIntr": 24,
            "pPmcIntrEnSet": 32, "pPmcIntrEnClear": 40,
            "pPrefetchCtrl": 48, "replayableFaultMask": 56,
            "bufferAddress": 64, "bufferSize": 72,
            "bufferMetadata": 80, "cslCtx": 88,
        })
        self.assertEqual(faults["gpu_fault_info"]["nonreplayable_offsets"], {
            "shadowBufferAddress": 0, "shadowBufferContext": 8,
            "bufferSize": 16, "isr_sp": 24, "isr_bh_sp": 32,
            "pFaultBufferPut": 40, "shadowBufferGet": 48,
            "shadowBufferMetadata": 56,
        })
        self.assertTrue(faults["metadata_packet"]["size_and_offsets_equal"])
        self.assertEqual(faults["metadata_packet"]["size"], 32)
        self.assertEqual(faults["metadata_packet"]["offsets"],
                         {"authTag": 0, "valid": 16})
        self.assertEqual(faults["csl_context"]["size"], 16)
        self.assertTrue(faults["fault_api_signatures_identical"])
        self.assertEqual(faults["fault_api_count"], 8)
        self.assertEqual(faults["uvm_field_access_sets"]["r580"], [
            "nonReplayable.bufferSize", "replayable.bufferAddress",
            "replayable.bufferMetadata", "replayable.bufferSize",
            "replayable.cslCtx", "replayable.pFaultBufferGet",
            "replayable.pFaultBufferPut", "replayable.pPmcIntr",
            "replayable.pPmcIntrEnClear", "replayable.pPmcIntrEnSet",
            "replayable.pPrefetchCtrl", "replayable.replayableFaultMask",
        ])
        self.assertEqual(faults["uvm_field_access_sets"]["r580"],
                         faults["uvm_field_access_sets"]["r595"])
        self.assertEqual(faults["fault_api_signatures"], {
            "nvUvmInterfaceOwnPageFaultIntr":
                "NV_STATUS nvUvmInterfaceOwnPageFaultIntr(uvmGpuDeviceHandle device, NvBool bOwnInterrupts);",
            "nvUvmInterfaceInitFaultInfo":
                "NV_STATUS nvUvmInterfaceInitFaultInfo(uvmGpuDeviceHandle device, UvmGpuFaultInfo *pFaultInfo);",
            "nvUvmInterfaceDestroyFaultInfo":
                "NV_STATUS nvUvmInterfaceDestroyFaultInfo(uvmGpuDeviceHandle device, UvmGpuFaultInfo *pFaultInfo);",
            "nvUvmInterfaceHasPendingNonReplayableFaults":
                "NV_STATUS nvUvmInterfaceHasPendingNonReplayableFaults(UvmGpuFaultInfo *pFaultInfo, NvBool *hasPendingFaults);",
            "nvUvmInterfaceGetNonReplayableFaults":
                "NV_STATUS nvUvmInterfaceGetNonReplayableFaults(UvmGpuFaultInfo *pFaultInfo, void *pFaultBuffer, NvU32 *numFaults);",
            "nvUvmInterfaceFlushReplayableFaultBuffer":
                "NV_STATUS nvUvmInterfaceFlushReplayableFaultBuffer(UvmGpuFaultInfo *pFaultInfo, NvBool bCopyAndFlush);",
            "nvUvmInterfaceTogglePrefetchFaults":
                "NV_STATUS nvUvmInterfaceTogglePrefetchFaults(UvmGpuFaultInfo *pFaultInfo, NvBool bEnable);",
            "nvUvmInterfaceReportNonReplayableFault":
                "NV_STATUS nvUvmInterfaceReportNonReplayableFault(uvmGpuDeviceHandle device, const void *pFaultPacket);",
        })
        self.assertFalse(faults["hardware_validated"])
        fault_hal = report["fault_hal_abi"]
        self.assertEqual(fault_hal["classification"],
                         "pinned-UVM-HAL-table-and-static-parent-resolution")
        self.assertTrue(fault_hal["parent_resolution_algorithm_verified"])
        self.assertTrue(fault_hal["r580"]["gv100_present"])
        self.assertEqual(fault_hal["r580"]["gv100_parent"],
                         "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100")
        self.assertEqual(
            fault_hal["r580"]["resolved_gv100"]["parse_replayable_entry"],
            "uvm_hal_volta_fault_buffer_parse_replayable_entry")
        self.assertEqual(fault_hal["r580"]["resolved_gv100"]["entry_size"],
                         "uvm_hal_pascal_fault_buffer_entry_size")
        self.assertEqual(
            fault_hal["r580"]["resolved_gb100"]["parse_replayable_entry"],
            "uvm_hal_volta_fault_buffer_parse_replayable_entry")
        self.assertEqual(fault_hal["r580"]["resolved_gb100"]["get_fault_type"],
                         "uvm_hal_blackwell_fault_buffer_get_fault_type")
        self.assertFalse(fault_hal["r595"]["gv100_present"])
        self.assertEqual(
            fault_hal["r595"]["resolved_gb100"]["parse_replayable_entry"],
            "uvm_hal_turing_fault_buffer_parse_replayable_entry")
        self.assertEqual(fault_hal["r595"]["resolved_gb100"]["entry_size"],
                         "uvm_hal_turing_fault_buffer_entry_size")
        self.assertEqual(fault_hal["entry_size_constants"], {
            "r580_nvb069_fault_buf_size": 32,
            "r580_nvc369_buf_size": 32,
            "r595_nvc369_buf_size": 32,
            "resolved_r580_gv100_entry_size_symbol": "NVB069_FAULT_BUF_SIZE",
            "resolved_r595_gb100_entry_size_symbol": "NVC369_BUF_SIZE",
            "numerical_sizes_equal": True,
        })
        callback_delta = report["fault_hal_callback_delta"]
        self.assertEqual(callback_delta["classification"],
                         "pinned-UVM-callback-source-and-hardware-constant-census")
        self.assertTrue(callback_delta["common_c369_fault_parser"][
            "normalized_definition_identical"])
        self.assertTrue(callback_delta["fault_type_decoder"][
            "normalized_definition_identical"])
        self.assertEqual(callback_delta["mmu_engine_classification"], {
            "r580_host_engine_limit_symbol": "NV_PFAULT_MMU_ENG_ID_HOST13",
            "r580_host_engine_limit_value": 45,
            "r595_host_engine_limit_symbol": "NV_PFAULT_MMU_ENG_ID_HOST14",
            "r595_host_engine_limit_value": 46,
            "r580_bar1_engine_enum_value": 4,
            "r595_bar1_engine_enum_value": 128,
            "r580_graphics_guard_has_bar1_upper_bound": False,
            "r595_graphics_guard_has_bar1_upper_bound": True,
        })
        self.assertFalse(callback_delta["hardware_validated"])
        self.assertFalse(memory["hardware_validated"])

    def test_pinned_release_layouts_are_distinguished(self):
        source = ROOT / "tests/fixtures/uvm_branch_layout_probe.c"
        r580 = json.loads(self._compile_and_run(source, R580_INC))
        r595 = json.loads(self._compile_and_run(source, R595_INC, "HYBRID_BRANCH_R595"))

        self.assertEqual(r580["p2p_size"], 64)
        self.assertEqual(r595["p2p_size"], 72)
        self.assertEqual((r580["link_pcie"], r580["link_nvlink1"],
                          r580["link_c2c"]), (1, 2, 7))
        self.assertEqual((r595["link_pcie"], r595["link_pcie_bar1"],
                          r595["link_nvlink1"], r595["link_c2c"]), (1, 2, 3, 8))
        self.assertEqual((r580["copy_caps_size"], r595["copy_caps_size"]), (8, 8))
        self.assertEqual((r580["copy_mask_offset"], r595["copy_mask_offset"]), (4, 4))
        self.assertEqual((r580["channel_size"], r595["channel_size"]), (1120, 1128))
        self.assertEqual((r580["channel_divergence_offset"],
                          r595["channel_divergence_offset"]), (1104, 1104))
        self.assertEqual((r580["pma_size"], r595["pma_size"]), (48, 96))
        self.assertEqual((r580["pma_free64k_offset"], r595["pma_free64k_offset"]), (8, 8))
        self.assertEqual((r580["pma_free2m_offset"], r595["pma_free2m_offset"]), (16, 16))
        self.assertEqual(r580["channel_resource_size"], r595["channel_resource_size"])

        self.assertEqual((r580["event_table_size"], r595["event_table_size"]),
                         (56, 40))
        gpu_info_fields = {
            "name", "uuid", "gpuArch", "gpuImplementation", "hostClass", "ceClass",
            "computeClass", "gpuInTcc", "subdeviceCount", "virtMode", "isSimulated",
            "gpcCount", "maxGpcCount", "tpcCount", "maxTpcPerGpcCount",
            "accessCntrBufferCount", "smcEnabled", "smcSwizzId", "smcUserClientInfo",
            "gpuConfComputeCaps", "sysmemLink", "sysmemLinkRateMBps",
            "systemMemoryWindowStart", "systemMemoryWindowSize", "connectedToSwitch",
            "nvswitchMemoryWindowStart", "egmEnabled", "egmPeerId", "egmBaseAddr",
            "nvswitchEgmMemoryWindowStart", "atsSupport", "nonPasidAtsSupport",
            "cdmmEnabled", "nvlDirectConnect", "nvlDirectConnectMemoryWindowStart",
        }
        self.assertEqual(set(r580["gpu_info_offsets"]), gpu_info_fields)
        self.assertEqual(r580["gpu_info_size"], r595["gpu_info_size"])
        self.assertEqual(r580["gpu_info_offsets"], r595["gpu_info_offsets"])
        self.assertEqual(r580["gpu_client_info_size"], r595["gpu_client_info_size"])
        self.assertEqual(r580["gpu_client_info_offsets"], r595["gpu_client_info_offsets"])
        self.assertEqual(r580["gpu_conf_caps_size"], r595["gpu_conf_caps_size"])
        self.assertEqual(r580["gpu_conf_caps_offsets"], r595["gpu_conf_caps_offsets"])

        fb_info_fields = {
            "maxAllocatableAddress", "heapSize", "reservedHeapSize", "bZeroFb",
            "maxVidmemPageSize", "bStaticBar1Enabled", "bStaticBar1WriteCombined",
            "staticBar1StartOffset", "staticBar1Size", "heapStart",
        }
        self.assertEqual(set(r580["fb_info_offsets"]), fb_info_fields)
        expected_fb_info_offsets = {
            "maxAllocatableAddress": 0, "heapSize": 8, "reservedHeapSize": 12,
            "bZeroFb": 16, "maxVidmemPageSize": 24,
            "bStaticBar1Enabled": 32, "bStaticBar1WriteCombined": 33,
            "staticBar1StartOffset": 40, "staticBar1Size": 48, "heapStart": 56,
        }
        self.assertEqual((r580["fb_info_size"], r595["fb_info_size"]), (64, 64))
        self.assertEqual(r580["fb_info_offsets"], expected_fb_info_offsets)
        self.assertEqual(r580["fb_info_offsets"], r595["fb_info_offsets"])
        pma_option_fields = {
            "flags", "minimumSpeed", "physBegin", "physEnd", "regionId",
            "alignment", "numPagesAllocated", "resultFlags",
        }
        self.assertEqual(set(r580["pma_options_offsets"]), pma_option_fields)
        self.assertEqual((r580["pma_options_size"], r595["pma_options_size"]),
                         (56, 56))
        self.assertEqual(r580["pma_options_offsets"], {
            "flags": 0, "minimumSpeed": 4, "physBegin": 8, "physEnd": 16,
            "regionId": 24, "alignment": 32, "numPagesAllocated": 40,
            "resultFlags": 48,
        })
        self.assertEqual(r580["pma_options_offsets"], r595["pma_options_offsets"])
        expected_pma_flags = {
            "ALLOCATE_ALLOW_PARTIAL": 4096, "ALLOCATE_CONTIGUOUS": 64,
            "ALLOCATE_DONT_EVICT": 1, "ALLOCATE_NO_ZERO": 1024,
            "ALLOCATE_PINNED": 2, "ALLOCATE_PROTECTED_REGION": 256,
            "ALLOCATE_RESULT_IS_ZERO": 1, "ALLOCATE_SPECIFY_ADDRESS_RANGE": 8,
        }
        self.assertEqual(r580["pma_allocation_flags"], expected_pma_flags)
        self.assertEqual(r580["pma_allocation_flags"], r595["pma_allocation_flags"])
        def platform_info_declaration(include_dir):
            header = (include_dir / "nv_uvm_interface.h").read_text()
            match = re.search(
                r"typedef\s+struct\s*\{.*?\}\s*UvmGpuPlatformInfo\s*;",
                header, re.DOTALL)
            self.assertIsNotNone(match, "UvmGpuPlatformInfo declaration missing")
            declaration = re.sub(r"/\*.*?\*/|//[^\n]*", "", match.group(),
                                 flags=re.DOTALL)
            return re.sub(r"\s+", " ", declaration).strip()

        expected_platform_info = (
            "typedef struct { struct pci_dev *pci_dev; "
            "NvU64 dma_addressable_start; NvU64 dma_addressable_limit; "
            "} UvmGpuPlatformInfo;")
        self.assertEqual(platform_info_declaration(R580_INC), expected_platform_info)
        self.assertEqual(platform_info_declaration(R595_INC), expected_platform_info)
        self.assertEqual(
            tuple(r580[name] for name in (
                "event_suspend_offset", "event_resume_offset",
                "event_start_device_offset", "event_stop_device_offset",
                "event_isr_top_half_offset", "event_drain_p2p_offset",
                "event_resume_p2p_offset")),
            (0, 8, 16, 24, 32, 40, 48))
        self.assertEqual(
            tuple(r595[name] for name in (
                "event_isr_top_half_offset", "event_suspend_offset",
                "event_resume_offset", "event_drain_p2p_offset",
                "event_resume_p2p_offset")),
            (0, 8, 16, 24, 32))

        r580_uvm = ROOT / "build/experiments/r580-private-proprietary-build-v2-20261023/nvidia-580.178.04/nvidia-uvm"
        legacy_host = (r580_uvm / "uvm_ampere_host.c").read_text()
        self.assertIn("user_channel->runlist_pri_base_register + NV_RUNLIST_INTERNAL_DOORBELL",
                      legacy_host)
        self.assertIn("HWVALUE(_RUNLIST, INTERNAL_DOORBELL, CHID, user_channel->hw_channel_id)",
                      legacy_host)
        legacy_runlist = (r580_uvm / "hwref/ampere/ga100/dev_runlist.h").read_text()
        self.assertRegex(legacy_runlist,
                         r"#define\s+NV_RUNLIST_INTERNAL_DOORBELL\s+0x090")
        self.assertRegex(legacy_runlist,
                         r"#define\s+NV_RUNLIST_INTERNAL_DOORBELL_CHID\s+11:0")

        r595_uvm = ROOT / "build/experiments/r595-r580-open-fullbuild-v3-20261023/source/kernel-open/nvidia-uvm"
        pmm = (r595_uvm / "uvm_pmm_gpu.c").read_text()
        stats_reads = set(re.findall(r"pma_stats->([A-Za-z0-9_]+)", pmm))
        self.assertEqual(stats_reads, {"numFreePages64k", "numFreePages2m"})
        self.assertNotIn("numPages2mLocalizable", pmm)

        self.assertIn("passed", self._compile_and_run(
            ROOT / "tests/fixtures/hybrid580_uvm_abi_compat_test.c", R595_INC,
            "HYBRID_BRANCH_R595"))


    def test_legacy_gpu_info_callback_composes_with_uuid_owner_route(self):
        for relative, expected_hash in R580_GPU_INFO_HEADER_SHA256.items():
            header = R580_CURRENT_ROOT / relative
            self.assertTrue(header.is_file(), f"pinned R580 header is missing: {relative}")
            self.assertEqual(hashlib.sha256(header.read_bytes()).hexdigest(), expected_hash,
                             f"R580 source header changed: {relative}")
        source_values_output = self._compile_and_run(
            ROOT / "tests/fixtures/r580_gpu_info_source_values.c",
            R580_CURRENT_ROOT / "common/inc",
            extra_include_dirs=(
                R580_CURRENT_ROOT / "nvidia-uvm",
                R580_CURRENT_ROOT / "hybrid-sdk/common/sdk/nvidia/inc/class",
            ),
        )
        source_values = json.loads(source_values_output)
        self.assertEqual(source_values, {
            "gpu_arch": 0x140,
            "host_class": 0xC36F,
            "ce_class": 0xC3B5,
            "compute_class": 0xC3C0,
        })

        bridge = BRIDGE.read_text()
        open_start = "static uint32_t hybrid580_open_gpu_get_info("
        open_end = "static uint32_t hybrid580_legacy_gpu_get_info("
        start = "static uint32_t hybrid580_legacy_gpu_get_info("
        end = "static const struct hybrid580_uvm_gpu_info_backend_ops hybrid580_open_gpu_info_ops"
        self.assertEqual(bridge.count(open_start), 1)
        self.assertEqual(bridge.count(open_end), 1)
        self.assertEqual(bridge.count(start), 1)
        self.assertEqual(bridge.count(end), 1)
        open_callback = bridge.split(open_start, 1)[1].split(open_end, 1)[0]
        open_callback = open_start + open_callback
        callback = bridge.split(start, 1)[1].split(end, 1)[0]
        callback = start + callback

        register_start = "NV_STATUS nvUvmInterfaceRegisterGpu("
        register_end = "EXPORT_SYMBOL(nvUvmInterfaceRegisterGpu);"
        info_start = "NV_STATUS nvUvmInterfaceGetGpuInfo("
        info_end = "EXPORT_SYMBOL(nvUvmInterfaceGetGpuInfo);"
        self.assertEqual(bridge.count(register_start), 1)
        self.assertEqual(bridge.count(register_end), 1)
        self.assertEqual(bridge.count(info_start), 1)
        self.assertEqual(bridge.count(info_end), 1)
        register_wrapper = bridge.split(register_start, 1)[1].split(register_end, 1)[0]
        info_wrapper = bridge.split(info_start, 1)[1].split(info_end, 1)[0]
        register_wrapper = register_start + register_wrapper
        info_wrapper = info_start + info_wrapper

        fixture = (ROOT / "tests/fixtures/hybrid580_uvm_legacy_gpu_info_compat_test.c").read_text()
        open_insertion = "/* INSERT_EXACT_OPEN_GPU_INFO_CALLBACK */"
        insertion = "/* INSERT_EXACT_LEGACY_GPU_INFO_CALLBACK */"
        wrappers_insertion = "/* INSERT_EXACT_PUBLIC_GPU_API_WRAPPERS */"
        self.assertEqual(fixture.count(open_insertion), 1)
        self.assertEqual(fixture.count(insertion), 1)
        self.assertEqual(fixture.count(wrappers_insertion), 1)
        generated = (fixture.replace(open_insertion, open_callback)
                     .replace(insertion, callback)
                     .replace(wrappers_insertion,
                              register_wrapper + "\n" + info_wrapper))

        with tempfile.TemporaryDirectory(prefix="hybrid580-uvm-gpu-info-") as directory:
            source = Path(directory) / "legacy_gpu_info_compat_test.c"
            binary = Path(directory) / "legacy_gpu_info_compat_test"
            source.write_text(generated)
            build = subprocess.run(
                ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined", "-fno-sanitize-recover=all",
                 *(f"-DHYBRID580_TEST_{field.upper()}=0x{value:X}"
                   for field, value in (
                       ("gpu_arch", source_values["gpu_arch"]),
                       ("host_class", source_values["host_class"]),
                       ("ce_class", source_values["ce_class"]),
                       ("compute_class", source_values["compute_class"]),
                   )),
                 "-I", str(R595_INC), "-I", str(ROOT / "src"),
                 str(source), "-o", str(binary)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("legacy GPU-info adapter, UUID-owner route, and exported wrappers passed",
                      run.stdout)

    def test_current_r580_r595_gpu_info_value_domains(self):
        fixture = ROOT / "tests/fixtures/uvm_gpu_info_value_domain_probe.c"
        r580_uvm = R580_CURRENT_ROOT / "nvidia-uvm"
        r595_uvm = R595_CURRENT_ROOT / "nvidia-uvm"
        r580 = json.loads(self._compile_and_run(
            fixture, R580_CURRENT_ROOT / "common/inc", extra_include_dirs=(r580_uvm,)))
        r595 = json.loads(self._compile_and_run(
            fixture, R595_CURRENT_ROOT / "common/inc", "HYBRID_BRANCH_R595",
            extra_include_dirs=(r595_uvm,)))

        expected_gpu_info_fields = {
            "name", "uuid", "gpuArch", "gpuImplementation", "hostClass", "ceClass",
            "computeClass", "gpuInTcc", "subdeviceCount", "virtMode", "isSimulated",
            "gpcCount", "maxGpcCount", "tpcCount", "maxTpcPerGpcCount",
            "accessCntrBufferCount", "smcEnabled", "smcSwizzId", "smcUserClientInfo",
            "gpuConfComputeCaps", "sysmemLink", "sysmemLinkRateMBps",
            "systemMemoryWindowStart", "systemMemoryWindowSize", "connectedToSwitch",
            "nvswitchMemoryWindowStart", "egmEnabled", "egmPeerId", "egmBaseAddr",
            "nvswitchEgmMemoryWindowStart", "atsSupport", "nonPasidAtsSupport",
            "cdmmEnabled", "nvlDirectConnect", "nvlDirectConnectMemoryWindowStart",
        }
        self.assertEqual(set(r580["gpu_info_offsets"]), expected_gpu_info_fields)
        self.assertEqual(set(r595["gpu_info_offsets"]), expected_gpu_info_fields)
        self.assertEqual(r580["gpu_info_size"], r595["gpu_info_size"])
        self.assertEqual(r580["gpu_info_offsets"], r595["gpu_info_offsets"])
        self.assertEqual(r580["gpu_arch_gv100"], 0x140)
        self.assertEqual(r595["gpu_arch_gv100"], r580["gpu_arch_gv100"])
        self.assertEqual(r580["virt_mode"], {
            "none": 0, "legacy": 1, "sriov_heavy": 2,
            "sriov_standard": 3, "count": 4,
        })
        self.assertEqual(r595["virt_mode"], r580["virt_mode"])
        self.assertEqual(r580["sysmem_link"], {
            "none": 0, "pcie": 1, "nvlink1": 2, "nvlink2": 3,
            "nvlink3": 4, "nvlink4": 5, "nvlink5": 6, "c2c": 7,
        })
        self.assertEqual(r595["sysmem_link"], {
            "none": 0, "pcie": 1, "pcie_bar1": 2, "nvlink1": 3,
            "nvlink2": 4, "nvlink3": 5, "nvlink4": 6, "nvlink5": 7,
            "c2c": 8,
        })

    def test_r580_gpu_info_selector_ids_match_pinned_r595112_gv100_ids(self):
        for relative, expected_hash in R580_GPU_INFO_HEADER_SHA256.items():
            header = R580_CURRENT_ROOT / relative
            self.assertTrue(header.is_file(), f"pinned R580 header is missing: {relative}")
            self.assertEqual(hashlib.sha256(header.read_bytes()).hexdigest(), expected_hash,
                             f"R580 source header changed: {relative}")

        for relative, expected_hash in R595112_GPU_INFO_HEADER_SHA256.items():
            source_file = R595112_CURRENT_SOURCE / relative
            self.assertTrue(source_file.is_file(),
                            f"pinned R595.112.07 source file is missing: {relative}")
            self.assertEqual(hashlib.sha256(source_file.read_bytes()).hexdigest(),
                             expected_hash,
                             f"R595.112.07 source file changed: {relative}")
        self.assertIn("NVIDIA_VERSION = 595.112.07",
                      (R595112_CURRENT_SOURCE / "version.mk").read_text())

        probe = ROOT / "tests/fixtures/r580_gpu_info_source_values.c"
        branch_includes = {
            "R580.196.07": (
                R580_CURRENT_ROOT / "common/inc",
                R580_CURRENT_ROOT / "nvidia-uvm",
                R580_CURRENT_ROOT / "hybrid-sdk/common/sdk/nvidia/inc/class",
            ),
            "R595.112.07": (
                R595112_CURRENT_ROOT / "common/inc",
                R595112_CURRENT_ROOT / "nvidia-uvm",
                R595112_CURRENT_SOURCE / "src/common/sdk/nvidia/inc/class",
            ),
        }
        values = {}
        for branch, includes in branch_includes.items():
            values[branch] = json.loads(self._compile_and_run(
                probe, includes[0], extra_include_dirs=includes[1:]))

        expected = {
            "gpu_arch": 0x140,
            "host_class": 0xC36F,
            "ce_class": 0xC3B5,
            "compute_class": 0xC3C0,
        }
        self.assertEqual(values["R580.196.07"], expected)
        self.assertEqual(values["R595.112.07"], expected)

if __name__ == "__main__":
    unittest.main()
