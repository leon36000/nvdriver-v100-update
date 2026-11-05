# SPDX-License-Identifier: MIT
"""Tests for the R580-to-R595 candidate UVM capability-path audit."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_volta_uvm_candidate_paths import (  # noqa: E402
    R580_CAPABILITIES,
    R595_CAPABILITY_PATHS,
    build_prefetch_callback_comparison,
    build_volta_noncoherent_aperture_comparison,
    build_p2p_direction_mapping_audit,
    build_capability_report,
    source_anchors,
    source_manifest,
)


class VoltaUvmCandidatePathAuditTests(unittest.TestCase):
    def test_anchor_lookup_reports_exact_physical_lines(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "sample.c"
            source.write_text(
                "// selected_callback();\nconst char *s = \"selected_callback();\";\n"
                "selected_callback();\nselected_callback();\n",
                encoding="utf-8",
            )

            self.assertEqual(source_anchors(source, "selected_callback();"), [
                {"line": 3},
                {"line": 4},
            ])

    def test_anchor_lookup_rejects_symlink_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.c"
            target.write_text("selected_callback();\n", encoding="utf-8")
            link = root / "link.c"
            link.symlink_to(target)

            with self.assertRaisesRegex(ValueError, "non-symlink"):
                source_anchors(link, "selected_callback();")

    def test_source_manifest_is_stable_and_content_sensitive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "z.c").write_text("z;\n", encoding="utf-8")
            (root / "a.h").write_text("a;\n", encoding="utf-8")
            first = source_manifest(root)
            second = source_manifest(root)
            (root / "a.h").write_text("changed;\n", encoding="utf-8")
            changed = source_manifest(root)

        self.assertEqual(first, second)
        self.assertEqual(first[0], 2)
        self.assertNotEqual(first[1], changed[1])

    def test_source_manifest_rejects_symlink_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.c"
            target.write_text("source;\n", encoding="utf-8")
            (root / "link.c").symlink_to(target)

            with self.assertRaisesRegex(ValueError, "rejects symlink"):
                source_manifest(root)

    def _write_source_fixture(self, r580_root: Path, candidate_root: Path):
        assignments = "\n".join(item["assignment"] for item in R580_CAPABILITIES)
        (r580_root / "uvm_volta.c").write_text(assignments + "\n", encoding="utf-8")
        for item in R580_CAPABILITIES:
            relative_path, anchor = item["r580_consumers"][0]
            path = r580_root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as output:
                output.write(anchor + "\n")

        for mapping in R595_CAPABILITY_PATHS.values():
            for relative_path, anchor, _role in mapping["anchors"]:
                path = candidate_root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as output:
                    output.write(anchor + "\n")
            for relative_path, _token, _role in mapping.get("absent_candidate_tokens", []):
                path = candidate_root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch(exist_ok=True)

    def test_candidate_map_covers_all_old_fields_and_marks_runtime_unknown(self):
        self.assertEqual(
            {item["field"] for item in R580_CAPABILITIES},
            set(R595_CAPABILITY_PATHS),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r580_root = root / "r580"
            candidate_root = root / "candidate"
            r580_root.mkdir()
            candidate_root.mkdir()
            self._write_source_fixture(r580_root, candidate_root)

            report = build_capability_report(r580_root, candidate_root)

        self.assertEqual(report["capability_count"], 11)
        self.assertEqual(report["candidate_legacy_identifiers_absent_count"], 11)
        self.assertTrue(all(not item["runtime_or_hardware_validated"]
                            for item in report["capabilities"]))
        scoped = next(item for item in report["capabilities"]
                      if item["field"] == "scoped_atomics_supported")
        self.assertEqual(scoped["candidate_source_anchors"], [])
        self.assertEqual(
            scoped["candidate_disposition"],
            "legacy-system-wide-atomics-uapi-removed",
        )
        self.assertEqual(len(scoped["candidate_absent_source_tokens"]), 7)
        self.assertTrue(all(
            item["qualification"] == "absent-from-live-source"
            for item in scoped["candidate_absent_source_tokens"]
        ))

    def test_removed_system_wide_atomics_route_must_remain_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r580_root = root / "r580"
            candidate_root = root / "candidate"
            r580_root.mkdir()
            candidate_root.mkdir()
            self._write_source_fixture(r580_root, candidate_root)

            (candidate_root / "uvm.c").write_text(
                "UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_ENABLE_SYSTEM_WIDE_ATOMICS, handler);\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "legacy candidate token unexpectedly appears"):
                build_capability_report(r580_root, candidate_root)

    def _write_prefetch_fixture(self, r580_root: Path, candidate_root: Path):
        helper = """static void mmu_set_prefetch_faults(uvm_parent_gpu_t *parent_gpu, bool enable)
{
    volatile NvU32 *prefetch_ctrl = parent_gpu->fault_buffer.rm_info.replayable.pPrefetchCtrl;
    if (prefetch_ctrl == NULL) {
        NV_STATUS status;
        UVM_ASSERT(g_uvm_global.conf_computing_enabled);
        status = nvUvmInterfaceTogglePrefetchFaults(&parent_gpu->fault_buffer.rm_info, (NvBool)enable);
        UVM_ASSERT(status == NV_OK);
    }
    else {
        NvU32 prefetch_ctrl_value = UVM_GPU_READ_ONCE(*prefetch_ctrl);
        if (enable)
            prefetch_ctrl_value = WRITE_HWCONST(prefetch_ctrl_value, _PFB_PRI_MMU_PAGE, FAULT_CTRL, PRF_FILTER, SEND_ALL);
        else
            prefetch_ctrl_value = WRITE_HWCONST(prefetch_ctrl_value, _PFB_PRI_MMU_PAGE, FAULT_CTRL, PRF_FILTER, SEND_NONE);
        UVM_GPU_WRITE_ONCE(*prefetch_ctrl, prefetch_ctrl_value);
    }
}
"""
        old_wrapper = """void uvm_hal_pascal_mmu_enable_prefetch_faults(uvm_parent_gpu_t *parent_gpu)
{
    UVM_ASSERT(parent_gpu->prefetch_fault_supported);
    mmu_set_prefetch_faults(parent_gpu, true);
}
"""
        candidate_wrapper = """void uvm_hal_turing_mmu_enable_prefetch_faults(uvm_parent_gpu_t *parent_gpu)
{
    mmu_set_prefetch_faults(parent_gpu, true);
}
"""
        (r580_root / "uvm_pascal_mmu.c").write_text(helper + old_wrapper, encoding="utf-8")
        (candidate_root / "uvm_turing_mmu.c").write_text(helper + candidate_wrapper, encoding="utf-8")
        (r580_root / "uvm_hal.c").write_text(
            """static uvm_hal_class_ops_t arch_table[] = {
{ .id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100,
  .enable_prefetch_faults = uvm_hal_pascal_mmu_enable_prefetch_faults, }
{ .id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100,
  .parent_id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100, }
};
""",
            encoding="utf-8",
        )
        (candidate_root / "uvm_hal.c").write_text(
            """static uvm_hal_class_ops_t arch_table[] = {
{ .id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100,
  .enable_prefetch_faults = uvm_hal_turing_mmu_enable_prefetch_faults,
  .disable_prefetch_faults = uvm_hal_turing_mmu_disable_prefetch_faults, }
};
""",
            encoding="utf-8",
        )
        (r580_root / "uvm_volta.c").write_text(
            "parent_gpu->prefetch_fault_supported = true;\n", encoding="utf-8",
        )
        (r580_root / "uvm_gpu_replayable_faults.c").write_text(
            "parent_gpu->fault_buffer.prefetch_faults_enabled = parent_gpu->prefetch_fault_supported;\n",
            encoding="utf-8",
        )
        (candidate_root / "uvm_gpu_replayable_faults.c").write_text(
            "parent_gpu->fault_buffer.prefetch_faults_enabled = true;\n"
            "parent_gpu->arch_hal->enable_prefetch_faults(parent_gpu);\n",
            encoding="utf-8",
        )

    def test_prefetch_control_matches_and_guard_moves_to_candidate_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r580_root = root / "r580"
            candidate_root = root / "candidate"
            r580_root.mkdir()
            candidate_root.mkdir()
            self._write_prefetch_fixture(r580_root, candidate_root)

            report = build_prefetch_callback_comparison(r580_root, candidate_root)

        self.assertTrue(report["control_helper"]["identical_after_comments_literals_and_whitespace_masked"])
        self.assertEqual(
            report["control_helper"]["r580"]["normalized_sha256"],
            report["control_helper"]["candidate"]["normalized_sha256"],
        )
        self.assertTrue(report["enable_wrapper_guard"]["r580_prefetch_fault_supported_assertion"])
        self.assertFalse(report["enable_wrapper_guard"]["candidate_prefetch_fault_supported_assertion"])
        self.assertTrue(report["selected_architecture_rows"]["r580_gv100"]["parent_gp100"])
        self.assertTrue(report["selected_architecture_rows"]["candidate_gv100"]["enable_turing_callback"])
        self.assertFalse(report["runtime_or_hardware_validated"])

    def test_prefetch_callback_moved_outside_gv100_architecture_row_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r580_root = root / "r580"
            candidate_root = root / "candidate"
            r580_root.mkdir()
            candidate_root.mkdir()
            self._write_prefetch_fixture(r580_root, candidate_root)

            candidate_path = candidate_root / "uvm_hal.c"
            candidate_path.write_text(
                """static uvm_hal_class_ops_t arch_table[] = {
{ .id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100, }
{ .id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_TU100,
  .enable_prefetch_faults = uvm_hal_turing_mmu_enable_prefetch_faults,
  .disable_prefetch_faults = uvm_hal_turing_mmu_disable_prefetch_faults, }
};
""",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "candidate GV100 row does not select"):
                build_prefetch_callback_comparison(r580_root, candidate_root)

    def test_prefetch_control_change_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r580_root = root / "r580"
            candidate_root = root / "candidate"
            r580_root.mkdir()
            candidate_root.mkdir()
            self._write_prefetch_fixture(r580_root, candidate_root)

            candidate_path = candidate_root / "uvm_turing_mmu.c"
            candidate_path.write_text(
                candidate_path.read_text(encoding="utf-8").replace("SEND_ALL", "SEND_NONE", 1),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "prefetch MMU control helpers differ"):
                build_prefetch_callback_comparison(r580_root, candidate_root)

    def _write_noncoherent_aperture_fixture(self, r580_root: Path, candidate_root: Path):
        old_pte = """static NvU64 make_pte_volta(uvm_aperture_t aperture, NvU64 address, uvm_prot_t prot, NvU64 flags)
{
    if (aperture == UVM_APERTURE_SYS)
        aperture_bits = NV_MMU_VER2_PTE_APERTURE_SYSTEM_COHERENT_MEMORY;
    address >>= NV_MMU_VER2_PTE_ADDRESS_SHIFT;
    if (aperture == UVM_APERTURE_SYS)
        pte_bits |= HWVALUE64(_MMU_VER2, PTE, ADDRESS_SYS, address);
    return pte_bits;
}
"""
        candidate_pte = """static NvU64 make_pte_volta(uvm_aperture_t aperture, NvU64 address, uvm_prot_t prot, NvU64 flags)
{
    if (aperture == UVM_APERTURE_SYS)
        aperture_bits = NV_MMU_VER2_PTE_APERTURE_SYSTEM_COHERENT_MEMORY;
    else if (aperture == UVM_APERTURE_SYS_NON_COHERENT)
        aperture_bits = NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY;
    address >>= NV_MMU_VER2_PTE_ADDRESS_SHIFT;
    if (aperture == UVM_APERTURE_SYS || aperture == UVM_APERTURE_SYS_NON_COHERENT)
        pte_bits |= HWVALUE64(_MMU_VER2, PTE, ADDRESS_SYS, address);
    return pte_bits;
}
"""
        old_peer = """static uvm_aperture_t parent_gpu_peer_aperture(uvm_parent_gpu_t *local, uvm_parent_gpu_t *remote, uvm_parent_gpu_peer_t *parent_peer_caps)
{
    return UVM_APERTURE_PEER(parent_peer_caps->peer_ids[peer_index]);
}
"""
        candidate_peer = """static uvm_aperture_t parent_gpu_peer_aperture(uvm_parent_gpu_t *local, uvm_parent_gpu_t *remote, uvm_parent_gpu_peer_t *parent_peer_caps)
{
    if (parent_peer_caps->link_type == UVM_GPU_LINK_PCIE_BAR1) {
        const bool enable_atomics = parent_peer_caps->bar1_p2p_pcie_atomics_enabled[peer_index];
        return enable_atomics ? UVM_APERTURE_SYS : UVM_APERTURE_SYS_NON_COHERENT;
    }
    return UVM_APERTURE_PEER(parent_peer_caps->peer_ids[peer_index]);
}
"""
        old_ce = """static NvU32 ce_aperture(uvm_aperture_t aperture)
{
    UVM_ASSERT_MSG(aperture == UVM_APERTURE_VID || aperture == UVM_APERTURE_SYS, "aperture");
    if (aperture == UVM_APERTURE_SYS)
        return HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, COHERENT_SYSMEM);
    else
        return HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, LOCAL_FB);
}
"""
        candidate_ce = """static NvU32 ce_aperture(uvm_aperture_t aperture)
{
    UVM_ASSERT_MSG(aperture == UVM_APERTURE_VID || aperture == UVM_APERTURE_SYS || aperture == UVM_APERTURE_SYS_NON_COHERENT, "aperture");
    if (aperture == UVM_APERTURE_SYS)
        return HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, COHERENT_SYSMEM);
    else if (aperture == UVM_APERTURE_SYS_NON_COHERENT)
        return HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, NONCOHERENT_SYSMEM);
    else
        return HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, LOCAL_FB);
}
"""

        for root, pte, peer, ce in (
            (r580_root, old_pte, old_peer, old_ce),
            (candidate_root, candidate_pte, candidate_peer, candidate_ce),
        ):
            (root / "uvm_volta_mmu.c").write_text(pte, encoding="utf-8")
            (root / "uvm_gpu.c").write_text(peer, encoding="utf-8")
            (root / "uvm_volta_ce.c").write_text(ce, encoding="utf-8")
            header = root / "hwref/volta/gv100/dev_mmu.h"
            header.parent.mkdir(parents=True, exist_ok=True)
            header.write_text(
                "#define NV_MMU_VER2_PTE_APERTURE 2:1\n"
                "#define NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY 0x00000003\n",
                encoding="utf-8",
            )
            (root / "clc3b5.h").write_text(
                "#define NVC3B5_SET_SRC_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM (0x00000002)\n"
                "#define NVC3B5_SET_DST_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM (0x00000002)\n",
                encoding="utf-8",
            )

        (candidate_root / "uvm_gpu.c").write_text(
            candidate_peer + "\n"
            "return enable_atomics ? UVM_APERTURE_SYS : UVM_APERTURE_SYS_NON_COHERENT;\n"
            "address += parent_peer_caps->bar1_p2p_dma_base_address[peer_index];\n",
            encoding="utf-8",
        )
        (candidate_root / "uvm_get_rm_ptes_test.c").write_text(
            "aperture = get_aperture(va_space, memory_owning_gpu, memory_mapping_gpu);\n"
            "pte = hal->make_pte(aperture, phys_addr, prot, flags);\n",
            encoding="utf-8",
        )
        (candidate_root / "uvm_map_external.c").write_text(
            "nvUvmInterfaceGetExternalAllocPtes(gpu_va_space, memory);\n", encoding="utf-8",
        )
        (candidate_root / "uvm_hal_types.h").write_text(
            "// UVM does not use SYS_NON_COHERENT for its internal mappings,\n", encoding="utf-8",
        )

    def test_noncoherent_aperture_path_is_explicitly_traced_for_volta(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r580_root = root / "r580"
            candidate_root = root / "candidate"
            r580_root.mkdir()
            candidate_root.mkdir()
            self._write_noncoherent_aperture_fixture(r580_root, candidate_root)

            report = build_volta_noncoherent_aperture_comparison(r580_root, candidate_root)

        self.assertFalse(report["r580"]["volta_pte_and_ce_support_sys_noncoherent"])
        self.assertTrue(all(report["candidate"]["checks"].values()))
        self.assertFalse(report["runtime_or_hardware_validated"])

    def test_noncoherent_aperture_encoding_change_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r580_root = root / "r580"
            candidate_root = root / "candidate"
            r580_root.mkdir()
            candidate_root.mkdir()
            self._write_noncoherent_aperture_fixture(r580_root, candidate_root)

            candidate_pte = candidate_root / "uvm_volta_mmu.c"
            candidate_pte.write_text(
                candidate_pte.read_text(encoding="utf-8").replace(
                    "NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY",
                    "NV_MMU_VER2_PTE_APERTURE_SYSTEM_COHERENT_MEMORY",
                    1,
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "candidate Volta SYS_NON_COHERENT PTE/P2P/CE path is incomplete"):
                build_volta_noncoherent_aperture_comparison(r580_root, candidate_root)

    def _write_p2p_direction_fixture(self, candidate_root: Path):
        uvm = candidate_root / "nvidia-uvm"
        common = candidate_root / "common/inc"
        nvidia = candidate_root / "nvidia"
        uvm.mkdir(parents=True)
        common.mkdir(parents=True)
        nvidia.mkdir(parents=True)
        (uvm / "uvm_gpu.c").write_text(
            """static NV_STATUS get_parent_p2p_caps(uvm_parent_gpu_t *parent_gpu0,
                                     uvm_parent_gpu_t *parent_gpu1,
                                     UvmGpuP2PCapsParams *p2p_caps_params)
{
    uvmGpuDeviceHandle rm_device0, rm_device1;
    if (uvm_parent_id_value(parent_gpu0->id) < uvm_parent_id_value(parent_gpu1->id)) {
        rm_device0 = parent_gpu0->rm_device;
        rm_device1 = parent_gpu1->rm_device;
    }
    else {
        rm_device0 = parent_gpu1->rm_device;
        rm_device1 = parent_gpu0->rm_device;
    }
    memset(p2p_caps_params, 0, sizeof(*p2p_caps_params));
    status = uvm_rm_locked_call(nvUvmInterfaceGetP2PCaps(rm_device0, rm_device1, p2p_caps_params));
    return NV_OK;
}
static NV_STATUS parent_peers_init(uvm_parent_gpu_t *parent_gpu0,
                                   uvm_parent_gpu_t *parent_gpu1,
                                   uvm_parent_gpu_peer_t *parent_peer_caps)
{
    parent_peer_caps->bar1_p2p_pcie_atomics_enabled[0] = p2p_caps_params.bar1PcieAtomics[0];
    parent_peer_caps->bar1_p2p_pcie_atomics_enabled[1] = p2p_caps_params.bar1PcieAtomics[1];
    return NV_OK;
}
static uvm_aperture_t parent_gpu_peer_aperture(uvm_parent_gpu_t *local,
                                               uvm_parent_gpu_t *remote,
                                               uvm_parent_gpu_peer_t *parent_peer_caps)
{
    size_t peer_index;
    if (uvm_parent_id_value(local->id) < uvm_parent_id_value(remote->id))
        peer_index = 0;
    else
        peer_index = 1;
    if (parent_peer_caps->link_type == UVM_GPU_LINK_PCIE_BAR1) {
        const bool enable_atomics = parent_peer_caps->bar1_p2p_pcie_atomics_enabled[peer_index];
        return enable_atomics ? UVM_APERTURE_SYS : UVM_APERTURE_SYS_NON_COHERENT;
    }
    return UVM_APERTURE_PEER(parent_peer_caps->peer_ids[peer_index]);
}
static bool gpu_phys_address_is_bar1p2p_peer(uvm_gpu_t *gpu, uvm_gpu_phys_address_t address)
{
    const int peer_index = (uvm_parent_id_cmp(gpu->parent->id, peer_parent_gpu->id) < 0) ? 0 : 1;
    if (address.address >= peer_caps->bar1_p2p_dma_base_address[peer_index] &&
        address.address < (peer_caps->bar1_p2p_dma_base_address[peer_index] +
                           peer_caps->bar1_p2p_dma_size[peer_index]))
        return true;
    return false;
}
""",
            encoding="utf-8",
        )
        (nvidia / "nv_uvm_interface.c").write_text(
            """NV_STATUS nvUvmInterfaceGetP2PCaps(uvmGpuDeviceHandle device1,
                                   uvmGpuDeviceHandle device2,
                                   UvmGpuP2PCapsParams *p2pCapsParams)
{
    status = rm_gpu_ops_get_p2p_caps(sp,
                                     (gpuDeviceHandle)device1,
                                     (gpuDeviceHandle)device2,
                                     p2pCapsParams);
    return status;
}
""",
            encoding="utf-8",
        )
        (common / "nv_uvm_types.h").write_text(
            """typedef struct UvmGpuP2PCapsParams_tag {
    // Out: peerId[i] contains gpu[i]'s peer id of gpu[1 - i]. Only defined if
    // True if GPU i can use PCIe atomics on locations in GPU[i-1]
    NvBool bar1PcieAtomics[2];
} UvmGpuP2PCapsParams;
""",
            encoding="utf-8",
        )
        (common / "rm-gpu-ops.h").write_text(
            "NV_STATUS rm_gpu_ops_get_p2p_caps(nvidia_stack_t *, nvgpuDeviceHandle_t, "
            "nvgpuDeviceHandle_t, nvgpuP2PCapsParams_t);\n",
            encoding="utf-8",
        )

    def test_p2p_consumer_direction_is_traced_but_rm_values_remain_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate_root = Path(temporary) / "candidate"
            candidate_root.mkdir()
            self._write_p2p_direction_fixture(candidate_root)

            report = build_p2p_direction_mapping_audit(candidate_root)

        self.assertEqual(report["source_scan"]["rm_gpu_ops_get_p2p_caps_definition_count"], 0)
        self.assertEqual(report["consumer_direction_contract"]["bar1PcieAtomics_index_0"],
                         "consumer uses for lower-ID local GPU accessing higher-ID peer")
        self.assertEqual(report["consumer_direction_contract"]["bar1PcieAtomics_index_1"],
                         "consumer uses for higher-ID local GPU accessing lower-ID peer")
        self.assertIn("ambiguous", report["header_comment_review"]["ambiguity"])
        self.assertFalse(report["rm_capability_values_observed"])
        self.assertFalse(report["runtime_or_hardware_validated"])

    def test_p2p_reversed_rm_handle_order_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate_root = Path(temporary) / "candidate"
            candidate_root.mkdir()
            self._write_p2p_direction_fixture(candidate_root)
            path = candidate_root / "nvidia-uvm/uvm_gpu.c"
            source = path.read_text(encoding="utf-8").replace(
                "nvUvmInterfaceGetP2PCaps(rm_device0, rm_device1, p2p_caps_params)",
                "nvUvmInterfaceGetP2PCaps(rm_device1, rm_device0, p2p_caps_params)",
                1,
            )
            path.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "rm_handles_normalized_to_ascending_parent_id"):
                build_p2p_direction_mapping_audit(candidate_root)

    def test_p2p_swapped_atomic_capability_copy_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate_root = Path(temporary) / "candidate"
            candidate_root.mkdir()
            self._write_p2p_direction_fixture(candidate_root)
            path = candidate_root / "nvidia-uvm/uvm_gpu.c"
            source = path.read_text(encoding="utf-8").replace(
                "bar1_p2p_pcie_atomics_enabled[0] = p2p_caps_params.bar1PcieAtomics[0]",
                "bar1_p2p_pcie_atomics_enabled[0] = p2p_caps_params.bar1PcieAtomics[1]",
                1,
            )
            path.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "atomic_capability_indices_copied_without_swapping"):
                build_p2p_direction_mapping_audit(candidate_root)

    def test_p2p_inverted_local_direction_index_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate_root = Path(temporary) / "candidate"
            candidate_root.mkdir()
            self._write_p2p_direction_fixture(candidate_root)
            path = candidate_root / "nvidia-uvm/uvm_gpu.c"
            source = path.read_text(encoding="utf-8").replace(
                "peer_index = 0;\n    else\n        peer_index = 1;",
                "peer_index = 1;\n    else\n        peer_index = 0;",
                1,
            )
            path.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "lower_id_to_higher_id_uses_capability_index_zero"):
                build_p2p_direction_mapping_audit(candidate_root)

    def test_rm_p2p_capability_definition_in_candidate_tree_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate_root = Path(temporary) / "candidate"
            candidate_root.mkdir()
            self._write_p2p_direction_fixture(candidate_root)
            (candidate_root / "nvidia/rm_adapter.c").write_text(
                "NV_STATUS rm_gpu_ops_get_p2p_caps(nvidia_stack_t *sp) { return NV_OK; }\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "RM P2P capability producer unexpectedly found"):
                build_p2p_direction_mapping_audit(candidate_root)

    def test_missing_candidate_path_anchor_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r580_root = root / "r580"
            candidate_root = root / "candidate"
            r580_root.mkdir()
            candidate_root.mkdir()
            self._write_source_fixture(r580_root, candidate_root)

            path = candidate_root / "uvm_map_external.c"
            source = path.read_text(encoding="utf-8")
            source = source.replace("return NV_ERR_INVALID_DEVICE;\n", "", 1)
            path.write_text(source, encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "candidate source anchor is missing"):
                build_capability_report(r580_root, candidate_root)


if __name__ == "__main__":
    unittest.main()
