# SPDX-License-Identifier: MIT
"""Tests for explicit, source-derived R595 GV100 UVM HAL row staging."""
import sys
from pathlib import Path
import io
import hashlib
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.probe_r595_gv100_complete_hal import (  # noqa: E402
    add_volta_mmu_mode_adapter,
    audit_private_hal_helper_linkage,
    extract_callback_prototype,
    format_complete_hal_row,
    insert_complete_hal_row,
    localize_unreferenced_hal_helpers,
    merge_callback_prototypes,
    _stage_extra_sources,
    stage_missing_archive_headers,
    stage_legacy_subchannel_aliases,
    adapt_unsupported_access_counter_return,
    adapt_volta_prefetch_callbacks,
    audit_volta_prefetch_capability_contract,
    adapt_volta_noncoherent_mmu_pte,
    adapt_volta_noncoherent_ce_aperture,
    adapt_volta_shared_maxwell_ce_phys_mode,
    adapt_gv100_plc_external_map_guard,
    audit_staged_gv100_dispatch,
    candidate_limitations,
)
from tools.audit_volta_uvm_hal_dispatch import (  # noqa: E402
    audit_volta_uvm_dispatch,
)
from tools.audit_r595_uvm_hal_table_closure import (  # noqa: E402
    REQUIRED_GV100_TABLE_TARGETS,
)

TARGETS = dict(REQUIRED_GV100_TABLE_TARGETS)


class R595Gv100CompleteHalTests(unittest.TestCase):
    def test_v12_limitations_describe_direct_prefetch_callback_reuse(self):
        limitations = candidate_limitations()
        prefetch = [item for item in limitations if "prefetch callbacks" in item]
        self.assertEqual(1, len(prefetch))
        self.assertIn("directly selects R595's existing Turing", prefetch[0])
        self.assertIn("no private capability field or Volta wrapper is added", prefetch[0])
        self.assertIn("not runtime behavior on Volta", prefetch[0])
        self.assertNotIn("asserts the capability", prefetch[0])

    def test_pinned_r595112_source_excludes_volta_and_overlay_restores_selectable_rows(self):
        fixture_root = ROOT / "tests/fixtures"
        r580_path = fixture_root / (
            "upstream/nvidia-kernel-module-source/580.196.07/uvm_hal.c")
        stock_path = fixture_root / (
            "upstream/nvidia-open-gpu-kernel-modules/595.112.07/uvm_hal.c")
        overlay_path = fixture_root / (
            "candidates/r595112-gv100-hal-r580196/uvm_hal.c")
        expected_hashes = {
            r580_path: "9e1c8c1e0e70d26328809713fc7af7f79e49a57a545ea474b36d70a07d56325d",
            stock_path: "d3815691e974e551b0fb51ac0d7c3101b31452a56f20f8ba4098e873f6673199",
            overlay_path: "3a7c5f6f892102663af00fdcb9e638a3a96a2b8cddd00af25d9054169106c248",
        }
        sources = {}
        for path, expected_hash in expected_hashes.items():
            source_bytes = path.read_bytes()
            self.assertEqual(hashlib.sha256(source_bytes).hexdigest(), expected_hash)
            sources[path] = source_bytes.decode("utf-8", errors="strict")

        stock = audit_volta_uvm_dispatch(
            sources[r580_path], sources[stock_path],
            modern_branch="R595.112.07",
        )
        self.assertEqual(set(stock["modern_missing_targets"]), set(TARGETS))
        self.assertFalse(stock["modern_static_dispatch_candidate"])
        self.assertEqual(set(stock["modern_selector_contract"]), set(TARGETS))

        candidate = audit_volta_uvm_dispatch(
            sources[r580_path], sources[overlay_path],
            modern_branch="R595.112.07-plus-R580.196.07-GV100-HAL",
        )
        self.assertEqual(candidate["modern_missing_targets"], {})
        self.assertTrue(candidate["modern_inheritance_closure_valid"])
        self.assertTrue(candidate["modern_static_dispatch_candidate"])
        self.assertEqual(candidate["modern_resolved_callback_counts"], {
            "ce_table": 22,
            "host_table": 33,
            "arch_table": 5,
            "fault_buffer_table": 14,
            "access_counter_buffer_table": 7,
            "sec2_table": 5,
        })
        self.assertEqual(candidate["r580_to_modern_callback_change_count"], 3)

        dispatch = audit_staged_gv100_dispatch(sources[overlay_path])
        self.assertTrue(dispatch["static_dispatch_candidate"])
        self.assertEqual(len(dispatch["selector_contract"]), 6)
        self.assertEqual(sum(row["callback_count"]
                             for row in dispatch["selected_rows"].values()), 86)
        self.assertFalse(dispatch["runtime_or_hardware_validated"])

    def test_staged_dispatch_gate_rejects_a_missing_gv100_class_row(self):
        candidate = (
            ROOT / "tests/fixtures/candidates/r595112-gv100-hal-r580196/uvm_hal.c"
        ).read_text()
        mutated = candidate.replace(
            ".id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100,",
            ".id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100_REMOVED,",
            1,
        )
        dispatch = audit_staged_gv100_dispatch(mutated)
        self.assertFalse(dispatch["static_dispatch_candidate"])
        self.assertIn("arch_table", dispatch["errors"])

        mutated_selector = candidate.replace(
            "ops_find_by_id(fault_buffer_table,",
            "ops_find_by_id(missing_fault_buffer_table,",
            1,
        )
        with self.assertRaisesRegex(ValueError, "fault_buffer_table lookup"):
            audit_staged_gv100_dispatch(mutated_selector)

    @staticmethod
    def noncoherent_ce_fixtures():
        source = '''
            static NvU32 ce_aperture(uvm_aperture_t aperture)
            {
                BUILD_BUG_ON(HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, LOCAL_FB) !=
                             HWCONST(C3B5, SET_DST_PHYS_MODE, TARGET, LOCAL_FB));
                BUILD_BUG_ON(HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, COHERENT_SYSMEM) !=
                             HWCONST(C3B5, SET_DST_PHYS_MODE, TARGET, COHERENT_SYSMEM));

                UVM_ASSERT_MSG(aperture == UVM_APERTURE_VID || aperture == UVM_APERTURE_SYS,
                               "aperture 0x%x\\n", aperture);

                if (aperture == UVM_APERTURE_SYS)
                    return HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, COHERENT_SYSMEM);
                else
                    return HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, LOCAL_FB);
            }
        '''
        header = '''
            #define NVC3B5_SET_SRC_PHYS_MODE_TARGET 1:0
            #define NVC3B5_SET_SRC_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM (0x00000002)
            #define NVC3B5_SET_DST_PHYS_MODE_TARGET 1:0
            #define NVC3B5_SET_DST_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM (0x00000002)
        '''
        hal_types = "UVM_APERTURE_SYS_NON_COHERENT,"
        return source, header, hal_types

    def test_volta_ce_noncoherent_aperture_adapter_uses_c3b5_encoding(self):
        source, header, hal_types = self.noncoherent_ce_fixtures()
        adapted, evidence = adapt_volta_noncoherent_ce_aperture(
            source, header, header, hal_types)
        self.assertIn(
            "HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, NONCOHERENT_SYSMEM) !=",
            adapted,
        )
        self.assertIn(
            "aperture == UVM_APERTURE_SYS_NON_COHERENT",
            adapted,
        )
        self.assertIn(
            "return HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, NONCOHERENT_SYSMEM);",
            adapted,
        )
        self.assertTrue(evidence["gv100_c3b5_noncoherent_target_is_2"])
        self.assertTrue(evidence["src_dst_target_encodings_match"])
        self.assertTrue(evidence["coherent_and_vid_routes_preserved"])

    def test_volta_ce_noncoherent_adapter_fails_closed_on_header_or_source_drift(self):
        source, header, hal_types = self.noncoherent_ce_fixtures()
        with self.assertRaisesRegex(ValueError, "GV100 C3B5 field width/value contract"):
            adapt_volta_noncoherent_ce_aperture(
                source, header, header.replace("00000002", "00000003", 1), hal_types)
        with self.assertRaisesRegex(ValueError, "GV100 C3B5 field width"):
            adapt_volta_noncoherent_ce_aperture(
                source, header.replace("1:0", "0:0", 1), header, hal_types)
        with self.assertRaisesRegex(ValueError, "legacy ce_aperture contract"):
            adapt_volta_noncoherent_ce_aperture(
                source.replace(
                    "return HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, LOCAL_FB);",
                    "return HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, COHERENT_SYSMEM);"),
                header, header, hal_types)

    @staticmethod
    def shared_maxwell_ce_fixtures():
        source = '''
            static NvU32 ce_aperture(uvm_aperture_t aperture)
            {
                BUILD_BUG_ON(HWCONST(B0B5, SET_SRC_PHYS_MODE, TARGET, LOCAL_FB) !=
                             HWCONST(B0B5, SET_DST_PHYS_MODE, TARGET, LOCAL_FB));
                BUILD_BUG_ON(HWCONST(B0B5, SET_SRC_PHYS_MODE, TARGET, COHERENT_SYSMEM) !=
                             HWCONST(B0B5, SET_DST_PHYS_MODE, TARGET, COHERENT_SYSMEM));

                UVM_ASSERT_MSG(aperture == UVM_APERTURE_VID || aperture == UVM_APERTURE_SYS,
                               "aperture 0x%x\\n", aperture);

                if (aperture == UVM_APERTURE_SYS)
                    return HWCONST(B0B5, SET_SRC_PHYS_MODE, TARGET, COHERENT_SYSMEM);
                else
                    return HWCONST(B0B5, SET_SRC_PHYS_MODE, TARGET, LOCAL_FB);
            }
            NvU32 uvm_hal_maxwell_ce_phys_mode(uvm_push_t *push,
                                                uvm_gpu_address_t dst,
                                                uvm_gpu_address_t src)
            {
                return ce_aperture(dst.aperture) + ce_aperture(src.aperture);
            }
        '''

        def header(class_name):
            prefix = "NV" + class_name
            return f'''\
                #define {prefix}_SET_SRC_PHYS_MODE (0x00000260)
                #define {prefix}_SET_SRC_PHYS_MODE_TARGET 1:0
                #define {prefix}_SET_SRC_PHYS_MODE_TARGET_LOCAL_FB (0x00000000)
                #define {prefix}_SET_SRC_PHYS_MODE_TARGET_COHERENT_SYSMEM (0x00000001)
                #define {prefix}_SET_SRC_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM (0x00000002)
                #define {prefix}_SET_DST_PHYS_MODE (0x00000264)
                #define {prefix}_SET_DST_PHYS_MODE_TARGET 1:0
                #define {prefix}_SET_DST_PHYS_MODE_TARGET_LOCAL_FB (0x00000000)
                #define {prefix}_SET_DST_PHYS_MODE_TARGET_COHERENT_SYSMEM (0x00000001)
                #define {prefix}_SET_DST_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM (0x00000002)
            '''

        return source, header("B0B5"), header("C3B5"), "UVM_APERTURE_SYS_NON_COHERENT,"

    def test_volta_memcopy_dispatch_uses_adapted_maxwell_phys_mode(self):
        source, b0b5, c3b5, hal_types = self.shared_maxwell_ce_fixtures()
        adapted, evidence = adapt_volta_shared_maxwell_ce_phys_mode(
            source, b0b5, b0b5, c3b5, c3b5, hal_types,
            "uvm_hal_maxwell_ce_phys_mode")
        self.assertIn(
            "return HWCONST(B0B5, SET_SRC_PHYS_MODE, TARGET, NONCOHERENT_SYSMEM);",
            adapted,
        )
        self.assertIn("uvm_hal_maxwell_ce_phys_mode", evidence["volta_phys_mode_callback"])
        self.assertTrue(evidence["b0b5_and_c3b5_method_contracts_match"])
        self.assertTrue(evidence["src_dst_target_encodings_match"])

    def test_volta_shared_maxwell_ce_adapter_rejects_dispatch_or_header_drift(self):
        source, b0b5, c3b5, hal_types = self.shared_maxwell_ce_fixtures()
        with self.assertRaisesRegex(ValueError, "Volta CE phys_mode dispatch"):
            adapt_volta_shared_maxwell_ce_phys_mode(
                source, b0b5, b0b5, c3b5, c3b5, hal_types,
                "uvm_hal_turing_ce_phys_mode")
        with self.assertRaisesRegex(ValueError, "C3B5 physical-mode method contract changed"):
            adapt_volta_shared_maxwell_ce_phys_mode(
                source, b0b5, b0b5,
                c3b5.replace("0x00000260", "0x00000268", 1), c3b5,
                hal_types, "uvm_hal_maxwell_ce_phys_mode")
        with self.assertRaisesRegex(ValueError, "legacy Maxwell ce_aperture contract"):
            adapt_volta_shared_maxwell_ce_phys_mode(
                source.replace("LOCAL_FB);", "COHERENT_SYSMEM);", 1),
                b0b5, b0b5, c3b5, c3b5, hal_types,
                "uvm_hal_maxwell_ce_phys_mode")

    @staticmethod
    def plc_source_fixtures():
        modern = '''
            static NV_STATUS uvm_map_external_allocation_on_gpu(
                uvm_gpu_t *mapping_gpu, const uvm_map_rm_params_t *map_rm_params)
            {
                uvm_assert_rwsem_locked_read(&va_space->lock);
                if (!uvm_gpu_can_address(mapping_gpu, base, length))
                    return NV_ERR_OUT_OF_RANGE;
                uvm_unmap_external_in_range(mapping_gpu);
                ext_gpu_map = uvm_kvmalloc_zero(sizeof(*ext_gpu_map));
                uvm_rm_locked_call(nvUvmInterfaceDupMemory(mapping_gpu));
                return uvm_va_range_map_rm_allocation(mapping_gpu, map_rm_params);
            }
        '''
        legacy_map = '''
            static NV_STATUS uvm_map_external_allocation_on_gpu(
                uvm_gpu_t *mapping_gpu, const uvm_map_rm_params_t *map_rm_params)
            {
                uvm_assert_rwsem_locked_read(&va_space->lock);
                if ((map_rm_params->compression_type == UvmGpuCompressionTypeEnabledNoPlc) &&
                    !mapping_gpu->parent->plc_supported)
                    return NV_ERR_INVALID_DEVICE;
                if (!uvm_gpu_can_address(mapping_gpu, base, length))
                    return NV_ERR_OUT_OF_RANGE;
                return nvUvmInterfaceGetExternalAllocPtes(mapping_gpu);
            }
        '''
        legacy_volta = "parent_gpu->plc_supported = false;"
        modern_gpu_header = "struct uvm_parent_gpu_struct { UvmGpuInfo rm_info; };\n"
        modern_uvm_types = (
            "typedef struct UvmGpuInfo_tag { NvU32 gpuArch; } UvmGpuInfo;\n"
        )
        modern_user_types = (
            "typedef enum { UvmGpuCompressionTypeDefault = 0, "
            "UvmGpuCompressionTypeEnabledNoPlc = 1, UvmGpuCompressionTypeCount = 2 } "
            "UvmGpuCompressionType;\n"
        )
        modern_arch_header = (
            "#define NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100 (0x00000140)\n"
        )
        return (modern, legacy_map, legacy_volta, modern_gpu_header,
                modern_uvm_types, modern_user_types, modern_arch_header)

    def test_gv100_plc_guard_rejects_before_address_unmap_and_rm_work(self):
        adapted, evidence = adapt_gv100_plc_external_map_guard(
            *self.plc_source_fixtures())
        guard = evidence["guard_statement"]
        self.assertEqual(adapted.count(guard), 1)
        self.assertLess(adapted.index(guard), adapted.index("uvm_gpu_can_address"))
        self.assertLess(adapted.index(guard), adapted.index("uvm_unmap_external_in_range"))
        self.assertLess(adapted.index(guard), adapted.index("uvm_kvmalloc_zero"))
        self.assertLess(adapted.index(guard), adapted.index("uvm_rm_locked_call"))
        self.assertLess(adapted.index(guard), adapted.index("uvm_va_range_map_rm_allocation"))
        self.assertTrue(evidence["r580_volta_plc_disabled"])
        self.assertTrue(evidence["gv100_no_plc_rejected_before_mapping_side_effects"])

        c_source = f'''
            #define UvmGpuCompressionTypeEnabledNoPlc 1
            #define NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100 0x140
            #define NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GB200 0x1B0
            #define NV_ERR_INVALID_DEVICE -7
            #define NV_OK 0
            typedef struct {{ int compression_type; }} map_rm_params_t;
            typedef struct {{ struct {{ int gpuArch; }} rm_info; }} parent_gpu_t;
            typedef struct {{ parent_gpu_t *parent; }} mapping_gpu_t;
            static int evaluate(int compression_type, int gpu_arch)
            {{
                map_rm_params_t params = {{ compression_type }};
                parent_gpu_t parent = {{ .rm_info.gpuArch = gpu_arch }};
                mapping_gpu_t gpu = {{ .parent = &parent }};
                const map_rm_params_t *map_rm_params = &params;
                const mapping_gpu_t *mapping_gpu = &gpu;
                {guard}
                return NV_OK;
            }}
            int main(void)
            {{
                if (evaluate(UvmGpuCompressionTypeEnabledNoPlc,
                             NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100) !=
                    NV_ERR_INVALID_DEVICE) return 1;
                if (evaluate(0, NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100) != NV_OK) return 2;
                if (evaluate(UvmGpuCompressionTypeEnabledNoPlc,
                             NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GB200) != NV_OK) return 3;
                return 0;
            }}
        '''
        with tempfile.TemporaryDirectory(prefix="gv100-plc-guard-test-") as temporary:
            c_path = Path(temporary) / "guard.c"
            binary = Path(temporary) / "guard"
            c_path.write_text(c_source)
            compiled = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 str(c_path), "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(binary)], capture_output=True, text=True)
        self.assertEqual(executed.returncode, 0, executed.stderr)

    def test_gv100_plc_guard_adapter_fails_closed_on_contract_drift(self):
        (modern, legacy_map, legacy_volta, gpu_header, uvm_types,
         user_types, arch_header) = self.plc_source_fixtures()
        with self.assertRaisesRegex(ValueError, "R580 PLC rejection contract"):
            adapt_gv100_plc_external_map_guard(
                modern, legacy_map.replace("NV_ERR_INVALID_DEVICE", "NV_ERR_NOT_SUPPORTED"),
                legacy_volta, gpu_header, uvm_types, user_types, arch_header)
        with self.assertRaisesRegex(ValueError, "GV100 architecture value"):
            adapt_gv100_plc_external_map_guard(
                modern, legacy_map, legacy_volta, gpu_header,
                uvm_types, user_types,
                arch_header.replace("0x00000140", "0x00000130"))
        duplicated = modern.replace(
            "uvm_assert_rwsem_locked_read(&va_space->lock);",
            "uvm_assert_rwsem_locked_read(&va_space->lock);\n"
            "if (map_rm_params->compression_type == UvmGpuCompressionTypeEnabledNoPlc)\n"
            "    return NV_ERR_INVALID_DEVICE;")
        with self.assertRaisesRegex(ValueError, "modern mapping function already has PLC guard"):
            adapt_gv100_plc_external_map_guard(
                duplicated, legacy_map, legacy_volta, gpu_header, uvm_types,
                user_types, arch_header)

    def test_noncoherent_pte_adapter_uses_gv100_system_field(self):
        source = '''
            static NvU64 make_pte_volta(uvm_aperture_t aperture, NvU64 address,
                                        uvm_prot_t prot, NvU64 flags)
            {
                NvU8 aperture_bits = 0;
                if (aperture == UVM_APERTURE_SYS)
                    aperture_bits = NV_MMU_VER2_PTE_APERTURE_SYSTEM_COHERENT_MEMORY;
                else if (aperture == UVM_APERTURE_VID)
                    aperture_bits = NV_MMU_VER2_PTE_APERTURE_VIDEO_MEMORY;
                else
                    UVM_ASSERT_MSG(0, "Invalid aperture: %d\\n", aperture);
                pte_bits |= HWVALUE64(_MMU_VER2, PTE, APERTURE, aperture_bits);
                address >>= NV_MMU_VER2_PTE_ADDRESS_SHIFT;
                if (aperture == UVM_APERTURE_SYS) {
                    pte_bits |= HWVALUE64(_MMU_VER2, PTE, ADDRESS_SYS, address);
                }
                else {
                    pte_bits |= HWVALUE64(_MMU_VER2, PTE, ADDRESS_VID, address);
                }
                return pte_bits;
            }
        '''
        adapted, evidence = adapt_volta_noncoherent_mmu_pte(
            source,
            "#define NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY 0x00000003\n",
            "UVM_APERTURE_SYS_NON_COHERENT",
        )
        self.assertIn(
            "else if (aperture == UVM_APERTURE_SYS_NON_COHERENT)\n"
            "                    aperture_bits = NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY;",
            adapted,
        )
        self.assertIn(
            "if (aperture == UVM_APERTURE_SYS || aperture == UVM_APERTURE_SYS_NON_COHERENT)",
            adapted,
        )
        self.assertTrue(evidence["noncoherent_aperture_is_gv100_pte_value_3"])
        self.assertTrue(evidence["uses_system_physical_address_field"])

    def test_noncoherent_pte_adapter_fails_closed_on_header_or_source_drift(self):
        source = '''
            static NvU64 make_pte_volta(uvm_aperture_t aperture, NvU64 address,
                                        uvm_prot_t prot, NvU64 flags)
            {
                if (aperture == UVM_APERTURE_SYS)
                    aperture_bits = NV_MMU_VER2_PTE_APERTURE_SYSTEM_COHERENT_MEMORY;
                else if (aperture == UVM_APERTURE_VID)
                    aperture_bits = NV_MMU_VER2_PTE_APERTURE_VIDEO_MEMORY;
                if (aperture == UVM_APERTURE_SYS) {
                    pte_bits |= HWVALUE64(_MMU_VER2, PTE, ADDRESS_SYS, address);
                }
                return pte_bits;
            }
        '''
        header = "#define NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY 0x00000003\n"
        with self.assertRaisesRegex(ValueError, "GV100 PTE aperture value"):
            adapt_volta_noncoherent_mmu_pte(
                source, header.replace("00000003", "00000002"),
                "UVM_APERTURE_SYS_NON_COHERENT")
        with self.assertRaisesRegex(ValueError, "source pattern"):
            adapt_volta_noncoherent_mmu_pte(
                source.replace("if (aperture == UVM_APERTURE_SYS) {",
                               "if (aperture == UVM_APERTURE_VID) {"), header,
                "UVM_APERTURE_SYS_NON_COHERENT")

    def test_gv100_prefetch_directly_reuses_r595_callbacks_after_source_proof(self):
        legacy = """
            static void mmu_set_prefetch_faults(uvm_parent_gpu_t *parent_gpu, bool enable)
            { if (enable) set_register(1); else set_register(0); }
            void uvm_hal_pascal_mmu_enable_prefetch_faults(uvm_parent_gpu_t *parent_gpu)
            { UVM_ASSERT(parent_gpu->prefetch_fault_supported); mmu_set_prefetch_faults(parent_gpu, true); }
            void uvm_hal_pascal_mmu_disable_prefetch_faults(uvm_parent_gpu_t *parent_gpu)
            { mmu_set_prefetch_faults(parent_gpu, false); }
        """
        modern = """
            static void mmu_set_prefetch_faults(uvm_parent_gpu_t *parent_gpu, bool enable)
            { if (enable) set_register(1); else set_register(0); }
            void uvm_hal_turing_mmu_enable_prefetch_faults(uvm_parent_gpu_t *parent_gpu)
            { mmu_set_prefetch_faults(parent_gpu, true); }
            void uvm_hal_turing_mmu_disable_prefetch_faults(uvm_parent_gpu_t *parent_gpu)
            { mmu_set_prefetch_faults(parent_gpu, false); }
        """
        header = """
            void uvm_hal_turing_mmu_enable_prefetch_faults(uvm_parent_gpu_t *parent_gpu);
            void uvm_hal_turing_mmu_disable_prefetch_faults(uvm_parent_gpu_t *parent_gpu);
        """
        gpu_header = """
            struct uvm_parent_gpu_struct {
                bool access_counters_supported;
            };
        """
        r580_volta = """
            void uvm_hal_volta_arch_init_properties(uvm_parent_gpu_t *parent_gpu)
            {
                UVM_ASSERT(parent_gpu->rm_info.gpuArch ==
                           NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100);
                parent_gpu->prefetch_fault_supported = true;
            }
        """
        r595_volta = """
            void uvm_hal_volta_arch_init_properties(uvm_parent_gpu_t *parent_gpu)
            {
                UVM_ASSERT(parent_gpu->rm_info.gpuArch ==
                           NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100);
            }
        """
        common = r"""
            #if UVM_IS_DEBUG() || defined __COVERITY__
            #define UVM_ASSERT(expr) _UVM_ASSERT_MSG(expr)
            #else
            #define UVM_ASSERT(expr) UVM_ASSERT_MSG_IGNORE(expr, "\n")
            #endif
        """
        fault_source = """
            // Re-enable fault prefetching just in case it was disabled in a previous run
            parent_gpu->fault_buffer.prefetch_faults_enabled = true;
        """
        stage = audit_volta_prefetch_capability_contract(
            r580_volta, common, gpu_header, r595_volta, header, common, fault_source)
        callbacks = {"arch_table": {
            "enable_prefetch_faults": "uvm_hal_pascal_mmu_enable_prefetch_faults",
            "disable_prefetch_faults": "uvm_hal_pascal_mmu_disable_prefetch_faults",
        }}
        adapted, evidence = adapt_volta_prefetch_callbacks(
            callbacks, legacy, modern, header, gpu_header)

        self.assertEqual(adapted["arch_table"]["enable_prefetch_faults"],
                         "uvm_hal_turing_mmu_enable_prefetch_faults")
        self.assertEqual(adapted["arch_table"]["disable_prefetch_faults"],
                         "uvm_hal_turing_mmu_disable_prefetch_faults")
        self.assertTrue(evidence["shared_register_helper_identical"])
        self.assertTrue(evidence["enable_action_identical_after_assertion_removal"])
        self.assertTrue(evidence["disable_action_identical"])
        self.assertTrue(evidence["direct_r595_turing_callbacks_selected"])
        self.assertTrue(stage["r580_gv100_capability_true"])
        self.assertTrue(stage["r580_enable_assert_is_debug_only_in_release"])
        self.assertTrue(stage["r595_assert_is_debug_only_in_release"])
        self.assertTrue(stage["r595_replayable_fault_init_enables_prefetch"])
        self.assertFalse(stage["private_parent_gpu_capability_added"])
        self.assertFalse(stage["volta_prefetch_wrapper_added"])
        self.assertFalse(any("volta_mmu_" in symbol
                             for symbol in adapted["arch_table"].values()))

    def test_volta_prefetch_audit_fails_closed_on_source_contract_drift(self):
        inputs = {
            "r580_volta_source": """
                void uvm_hal_volta_arch_init_properties(uvm_parent_gpu_t *parent_gpu) {
                    UVM_ASSERT(parent_gpu->rm_info.gpuArch ==
                               NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100);
                    parent_gpu->prefetch_fault_supported = true;
                }
            """,
            "r580_common_header": r"""
                #if UVM_IS_DEBUG() || defined __COVERITY__
                #define UVM_ASSERT(expr) _UVM_ASSERT_MSG(expr)
                #else
                #define UVM_ASSERT(expr) UVM_ASSERT_MSG_IGNORE(expr, "\n")
                #endif
            """,
            "r595_gpu_header": "struct uvm_parent_gpu_struct { bool access_counters_supported; };",
            "r595_volta_source": "void uvm_hal_volta_arch_init_properties(uvm_parent_gpu_t *parent_gpu) {}",
            "r595_hal_header": """
                void uvm_hal_turing_mmu_enable_prefetch_faults(uvm_parent_gpu_t *parent_gpu);
                void uvm_hal_turing_mmu_disable_prefetch_faults(uvm_parent_gpu_t *parent_gpu);
            """,
            "r595_common_header": r"""
                #if UVM_IS_DEBUG() || defined __COVERITY__
                #define UVM_ASSERT(expr) _UVM_ASSERT_MSG(expr)
                #else
                #define UVM_ASSERT(expr) UVM_ASSERT_MSG_IGNORE(expr, "\n")
                #endif
            """,
            "r595_fault_source": """
                // Re-enable fault prefetching just in case it was disabled in a previous run
                parent_gpu->fault_buffer.prefetch_faults_enabled = true;
            """,
        }
        audit_volta_prefetch_capability_contract(**inputs)

        broken = dict(inputs)
        broken["r580_volta_source"] = broken["r580_volta_source"].replace(
            "prefetch_fault_supported = true", "prefetch_fault_supported = false")
        with self.assertRaisesRegex(ValueError, "marks GV100 prefetch capability true"):
            audit_volta_prefetch_capability_contract(**broken)

        broken = dict(inputs)
        broken["r595_common_header"] = broken["r595_common_header"].replace(
            "UVM_ASSERT_MSG_IGNORE(expr", "_UVM_ASSERT_MSG(expr")
        with self.assertRaisesRegex(ValueError, "elision contract changed"):
            audit_volta_prefetch_capability_contract(**broken)

        broken = dict(inputs)
        broken["r580_common_header"] = broken["r580_common_header"].replace(
            "UVM_ASSERT_MSG_IGNORE(expr", "_UVM_ASSERT_MSG(expr")
        with self.assertRaisesRegex(ValueError, "R580 release UVM_ASSERT"):
            audit_volta_prefetch_capability_contract(**broken)

        broken = dict(inputs)
        broken["r595_fault_source"] = broken["r595_fault_source"].replace(
            "prefetch_faults_enabled = true", "prefetch_faults_enabled = false")
        with self.assertRaisesRegex(ValueError, "prefetch initialization changed"):
            audit_volta_prefetch_capability_contract(**broken)

    def test_prefetch_callback_reuse_fails_closed_on_helper_drift(self):
        callbacks = {"arch_table": {
            "enable_prefetch_faults": "uvm_hal_pascal_mmu_enable_prefetch_faults",
            "disable_prefetch_faults": "uvm_hal_pascal_mmu_disable_prefetch_faults",
        }}
        with self.assertRaisesRegex(ValueError, "register helper differs"):
            adapt_volta_prefetch_callbacks(
                callbacks,
                "static void mmu_set_prefetch_faults(void) { old_reg(); }",
                "static void mmu_set_prefetch_faults(void) { new_reg(); }",
                "void uvm_hal_turing_mmu_enable_prefetch_faults(void);\n"
                "void uvm_hal_turing_mmu_disable_prefetch_faults(void);\n",
                "struct uvm_parent_gpu_struct { bool access_counters_supported; };",
            )

    def test_adds_only_source_derived_legacy_subchannel_aliases(self):
        r580_macros = '''
            #define UVM_SUBCHANNEL_HOST 0
            #define UVM_SUBCHANNEL_CE 1
            #define UVM_SUBCHANNEL_SW 5
            #define UVM_SUBCHANNEL_C06F UVM_SUBCHANNEL_HOST
            #define UVM_SUBCHANNEL_C0B5 UVM_SUBCHANNEL_CE
            #define UVM_SUBCHANNEL_C076 UVM_SUBCHANNEL_SW
        #endif
        '''
        r595_macros = '''
            #define UVM_SUBCHANNEL_HOST 0
            #define UVM_SUBCHANNEL_CE 1
            #define UVM_SUBCHANNEL_SW 5
            #define UVM_SUBCHANNEL_C076 UVM_SUBCHANNEL_SW
        #endif
        '''
        updated, evidence = stage_legacy_subchannel_aliases(
            r580_macros, r595_macros,
            {"legacy.c": "NV_PUSH_2U(C06F, METHOD, 0, OTHER, 1);\n"
                         "NV_PUSH_2U(C0B5, METHOD, 0, OTHER, 1);\n"
                         "NV_PUSH_2U(C076, METHOD, 0, OTHER, 1);"},
        )
        self.assertIn("#define UVM_SUBCHANNEL_C06F UVM_SUBCHANNEL_HOST", updated)
        self.assertIn("#define UVM_SUBCHANNEL_C0B5 UVM_SUBCHANNEL_CE", updated)
        self.assertEqual(evidence["added_aliases"], {
            "C06F": "UVM_SUBCHANNEL_HOST", "C0B5": "UVM_SUBCHANNEL_CE"})
        self.assertEqual(evidence["already_compatible"], ["C076"])

    def test_adapts_only_unreachable_legacy_none_enum_to_same_modern_value(self):
        old_types = '''
            typedef enum { UVM_ACCESS_COUNTER_CLEAR_OP_NONE = 0,
                           UVM_ACCESS_COUNTER_CLEAR_OP_TARGETED,
                           UVM_ACCESS_COUNTER_CLEAR_OP_ALL }
                uvm_access_counter_clear_op_t;
        '''
        modern_types = '''
            typedef enum { UVM_ACCESS_COUNTER_CLEAR_OP_TARGETED = 0,
                           UVM_ACCESS_COUNTER_CLEAR_OP_ALL,
                           UVM_ACCESS_COUNTER_CLEAR_OP_COUNT }
                uvm_access_counter_clear_op_t;
        '''
        callback = '''
            uvm_access_counter_clear_op_t
            uvm_hal_maxwell_access_counter_query_clear_op_unsupported(void)
            {
                UVM_ASSERT_MSG(false, "unsupported callback");
                return UVM_ACCESS_COUNTER_CLEAR_OP_NONE;
            }
        '''
        adapted, evidence = adapt_unsupported_access_counter_return(
            callback, old_types, modern_types)
        self.assertIn("UVM_ASSERT_MSG(false", adapted)
        self.assertIn("return UVM_ACCESS_COUNTER_CLEAR_OP_TARGETED;", adapted)
        self.assertNotIn("return UVM_ACCESS_COUNTER_CLEAR_OP_NONE;", adapted)
        self.assertEqual(evidence["legacy_none_numeric_value"], 0)
        self.assertEqual(evidence["modern_targeted_numeric_value"], 0)

    def test_enum_adapter_fails_if_values_or_unsupported_assertion_drift(self):
        old_types = "typedef enum { UVM_ACCESS_COUNTER_CLEAR_OP_NONE = 0 } uvm_access_counter_clear_op_t;"
        modern_types = "typedef enum { UVM_ACCESS_COUNTER_CLEAR_OP_TARGETED = 1 } uvm_access_counter_clear_op_t;"
        callback = "uvm_access_counter_clear_op_t uvm_hal_maxwell_access_counter_query_clear_op_unsupported(void) { return UVM_ACCESS_COUNTER_CLEAR_OP_NONE; }"
        with self.assertRaisesRegex(ValueError, "numeric contract"):
            adapt_unsupported_access_counter_return(callback, old_types, modern_types)

    def test_stages_only_missing_quoted_headers_from_pinned_uvm_archive(self):
        with tempfile.TemporaryDirectory(prefix="r595-hal-header-stage-") as temporary:
            root = Path(temporary)
            archive_path = root / "legacy.tar"
            member_name = "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm/legacy_class.h"
            data = b"/* archived legacy class header */\n"
            with tarfile.open(archive_path, "w") as archive:
                root_sentinel = tarfile.TarInfo(
                    "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm/uvm_volta.c")
                root_sentinel.size = 0
                archive.addfile(root_sentinel, io.BytesIO(b""))
                info = tarfile.TarInfo(member_name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            source_tree = root / "r580"
            source_tree.mkdir()
            (source_tree / "legacy_callbacks.c").write_text(
                '#include "legacy_class.h"\n#include "modern_uvm.h"\n')
            candidate_root = root / "candidate"
            candidate_uvm = candidate_root / "nvidia-uvm"
            candidate_uvm.mkdir(parents=True)
            (candidate_uvm / "modern_uvm.h").write_text("/* already modern */\n")

            result = stage_missing_archive_headers(
                archive_path, source_tree, candidate_root, candidate_uvm,
                {"legacy_callbacks.c"},
            )
            self.assertEqual(result["added_headers"], ["legacy_class.h"])
            self.assertEqual((candidate_uvm / "legacy_class.h").read_bytes(), data)
            self.assertTrue(result["header_sha256"]["legacy_class.h"])

    def test_volta_mode_adapter_preserves_legacy_factory_and_maps_128k_to_page_mask(self):
        volta = '''
            uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_volta(NvU64 big_page_size)
            {
                UVM_ASSERT(big_page_size == UVM_PAGE_SIZE_64K || big_page_size == UVM_PAGE_SIZE_128K);
                if (big_page_size == UVM_PAGE_SIZE_128K)
                    return NULL;
                return uvm_hal_mmu_mode_pascal(big_page_size);
            }
        '''
        pascal = '''
            static NvU64 page_sizes_pascal(void)
            {
                return UVM_PAGE_SIZE_2M | UVM_PAGE_SIZE_64K | UVM_PAGE_SIZE_4K;
            }
            uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_pascal(NvU64 big_page_size)
            {
                if (big_page_size == UVM_PAGE_SIZE_128K)
                    return NULL;
                return &pascal_mmu_mode_hal;
            }
        '''
        modern_header = "#ifndef UVM_HAL_H\n#define UVM_HAL_H\n#endif\n"
        adapted_source, adapted_header, evidence = add_volta_mmu_mode_adapter(
            volta, pascal, modern_header)
        self.assertIn("uvm_hal_mmu_mode_volta(NvU64 big_page_size)", adapted_source)
        self.assertIn("uvm_hal_mmu_mode_volta_r595(void)", adapted_source)
        self.assertIn(
            "return uvm_hal_mmu_mode_volta(UVM_PAGE_SIZE_64K);", adapted_source)
        self.assertIn("UVM_PAGE_SIZE_2M | UVM_PAGE_SIZE_64K | UVM_PAGE_SIZE_4K", pascal)
        self.assertIn("uvm_hal_mmu_mode_volta_r595(void);", adapted_header)
        self.assertTrue(evidence["legacy_128k_rejected"])
        self.assertTrue(evidence["128k_excluded_by_pascal_page_size_mask"])

    def test_volta_adapter_fails_closed_when_legacy_page_contract_changes(self):
        volta = '''
            uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_volta(NvU64 big_page_size)
            {
                return uvm_hal_mmu_mode_pascal(big_page_size);
            }
        '''
        pascal = "static NvU64 page_sizes_pascal(void) { return UVM_PAGE_SIZE_4K; }"
        header = "#ifndef UVM_HAL_H\n#define UVM_HAL_H\n#endif\n"
        with self.assertRaisesRegex(ValueError, "legacy Volta page-size contract"):
            add_volta_mmu_mode_adapter(volta, pascal, header)

    def test_source_staging_is_hashable_idempotent_and_conflict_safe(self):
        with tempfile.TemporaryDirectory(prefix="r595-hal-source-stage-") as temporary:
            root = Path(temporary)
            source_tree = root / "r580"
            source_tree.mkdir()
            target_tree = root / "r595/nvidia-uvm"
            target_tree.mkdir(parents=True)
            source = source_tree / "uvm_maxwell_host.c"
            source.write_text("/* pinned source */\n")
            source_list = target_tree / "nvidia-uvm-sources.Kbuild"
            source_list.write_text(
                "NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_tracker.c\n")
            result = _stage_extra_sources(
                source_tree, target_tree, {"uvm_maxwell_host.c"})
            self.assertTrue(result["copied_source_hashes"]["uvm_maxwell_host.c"])
            self.assertTrue((target_tree / "uvm_maxwell_host.c").is_file())
            self.assertEqual(source_list.read_text().count("uvm_maxwell_host.c"), 1)
            (target_tree / "uvm_maxwell_host.c").write_text("user change\n")
            before = source_list.read_bytes()
            with self.assertRaisesRegex(FileExistsError, "non-identical R595 source"):
                _stage_extra_sources(source_tree, target_tree, {"uvm_maxwell_host.c"})
            self.assertEqual(source_list.read_bytes(), before)

    def test_formats_complete_row_without_parent_using_each_resolved_callback(self):
        row = format_complete_hal_row(
            "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
            "arch_ops",
            {"init_properties": "uvm_hal_volta_arch_init_properties",
             "mmu_mode_hal": "uvm_hal_mmu_mode_volta"},
        )
        self.assertIn(".id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100", row)
        self.assertNotIn(".parent_id", row)
        self.assertIn(".init_properties = uvm_hal_volta_arch_init_properties", row)
        self.assertIn(".mmu_mode_hal = uvm_hal_mmu_mode_volta", row)

    def test_inserts_one_row_before_existing_rows_and_refuses_duplicate(self):
        source = '''
            static uvm_hal_class_ops_t arch_table[] = {
                { .id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_TU100,
                  .u.arch_ops = { .init_properties = turing_init, } },
            };
        '''
        row = format_complete_hal_row("GV100", "arch_ops", {"init": "volta_init"})
        updated = insert_complete_hal_row(source, "arch_table", "GV100", row)
        self.assertLess(updated.index(".id = GV100"), updated.index(".id = NV2080"))
        with self.assertRaisesRegex(ValueError, "already contains target id"):
            insert_complete_hal_row(updated, "arch_table", "GV100", row)

    def test_extracts_multiline_return_type_and_parameter_declaration(self):
        header = '''
            typedef struct uvm_access_counter_buffer_query_clear_op_struct query_op_t;
            query_op_t *
            uvm_hal_maxwell_access_counter_query_clear_op_unsupported(
                uvm_parent_gpu_t *parent_gpu,
                uvm_access_counter_buffer_entry_t **buffer_entries,
                NvU32 num_entries);
        '''
        self.assertEqual(
            extract_callback_prototype(
                header, "uvm_hal_maxwell_access_counter_query_clear_op_unsupported"),
            "query_op_t * uvm_hal_maxwell_access_counter_query_clear_op_unsupported( uvm_parent_gpu_t *parent_gpu, uvm_access_counter_buffer_entry_t **buffer_entries, NvU32 num_entries);",
        )

    def test_adds_only_missing_prototypes_and_rejects_signature_drift(self):
        original = "void first_callback(void);\nvoid second_callback(int value);\n"
        modern = "void first_callback(void);\n#ifndef UVM_HAL_H\n#define UVM_HAL_H\n#endif\n"
        merged, evidence = merge_callback_prototypes(
            original, modern, {"first_callback", "second_callback"})
        self.assertEqual(evidence["added"], ["second_callback"])
        self.assertEqual(merged.count("first_callback(void)"), 1)
        self.assertIn("void second_callback(int value);", merged)
        changed = "void first_callback(int value);\n#ifndef UVM_HAL_H\n#define UVM_HAL_H\n#endif\n"
        with self.assertRaisesRegex(ValueError, "prototype differs"):
            merge_callback_prototypes(original, changed, {"first_callback"})

    def test_localizes_only_pinned_unreferenced_legacy_hal_helpers(self):
        with tempfile.TemporaryDirectory(prefix="r595-hal-local-linkage-") as temporary:
            root = Path(temporary)
            (root / "uvm_hal.c").write_text(
                "static int (*hal_table[])(void) = { uvm_hal_used };\n")
            legacy = root / "uvm_pascal_host.c"
            legacy.write_text('''\
                void uvm_hal_used(void) { }
                NvU32
                uvm_hal_orphan(NvU32 input)
                {
                    return input;
                }
            ''')
            result = localize_unreferenced_hal_helpers(
                root, {"uvm_pascal_host.c"}, {"uvm_hal_orphan"},
                referenced_symbols={"uvm_hal_used"},
            )
            updated = legacy.read_text()
            self.assertIn("static NvU32\n                uvm_hal_orphan", updated)
            self.assertIn("void uvm_hal_used(void)", updated)
            self.assertEqual(result["localized_symbols"], ["uvm_hal_orphan"])
            self.assertEqual(result["source_occurrences_before"], {"uvm_hal_orphan": 1})
            self.assertTrue(result["bodies_unchanged"])

    def test_localization_fails_closed_for_references_exports_and_missing_definitions(self):
        with tempfile.TemporaryDirectory(prefix="r595-hal-local-linkage-guard-") as temporary:
            root = Path(temporary)
            legacy = root / "legacy.c"
            legacy.write_text("void uvm_hal_orphan(void) { }\n")
            caller = root / "caller.c"
            caller.write_text("void caller(void) { uvm_hal_orphan(); }\n")
            before = legacy.read_bytes()
            with self.assertRaisesRegex(ValueError, "source references"):
                localize_unreferenced_hal_helpers(
                    root, {"legacy.c"}, {"uvm_hal_orphan"}, referenced_symbols=set())
            self.assertEqual(legacy.read_bytes(), before)

            caller.unlink()
            legacy.write_text("void uvm_hal_orphan(void) { }\nEXPORT_SYMBOL(uvm_hal_orphan);\n")
            with self.assertRaisesRegex(ValueError, "source references"):
                localize_unreferenced_hal_helpers(
                    root, {"legacy.c"}, {"uvm_hal_orphan"}, referenced_symbols=set())

            legacy.write_text("void other_function(void) { }\n")
            with self.assertRaisesRegex(ValueError, "expected one definition"):
                localize_unreferenced_hal_helpers(
                    root, {"legacy.c"}, {"uvm_hal_orphan"}, referenced_symbols=set())

    def test_linkage_audit_accepts_dead_static_helper_removed_from_object(self):
        with tempfile.TemporaryDirectory(prefix="r595-hal-dead-helper-audit-") as temporary:
            root = Path(temporary)
            source = root / "dead_helper.c"
            obj = root / "dead_helper.o"
            source.write_text('''\
                static int uvm_hal_orphan(void) { return 7; }
                int live_callback(void) { return 3; }
            ''')
            subprocess.run(
                ["cc", "-O2", "-c", str(source), "-o", str(obj)],
                check=True, capture_output=True, text=True,
            )
            audit = audit_private_hal_helper_linkage(
                obj, [obj], {"uvm_hal_orphan"})
            self.assertTrue(audit["passed"])
            self.assertTrue(audit["all_symbols_absent_from_compiled_objects"])
            self.assertTrue(audit["all_symbols_absent_from_linked_module"])
            self.assertEqual(audit["cross_object_undefined_references"],
                             {"uvm_hal_orphan": []})


if __name__ == "__main__":
    unittest.main()
