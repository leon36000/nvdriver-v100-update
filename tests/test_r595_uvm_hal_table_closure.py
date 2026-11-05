# SPDX-License-Identifier: MIT
"""Tests for the fail-closed cross-branch UVM HAL table census."""
import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.audit_r595_uvm_hal_table_closure import (  # noqa: E402
    REQUIRED_GV100_TABLE_TARGETS,
    SELECTOR_EXPECTATIONS,
    audit_candidate_module_symbols,
    compare_hal_tables,
    map_callback_definitions,
    parse_hal_class_tables,
    parse_gpu_hal_selector_contract,
    parse_r580_gpu_info_producer_contract,
)


class R595UvmHalTableClosureTests(unittest.TestCase):
    def _r580_gpu_info_producer_fixture(self):
        return r"""
            NV_STATUS nvGpuOpsGetGpuInfo(void) {
                status = pRmApi->Control(pRmApi, client, subDeviceHandle,
                    NV2080_CTRL_CMD_MC_GET_ARCH_INFO, &archInfoParams,
                    sizeof(archInfoParams));
                if (NV_OK != status) goto cleanup;
                pGpuInfo->gpuArch = archInfoParams.architecture;
                status = findDeviceClasses(client, device, subdevice,
                    &pGpuInfo->hostClass, &pGpuInfo->ceClass,
                    &pGpuInfo->computeClass, &fault, &access, &sec2);
                if (status != NV_OK) goto cleanup;
                return NV_OK;
            }
            NV_STATUS findDeviceClasses(void) {
                status = pRmApi->Control(api, root, device,
                    NV0080_CTRL_CMD_GPU_GET_CLASSLIST, &classParams,
                    sizeof(classParams));
                if (status != NV_OK) return status;
                classList = portMemAllocNonPaged(
                    sizeof(NvU32) * classParams.numClasses);
                if (classList == NULL) {
                    return NV_ERR_INSUFFICIENT_RESOURCES;
                }
                classParams.classList = NV_PTR_TO_NvP64(classList);
                status = pRmApi->Control(api, root, device,
                    NV0080_CTRL_CMD_GPU_GET_CLASSLIST, &classParams,
                    sizeof(classParams));
                if (status != NV_OK) goto Cleanup_classlist;
                for (i = 0; i < classParams.numClasses; i++) {
                if (isClassHost(classList[i]))
                    *hostClass = NV_MAX(*hostClass, classList[i]);
                else if (isClassCE(classList[i]))
                    *ceClass = NV_MAX(*ceClass, classList[i]);
                else if (isClassCompute(classList[i]))
                    *computeClass = NV_MAX(*computeClass, classList[i]);
                }
                Cleanup_classlist:
                portMemFree(classList);
                return status;
            }
            NvBool isClassHost(NvU32 class) {
                CliGetChannelClassInfo(class, &classInfo);
                return classInfo.classType == CHANNEL_CLASS_TYPE_GPFIFO;
            }
            NvBool isClassCE(NvU32 class) {
                switch (class) {
                    case VOLTA_DMA_COPY_A: return NV_TRUE;
                    default: return NV_FALSE;
                }
            }
            NvBool isClassCompute(NvU32 class) {
                switch (class) {
                    case VOLTA_COMPUTE_A: return NV_TRUE;
                    default: return NV_FALSE;
                }
            }
        """

    def test_source_map_requires_a_c_definition_not_a_call_or_prototype(self):
        with tempfile.TemporaryDirectory(prefix="r580-callback-map-test-") as temporary:
            root = Path(temporary)
            (root / "definition.c").write_text("int present_callback(void) { return 0; }\n")
            (root / "reference.c").write_text(
                "int absent_callback(void);\nvoid caller(void) { absent_callback(); }\n")
            result = map_callback_definitions(
                root, {"present_callback", "absent_callback"})
        self.assertEqual(result["present_callback"], ["definition.c"])
        self.assertEqual(result["absent_callback"], [])

    def _selector_fixture(self):
        rows = (
            ("ce_table", "gpu_info->ceClass", "ce_hal", "ce_ops"),
            ("host_table", "gpu_info->hostClass", "host_hal", "host_ops"),
            ("arch_table", "gpu_info->gpuArch", "arch_hal", "arch_ops"),
            ("fault_buffer_table", "gpu_info->gpuArch", "fault_buffer_hal", "fault_buffer_ops"),
            ("access_counter_buffer_table", "gpu_info->gpuArch", "access_counter_buffer_hal", "access_counter_buffer_ops"),
            ("sec2_table", "gpu_info->gpuArch", "sec2_hal", "sec2_ops"),
        )
        body = []
        for table, field, member, union in rows:
            body.append(
                f"class_ops = ops_find_by_id({table}, ARRAY_SIZE({table}), {field});\n"
                "if (class_ops == NULL) {\n"
                "    return NV_ERR_INVALID_CLASS;\n"
                "}\n"
                f"parent_gpu->{member} = &class_ops->u.{union};\n"
            )
        return "NV_STATUS uvm_hal_init_gpu(uvm_parent_gpu_t *gpu) {\n" + "".join(body) + "}\n"

    def test_reports_fail_closed_class_selection_for_every_required_table(self):
        contract = parse_gpu_hal_selector_contract(self._selector_fixture())
        self.assertEqual(set(contract), set(REQUIRED_GV100_TABLE_TARGETS))
        for result in contract.values():
            self.assertEqual(result["missing_class_status"], "NV_ERR_INVALID_CLASS")
            self.assertTrue(result["null_checked_before_install"])
            self.assertTrue(result["installs_hal_pointer"])

    def test_composes_r580_gpu_info_producer_with_candidate_r595_dispatch_keys(self):
        producer = parse_r580_gpu_info_producer_contract(
            self._r580_gpu_info_producer_fixture())
        self.assertEqual(producer["architecture"], {
            "query": "NV2080_CTRL_CMD_MC_GET_ARCH_INFO",
            "assigned_field": "gpuArch",
            "source_field": "archInfoParams.architecture",
            "status_checked_before_assignment": True,
        })
        self.assertEqual(producer["class_list"]["selected_fields"],
                         ["hostClass", "ceClass", "computeClass"])
        self.assertTrue(producer["class_list"]["sizing_query_error_checked"])
        self.assertTrue(producer["class_list"]["allocation_error_checked"])
        self.assertTrue(producer["class_list"]["class_read_error_checked_before_scan"])
        self.assertEqual(producer["class_list"]["class_read_error_path"],
                         "Cleanup_classlist")
        self.assertTrue(producer["class_list"]["class_list_freed_before_status_return"])
        self.assertTrue(producer["class_list"]["producer_stops_on_class_query_error"])
        self.assertFalse(producer["live_rm_values_observed"])

        candidate_path = (ROOT / "tests/fixtures/candidates/"
                          "r595112-gv100-hal-r580196/uvm_hal.c")
        candidate = candidate_path.read_text(encoding="utf-8")
        selectors = parse_gpu_hal_selector_contract(candidate)
        tables = parse_hal_class_tables(candidate)
        self.assertEqual(set(selectors), set(REQUIRED_GV100_TABLE_TARGETS))
        for table, (class_field, _hal_member, _union_member) in SELECTOR_EXPECTATIONS.items():
            self.assertEqual(selectors[table]["class_id_field"], class_field)
        for table, target in REQUIRED_GV100_TABLE_TARGETS.items():
            self.assertIn(target, {row["id"] for row in tables[table]})

    def test_r580_gpu_info_producer_contract_rejects_wrong_arch_source(self):
        source = self._r580_gpu_info_producer_fixture().replace(
            "pGpuInfo->gpuArch = archInfoParams.architecture;",
            "pGpuInfo->gpuArch = 0;", 1)
        with self.assertRaisesRegex(ValueError, "does not source gpuArch"):
            parse_r580_gpu_info_producer_contract(source)

    def test_r580_gpu_info_producer_contract_rejects_missing_volta_class(self):
        source = self._r580_gpu_info_producer_fixture().replace(
            "case VOLTA_DMA_COPY_A: return NV_TRUE;",
            "case TURING_DMA_COPY_A: return NV_TRUE;", 1)
        with self.assertRaisesRegex(ValueError, "omits VOLTA_DMA_COPY_A"):
            parse_r580_gpu_info_producer_contract(source)

    def test_r580_gpu_info_producer_contract_rejects_unchecked_second_class_query(self):
        source = self._r580_gpu_info_producer_fixture().replace(
            "if (status != NV_OK) goto Cleanup_classlist;", "", 1)
        with self.assertRaisesRegex(ValueError, "does not fail closed before scanning"):
            parse_r580_gpu_info_producer_contract(source)

    def test_r580_gpu_info_producer_contract_rejects_unchecked_sizing_query(self):
        source = self._r580_gpu_info_producer_fixture().replace(
            "if (status != NV_OK) return status;", "", 1)
        with self.assertRaisesRegex(ValueError, "sizing query does not propagate"):
            parse_r580_gpu_info_producer_contract(source)

    def test_r580_gpu_info_producer_contract_rejects_ignored_class_query_failure(self):
        source = self._r580_gpu_info_producer_fixture().replace(
            "if (status != NV_OK) goto cleanup;", "", 1)
        with self.assertRaisesRegex(ValueError, "does not stop and clean up"):
            parse_r580_gpu_info_producer_contract(source)

    def test_r580_gpu_info_producer_contract_rejects_unchecked_class_list_allocation(self):
        source = self._r580_gpu_info_producer_fixture().replace(
            "if (classList == NULL) {\n"
            "                    return NV_ERR_INSUFFICIENT_RESOURCES;\n"
            "                }", "", 1)
        with self.assertRaisesRegex(ValueError, "allocation is not checked"):
            parse_r580_gpu_info_producer_contract(source)

    def test_r580_gpu_info_producer_contract_rejects_class_list_leak_on_error(self):
        source = self._r580_gpu_info_producer_fixture().replace(
            "portMemFree(classList);", "", 1)
        with self.assertRaisesRegex(ValueError, "does not free its buffer"):
            parse_r580_gpu_info_producer_contract(source)

    def test_selector_audit_rejects_null_lookup_without_failure_return(self):
        source = self._selector_fixture().replace(
            "return NV_ERR_INVALID_CLASS;", "return NV_OK;", 1)
        with self.assertRaisesRegex(ValueError, "does not fail on an absent class"):
            parse_gpu_hal_selector_contract(source)

    def test_parses_nested_rows_and_ignores_comments(self):
        source = '''
            // static uvm_hal_class_ops_t fake_table[] = { };
            static uvm_hal_class_ops_t arch_table[] = {
                { .id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100,
                  .u.arch_ops = { .init = fn, .nested = { 1, 2 } } },
                { .id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_TU100,
                  .parent_id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100,
                  .u.arch_ops = {} },
            };
        '''
        tables = parse_hal_class_tables(source)
        self.assertEqual(len(tables["arch_table"]), 2)
        self.assertEqual(tables["arch_table"][0]["id"],
                         "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100")
        self.assertEqual(tables["arch_table"][1]["parent_id"],
                         "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100")
        self.assertEqual(tables["arch_table"][0]["assignments"], {"init": "fn"})

    def test_reports_every_required_volta_hal_table_missing_from_r595(self):
        rows580 = []
        rows595 = []
        for table, target in REQUIRED_GV100_TABLE_TARGETS.items():
            rows580.append(
                f"static uvm_hal_class_ops_t {table}[] = "
                f"{{ {{ .id = BASE_{table}, .u.ops = {{ .base = legacy_fn, }} }}, "
                f"{{ .id = {target}, .parent_id = BASE_{table}, "
                ".u.ops = { .volta = volta_fn, } } };"
            )
            rows595.append(
                f"static uvm_hal_class_ops_t {table}[] = "
                "{ { .id = BLACKWELL_ID, .u.ops = {} } };"
            )
        comparison = compare_hal_tables("\n".join(rows580), "\n".join(rows595))
        self.assertEqual(comparison["required_table_count"],
                         len(REQUIRED_GV100_TABLE_TARGETS))
        self.assertTrue(comparison["r580_all_required_targets_present"])
        self.assertEqual(set(comparison["r595_missing_targets"]),
                         set(REQUIRED_GV100_TABLE_TARGETS))
        for callbacks in comparison["r580_resolved_callbacks"].values():
            self.assertEqual(callbacks, {"base": "legacy_fn", "volta": "volta_fn"})

    def test_candidate_module_closure_uses_candidate_callbacks_and_reports_port_delta(self):
        r580_tables = []
        r595_tables = []
        candidate_symbols = []
        for index, (table, target) in enumerate(REQUIRED_GV100_TABLE_TARGETS.items()):
            old_symbol = f"r580_callback_{index}"
            candidate_symbol = f"r595_callback_{index}"
            candidate_symbols.append(candidate_symbol)
            r580_tables.append(
                f"static uvm_hal_class_ops_t {table}[] = {{ "
                f"{{ .id = BASE_{index}, .u.ops = {{ .init = base_{index}, }} }}, "
                f"{{ .id = {target}, .parent_id = BASE_{index}, "
                f".u.ops = {{ .init = {old_symbol}, }} }} }};")
            r595_tables.append(
                f"static uvm_hal_class_ops_t {table}[] = {{ "
                f"{{ .id = {target}, .u.ops = {{ .init = {candidate_symbol}, }} }} }};")

        comparison = compare_hal_tables("\n".join(r580_tables),
                                        "\n".join(r595_tables))
        self.assertEqual(
            comparison["r580_to_r595_callback_differences"]["arch_table"]["init"],
            {"r580": "r580_callback_2", "r595": "r595_callback_2"})
        nm_output = "\n".join(
            f"00000000 T {symbol}" for symbol in candidate_symbols)
        module_audit = audit_candidate_module_symbols(
            comparison["r595_resolved_callbacks"], nm_output)
        self.assertTrue(module_audit["all_callbacks_defined"])

    def test_candidate_module_audit_counts_only_defined_callback_symbols(self):
        callbacks = {"arch_table": {"init": "uvm_hal_volta_init"},
                     "fault_buffer_table": {"read": "uvm_hal_volta_read"}}
        nm_output = (
            "00000000 T uvm_hal_volta_init\n"
            "                 U uvm_hal_volta_read\n"
            "00000010 t unrelated_local_symbol\n"
        )
        audit = audit_candidate_module_symbols(callbacks, nm_output)
        self.assertFalse(audit["all_callbacks_defined"])
        self.assertEqual(audit["tables"]["arch_table"]["missing_symbols"], [])
        self.assertEqual(audit["tables"]["fault_buffer_table"]["missing_symbols"],
                         ["uvm_hal_volta_read"])

    def test_empty_candidate_table_map_does_not_pass_symbol_closure_vacuously(self):
        audit = audit_candidate_module_symbols({}, "00000000 T unrelated_symbol\n")
        self.assertFalse(audit["all_callbacks_defined"])
        self.assertEqual(audit["tables"], {})

    def test_rejects_duplicate_table_or_row_ids(self):
        source = '''
            static uvm_hal_class_ops_t arch_table[] = {
                { .id = GV100, .u.ops = {} },
                { .id = GV100, .u.ops = {} },
            };
        '''
        with self.assertRaisesRegex(ValueError, "duplicate row id"):
            parse_hal_class_tables(source)

    def test_rejects_missing_required_table_in_a_branch(self):
        source = "static uvm_hal_class_ops_t arch_table[] = { { .id = GV100 } };"
        with self.assertRaisesRegex(ValueError, "required HAL table missing"):
            compare_hal_tables(source, source)


if __name__ == "__main__":
    unittest.main()
