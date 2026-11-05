# SPDX-License-Identifier: MIT
"""Behavioral tests for the cross-branch GV100 UVM dispatch audit."""
from pathlib import Path
import hashlib
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_volta_uvm_hal_dispatch import (  # noqa: E402
    DEFAULT_R580_ARCHIVE,
    audit_candidate_callback_closure,
    audit_r580_callback_closure,
    audit_volta_uvm_dispatch,
)
from tools.audit_r595_uvm_hal_table_closure import (  # noqa: E402
    checked_source_archive_root,
)
from tools.probe_volta_uvm_port import (  # noqa: E402
    DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
    R580_SOURCE_ROOT,
    read_member,
)


TARGETS = {
    "ce_table": "VOLTA_DMA_COPY_A",
    "host_table": "VOLTA_CHANNEL_GPFIFO_A",
    "arch_table": "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    "fault_buffer_table": "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    "access_counter_buffer_table": "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    "sec2_table": "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
}


def _source(*, include_volta_rows):
    lines = []
    for table, target in TARGETS.items():
        base = f"BASE_{table}"
        lines.append(
            f"static uvm_hal_class_ops_t {table}[] = "
            f"{{ {{ .id = {base}, .u.ops = {{ .base = base_callback, }} }},"
        )
        if include_volta_rows:
            lines.append(
                f"{{ .id = {target}, .parent_id = {base}, "
                ".u.ops = { .volta = volta_callback, } }},"
            )
        lines.append("};")
    lookups = (
        ("ce_table", "gpu_info->ceClass", "ce_hal", "ce_ops"),
        ("host_table", "gpu_info->hostClass", "host_hal", "host_ops"),
        ("arch_table", "gpu_info->gpuArch", "arch_hal", "arch_ops"),
        ("fault_buffer_table", "gpu_info->gpuArch", "fault_buffer_hal", "fault_buffer_ops"),
        ("access_counter_buffer_table", "gpu_info->gpuArch", "access_counter_buffer_hal", "access_counter_buffer_ops"),
        ("sec2_table", "gpu_info->gpuArch", "sec2_hal", "sec2_ops"),
    )
    body = []
    for table, class_field, hal_member, union_member in lookups:
        body.append(
            f"class_ops = ops_find_by_id({table}, ARRAY_SIZE({table}), {class_field});\n"
            "if (class_ops == NULL) { return NV_ERR_INVALID_CLASS; }\n"
            f"parent_gpu->{hal_member} = &class_ops->u.{union_member};\n"
        )
    lines.append(
        "NV_STATUS uvm_hal_init_gpu(uvm_parent_gpu_t *gpu) {\n"
        + "".join(body)
        + "return NV_OK;\n}"
    )
    return "\n".join(lines)


class VoltaUvmDispatchAuditTests(unittest.TestCase):
    def test_pinned_r595_9902_source_fails_closed_for_all_six_volta_hal_tables(self):
        archive_bytes = DEFAULT_R580_ARCHIVE.read_bytes()
        self.assertEqual(
            hashlib.sha256(archive_bytes).hexdigest(),
            DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
        )
        with tarfile.open(DEFAULT_R580_ARCHIVE, "r:*") as archive:
            source_root = checked_source_archive_root(archive, R580_SOURCE_ROOT)
            r580_source = read_member(
                archive, source_root + "/kernel-open/nvidia-uvm/uvm_hal.c"
            ).decode("utf-8", errors="strict")

        r595_hal_path = (
            ROOT
            / "build/experiments/r595-r580-patch-replay-v39-20261023/source"
            / "kernel-open/nvidia-uvm/uvm_hal.c"
        )
        r595_bytes = r595_hal_path.read_bytes()
        self.assertEqual(
            hashlib.sha256(r595_bytes).hexdigest(),
            "d3815691e974e551b0fb51ac0d7c3101b31452a56f20f8ba4098e873f6673199",
        )
        result = audit_volta_uvm_dispatch(
            r580_source,
            r595_bytes.decode("utf-8", errors="strict"),
            modern_branch="R595.99.02",
        )

        self.assertTrue(result["r580_all_required_targets_present"])
        self.assertEqual(result["modern_missing_targets"], TARGETS)
        self.assertFalse(result["modern_static_dispatch_candidate"])
        self.assertFalse(result["runtime_or_hardware_validated"])
        self.assertEqual(set(result["modern_selector_contract"]), set(TARGETS))
        for selector in result["modern_selector_contract"].values():
            self.assertEqual(selector["missing_class_status"], "NV_ERR_INVALID_CLASS")
            self.assertTrue(selector["null_checked_before_install"])

    def test_finds_all_six_gv100_rows_missing_from_modern_dispatch(self):
        result = audit_volta_uvm_dispatch(
            _source(include_volta_rows=True),
            _source(include_volta_rows=False),
            modern_branch="R615 fixture",
        )

        self.assertEqual(result["modern_branch"], "R615 fixture")
        self.assertTrue(result["r580_all_required_targets_present"])
        self.assertEqual(result["modern_missing_targets"], TARGETS)
        self.assertFalse(result["modern_all_required_targets_present"])
        self.assertFalse(result["modern_inheritance_closure_valid"])
        self.assertEqual(len(result["modern_selector_contract"]), 6)
        self.assertEqual(
            result["modern_initial_row_ids"],
            {table: f"BASE_{table}" for table in TARGETS},
        )
        self.assertEqual(
            result["r580_target_lineage"],
            {table: [f"BASE_{table}", target] for table, target in TARGETS.items()},
        )
        self.assertEqual(
            result["r580_resolved_callbacks"],
            {
                table: {"base": "base_callback", "volta": "volta_callback"}
                for table in TARGETS
            },
        )

    def test_accepts_target_rows_with_resolvable_parent_chains(self):
        source = _source(include_volta_rows=True)
        result = audit_volta_uvm_dispatch(
            source, source, modern_branch="R615 fixture",
        )

        self.assertEqual(result["modern_missing_targets"], {})
        self.assertTrue(result["modern_all_required_targets_present"])
        self.assertTrue(result["modern_inheritance_closure_valid"])
        self.assertEqual(
            result["modern_resolved_callback_counts"],
            {table: 2 for table in TARGETS},
        )

    def test_modern_callback_replacements_are_used_for_candidate_module_closure(self):
        r580 = _source(include_volta_rows=True).replace(
            "volta_callback", "pascal_callback"
        )
        modern = _source(include_volta_rows=True).replace(
            "volta_callback", "turing_callback"
        )
        result = audit_volta_uvm_dispatch(
            r580, modern, modern_branch="R615 replacement fixture",
        )

        self.assertEqual(
            result["r580_resolved_callbacks"]["ce_table"]["volta"],
            "pascal_callback",
        )
        self.assertEqual(
            result["modern_resolved_callbacks"]["ce_table"]["volta"],
            "turing_callback",
        )
        self.assertIn(
            {
                "table": "ce_table",
                "operation": "volta",
                "r580_callback": "pascal_callback",
                "modern_callback": "turing_callback",
                "change": "replaced",
            },
            result["r580_to_modern_callback_changes"],
        )
        candidate_closure = audit_candidate_callback_closure(
            result["modern_resolved_callbacks"],
            "00000000 T base_callback\n00000010 T turing_callback\n",
            {
                "base_callback": ["uvm_hal.c"],
                "turing_callback": ["uvm_turing.c"],
            },
        )

        self.assertTrue(
            candidate_closure["module_symbol_audit"]["all_callbacks_defined"]
        )
        self.assertEqual(candidate_closure["callback_symbols_missing"], [])
        self.assertNotIn(
            "pascal_callback", candidate_closure["callback_source_definitions"]
        )

    def test_stock_modern_source_with_no_volta_rows_has_no_callback_delta(self):
        result = audit_volta_uvm_dispatch(
            _source(include_volta_rows=True),
            _source(include_volta_rows=False),
            modern_branch="stock fixture without Volta rows",
        )

        self.assertEqual(result["modern_resolved_callbacks"], {})
        self.assertEqual(result["r580_to_modern_callback_changes"], [])

    def test_rejects_a_broken_target_inheritance_chain(self):
        modern = _source(include_volta_rows=True).replace(
            ".parent_id = BASE_arch_table",
            ".parent_id = MISSING_ARCH_PARENT",
        )
        result = audit_volta_uvm_dispatch(
            _source(include_volta_rows=True), modern,
            modern_branch="R615 fixture",
        )

        self.assertFalse(result["modern_inheritance_closure_valid"])
        self.assertEqual(
            result["modern_inheritance_errors"]["arch_table"],
            "HAL table inheritance parent is missing: MISSING_ARCH_PARENT",
        )

    def test_reports_module_symbol_gaps_with_r580_source_definitions(self):
        callbacks = {
            "ce_table": {"init": "maxwell_ce_init", "copy": "volta_ce_copy"},
            "sec2_table": {"init": "volta_sec2_init"},
        }
        definitions = {
            "maxwell_ce_init": ["uvm_maxwell_ce.c"],
            "volta_ce_copy": ["uvm_volta_ce.c"],
            "volta_sec2_init": ["uvm_volta.c"],
        }
        result = audit_r580_callback_closure(
            callbacks,
            "00000000 T volta_ce_copy\n00000010 T volta_sec2_init\n",
            definitions,
        )

        self.assertFalse(result["module_symbol_audit"]["all_callbacks_defined"])
        self.assertEqual(
            result["source_files_for_undefined_callbacks"],
            {"maxwell_ce_init": ["uvm_maxwell_ce.c"]},
        )
        self.assertEqual(result["callback_symbols_missing_count"], 1)
        self.assertEqual(result["callback_symbols_missing"], ["maxwell_ce_init"])
        self.assertEqual(result["callback_source_missing"], [])
        self.assertEqual(result["callback_duplicate_definitions"], {})


if __name__ == "__main__":
    unittest.main()
