# SPDX-License-Identifier: MIT
"""Tests for the pinned R580-to-R615 Volta UVM capability audit."""
from pathlib import Path
import hashlib
import io
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_volta_uvm_capability_map import (  # noqa: E402
    CAPABILITIES,
    PLC_R580_UNMAP_ANCHOR,
    PLC_R615_ANCHORS,
    SHARED_CODE_ANCHORS,
    _line_hits,
    audit_capability_sources,
    build_report,
    source_manifest_sha256,
)
from tools.audit_r595_uvm_hal_table_closure import (  # noqa: E402
    REQUIRED_GV100_TABLE_TARGETS,
    SELECTOR_EXPECTATIONS,
)


def _hal_source(*, volta_rows):
    rows = []
    for table, target in REQUIRED_GV100_TABLE_TARGETS.items():
        modern_id = {
            "ce_table": "TURING_DMA_COPY_A",
            "host_table": "TURING_CHANNEL_GPFIFO_A",
        }.get(table, "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_TU100")
        row_id = target if volta_rows else modern_id
        union = SELECTOR_EXPECTATIONS[table][2]
        rows.append(
            f"static uvm_hal_class_ops_t {table}[] = "
            f"{{ {{ .id = {row_id}, .u.{union} = {{}} }}, }};"
        )
    selectors = []
    for table, (class_field, hal_member, union_member) in SELECTOR_EXPECTATIONS.items():
        selectors.append(
            f"class_ops = ops_find_by_id({table}, ARRAY_SIZE({table}), gpu_info->{class_field});\n"
            "if (class_ops == NULL) { return NV_ERR_INVALID_CLASS; }\n"
            f"parent_gpu->{hal_member} = &class_ops->u.{union_member};"
        )
    rows.append(
        "NV_STATUS uvm_hal_init_gpu(void) {\n"
        "uvm_hal_class_ops_t *class_ops;\n"
        + "\n".join(selectors)
        + "\nreturn NV_OK;\n}"
    )
    return "\n".join(rows)


def _fixture_sources():
    r580 = {
        "uvm_volta.c": "\n".join(item["assignment"] for item in CAPABILITIES),
        "uvm_hal.c": _hal_source(volta_rows=True),
    }
    r615 = {"uvm_hal.c": _hal_source(volta_rows=False)}
    for anchors in SHARED_CODE_ANCHORS.values():
        for relative_path, marker in anchors:
            r580.setdefault(relative_path, "")
            r580[relative_path] += marker + "\n"
            r615.setdefault(relative_path, "")
            r615[relative_path] += marker + "\n"
    for item in CAPABILITIES:
        for relative_path, marker in item["r580_consumers"]:
            r580.setdefault(relative_path, "")
            r580[relative_path] += marker + "\n"
        for relative_path, marker in item["r615_anchors"]:
            r615.setdefault(relative_path, "")
            r615[relative_path] += marker + "\n"
    r580.setdefault("uvm_map_external.c", "")
    r580["uvm_map_external.c"] += (
        "if ((map_rm_params->compression_type == UvmGpuCompressionTypeEnabledNoPlc) "
        "&& !mapping_gpu->parent->plc_supported) return NV_ERR_INVALID_DEVICE;\n" +
        PLC_R580_UNMAP_ANCHOR[1] + "\n"
    )
    r615.setdefault("uvm_map_external.c", "")
    r615["uvm_map_external.c"] += (
        "status = uvm_unmap_external_in_range(external_range, mapping_gpu, base, base + length - 1, NULL);\n"
        "map_rm_params.compression_type = params->perGpuAttributes[i].gpuCompressionType;\n"
        "uvm_va_range_map_rm_allocation(&external_range->va_range,\n"
        "nvUvmInterfaceGetExternalAllocPtes(gpu_va_space, mem_handle, offset, size, mapping_info);\n"
        "pte_buffer->mapping_info.compressionType    = map_rm_params->compression_type;\n"
        "uvm_ext_gpu_map_destroy(external_range, ext_gpu_map, NULL);\n"
    )
    r615["uvm.h"] = (
        "//           UvmGpuCompressionTypeEnabledNoPlc compression type was used on one\n"
        "// or more GPUs that don't support PLC.\n"
    )
    return r580, r615


def _write_tar(path, files, root):
    with tarfile.open(path, "w:gz") as archive:
        for name, content in files.items():
            member = tarfile.TarInfo(f"{root}/{name}")
            data = content.encode("utf-8") if isinstance(content, str) else content
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


class VoltaUvmCapabilityMapTests(unittest.TestCase):
    def test_maps_all_eleven_assignments_and_keeps_runtime_unvalidated(self):
        r580, r615 = _fixture_sources()

        result = audit_capability_sources(r580, r615)

        self.assertEqual(result["capability_count"], 11)
        self.assertEqual(
            {item["field"] for item in result["capabilities"]},
            {item["field"] for item in CAPABILITIES},
        )
        self.assertFalse(result["runtime_or_hardware_validated"])
        self.assertTrue(all(item["r580_assignment"] for item in result["capabilities"]))

    def test_reports_missing_r615_gv100_dispatch_as_a_prerequisite(self):
        r580, r615 = _fixture_sources()

        result = audit_capability_sources(r580, r615)
        prerequisite = result["prerequisites"]["r615_gv100_uvm_hal_dispatch"]

        self.assertTrue(prerequisite["r580_all_required_targets_present"])
        self.assertFalse(prerequisite["r615_all_required_targets_present"])
        self.assertEqual(set(prerequisite["r615_missing_targets"]), set(REQUIRED_GV100_TABLE_TARGETS))
        self.assertEqual(
            set(prerequisite["r615_missing_class_status_by_table"].values()),
            {"NV_ERR_INVALID_CLASS"},
        )

    def test_plc_mapping_risk_is_conditional_and_preserves_unknown_rm_behavior(self):
        r580, r615 = _fixture_sources()

        result = audit_capability_sources(r580, r615)
        risk = next(item for item in result["behavioral_risks"] if item["id"] == "plc-rejection-after-overlap-unmap")

        self.assertEqual(risk["priority"], "high")
        self.assertTrue(risk["conditional_impact"])
        self.assertEqual(risk["r615_rm_rejection_on_gv100"], "unknown")
        self.assertLess(
            risk["r580_guard_prevents_this_ordering"]["guard"]["line"],
            risk["r580_guard_prevents_this_ordering"]["overlap_unmap"]["line"],
        )

    def test_report_marks_consumer_coverage_as_representative_and_compares_shared_calls(self):
        r580, r615 = _fixture_sources()

        result = audit_capability_sources(r580, r615)
        self.assertEqual(
            result["coverage"]["r580_consumer_evidence"],
            "representative_not_exhaustive",
        )
        row = next(item for item in result["capabilities"] if item["field"] == "va_invalidate_supported")
        self.assertTrue(row["r580_r615_shared_code_anchors"])
        self.assertTrue(row["r580_r615_shared_code_anchors"][0]["same_marker_in_both_releases"])

    def test_fails_closed_when_a_historical_assignment_is_missing(self):
        r580, r615 = _fixture_sources()
        field = CAPABILITIES[0]["field"]
        r580["uvm_volta.c"] = r580["uvm_volta.c"].replace(
            CAPABILITIES[0]["assignment"] + "\n", "", 1
        )

        with self.assertRaisesRegex(ValueError, field):
            audit_capability_sources(r580, r615)

    def test_fails_closed_when_a_modern_evidence_anchor_disappears(self):
        r580, r615 = _fixture_sources()
        item = next(item for item in CAPABILITIES if item["r615_anchors"])
        relative_path, marker = item["r615_anchors"][0]
        r615[relative_path] = r615[relative_path].replace(marker, "")

        with self.assertRaisesRegex(ValueError, item["field"]):
            audit_capability_sources(r580, r615)

    def test_manifest_is_path_sensitive_and_order_independent(self):
        files = {"a.c": b"a", "sub/b.h": b"b"}

        self.assertEqual(
            source_manifest_sha256(files),
            source_manifest_sha256(dict(reversed(list(files.items())))),
        )
        self.assertNotEqual(
            source_manifest_sha256(files),
            source_manifest_sha256({"renamed.c": b"a", "sub/b.h": b"b"}),
        )

    def test_legacy_name_in_comment_is_reported_but_not_counted_as_code(self):
        r580, r615 = _fixture_sources()
        r615["uvm_user_channel.h"] = "// non_replayable_faults_supported is a legacy field\n"

        result = audit_capability_sources(r580, r615)
        mapped = next(
            item for item in result["capabilities"]
            if item["field"] == "non_replayable_faults_supported"
        )

        self.assertEqual(len(mapped["r615_legacy_identifier_occurrences"]), 1)
        self.assertEqual(mapped["r615_legacy_identifier_code_occurrences"], [])
        self.assertTrue(mapped["r615_legacy_identifier_absent_from_code"])

    def test_legacy_name_in_executable_code_is_not_hidden_by_comment_mask(self):
        r580, r615 = _fixture_sources()
        r615["uvm_probe.c"] = "if (parent_gpu->scoped_atomics_supported)\n    return;\n"

        result = audit_capability_sources(r580, r615)
        mapped = next(
            item for item in result["capabilities"]
            if item["field"] == "scoped_atomics_supported"
        )

        self.assertEqual(len(mapped["r615_legacy_identifier_code_occurrences"]), 1)
        self.assertFalse(mapped["r615_legacy_identifier_absent_from_code"])

    def test_line_spliced_line_comments_remain_comments_for_lf_and_crlf(self):
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)):
                r580, r615 = _fixture_sources()
                r615["uvm_probe.c"] = "// comment continued \\" + newline + "scoped_atomics_supported\n"

                result = audit_capability_sources(r580, r615)
                mapped = next(
                    item for item in result["capabilities"]
                    if item["field"] == "scoped_atomics_supported"
                )

                self.assertEqual(len(mapped["r615_legacy_identifier_occurrences"]), 1)
                self.assertEqual(mapped["r615_legacy_identifier_code_occurrences"], [])

    def test_identifiers_joined_by_line_splice_are_detected_for_lf_and_crlf(self):
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)):
                r580, r615 = _fixture_sources()
                r615["uvm_probe.c"] = "if (gpu->scoped_atomics_\\" + newline + "supported) return;\n"

                result = audit_capability_sources(r580, r615)
                mapped = next(
                    item for item in result["capabilities"]
                    if item["field"] == "scoped_atomics_supported"
                )

                self.assertEqual(len(mapped["r615_legacy_identifier_occurrences"]), 1)
                self.assertEqual(len(mapped["r615_legacy_identifier_code_occurrences"]), 1)
                self.assertEqual(mapped["r615_legacy_identifier_code_occurrences"][0]["line"], 1)

    def test_code_anchor_inside_comment_or_string_is_not_accepted(self):
        for wrapper in ("// {}", 'const char *fake = "{}";'):
            with self.subTest(wrapper=wrapper):
                r580, r615 = _fixture_sources()
                relative_path, marker = CAPABILITIES[0]["r615_anchors"][0]
                r615[relative_path] = wrapper.format(marker) + "\n"
                with self.assertRaisesRegex(ValueError, "anchor missing"):
                    audit_capability_sources(r580, r615)

    def test_line_hit_scanner_ignores_markers_in_comments_and_strings(self):
        marker = "dispatch_target()"
        files = {
            "a.c": '// dispatch_target()\nconst char *s = "dispatch_target()";\n'
            "dispatch_target();\n"
        }

        hits = _line_hits(files, "a.c", marker)

        self.assertEqual([item["line"] for item in hits], [3])

    def test_unclosed_apostrophe_does_not_hide_later_code(self):
        r580, r615 = _fixture_sources()
        r615["uvm_probe.c"] = "#warning don't\nif (gpu->scoped_atomics_supported) {}\n"

        result = audit_capability_sources(r580, r615)
        row = next(item for item in result["capabilities"] if item["field"] == "scoped_atomics_supported")
        self.assertEqual(len(row["r615_legacy_identifier_code_occurrences"]), 1)

    def test_physical_line_mapping_uses_lf_not_unicode_splitlines(self):
        r580, r615 = _fixture_sources()
        r615["uvm_probe.c"] = "/*\u2028*/\nif (gpu->scoped_atomics_supported) {}\n"

        result = audit_capability_sources(r580, r615)
        row = next(item for item in result["capabilities"] if item["field"] == "scoped_atomics_supported")
        occurrence = row["r615_legacy_identifier_code_occurrences"][0]
        self.assertEqual(occurrence["line"], 2)
        self.assertIn("scoped_atomics_supported", occurrence["text"])

    def test_gcc_whitespace_line_splice_keeps_comments_contiguous(self):
        r580, r615 = _fixture_sources()
        r615["uvm_probe.c"] = "// comment \\\t  \nscoped_atomics_supported\n"

        result = audit_capability_sources(r580, r615)
        row = next(item for item in result["capabilities"] if item["field"] == "scoped_atomics_supported")
        self.assertEqual(row["r615_legacy_identifier_code_occurrences"], [])

    def test_build_report_exercises_archive_and_tree_pipeline_reproducibly(self):
        r580, r615 = _fixture_sources()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r580_archive = root / "r580.tar.gz"
            r615_archive = root / "r615.tar.gz"
            r615_tree = root / "r615-source"
            r615_tree.mkdir()
            _write_tar(
                r580_archive,
                r580,
                "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm",
            )
            _write_tar(r615_archive, {"version.txt": b"fixture"}, "R615")
            for relative, source in r615.items():
                target = r615_tree / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
            modern_bytes = {
                relative: path.read_bytes()
                for relative, path in ((name, r615_tree / name) for name in r615)
            }
            expected_r580_hash = hashlib.sha256(r580_archive.read_bytes()).hexdigest()
            expected_r615_hash = hashlib.sha256(r615_archive.read_bytes()).hexdigest()
            expected_manifest = source_manifest_sha256(modern_bytes)
            with patch("tools.audit_volta_uvm_capability_map.R580_ARCHIVE_SHA256", expected_r580_hash), \
                 patch("tools.audit_volta_uvm_capability_map.R615_ARCHIVE_SHA256", expected_r615_hash), \
                 patch("tools.audit_volta_uvm_capability_map.R615_EXPECTED_FILE_COUNT", len(modern_bytes)), \
                 patch("tools.audit_volta_uvm_capability_map.R615_UVM_MANIFEST_SHA256", expected_manifest):
                first = build_report(r580_archive, r615_archive, r615_tree)
                second = build_report(r580_archive, r615_archive, r615_tree)

        first.pop("generated_utc")
        second.pop("generated_utc")
        self.assertEqual(first, second)
        self.assertEqual(first["sources"]["r580"]["selected_uvm_file_count"], len(r580))
        self.assertTrue(first["sources"]["audit_script_sha256"])
        self.assertTrue(first["prerequisites"]["r615_gv100_uvm_hal_dispatch"]["r615_missing_targets"])


if __name__ == "__main__":
    unittest.main()
