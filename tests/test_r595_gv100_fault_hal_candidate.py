# SPDX-License-Identifier: MIT
"""Tests for the compile-only R595 GV100 fault-HAL candidate staging."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.probe_r595_gv100_fault_hal import (  # noqa: E402
    FAULT_CALLBACKS,
    callback_symbol_audit,
    stage_fault_hal_candidate,
)


class R595Gv100FaultHalCandidateTests(unittest.TestCase):
    def test_symbol_audit_requires_every_real_callback_definition(self):
        nm_output = "\n".join(
            f"00000000 T {symbol}" for symbol in FAULT_CALLBACKS.values())
        audit = callback_symbol_audit(nm_output, FAULT_CALLBACKS)
        self.assertTrue(audit["verified"])
        self.assertEqual(audit["defined_callbacks"], sorted(FAULT_CALLBACKS.values()))
        self.assertEqual(audit["missing_callbacks"], [])

    def test_symbol_audit_rejects_missing_or_undefined_symbols(self):
        names = list(FAULT_CALLBACKS.values())
        nm_output = "00000000 T " + names[0] + "\n00000000 U " + names[1]
        audit = callback_symbol_audit(nm_output, FAULT_CALLBACKS)
        self.assertFalse(audit["verified"])
        self.assertEqual(audit["defined_callbacks"], [names[0]])
        self.assertEqual(audit["missing_callbacks"], sorted(names[1:]))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="r595-gv100-fault-hal-")
        self.root = Path(self.temporary.name)
        self.r580 = self.root / "r580"
        self.r595 = self.root / "r595"
        (self.r580 / "hwref/pascal/gp100").mkdir(parents=True)
        (self.r580 / "nvidia-uvm").mkdir()
        (self.r595 / "hwref/turing/tu102").mkdir(parents=True)
        for relative in (
            "uvm_volta_fault_buffer.c", "uvm_pascal_fault_buffer.c",
            "uvm_hal.h", "uvm_hal.c", "nvidia-uvm-sources.Kbuild",
        ):
            (self.r580 / relative).parent.mkdir(parents=True, exist_ok=True)
        for relative in (
            "uvm_volta_fault_buffer.c", "uvm_volta_fault_buffer.h",
            "uvm_pascal_fault_buffer.c", "uvm_pascal_fault_buffer.h",
            "hwref/pascal/gp100/dev_fault.h", "clb069.h",
        ):
            path = self.r580 / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("/* pinned fixture: " + relative + " */\n")

        pascal = set(FAULT_CALLBACKS.values()) & {
            "uvm_hal_pascal_enable_replayable_faults",
            "uvm_hal_pascal_disable_replayable_faults",
            "uvm_hal_pascal_clear_replayable_faults",
            "uvm_hal_pascal_fault_buffer_entry_is_valid",
            "uvm_hal_pascal_fault_buffer_entry_clear_valid",
            "uvm_hal_pascal_fault_buffer_entry_size",
        }
        volta = set(FAULT_CALLBACKS.values()) - pascal
        self._write_definitions(self.r580 / "uvm_pascal_fault_buffer.c", pascal)
        (self.r580 / "uvm_pascal_fault_buffer.c").write_text(
            '#include "clb069.h"\n' +
            (self.r580 / "uvm_pascal_fault_buffer.c").read_text())
        self._write_definitions(self.r580 / "uvm_volta_fault_buffer.c", volta)
        prototypes = "\n".join(f"void {name}(void);" for name in sorted(FAULT_CALLBACKS.values()))
        (self.r580 / "uvm_hal.h").write_text(prototypes + "\n")

        (self.r595 / "nvidia-uvm-sources.Kbuild").write_text(
            "NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_tracker.c\n"
        )
        (self.r595 / "uvm_hal.h").write_text(
            "typedef struct { int placeholder; } uvm_fault_buffer_hal_t;\n"
            "struct uvm_fault_buffer_hal_struct\n{\n};\n"
        )
        (self.r595 / "uvm_hal.c").write_text(
            "static uvm_hal_class_ops_t arch_table[] =\n{\n"
            "    {\n"
            "        .id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_TU100,\n"
            "        .u.arch_ops = {}\n"
            "    },\n};\n"
            "static uvm_hal_class_ops_t fault_buffer_table[] =\n{\n"
            "    {\n"
            "        .id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_TU100,\n"
            "        .u.fault_buffer_ops = {}\n"
            "    },\n};\n"
        )
        self.callbacks = dict(FAULT_CALLBACKS)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def _write_definitions(path, symbols):
        path.write_text("\n".join(f"void {symbol}(void) {{ }}" for symbol in sorted(symbols)) + "\n")

    def test_stages_complete_explicit_gv100_row_and_legacy_fault_sources(self):
        for relative in ("uvm_pascal_fault_buffer.h",
                         "hwref/pascal/gp100/dev_fault.h"):
            target = self.r595 / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((self.r580 / relative).read_bytes())
        result = stage_fault_hal_candidate(self.r580, self.r595, self.callbacks)
        source_list = (self.r595 / "nvidia-uvm-sources.Kbuild").read_text()
        self.assertIn("NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_pascal_fault_buffer.c", source_list)
        self.assertEqual(source_list.count("uvm_pascal_fault_buffer.c"), 1)
        self.assertEqual(
            (self.r595 / "uvm_pascal_fault_buffer.c").read_text(),
            (self.r580 / "uvm_pascal_fault_buffer.c").read_text().replace(
                '"clb069.h"', '"uvm_pascal_compat_clb069.h"'),
        )
        self.assertTrue((self.r595 / "uvm_pascal_compat_clb069.h").is_file())

        hal = (self.r595 / "uvm_hal.c").read_text()
        gv100 = hal.split(".id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100", 1)[1]
        gv100 = gv100.split(".id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_TU100", 1)[0]
        self.assertNotIn(".parent_id", gv100)
        for operation, symbol in self.callbacks.items():
            self.assertIn(f".{operation} = {symbol}", gv100)
        self.assertEqual(result["callback_count"], 14)
        self.assertEqual(result["parent_id"], None)
        self.assertEqual(result["hardware_validated"], False)

        header = (self.r595 / "uvm_hal.h").read_text()
        for symbol in self.callbacks.values():
            self.assertEqual(header.count(f"{symbol}(void);"), 1)

    def test_refuses_incomplete_callback_map_before_mutating_tree(self):
        incomplete = dict(self.callbacks)
        incomplete.pop("get_fault_type")
        before = (self.r595 / "uvm_hal.c").read_bytes()
        with self.assertRaisesRegex(ValueError, "exactly 14 fault HAL operations"):
            stage_fault_hal_candidate(self.r580, self.r595, incomplete)
        self.assertEqual((self.r595 / "uvm_hal.c").read_bytes(), before)

    def test_refuses_missing_legacy_callback_body_before_mutating_tree(self):
        (self.r580 / "uvm_volta_fault_buffer.c").write_text("/* no callbacks */\n")
        before = (self.r595 / "nvidia-uvm-sources.Kbuild").read_bytes()
        with self.assertRaisesRegex(ValueError, "missing callback implementation"):
            stage_fault_hal_candidate(self.r580, self.r595, self.callbacks)
        self.assertEqual((self.r595 / "nvidia-uvm-sources.Kbuild").read_bytes(), before)

    def test_refuses_nonidentical_preexisting_pascal_header_without_partial_copy(self):
        target = self.r595 / "uvm_pascal_fault_buffer.h"
        target.write_text("different pinned header\n")
        with self.assertRaisesRegex(FileExistsError, "non-identical R595 input"):
            stage_fault_hal_candidate(self.r580, self.r595, self.callbacks)
        self.assertFalse((self.r595 / "uvm_pascal_fault_buffer.c").exists())
        self.assertEqual(target.read_text(), "different pinned header\n")


if __name__ == "__main__":
    unittest.main()
