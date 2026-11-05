# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/inspect_pc3_v100_module_ftrace.py"
SPEC = importlib.util.spec_from_file_location("pc3_v100_module_ftrace", TOOL_PATH)
TOOL = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(TOOL)


def valid_report():
    return {
        "schema":"nvidia-hybrid-pc3-v100-module-ftrace-v4",
        "status":"observed",
        "hostname":"pc3-v100",
        "execution_scope":{"read_only":True, "tracefs_write_attempted":False,
            "kprobe_event_definition_created":False, "experimental_module_loaded":False,
            "stock_driver_changed":False, "pci_binding_changed":False, "vm_management_issued":False},
        "gpus":[{"name":"Tesla V100-SXM2-16GB", "pci":"0000:00:05.0", "driver_version":"580.178.04"}],
        "module_elf":{"version":"580.178.04", "elf_class":"ELF64", "elf_type":"REL",
            "machine":"Advanced Micro Devices X86-64", "ftrace_related_sections":[],
            "target_symbols":{}},
        "target_fentry_inspection":{name:{"symbol_found":True, "objdump_succeeded":True,
            "fentry_reference":False, "mcount_reference":False, "matching_line_count":0,
            "symbol_header_found":True, "instruction_line_count":1}
            for name in TOOL.TARGETS},
        "available_filter_function_targets":[],
    }


class PC3V100ModuleFtraceTests(unittest.TestCase):
    def test_only_ftrace_related_sections_are_retained(self):
        sections = {
            1:{"name":".text", "type":"PROGBITS", "size":1024, "allocated":True, "executable":True},
            2:{"name":"__mcount_loc", "type":"PROGBITS", "size":80, "allocated":True, "executable":False},
            3:{"name":".rela__mcount_loc", "type":"RELA", "size":240, "allocated":False, "executable":False},
        }
        names = [item["name"] for item in TOOL.ftrace_sections(sections)]
        self.assertEqual(names, ["__mcount_loc", ".rela__mcount_loc"])

    def test_disassembly_classifies_only_fentry_and_mcount_references(self):
        result = TOOL.classify_disassembly("0000000000000000 <target>:\n  0: e8 00 00 00 00 call 5 <__fentry__>\nR_X86_64_PLT32 __fentry__-0x4\n", 0, "target")
        self.assertTrue(result["objdump_succeeded"])
        self.assertTrue(result["fentry_reference"])
        self.assertFalse(result["mcount_reference"])
        self.assertEqual(result["matching_line_count"], 2)
        self.assertTrue(result["symbol_header_found"])
        self.assertEqual(result["instruction_line_count"], 1)
        empty_success = TOOL.classify_disassembly("", 0, "target")
        self.assertFalse(empty_success["symbol_header_found"])
        self.assertEqual(empty_success["instruction_line_count"], 0)
        failed = TOOL.classify_disassembly("", 1, "target")
        self.assertIsNone(failed["fentry_reference"])

    def test_config_parser_distinguishes_unset_from_missing(self):
        lines = ["CONFIG_DYNAMIC_FTRACE=y", "# CONFIG_KPROBE_EVENTS_ON_NOTRACE is not set"]
        self.assertEqual(TOOL.config_value(lines, "DYNAMIC_FTRACE"), "y")
        self.assertEqual(TOOL.config_value(lines, "KPROBE_EVENTS_ON_NOTRACE"), "n")
        self.assertEqual(TOOL.config_value(lines, "FUNCTION_TRACER"), "unknown")

    def test_os_release_parser_retains_only_os_identity_fields(self):
        parsed = TOOL.parse_os_release('ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.3 LTS"\nHOME_URL="https://example.invalid"\n')
        self.assertEqual(parsed, {"ID":"ubuntu", "VERSION_ID":"24.04", "PRETTY_NAME":"Ubuntu 24.04.3 LTS"})

    def test_generated_guest_query_is_read_only_and_never_creates_probe_events(self):
        source = TOOL.guest_probe_script()
        self.assertIn("objdump", source)
        self.assertIn("-disassemble=", source)
        self.assertIn("available_filter_functions", source)
        self.assertNotIn('/sys/kernel/tracing/kprobe_events', source)
        self.assertNotIn('append_command(', source)
        self.assertNotIn('os.O_WRONLY', source)
        self.assertNotIn("tracefs_write_attempted=True", source)
        self.assertIn('"kprobe_event_definition_created":False', source)
        self.assertIn("pass_fds=(fd,)", source)
        compile(source, "<pc3-v100-module-ftrace>", "exec")

    def test_report_validator_requires_exact_guest_identity_and_no_mutation(self):
        self.assertEqual(TOOL.validate_report(valid_report())["status"], "observed")
        report = valid_report()
        report["execution_scope"]["tracefs_write_attempted"] = True
        with self.assertRaisesRegex(ValueError, "read-only"):
            TOOL.validate_report(report)
        report = valid_report()
        report["gpus"][0]["driver_version"] = "595.99.02"
        with self.assertRaisesRegex(ValueError, "stock R580 V100"):
            TOOL.validate_report(report)
        report = valid_report()
        report["target_fentry_inspection"][TOOL.TARGETS[0]]["instruction_line_count"] = 0
        with self.assertRaisesRegex(ValueError, "verified function body"):
            TOOL.validate_report(report)


if __name__ == "__main__":
    unittest.main()
