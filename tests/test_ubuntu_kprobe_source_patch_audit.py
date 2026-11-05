# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/audit_ubuntu_kprobe_source_patch.py"
SPEC = importlib.util.spec_from_file_location("ubuntu_kprobe_source_patch_audit", TOOL_PATH)
TOOL = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(TOOL)


class UbuntuKprobePatchAuditTests(unittest.TestCase):
    def test_descriptor_parses_source_version_and_exact_diff_digest(self):
        dsc = """Source: linux
Version: 6.8.0-147.147
Checksums-Sha256:
 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 17 linux_6.8.0-147.147.diff.gz
Files:
 00000000000000000000000000000000 17 linux_6.8.0-147.147.diff.gz
"""
        parsed = TOOL.source_dsc_metadata(dsc)
        self.assertEqual(parsed["source"], "linux")
        self.assertEqual(parsed["version"], "6.8.0-147.147")
        self.assertEqual(parsed["checksums_sha256"]["sha256"]["linux_6.8.0-147.147.diff.gz"],
                         "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        self.assertEqual(parsed["checksums_sha256"]["md5"]["linux_6.8.0-147.147.diff.gz"],
                         "00000000000000000000000000000000")

    def test_patch_hunks_parse_only_the_target_file_and_detect_overlap(self):
        hunks = [
            {"old_start":290, "old_count":7, "new_start":290, "new_count":7},
            {"old_start":670, "old_count":6, "new_start":670, "new_count":21},
        ]
        contract = {"name":"notrace", "start":433, "end":475}
        self.assertFalse(TOOL.hunk_overlaps_contract(hunks[0], contract))
        self.assertFalse(TOOL.hunk_overlaps_contract(hunks[1], contract))
        self.assertTrue(TOOL.hunk_overlaps_contract(
            {"old_start":470, "old_count":8, "new_start":470, "new_count":8}, contract))
        self.assertTrue(TOOL.hunk_overlaps_contract(
            {"old_start":475, "old_count":0, "new_start":475, "new_count":1}, contract))

    def test_source_contract_ranges_find_upstream_guard_and_registration(self):
        source = """#if defined(CONFIG_DYNAMIC_FTRACE) && \\
        !defined(CONFIG_KPROBE_EVENTS_ON_NOTRACE)
static bool within_notrace_func(void) { return true; }
#else
#define within_notrace_func(x) (false)
#endif
static int __register_trace_kprobe(void) {
 return -EINVAL;
}
static void __unregister_trace_kprobe(void) {
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace_kprobe.c"
            path.write_text(source)
            ranges = TOOL.source_contract_ranges(path)
        self.assertEqual(ranges[0], {"name":"dynamic-ftrace notrace guard", "start":1, "end":6})
        self.assertEqual(ranges[1], {"name":"trace-kprobe registration", "start":7, "end":9})


if __name__ == "__main__":
    unittest.main()
