# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/audit_linux68_bpf_kprobe_path.py"
SPEC = importlib.util.spec_from_file_location("linux68_bpf_kprobe_path_audit", TOOL_PATH)
TOOL = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(TOOL)


class Linux68BpfKprobePathAuditTests(unittest.TestCase):
    @staticmethod
    def evidence_fixtures():
        names = sorted(TOOL.EXPECTED_RM_TARGETS)
        capability = {
            "schema": "nvidia-hybrid-pc3-v100-trace-capability-transport-v2",
            "status": "observed",
            "remote": {"guest": {
                "hostname": "pc3-v100", "kernel_release": "6.8.0-147-generic",
                "gpus": [{"name": "Tesla V100-SXM2-16GB", "driver_version": "580.178.04"}],
                "kernel_probe_config": {
                    "config_dynamic_ftrace": "y", "config_kprobe_events_on_notrace": "n",
                    "config_bpf_syscall": "y", "config_bpf_events": "y", "config_fprobe": "y",
                },
                "bpf_attachment_capabilities": {
                    "tools_available": {"bpftool": True, "bpftrace": True, "clang": False},
                    "effective_capabilities": {"cap_bpf": True, "cap_perfmon": True, "cap_sys_admin": True},
                },
            }},
        }
        module = {
            "schema": "nvidia-hybrid-pc3-v100-module-ftrace-transport-v4",
            "status": "observed",
            "remote": {"guest": {
                "hostname": "pc3-v100", "available_filter_function_targets": [],
                "module_elf": {"target_symbols": {name: {} for name in names}},
                "target_fentry_inspection": {name: {
                    "fentry_reference": False, "mcount_reference": False,
                    "objdump_succeeded": True, "symbol_found": True,
                } for name in names},
            }},
        }
        return capability, module

    def test_function_body_balances_nested_braces_and_ignores_comments(self):
        source = '''
int target(void) {
    if (1) { /* } is not a function terminator */ return 0; }
    return 1;
}
int after(void) { return 2; }
'''
        body = TOOL.function_body(source, "int target(void)")
        self.assertIn("if (1)", body)
        self.assertNotIn("int after", body)

    def test_source_paths_capture_perf_guard_and_fprobe_mechanisms(self):
        sources = {
            "perf": "int perf_kprobe_init(void) { return create_local_trace_kprobe(); }",
            "trace_kprobe": '''
#if defined(CONFIG_DYNAMIC_FTRACE) && !defined(CONFIG_KPROBE_EVENTS_ON_NOTRACE)
static bool within_notrace_func(void *tk) { return true; }
#endif
static int __register_trace_kprobe(void *tk) {
    if (within_notrace_func(tk)) return -EINVAL;
    return register_kprobe(tk);
}
static void *create_local_trace_kprobe(void) {
    return __register_trace_kprobe(tk);
}
''',
            "bpf_trace": '''
int bpf_kprobe_multi_link_attach(void) {
    ftrace_lookup_symbols();
    return register_fprobe_ips();
}
''',
            "fprobe": '''
int register_fprobe_ips(void) {
    ftrace_set_filter_ips();
    return register_ftrace_function();
}
''',
        }
        result = TOOL.audit_source_paths(sources)
        self.assertTrue(result["perf_event_kprobe_uses_notrace_guard"])
        self.assertTrue(result["kprobe_multi_uses_ftrace_fprobe"])

    def test_source_path_audit_rejects_a_missing_notrace_guard(self):
        sources = {
            "perf": "int perf_kprobe_init(void) { return create_local_trace_kprobe(); }",
            "trace_kprobe": '''
#if defined(CONFIG_DYNAMIC_FTRACE) && !defined(CONFIG_KPROBE_EVENTS_ON_NOTRACE)
static bool within_notrace_func(void *tk) { return false; }
#endif
static int __register_trace_kprobe(void *tk) { return register_kprobe(tk); }
static void *create_local_trace_kprobe(void) { return __register_trace_kprobe(tk); }
''',
            "bpf_trace": "int bpf_kprobe_multi_link_attach(void) { return register_fprobe_ips(); }",
            "fprobe": "int register_fprobe_ips(void) { return register_ftrace_function(); }",
        }
        with self.assertRaisesRegex(ValueError, "notrace guard"):
            TOOL.audit_source_paths(sources)

    def test_source_path_audit_rejects_direct_kprobe_multi_bypass(self):
        capability, _ = self.evidence_fixtures()
        sources = {
            "perf": "int perf_kprobe_init(void) { return create_local_trace_kprobe(); }",
            "trace_kprobe": '''
#if defined(CONFIG_DYNAMIC_FTRACE) && !defined(CONFIG_KPROBE_EVENTS_ON_NOTRACE)
static bool within_notrace_func(void *tk) { return true; }
#endif
static int __register_trace_kprobe(void *tk) {
    if (within_notrace_func(tk)) return -EINVAL;
    return register_kprobe(tk);
}
static void *create_local_trace_kprobe(void) { return __register_trace_kprobe(tk); }
''',
            "bpf_trace": "int bpf_kprobe_multi_link_attach(void) { return register_kprobe(); }",
            "fprobe": "int register_fprobe_ips(void) { return ftrace_set_filter_ips(); }",
        }
        with self.assertRaisesRegex(ValueError, "BPF kprobe-multi"):
            TOOL.audit_source_paths(sources)

    def test_pc3_evidence_requires_exact_guest_config_and_complete_symbols(self):
        capability, module = self.evidence_fixtures()
        result = TOOL.validate_pc3_evidence(capability, module)
        self.assertEqual(result["target_fentry_mcount_references"], False)
        self.assertEqual(set(result["target_filter_functions"]), set())

        capability, module = self.evidence_fixtures()
        capability["remote"]["guest"]["kernel_probe_config"]["config_fprobe"] = "n"
        with self.assertRaisesRegex(ValueError, "kernel config"):
            TOOL.validate_pc3_evidence(capability, module)

        capability, module = self.evidence_fixtures()
        del module["remote"]["guest"]["target_fentry_inspection"]["rm_init_adapter"]
        with self.assertRaisesRegex(ValueError, "all target functions"):
            TOOL.validate_pc3_evidence(capability, module)

    def test_diff_extractor_keeps_only_requested_kernel_sources(self):
        diff = '''
--- linux-6.8.0.orig/kernel/trace/trace_kprobe.c
+++ linux-6.8.0/kernel/trace/trace_kprobe.c
@@ -1 +1 @@
-old
+new
--- linux-6.8.0.orig/kernel/other.c
+++ linux-6.8.0/kernel/other.c
@@ -1 +1 @@
-before
+after
'''
        selected = TOOL.selected_diff_blocks(diff, {"kernel/trace/trace_kprobe.c"})
        self.assertIn("trace_kprobe.c", selected)
        self.assertNotIn("kernel/other.c", selected)
        self.assertIn("kernel/trace/trace_kprobe.c", TOOL.diff_file_paths(diff))
        self.assertNotIn("kernel/trace/fprobe.c", TOOL.diff_file_paths(diff))


if __name__ == "__main__":
    unittest.main()
