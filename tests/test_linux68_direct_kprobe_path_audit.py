# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/audit_linux68_direct_kprobe_path.py"
SPEC = importlib.util.spec_from_file_location("linux68_direct_kprobe_path_audit", TOOL_PATH)
TOOL = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(TOOL)


def source_fixture():
    core = r'''
kprobe_opcode_t * __weak kprobe_lookup_name(const char *name, unsigned int unused) {
    return (void *)kallsyms_lookup_name(name);
}
static kprobe_opcode_t * _kprobe_addr(kprobe_opcode_t *addr, const char *symbol_name,
                                      unsigned long offset, bool *on_func_entry) {
    if (symbol_name) addr = kprobe_lookup_name(symbol_name, offset);
    return addr;
}
static int check_ftrace_location(struct kprobe *p) {
    if (ftrace_location(addr) == addr) p->flags |= KPROBE_FLAG_FTRACE;
    return 0;
}
static int check_kprobe_address_safe(struct kprobe *p, struct module **probed_mod) {
    if (check_ftrace_location(p)) return -EINVAL;
    *probed_mod = __module_text_address((unsigned long)p->addr);
    if (*probed_mod && !try_module_get(*probed_mod)) return -ENOENT;
    if (within_module_init((unsigned long)p->addr, *probed_mod) ||
        within_kprobe_blacklist((unsigned long)p->addr)) return -EINVAL;
    return 0;
}
static int __arm_kprobe(struct kprobe *p) { return 0; }
static int arm_kprobe(struct kprobe *kp) {
    if (kprobe_ftrace(kp)) return arm_kprobe_ftrace(kp);
    mutex_lock(&text_mutex);
    __arm_kprobe(kp);
    mutex_unlock(&text_mutex);
    return 0;
}
int register_kprobe(struct kprobe *p) {
    int ret = check_kprobe_address_safe(p, &probed_mod);
    if (ret) return ret;
    ret = prepare_kprobe(p);
    if (!ret) ret = arm_kprobe(p);
    if (probed_mod) module_put(probed_mod);
    return ret;
}
EXPORT_SYMBOL_GPL(register_kprobe);
void unregister_kprobes(struct kprobe **kps, int num) {
    mutex_lock(&kprobe_mutex);
    __unregister_kprobe_top(kps[0]);
    mutex_unlock(&kprobe_mutex);
    synchronize_rcu();
    __unregister_kprobe_bottom(kps[0]);
}
static void kill_kprobe(struct kprobe *p) { p->flags |= KPROBE_FLAG_GONE; }
static int kprobes_module_callback(struct notifier_block *nb, unsigned long val, void *data) {
    if (val == MODULE_STATE_GOING && within_module_core(p->addr, mod)) kill_kprobe(p);
    return NOTIFY_DONE;
}
'''
    return {
        "kernel/kprobes.c": core,
        "kernel/module/kallsyms.c": r'''
static unsigned long __module_kallsyms_lookup_name(const char *name) {
    char *colon = strnchr(name, MODULE_NAME_LEN, ':');
    if (colon) {
        mod = find_module_all(name, colon - name, false);
        if (mod) return __find_kallsyms_symbol_value(mod, colon + 1);
        return 0;
    }
    return 0;
}
''',
        "arch/x86/kernel/kprobes/core.c": r'''
kprobe_opcode_t *arch_adjust_kprobe_addr(unsigned long addr, unsigned long offset,
                                          bool *on_func_entry) {
    u32 insn;
    if (copy_from_kernel_nofault(&insn, (void *)addr, sizeof(u32))) return NULL;
    if (is_endbr(insn)) return (void *)addr;
    return (void *)addr + offset;
}
''',
        "include/linux/kprobes.h": "int register_kprobe(struct kprobe *p); void unregister_kprobe(struct kprobe *p);",
        "kernel/trace/trace_kprobe.c": r'''
static int __register_trace_kprobe(struct trace_kprobe *tk) {
    if (within_notrace_func(tk)) return -EINVAL;
    return register_kprobe(&tk->rp.kp);
}
''',
        "kernel/kallsyms.c": "unsigned long kallsyms_lookup_name(const char *name) { return module_kallsyms_lookup_name(name); }",
    }


class Linux68DirectKprobePathTests(unittest.TestCase):
    def test_direct_api_route_uses_symbol_lookup_and_module_qualified_name(self):
        result = TOOL.audit_direct_route(source_fixture())
        self.assertTrue(result["direct_register_kprobe_module_api"])
        self.assertTrue(result["module_qualified_symbol_resolution"])
        self.assertFalse(result["direct_path_notrace_guard"])
        self.assertIn("kprobe.symbol_name (module:symbol)", result["sequence"])

    def test_notrace_guard_in_trace_frontend_remains_distinct(self):
        result = TOOL.audit_direct_route(source_fixture())
        self.assertTrue(result["contrasting_trace_event_path_has_notrace_guard"])

    def test_audit_rejects_a_direct_path_that_adds_the_trace_guard(self):
        sources = source_fixture()
        sources["kernel/kprobes.c"] = sources["kernel/kprobes.c"].replace(
            "int ret = check_kprobe_address_safe(p, &probed_mod);",
            "int ret = within_notrace_func(p) ? -EINVAL : check_kprobe_address_safe(p, &probed_mod);",
        )
        with self.assertRaisesRegex(ValueError, "notrace guard"):
            TOOL.audit_direct_route(sources)

    def test_audit_requires_rcu_synchronized_unregister(self):
        sources = source_fixture()
        sources["kernel/kprobes.c"] = sources["kernel/kprobes.c"].replace("synchronize_rcu();", "")
        with self.assertRaisesRegex(ValueError, "synchronize handler lifetime"):
            TOOL.audit_direct_route(sources)

    def test_audit_requires_module_unload_invalidation(self):
        sources = source_fixture()
        sources["kernel/kprobes.c"] = sources["kernel/kprobes.c"].replace("kill_kprobe(p);", "")
        with self.assertRaisesRegex(ValueError, "module-unload probe invalidation"):
            TOOL.audit_direct_route(sources)

    def test_audit_requires_no_ftrace_callsite_fallback(self):
        sources = source_fixture()
        sources["kernel/kprobes.c"] = sources["kernel/kprobes.c"].replace("__arm_kprobe(kp);", "")
        with self.assertRaisesRegex(ValueError, "architecture breakpoint path"):
            TOOL.audit_direct_route(sources)

    def test_diff_selection_and_exact_path_set(self):
        diff = "".join(
            f"--- linux-6.8.0.orig/{name}\n+++ linux-6.8.0/{name}\n@@ -1 +1 @@\n-a\n+b\n"
            for name in sorted(TOOL.PATCHED_PATHS)
        ) + "--- linux-6.8.0.orig/kernel/unrelated.c\n+++ linux-6.8.0/kernel/unrelated.c\n@@ -1 +1 @@\n-x\n+y\n"
        selected = TOOL.selected_diff_blocks(diff, TOOL.PATCHED_PATHS)
        self.assertNotIn("kernel/unrelated.c", selected)
        self.assertIn("kernel/kprobes.c", selected)
        with self.assertRaisesRegex(ValueError, "exactly the six"):
            TOOL.apply_selected_patch(diff, {})

    @staticmethod
    def evidence_fixtures():
        config = {
            "config_kprobes": "y", "config_modules": "y", "config_module_unload": "y",
            "config_kallsyms": "y", "config_kallsyms_all": "y",
        }
        capability = {
            "status": "observed", "remote": {"guest": {
                "hostname": "pc3-v100", "kernel_release": "6.8.0-147-generic",
                "gpus": [{"name": "Tesla V100-SXM2-16GB", "driver_version": "580.178.04"}],
                "kernel_probe_config": config,
            }},
        }
        targets = sorted(TOOL.TARGETS)
        module = {"status": "observed", "remote": {"guest": {
            "hostname": "pc3-v100", "available_filter_function_targets": [],
            "module_elf": {"target_symbols": {name: {
                "section": ".text", "type": "FUNC", "size": 128,
            } for name in targets}},
            "target_fentry_inspection": {name: {
                "fentry_reference": False, "mcount_reference": False,
                "objdump_succeeded": True, "symbol_found": True,
            } for name in targets},
        }}}
        return capability, module

    def test_pc3_evidence_pins_guest_driver_config_and_targets(self):
        capability, module = self.evidence_fixtures()
        result = TOOL.validate_pc3_evidence(capability, module)
        self.assertEqual(result["driver"], "580.178.04")
        self.assertFalse(result["target_fentry_mcount_references"])
        self.assertTrue(result["target_functions_in_module_text"])
        capability, module = self.evidence_fixtures()
        capability["remote"]["guest"]["kernel_probe_config"]["config_kallsyms_all"] = "n"
        with self.assertRaisesRegex(ValueError, "config_kallsyms_all"):
            TOOL.validate_pc3_evidence(capability, module)
        capability, module = self.evidence_fixtures()
        module["remote"]["guest"]["module_elf"]["target_symbols"]["rm_init_adapter"]["section"] = ".init.text"
        with self.assertRaisesRegex(ValueError, "module .text functions"):
            TOOL.validate_pc3_evidence(capability, module)


if __name__ == "__main__":
    unittest.main()
