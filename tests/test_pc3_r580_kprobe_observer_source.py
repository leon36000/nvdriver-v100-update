# SPDX-License-Identifier: MIT
from pathlib import Path
import hashlib
import json
import re
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE_DIR = ROOT / "probes/pc3_r580_kprobe_observer"
SOURCE_PATH = PROBE_DIR / "pc3_r580_kprobe_observer.c"
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")
KBUILD = (PROBE_DIR / "Kbuild").read_text(encoding="utf-8")
PINNED_NV_H = ROOT / "build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04/common/inc/nv.h"
SELECTOR_REPORT = ROOT / "evidence/rea-r580-selector-state-field-v1-20261022.json"
DESCRIPTOR_SELECTOR_REPORT = ROOT / "evidence/rea-r580-normalized-descriptor-selector-v1-20261022.json"


def body(name: str) -> str:
    match = re.search(
        rf"static\s+(?:\w+\s+)*{re.escape(name)}\s*\([^)]*\)\s*\{{(.*?)\n\}}",
        SOURCE,
        re.S,
    )
    if not match:
        raise AssertionError(f"function body not found: {name}")
    return match.group(1)


class Pc3R580KprobeObserverSourceTests(unittest.TestCase):
    def test_build_is_one_gpl_module_and_target_is_fixed(self):
        self.assertIn("obj-m += pc3_r580_kprobe_observer.o", KBUILD)
        self.assertIn('#define PC3_R580_TARGET "nvidia:rm_init_adapter"', SOURCE)
        self.assertIn('MODULE_LICENSE("GPL")', SOURCE)
        self.assertNotRegex(SOURCE, r"module_param(_named)?\s*\(\s*target\b")

    def test_selector_path_uses_only_fixed_symbols_and_count_only_handlers(self):
        self.assertIn('#define PC3_R580_SELECTOR_TARGET "nvidia:_nv000790rm"', SOURCE)
        self.assertIn('#define PC3_R580_LOOKUP_TARGET "nvidia:_nv031399rm"', SOURCE)
        self.assertRegex(SOURCE,
                         r"static bool observe_selector_path;\s*module_param\(observe_selector_path, bool, 0400\);")
        self.assertIn("module_param_cb(selector_hits, &atomic_count_ops, &selector_hit_count, 0400)", SOURCE)
        self.assertIn("module_param_cb(lookup_hits, &lookup_hits_ops, NULL, 0400)", SOURCE)
        handler = body("pc3_r580_selector_probe_handler")
        self.assertIn("atomic64_inc(&selector_hit_count)", handler)
        self.assertIn("record_lookup_observation(registers)", handler)
        self.assertIn("Read-only count of _nv031399rm entries observed", SOURCE)
        self.assertRegex(handler,
                         r"if\s*\(probe\s*==\s*&selector_probe\)[\s\S]*?else if\s*\(probe\s*==\s*&lookup_probe\)")
        self.assertIn("if (capture_selector)", handler)
        self.assertNotIn("regs_get_kernel_argument", handler)
        for forbidden in ("copy_from_kernel", "kmalloc", "pr_", "printk",
                          "mutex_", "schedule("):
            self.assertNotIn(forbidden, handler)
        self.assertIn("NOKPROBE_SYMBOL(pc3_r580_selector_probe_handler)", SOURCE)
        self.assertNotRegex(SOURCE, r"module_param(_named)?\s*\(\s*(?:target|symbol)\b")

    def test_selector_value_capture_is_opt_in_and_reads_only_the_second_scalar_argument(self):
        self.assertRegex(SOURCE,
                         r"static bool capture_selector;\s*module_param\(capture_selector, bool, 0400\);")
        self.assertIn("regs_get_kernel_argument(registers, 1)", SOURCE)
        self.assertIn("module_param_cb(selector_observation,", SOURCE)
        getter = body("selector_observation_get")
        self.assertIn('"%08x unavailable\\n"', getter)
        self.assertIn("atomic64_read(&lookup_observation)", getter)
        self.assertIn("%08x %08x\\n", getter)
        handler = body("pc3_r580_selector_probe_handler")
        self.assertRegex(handler, r"probe\s*==\s*&lookup_probe[\s\S]*?record_lookup_observation\(registers\)")
        capture = body("record_lookup_observation")
        self.assertIn("regs_get_kernel_argument(registers, 1)", capture)
        self.assertRegex(handler,
                         r"if\s*\(capture_selector\)\s*record_lookup_observation\(registers\)")
        self.assertIn("atomic64_cmpxchg(&lookup_observation", capture)
        self.assertIn("NOKPROBE_SYMBOL(record_lookup_observation)", SOURCE)
        self.assertRegex(body("pc3_r580_kprobe_observer_init"),
                         r"if\s*\(capture_selector\s*&&\s*\(!arm\s*\|\|\s*!observe_selector_path\)\)\s*return\s+-EINVAL;")
        for forbidden in ("copy_from_kernel", "printk", "pr_", "kmalloc", "mutex_",
                          "schedule(", "regs->", "probe->addr"):
            self.assertNotIn(forbidden, handler)

    def test_lookup_count_and_scalar_are_one_atomic_observation(self):
        self.assertIn("static atomic64_t lookup_observation = ATOMIC64_INIT(0)", SOURCE)
        self.assertIn("module_param_cb(lookup_hits, &lookup_hits_ops, NULL, 0400)", SOURCE)
        count_getter = body("lookup_hits_get")
        observation_getter = body("selector_observation_get")
        self.assertIn("atomic64_read(&lookup_observation)", count_getter)
        self.assertIn("atomic64_read(&lookup_observation)", observation_getter)
        self.assertIn(">> 32", count_getter)
        self.assertIn("(u32)(snapshot >> 32)", observation_getter)
        capture = body("record_lookup_observation")
        self.assertIn("atomic64_cmpxchg(&lookup_observation", capture)
        self.assertIn("old_snapshot", capture)
        self.assertNotRegex(capture, r"\b(?:u64|s64)\s+current\b|\bcurrent\s*=")
        self.assertNotIn("selector_value_valid", SOURCE)

    def test_lookup_callsite_captures_all_three_arguments_as_one_bounded_snapshot(self):
        self.assertIn('#define PC3_R580_LOOKUP_CALL_TARGET "nvidia:_nv031364rm"', SOURCE)
        self.assertRegex(SOURCE, r"#define PC3_R580_LOOKUP_CALL_OFFSET 0x92UL")
        self.assertRegex(SOURCE,
                         r"static bool capture_lookup_callsite;\s*module_param\(capture_lookup_callsite, bool, 0400\);")
        self.assertIn("module_param_cb(lookup_callsite_observation,", SOURCE)
        self.assertIn("module_param_cb(lookup_callsite_dropped, &atomic_count_ops, &lookup_callsite_dropped, 0400)", SOURCE)
        capture = body("record_lookup_callsite")
        for argument in (0, 1, 2):
            self.assertIn(f"regs_get_kernel_argument(registers, {argument})", capture)
        self.assertEqual(capture.count("atomic64_cmpxchg(&lookup_callsite_sequence"), 2)
        self.assertIn("atomic64_inc(&lookup_callsite_dropped)", capture)
        self.assertIn("WRITE_ONCE(lookup_callsite_arg0", capture)
        self.assertIn("WRITE_ONCE(lookup_callsite_arg1", capture)
        self.assertIn("WRITE_ONCE(lookup_callsite_arg2", capture)
        self.assertIn("smp_wmb()", capture)
        self.assertIn("NOKPROBE_SYMBOL(record_lookup_callsite)", SOURCE)
        getter = body("lookup_callsite_observation_get")
        self.assertGreaterEqual(getter.count("atomic64_read(&lookup_callsite_sequence)"), 2)
        self.assertIn("READ_ONCE(lookup_callsite_arg0)", getter)
        self.assertIn("READ_ONCE(lookup_callsite_arg1)", getter)
        self.assertIn("READ_ONCE(lookup_callsite_arg2)", getter)
        self.assertIn("smp_rmb()", getter)
        self.assertIn("%016llx %08x %08x %08x\\n", getter)
        handler = body("pc3_r580_selector_probe_handler")
        self.assertRegex(handler,
                         r"probe\s*==\s*&callsite_probe[\s\S]*?record_lookup_callsite\(registers\)")
        init = body("pc3_r580_kprobe_observer_init")
        self.assertRegex(init,
                         r"if\s*\(capture_lookup_callsite\s*&&\s*\(!arm\s*\|\|\s*!observe_selector_path\)\)\s*return\s+-EINVAL;")
        self.assertIn("callsite_probe.offset = PC3_R580_LOOKUP_CALL_OFFSET", init)
        self.assertIn("register_kprobe(&callsite_probe)", init)
        for forbidden in ("copy_from_kernel", "mutex_", "spin_lock", "schedule(", "printk", "pr_"):
            self.assertNotIn(forbidden, capture)

    def test_lookup_return_site_capture_uses_hidden_call_continuation_and_nofault_stack_read(self):
        self.assertIn("#define PC3_R580_LOOKUP_CALL_LENGTH 5UL", SOURCE)
        self.assertRegex(SOURCE,
                         r"static bool capture_lookup_return_site;\s*module_param\(capture_lookup_return_site, bool, 0400\);")
        self.assertIn("static unsigned long lookup_expected_return_ip", SOURCE)
        self.assertIn("module_param_cb(lookup_return_site_matches", SOURCE)
        self.assertIn("module_param_cb(lookup_return_site_read_failures", SOURCE)
        self.assertIn("module_param_cb(lookup_return_site_unmatched", SOURCE)
        self.assertIn("module_param(lookup_return_site_ready, bool, 0400)", SOURCE)
        resolver = body("resolve_lookup_return_site")
        self.assertIn("KPROBE_FLAG_DISABLED", resolver)
        self.assertIn('.symbol_name = PC3_R580_LOOKUP_CALL_TARGET', resolver)
        self.assertIn(".offset = PC3_R580_LOOKUP_CALL_OFFSET", resolver)
        self.assertIn("resolver.addr + PC3_R580_LOOKUP_CALL_LENGTH", resolver)
        self.assertLess(resolver.index("register_kprobe(&resolver)"),
                        resolver.index("WRITE_ONCE(lookup_expected_return_ip"))
        self.assertLess(resolver.index("WRITE_ONCE(lookup_expected_return_ip"),
                        resolver.index("unregister_kprobe(&resolver)"))
        self.assertIn("NOKPROBE_SYMBOL(resolve_lookup_return_site)", SOURCE)
        capture = body("record_lookup_return_site")
        self.assertIn("copy_from_kernel_nofault(&return_ip", capture)
        self.assertIn("registers->sp", capture)
        self.assertIn("READ_ONCE(lookup_expected_return_ip)", capture)
        self.assertIn("atomic64_inc(&lookup_return_site_read_failures)", capture)
        self.assertIn("atomic64_inc(&lookup_return_site_unmatched)", capture)
        self.assertIn("atomic64_inc(&lookup_return_site_matches)", capture)
        self.assertIn("NOKPROBE_SYMBOL(record_lookup_return_site)", SOURCE)
        handler = body("pc3_r580_selector_probe_handler")
        self.assertRegex(handler,
                         r"probe\s*==\s*&lookup_probe[\s\S]*?record_lookup_return_site\(registers\)")
        for address_name in ("lookup_expected_return_ip", "lookup_return_site_address"):
            self.assertNotRegex(SOURCE, rf"module_param(?:_cb)?\([^\n]*{address_name}")

    def test_lookup_return_site_capture_is_active_only_and_excludes_other_capture_modes(self):
        init = body("pc3_r580_kprobe_observer_init")
        normalized = " ".join(init.split())
        self.assertIn("capture_lookup_return_site && (!arm || !observe_selector_path || capture_selector || capture_lookup_callsite || capture_lookup_branch)", normalized)
        self.assertIn("resolve_lookup_return_site()", init)
        self.assertLess(init.index("resolve_lookup_return_site()"),
                        init.index("register_kprobe(&lookup_probe)"))
        handler = body("pc3_r580_selector_probe_handler")
        self.assertRegex(handler,
                         r"probe\s*==\s*&lookup_probe[\s\S]*?record_lookup_return_site\(registers\)")

    def test_lookup_join_route_combines_only_fixed_count_sites_with_return_correlation(self):
        self.assertRegex(SOURCE,
                         r"static bool capture_lookup_join_route;\s*module_param\(capture_lookup_join_route, bool, 0400\);")
        init = body("pc3_r580_kprobe_observer_init")
        normalized = " ".join(init.split())
        self.assertIn("capture_lookup_join_route && (!arm || !observe_selector_path || !capture_lookup_return_site || capture_selector || capture_lookup_callsite || capture_lookup_branch)", normalized)
        self.assertIn("if (capture_lookup_join_route)", init)
        self.assertIn("register_lookup_join_predecessor_probes()", init)
        self.assertIn("register_kprobe(&lookup_join_predecessor_probes[index])",
                      body("register_lookup_join_predecessor_probes"))
        handler = body("pc3_r580_selector_probe_handler")
        self.assertIn("capture_lookup_branch || capture_lookup_join_route", handler)
        for forbidden in ("copy_from_kernel", "regs->", "pr_", "printk", "schedule("):
            self.assertNotIn(forbidden, handler)
        for suffix in ("031d", "09c1", "0a94", "0aaa", "0daa"):
            self.assertRegex(SOURCE,
                             rf"module_param_cb\(lookup_join_{suffix}_hits,\s*&atomic_count_ops,\s*&lookup_join_{suffix}_hit_count,\s*0400\)")

    def test_lookup_branch_counter_is_fixed_and_only_armed_with_callsite_capture(self):
        self.assertIn('#define PC3_R580_LOOKUP_BRANCH_TARGET "nvidia:_nv031364rm"', SOURCE)
        self.assertRegex(SOURCE, r"#define PC3_R580_LOOKUP_BRANCH_OFFSET 0x[dD]7[eE]UL")
        self.assertRegex(SOURCE, r"#define PC3_R580_LOOKUP_BRANCH_DECISION_OFFSET 0xa81UL")
        self.assertRegex(SOURCE,
                         r"static bool capture_lookup_branch;\s*module_param\(capture_lookup_branch, bool, 0400\);")
        self.assertRegex(SOURCE,
                         r"module_param_cb\(lookup_branch_hits,\s*&atomic_count_ops,\s*&lookup_branch_hit_count,\s*0400\)")
        handler = body("pc3_r580_selector_probe_handler")
        self.assertRegex(handler,
                         r"probe\s*==\s*&lookup_branch_probe[\s\S]*?atomic64_inc\(&lookup_branch_hit_count\)")
        self.assertIn("probe == &lookup_branch_decision_probe", handler)
        self.assertIn("registers->flags", handler)
        self.assertIn("X86_EFLAGS_CF", handler)
        self.assertIn("X86_EFLAGS_ZF", handler)
        self.assertIn("lookup_join_predecessor_offsets", SOURCE)
        self.assertIn("lookup_join_predecessor_probes", SOURCE)
        self.assertIn("lookup_join_predecessor_hit_counts", SOURCE)
        self.assertRegex(SOURCE, r"0x31dUL,\s*0x9c1UL,\s*0xa94UL,\s*0xaaaUL,\s*0xdaaUL")
        self.assertNotRegex(SOURCE, r"0x41fUL|0xac3UL|0xb97UL|0xbadUL|0xeadUL")
        for suffix in ("031d", "09c1", "0a94", "0aaa", "0daa"):
            self.assertIn(f"lookup_join_{suffix}_hits", SOURCE)
        self.assertNotRegex(SOURCE, r"lookup_join_(?:041f|0ac3|0b97|0bad|0ead)_hits")
        init = body("pc3_r580_kprobe_observer_init")
        self.assertRegex(init,
                         r"capture_lookup_branch\s*&&\s*\(!arm\s*\|\|\s*!observe_selector_path\s*\|\|\s*!capture_lookup_callsite\)")
        self.assertIn("lookup_branch_probe.offset = PC3_R580_LOOKUP_BRANCH_OFFSET", init)
        self.assertIn("lookup_branch_decision_probe.offset = PC3_R580_LOOKUP_BRANCH_DECISION_OFFSET", init)
        self.assertIn("register_lookup_join_predecessor_probes()", init)
        register = body("register_lookup_join_predecessor_probes")
        self.assertRegex(register,
                         r"register_kprobe\(\s*&lookup_join_predecessor_probes\[index\]\)")
        self.assertIn("unregister_kprobe(&lookup_branch_probe)", body("unregister_registered_probes"))
        for forbidden in ("copy_from_kernel", "mutex_", "schedule(", "printk", "pr_"):
            self.assertNotIn(forbidden, handler)

    def test_selector_register_argument_matches_pinned_callsite_dataflow(self):
        raw = DESCRIPTOR_SELECTOR_REPORT.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "998d3317f0289cf0f6a9e0402bd61acec473c6afa80a1b19c25901279a42781a")
        report = json.loads(raw)
        self.assertEqual(report["qualification"], "analysed_statically")
        self.assertEqual(report["key_for_this_call_path"]["call_arguments"], {
            "_nv031399rm_edi": 0,
            "_nv031399rm_esi": "record[0x12c8]",
            "_nv031399rm_edx": 0,
        })
        lookup = next(entry for entry in report["selector_flow"]
                      if entry["symbol"] == "_nv031364rm")
        self.assertIn("Loads ESI from record+0x12c8", lookup["observation"])
        self.assertIn("calls _nv031399rm", lookup["observation"])
        handler = body("record_lookup_observation")
        self.assertIn("regs_get_kernel_argument(registers, 1)", handler)

    def test_partial_selector_registration_and_module_exit_unregister_all_probes(self):
        cleanup = body("unregister_registered_probes")
        for probe, flag in (("adapter_probe", "adapter_probe_registered"),
                            ("selector_probe", "selector_probe_registered"),
                            ("lookup_probe", "lookup_probe_registered"),
                            ("callsite_probe", "callsite_probe_registered"),
                            ("lookup_branch_probe", "lookup_branch_probe_registered"),
                            ("lookup_branch_decision_probe", "lookup_branch_decision_probe_registered")):
            with self.subTest(probe=probe):
                self.assertRegex(cleanup,
                                 rf"if\s*\({flag}\)\s*\{{\s*unregister_kprobe\(&{probe}\);")
        self.assertIn("unregister_kprobe(&lookup_join_predecessor_probes[index])", cleanup)
        init = body("pc3_r580_kprobe_observer_init")
        self.assertIn("unregister_registered_probes()", init)
        exit_body = body("pc3_r580_kprobe_observer_exit")
        self.assertIn("unregister_registered_probes()", exit_body)

    def test_default_mode_registers_disabled_and_active_mode_is_explicit(self):
        self.assertRegex(SOURCE, r"static bool arm;\s*module_param\(arm, bool, 0400\);")
        init = body("pc3_r580_kprobe_observer_init")
        self.assertIn("adapter_probe.symbol_name = PC3_R580_TARGET", init)
        self.assertRegex(init, r"if\s*\(!arm\)\s*adapter_probe\.flags\s*=\s*KPROBE_FLAG_DISABLED;")
        self.assertIn("register_kprobe(&adapter_probe)", init)

    def test_scalar_capture_is_opt_in_and_cannot_fault_sleep_or_expose_pointer(self):
        handler = body("pc3_r580_probe_handler")
        self.assertIn("atomic64_inc(&hit_count)", handler)
        self.assertRegex(SOURCE, r"static bool capture_state;\s*module_param\(capture_state, bool, 0400\);")
        self.assertIn("if (!capture_state)", handler)
        self.assertIn("regs_get_kernel_argument(registers, 1)", handler)
        self.assertEqual(handler.count("copy_from_kernel_nofault(&"), 2)
        self.assertIn("NV_STATE_FLAGS_OFFSET 0x10UL", SOURCE)
        self.assertIn("NV_STATE_DISPLAY_SOC_CHIP_ID_OFFSET 0x274UL", SOURCE)
        forbidden = ("printk", "pr_", "kmalloc", "kzalloc", "mutex_", "spin_lock",
                     "msleep", "schedule(", "regs->", "probe->addr", "copy_from_kernel(")
        for token in forbidden:
            self.assertNotIn(token, handler)
        self.assertNotRegex(handler, r"\*\s*\(?(?:u32|int|unsigned)")
        self.assertNotRegex(SOURCE, r"module_param(_named)?\s*\(\s*(?:state_address|nv_state|pointer)\b")
        self.assertIn("NOKPROBE_SYMBOL(pc3_r580_probe_handler)", SOURCE)

    def test_capture_requires_an_armed_probe_and_reports_only_scalar_pair(self):
        init = body("pc3_r580_kprobe_observer_init")
        self.assertRegex(init, r"if\s*\(capture_state\s*&&\s*!arm\)\s*return\s+-EINVAL;")
        self.assertRegex(init, r"if\s*\(owner_nonce\s*==\s*0\)\s*return\s+-EINVAL;")
        getter = body("state_snapshot_get")
        self.assertIn("atomic64_read(&state_snapshot)", getter)
        self.assertIn("%08x %08x\\n", getter)
        self.assertIn('"unavailable\\n"', getter)
        self.assertIn("module_param_cb(state_snapshot, &state_snapshot_ops, NULL, 0400)", SOURCE)
        self.assertIn("module_param_cb(state_reads, &state_reads_ops, NULL, 0400)", SOURCE)
        self.assertIn("module_param_cb(state_read_failures, &state_read_failures_ops, NULL, 0400)", SOURCE)
        self.assertIn("Never publish the address", SOURCE)

    def test_hit_count_is_read_only_and_only_reports_a_number(self):
        getter = body("hit_count_get")
        self.assertIn("atomic64_read(&hit_count)", getter)
        self.assertIn("module_param_cb(hits, &hit_count_ops, NULL, 0400)", SOURCE)
        self.assertNotRegex(SOURCE, r"module_param(_named)?\s*\(\s*hits\b")

    def test_scalar_offsets_match_the_pinned_r580_wrapper_abi_evidence(self):
        report = json.loads(SELECTOR_REPORT.read_text(encoding="utf-8"))
        nv_header_hash = report["inputs"]["common/inc/nv.h"]["sha256"]
        self.assertEqual(nv_header_hash,
                         "bc5802ef5a0e47be045cac9b74e61a0092f0bb96fc1ede05e2361d164e3b7787")
        self.assertEqual(hashlib.sha256(PINNED_NV_H.read_bytes()).hexdigest(), nv_header_hash)
        state = report["selector"]
        self.assertEqual(state["input_offset"], "nv_state_t+0x274")
        self.assertEqual(state["source_field"], "nv_state_t.disp_sw_soc_chip_id")
        self.assertEqual(state["source_field_type"], "NvU32")
        self.assertEqual(state["dwarf_field_offset"], "0x274")
        self.assertEqual(state["nv_state_t_size"], 784)
        self.assertEqual(struct.calcsize("P"), 8)
        self.assertEqual(2 * struct.calcsize("P"), 0x10)  # priv, os_state, then flags
        header = PINNED_NV_H.read_text(encoding="utf-8")
        self.assertRegex(header, r"void\s*\*priv;\s*/\* private data \*/\s*void\s*\*os_state;")
        self.assertRegex(header, r"void\s*\*os_state;[^}]{0,100}?int\s+flags;")
        self.assertRegex(header, r"NvU32\s+disp_sw_soc_chip_id;")

    def test_every_successful_registration_is_unregistered_on_exit(self):
        init = body("pc3_r580_kprobe_observer_init")
        exit_body = body("pc3_r580_kprobe_observer_exit")
        self.assertIn("adapter_probe_registered = true", init)
        self.assertIn("unregister_registered_probes()", exit_body)


if __name__ == "__main__":
    unittest.main()
