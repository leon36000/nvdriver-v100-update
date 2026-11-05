# SPDX-License-Identifier: MIT
import ast
import fcntl
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "tools/run_pc3_r580_kprobe_observer.py"
SPEC = importlib.util.spec_from_file_location("pc3_r580_kprobe_observer_runner", RUNNER_PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(RUNNER)


class Pc3R580KprobeObserverRunnerTests(unittest.TestCase):
    def test_parent_and_all_generated_guest_modes_are_valid_python(self):
        compile(RUNNER_PATH.read_text(encoding="utf-8"), str(RUNNER_PATH), "exec")
        modes = ((False, False, False, False, False),
                 (True, False, False, False, False),
                 (False, True, False, False, False),
                 (True, False, True, False, False),
                 (True, False, False, True, False),
                 (True, False, False, True, True),
                 (True, False, False, True, False, True),
                 (True, False, False, True, False, True, True),
                 (True, False, False, True, False, False, False, True),
                 (True, False, False, True, False, False, False, True, True))
        for active, build_only, capture_state, observe_selector_path, capture_selector, *extra in modes:
            capture_lookup_callsite = extra[0] if extra else False
            capture_lookup_branch = extra[1] if len(extra) > 1 else False
            capture_lookup_return_site = extra[2] if len(extra) > 2 else False
            capture_lookup_join_route = extra[3] if len(extra) > 3 else False
            source = RUNNER.guest_probe_script(active, build_only, capture_state,
                                               observe_selector_path, capture_selector,
                                               capture_lookup_callsite,
                                               capture_lookup_branch,
                                               capture_lookup_return_site,
                                               capture_lookup_join_route)
            compile(source, f"<pc3 guest active={active} build_only={build_only} capture={capture_state} selector={observe_selector_path}>", "exec")
            self.assertNotIn("__BUILD_ONLY__", source)
            self.assertNotIn("__CAPTURE_STATE__", source)
            self.assertNotIn("__OBSERVE_SELECTOR_PATH__", source)
            self.assertNotIn("__CAPTURE_SELECTOR__", source)
            self.assertNotIn("__CAPTURE_LOOKUP_CALLSITE__", source)
            self.assertNotIn("__CAPTURE_LOOKUP_BRANCH__", source)
            self.assertNotIn("__CAPTURE_LOOKUP_RETURN_SITE__", source)
            self.assertNotIn("__CAPTURE_LOOKUP_JOIN_ROUTE__", source)
            self.assertNotIn("__LOOKUP_JOIN_PREDECESSOR_TARGETS__", source)
            self.assertNotIn("__LOOKUP_JOIN_PREDECESSOR_PARAMETERS__", source)

    def test_build_only_guest_branch_cannot_reach_module_load(self):
        guest = ast.parse(RUNNER.guest_probe_script(False, build_only=True))
        branch = next(node for node in ast.walk(guest) if isinstance(node, ast.If)
                      and isinstance(node.test, ast.Constant)
                      and node.test.value is True
                      and 'build_only_passed' in ast.unparse(node.body))
        self.assertIn("build_only_passed", ast.unparse(branch.body))
        self.assertNotIn("insmod", ast.unparse(branch.body))
        self.assertIn("insmod", ast.unparse(branch.orelse))

    def test_cli_modes_are_mutually_constrained_and_report_capture_safely(self):
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--build-only", action="store_true"', source)
        self.assertIn('parser.add_argument("--capture-state", action="store_true"', source)
        self.assertIn('parser.add_argument("--capture-lookup-branch", action="store_true"', source)
        self.assertIn('symbol="copy_from_kernel_nofault"', source)
        self.assertIn('"EXPORT_SYMBOL_GPL"', source)
        self.assertIn('"imported_by_module":imported', source)
        self.assertIn('parser.add_argument("--capture-lookup-return-site", action="store_true"', source)
        self.assertIn('args.capture_lookup_return_site or args.capture_lookup_join_route', source)
        self.assertIn('if args.capture_state and not args.active:', source)
        capture = RUNNER.guest_probe_script(True, capture_state=True)
        self.assertIn('active_argv.append("capture_state=1")', capture)
        self.assertIn('"state_snapshot_after_trigger"', capture)
        self.assertIn('re.fullmatch(r"[0-9a-fA-F]{8} [0-9a-fA-F]{8}"', capture)
        self.assertNotIn('"state_address"', capture)

    def test_selector_observation_requires_active_mode_and_records_fixed_counter_deltas(self):
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--observe-selector-path", action="store_true"', source)
        self.assertIn('if args.observe_selector_path and not args.active:', source)
        self.assertIn('args.capture_lookup_return_site or args.capture_lookup_join_route', source)
        guest = RUNNER.guest_probe_script(True, observe_selector_path=True)
        self.assertIn('active_argv.append("observe_selector_path=1")', guest)
        self.assertIn('"selector_hits_before_trigger":parameter_uint("selector_hits")', guest)
        self.assertIn('"selector_hits_after_trigger"', guest)
        self.assertIn('"lookup_hits_before_trigger":selector_observation_count(lookup_observation_before)', guest)
        self.assertIn('lookup_observation_after=read_parameter("selector_observation")', guest)
        self.assertIn('active_state["lookup_hits_after_trigger"]=selector_observation_count(lookup_observation_after)', guest)
        self.assertRegex(guest, r'lookup_hits_delta=\(\s*active_state\["lookup_hits_after_trigger"\]\s*-\s*active_state\["lookup_hits_before_trigger"\]')
        self.assertIn('active_state["lookup_hits_delta"]', guest)
        self.assertIn('isinstance(lookup_hits_delta,int) and lookup_hits_delta > 0', guest)
        self.assertIn('active_state["selector_path_observation_passed"]', guest)
        self.assertIn('state_capture_ok and selector_path_ok', guest)
        self.assertIn('"nvidia:_nv000790rm"', guest)
        self.assertIn('"nvidia:_nv031399rm"', guest)

    def test_selector_scalar_capture_requires_one_lookup_and_a_typed_read_only_sample(self):
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--capture-selector", action="store_true"', source)
        self.assertIn('if args.capture_selector and not args.active:', source)
        self.assertIn('if args.capture_selector and not args.observe_selector_path:', source)
        guest = RUNNER.guest_probe_script(True, observe_selector_path=True,
                                          capture_selector=True)
        self.assertIn('active_argv.append("capture_selector=1")', guest)
        self.assertIn('"selector_observation_before_trigger":lookup_observation_before', guest)
        self.assertIn('active_state["selector_observation_after_trigger"]=lookup_observation_after', guest)
        self.assertRegex(guest, r'after\[0\]\s*-\s*before\[0\]\s*==\s*1')
        self.assertIn('active_state["selector_capture_passed"]', guest)
        self.assertIn('selector_capture_ok', guest)
        self.assertIn('"nvidia-hybrid-pc3-r580-direct-kprobe-canary-v6"', guest)
        self.assertIn('"active_selector_capture_passed"', guest)
        self.assertIn('"active_selector_capture_passed"', source)
        self.assertNotIn('read_parameter("selector_value")', guest)
        parsed = ast.parse(guest)
        validators = [node for node in parsed.body
                      if isinstance(node, ast.FunctionDef)
                      and node.name in ("parse_selector_observation",
                                        "selector_capture_result")]
        namespace = {"re": __import__("re")}
        exec(compile(ast.Module(body=validators, type_ignores=[]),
                     "<selector capture gate>", "exec"), namespace)
        check = namespace["selector_capture_result"]
        self.assertTrue(check(True, "Y", "00000000 unavailable", "00000001 000000a0"))
        self.assertTrue(check(True, "1", "00000007 ffffffff", "00000008 12345678"))
        self.assertFalse(check(True, "N", "00000000 unavailable", "00000001 000000a0"))
        self.assertFalse(check(True, "Y", "00000000 unavailable", "00000002 000000a0"))
        self.assertFalse(check(True, "Y", "00000000 unavailable", "00000000 000000a0"))
        self.assertFalse(check(True, "Y", "00000000 unavailable", "00000001 unavailable"))
        self.assertFalse(check(True, "Y", "not-an-snapshot", "00000001 000000a0"))
        self.assertFalse(check(True, "Y", "00000000 unavailable", "00000001 000000a0 trailing"))
        self.assertIsNone(check(False, None, None, None))

    def test_lookup_callsite_capture_requires_one_tuple_and_no_dropped_samples(self):
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--capture-lookup-callsite", action="store_true"', source)
        self.assertIn('if args.capture_lookup_callsite and not args.active:', source)
        self.assertIn('if args.capture_lookup_callsite and not args.observe_selector_path:', source)
        guest = RUNNER.guest_probe_script(True, observe_selector_path=True,
                                          capture_lookup_callsite=True)
        self.assertIn('active_argv.append("capture_lookup_callsite=1")', guest)
        self.assertIn('lookup_callsite_observation_before=read_parameter("lookup_callsite_observation")', guest)
        self.assertIn('lookup_callsite_observation_after=read_parameter("lookup_callsite_observation")', guest)
        self.assertIn('parameter_uint("lookup_callsite_dropped")', guest)
        self.assertIn('active_state["lookup_callsite_capture_passed"]', guest)
        self.assertIn('"nvidia-hybrid-pc3-r580-direct-kprobe-canary-v7"', guest)
        self.assertIn('"active_lookup_callsite_capture_passed"', guest)
        self.assertIn('"nvidia:_nv031364rm+0x92"', guest)
        parsed = ast.parse(guest)
        validators = [node for node in parsed.body
                      if isinstance(node, ast.FunctionDef)
                      and node.name in ("parse_selector_observation",
                                        "parse_lookup_callsite_observation",
                                        "lookup_callsite_capture_result")]
        namespace = {"re": __import__("re")}
        exec(compile(ast.Module(body=validators, type_ignores=[]),
                     "<lookup callsite capture gate>", "exec"), namespace)
        check = namespace["lookup_callsite_capture_result"]
        self.assertTrue(check(True, "Y", "0000000000000000 unavailable",
                              "0000000000000001 00000000 000000a0 00000000", 0, 0,
                              "00000000 unavailable", "00000001 000000a0"))
        self.assertFalse(check(True, "Y", "0000000000000000 unavailable",
                              "0000000000000001 00000000 000000a0 00000000", 0, 0))
        self.assertFalse(check(True, "Y", "0000000000000000 unavailable",
                               "0000000000000001 00000000 000000a0 00000000", 0, 1))
        self.assertFalse(check(True, "Y", "0000000000000000 unavailable",
                               "0000000000000002 00000000 000000a0 00000000", 0, 0))
        self.assertFalse(check(True, "Y", "0000000000000000 unavailable",
                               "busy", 0, 0))
        self.assertFalse(check(True, "N", "0000000000000000 unavailable",
                               "0000000000000001 00000000 000000a0 00000000", 0, 0))
        self.assertIsNone(check(False, None, None, None, None, None))

    def test_lookup_branch_capture_requires_exactly_one_hit_and_fixed_target(self):
        self.assertTrue(hasattr(RUNNER, "lookup_branch_capture_result"),
                        "lookup-branch count validator has not been implemented")
        check = RUNNER.lookup_branch_capture_result
        self.assertTrue(check(True, "Y", 0, 1, 0, 1, 0, 0, 0, 1))
        self.assertTrue(check(True, "Y", 0, 1, 0, 0, 0, 1, 0, 0))
        self.assertFalse(check(True, "N", 0, 1, 0, 1, 0, 0, 0, 1))
        self.assertFalse(check(True, "Y", 0, 0, 0, 0, 0, 0, 0, 0))
        self.assertFalse(check(True, "Y", 0, 2, 0, 1, 0, 1, 0, 1))
        self.assertFalse(check(True, "Y", 0, 1, 0, 1, 0, 0, 0, 0))
        self.assertFalse(check(True, "Y", 0, 1, None, 1, 0, 0, 0, 1))
        self.assertIsNone(check(False, None, None, None, None, None,
                               None, None, None, None))

    def test_lookup_join_capture_maps_one_call_to_one_fixed_predecessor(self):
        self.assertTrue(hasattr(RUNNER, "lookup_join_predecessor_capture_result"))
        check = RUNNER.lookup_join_predecessor_capture_result
        before = {"nvidia:_nv031364rm+0x31d": 0,
                  "nvidia:_nv031364rm+0x9c1": 0,
                  "nvidia:_nv031364rm+0xa94": 0,
                  "nvidia:_nv031364rm+0xaaa": 0,
                  "nvidia:_nv031364rm+0xdaa": 0}
        after = {**before, "nvidia:_nv031364rm+0xa94": 1}
        self.assertEqual(check(True, "Y", before, after, 1),
                         "nvidia:_nv031364rm+0xa94")
        self.assertFalse(check(True, "N", before, after, 1))
        self.assertFalse(check(True, "Y", before, before, 1))
        self.assertFalse(check(True, "Y", before, {**after,
                         "nvidia:_nv031364rm+0x9c1": 1}, 1))
        self.assertIsNone(check(False, None, None, None, None))

    def test_lookup_branch_capture_is_fixed_opt_in_and_required_for_v8_canary(self):
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('LOOKUP_BRANCH_TARGET = "nvidia:_nv031364rm+0xd7e"', source)
        self.assertIn('if args.capture_lookup_branch and not args.capture_lookup_callsite:', source)
        guest = RUNNER.guest_probe_script(
            True, observe_selector_path=True, capture_lookup_callsite=True,
            capture_lookup_branch=True)
        self.assertIn('active_argv.append("capture_lookup_branch=1")', guest)
        self.assertIn('"lookup_branch_hits_before":parameter_uint("lookup_branch_hits")', guest)
        self.assertIn('active_state["lookup_branch_hits_delta"]', guest)
        self.assertIn('"insmod_error_excerpt"', guest)
        self.assertIn('"<address-redacted>"', guest)
        self.assertIn('"nvidia-hybrid-pc3-r580-direct-kprobe-canary-v10"', guest)
        functions = {node.name: node for node in ast.parse(guest).body
                     if isinstance(node, ast.FunctionDef)}
        self.assertIn("lookup_branch_capture_result", functions)
        for field in ("lookup_branch_decision_hits_before",
                      "lookup_branch_taken_hits_after_trigger",
                      "lookup_branch_not_taken_hits_after_trigger"):
            self.assertIn(field, guest)
        self.assertIn('"lookup_join_predecessor_hits_before"', guest)
        self.assertIn('"lookup_join_predecessor_hits_after_trigger"', guest)
        branch_guest = ast.parse(guest)
        self.assertIsNotNone(branch_guest)
        self.assertIn('LOOKUP_BRANCH_DECISION_TARGET = "nvidia:_nv031364rm+0xa81"', source)

    def test_lookup_return_site_gate_requires_one_exact_safe_same_invocation_match(self):
        self.assertTrue(hasattr(RUNNER, "lookup_return_site_capture_result"),
                        "return-site correlation gate has not been implemented")
        check = RUNNER.lookup_return_site_capture_result
        self.assertTrue(check(True, "Y", "Y", 0, 1, 0, 1, 0, 0, 0, 0))
        self.assertFalse(check(False, "Y", "Y", 0, 1, 0, 1, 0, 0, 0, 0))
        self.assertFalse(check(True, "N", "Y", 0, 1, 0, 1, 0, 0, 0, 0))
        self.assertFalse(check(True, "Y", "N", 0, 1, 0, 1, 0, 0, 0, 0))
        self.assertFalse(check(True, "Y", "Y", 0, 2, 0, 1, 0, 0, 0, 0))
        self.assertFalse(check(True, "Y", "Y", 0, 1, 0, 0, 0, 0, 0, 0))
        self.assertFalse(check(True, "Y", "Y", 0, 1, 0, 2, 0, 0, 0, 0))
        self.assertFalse(check(True, "Y", "Y", 0, 1, 0, 1, 0, 1, 0, 0))
        self.assertFalse(check(True, "Y", "Y", 0, 1, 0, 1, 0, 0, 0, 1))
        self.assertFalse(check(True, "Y", "Y", 0, 1, None, 1, 0, 0, 0, 0))
        self.assertIsNone(check(False, None, None, None, None, None,
                               None, None, None, None, None))

    def test_lookup_return_site_mode_is_isolated_and_publishes_no_kernel_address(self):
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--capture-lookup-return-site", action="store_true"', source)
        self.assertIn('if args.capture_lookup_return_site and not args.active:', source)
        self.assertIn('if args.capture_lookup_return_site and not args.observe_selector_path:', source)
        guest = RUNNER.guest_probe_script(True, observe_selector_path=True,
                                          capture_lookup_return_site=True)
        self.assertIn('active_argv.append("capture_lookup_return_site=1")', guest)
        self.assertIn('"lookup_return_site_ready_before":read_parameter("lookup_return_site_ready")', guest)
        for field in ("lookup_return_site_matches_before",
                      "lookup_return_site_read_failures_before",
                      "lookup_return_site_unmatched_before",
                      "lookup_return_site_matches_after_trigger",
                      "lookup_return_site_read_failures_after_trigger",
                      "lookup_return_site_unmatched_after_trigger"):
            self.assertIn(field, guest)
        self.assertIn('"nvidia-hybrid-pc3-r580-direct-kprobe-canary-v11"', guest)
        self.assertIn('"active_lookup_return_site_capture_passed"', guest)
        self.assertIn('if args.capture_lookup_return_site and (', source)
        self.assertNotIn('"expected_return_ip"', guest)
        self.assertNotIn('"callsite_address"', guest)
        parsed = ast.parse(guest)
        functions = {node.name: node for node in parsed.body
                     if isinstance(node, ast.FunctionDef)}
        namespace = {"LOOKUP_JOIN_PREDECESSOR_TARGETS": RUNNER.LOOKUP_JOIN_PREDECESSOR_TARGETS}
        exec(compile(ast.Module(body=[functions["lookup_return_site_capture_result"]],
                               type_ignores=[]), "<guest return-site gate>", "exec"),
             namespace)
        guest_check = namespace["lookup_return_site_capture_result"]
        self.assertTrue(guest_check(True, "Y", "Y", 0, 1, 0, 1, 0, 0, 0, 0))
        self.assertFalse(guest_check(True, "Y", "Y", 0, 1, 0, 2, 0, 0, 0, 0))

        probe_targets = functions["probe_targets_match"]
        namespace = {"LOOKUP_JOIN_PREDECESSOR_TARGETS": RUNNER.LOOKUP_JOIN_PREDECESSOR_TARGETS}
        exec(compile(ast.Module(body=[probe_targets], type_ignores=[]),
                     "<return-site active target gate>", "exec"), namespace)
        expected = ("rm_init_adapter", "_nv000790rm", "_nv031399rm")
        active = ["p:nvidia:" + name + " [ACTIVE]" for name in expected]
        self.assertTrue(namespace["probe_targets_match"](active, expected, False))
        self.assertFalse(namespace["probe_targets_match"](
            active + ["p:nvidia:_nv031364rm+0x92 [ACTIVE]"], expected, False))

    def test_lookup_join_return_route_gate_requires_one_fixed_route_and_safe_return(self):
        self.assertTrue(hasattr(RUNNER, "lookup_join_return_route_capture_result"),
                        "combined join-route gate has not been implemented")
        check = RUNNER.lookup_join_return_route_capture_result
        expected = RUNNER.LOOKUP_JOIN_PREDECESSOR_TARGETS
        before = {target: 0 for target in expected}
        after = dict(before)
        after[expected[3]] = 1
        self.assertEqual(check(True, "Y", before, after, True), expected[3])
        self.assertIsNone(check(False, None, None, None, None))
        self.assertFalse(check(True, "N", before, after, True))
        self.assertFalse(check(True, "Y", before, after, False))
        self.assertFalse(check(True, "Y", before, {**after, "other": 1}, True))
        self.assertFalse(check(True, "Y", before, before, True))
        self.assertFalse(check(True, "Y", before, {**after, expected[0]: 1}, True))
        decreased = dict(before)
        decreased[expected[0]] = 1
        self.assertFalse(check(True, "Y", decreased, before, True))
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--capture-lookup-join-route", action="store_true"', source)
        guest = RUNNER.guest_probe_script(
            True, observe_selector_path=True, capture_lookup_return_site=True,
            capture_lookup_join_route=True)
        self.assertIn('active_argv.append("capture_lookup_join_route=1")', guest)
        self.assertIn('"lookup_join_route_capture_passed"', guest)
        self.assertIn('"lookup_join_route_target"', guest)
        self.assertIn('active_lookup_join_route_capture_passed', guest)
        self.assertNotIn('"route_address"', guest)
        parsed = ast.parse(guest)
        functions = {node.name: node for node in parsed.body
                     if isinstance(node, ast.FunctionDef)}
        namespace = {"LOOKUP_JOIN_PREDECESSOR_TARGETS": RUNNER.LOOKUP_JOIN_PREDECESSOR_TARGETS}
        exec(compile(ast.Module(body=[functions["lookup_join_return_route_capture_result"]],
                               type_ignores=[]), "<guest join return gate>", "exec"),
             namespace)
        self.assertEqual(namespace["lookup_join_return_route_capture_result"](
            True, "Y", before, after, True), expected[3])

    def test_join_route_cli_is_return_correlated_and_emits_count_only_snapshot(self):
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--capture-lookup-join-route", action="store_true"',
                      source)
        self.assertIn("if args.capture_lookup_join_route and not args.capture_lookup_return_site:",
                      source)
        guest = RUNNER.guest_probe_script(
            True, observe_selector_path=True, capture_lookup_return_site=True,
            capture_lookup_join_route=True)
        self.assertIn('active_argv.append("capture_lookup_join_route=1")', guest)
        self.assertIn('"capture_lookup_join_route":read_parameter("capture_lookup_join_route")',
                      guest)
        self.assertIn('"lookup_join_predecessor_hits_before"', guest)
        self.assertIn('"lookup_join_predecessor_hits_after_trigger"', guest)
        self.assertIn('expected_active_names+=tuple(', guest)
        self.assertIn('"lookup_join_route_capture_passed"', guest)
        self.assertIn('"lookup_join_route_target"', guest)
        self.assertNotIn('"callsite_address"', guest)
        parsed = ast.parse(guest)
        functions = {node.name: node for node in parsed.body
                     if isinstance(node, ast.FunctionDef)}
        namespace = {"LOOKUP_JOIN_PREDECESSOR_TARGETS": RUNNER.LOOKUP_JOIN_PREDECESSOR_TARGETS}
        exec(compile(ast.Module(
            body=[functions["lookup_join_return_route_capture_result"]],
            type_ignores=[]), "<guest join return route>", "exec"), namespace)
        targets = RUNNER.LOOKUP_JOIN_PREDECESSOR_TARGETS
        before = {target: 2 for target in targets}
        after = dict(before)
        after[targets[2]] += 1
        self.assertEqual(namespace["lookup_join_return_route_capture_result"](
            True, "Y", before, after, True), targets[2])

    def test_active_lookup_join_route_status_is_a_success_exit(self):
        self.assertTrue(RUNNER.status_is_success(
            "active_lookup_join_route_capture_passed"))
        self.assertFalse(RUNNER.status_is_success("active_registration_failed"))

    def test_active_probe_registration_requires_each_expected_symbol_once(self):
        guest = ast.parse(RUNNER.guest_probe_script(
            True, observe_selector_path=True, capture_lookup_callsite=True))
        function = next(node for node in guest.body
                        if isinstance(node, ast.FunctionDef)
                        and node.name == "probe_targets_match")
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]),
                     "<active probe target validation>", "exec"), namespace)
        check = namespace["probe_targets_match"]
        expected = ("rm_init_adapter", "_nv000790rm", "_nv031399rm",
                    "_nv031364rm+0x92")
        active = ["p:nvidia:" + name + " [ACTIVE]" for name in expected]
        self.assertTrue(check(active, expected, disabled=False))
        self.assertFalse(check(active[:-1] + [active[1]], expected, disabled=False))
        self.assertFalse(check(active[:-1] + ["p:nvidia:_nv031364rm+0x91 [ACTIVE]"],
                               expected, disabled=False))
        self.assertFalse(check(active[:-1] + [active[-1] + " [DISABLED]"],
                               expected, disabled=False))
        disabled = [line.replace("[ACTIVE]", "[DISABLED]") for line in active]
        self.assertTrue(check(disabled, expected, disabled=True))
        self.assertFalse(check(disabled, expected, disabled=False))
        self.assertFalse(check(None, expected, disabled=False))
        branch_guest = ast.parse(RUNNER.guest_probe_script(
            True, observe_selector_path=True, capture_lookup_callsite=True,
            capture_lookup_branch=True))
        functions = {node.name: node for node in branch_guest.body
                     if isinstance(node, ast.FunctionDef)}
        ns = {}
        exec(compile(ast.Module(body=[functions["probe_targets_match"]],
                               type_ignores=[]), "<branch targets>", "exec"), ns)
        branch_names = expected + (
            "_nv031364rm+0xd7e", "_nv031364rm+0xa81",
            "_nv031364rm+0x31d", "_nv031364rm+0x9c1",
            "_nv031364rm+0xa94", "_nv031364rm+0xaaa",
            "_nv031364rm+0xdaa")
        branch_lines = ["p:nvidia:" + name + " [ACTIVE]" for name in branch_names]
        self.assertTrue(ns["probe_targets_match"](branch_lines, branch_names, False))

    def test_optional_observations_are_not_reported_as_passed_when_not_requested(self):
        source = RUNNER.guest_probe_script(True)
        self.assertRegex(source,
                         r'active_state\["state_capture_passed"\]=\(state_capture_ok\s+if False else None\)')
        self.assertRegex(source,
                         r'active_state\["selector_path_observation_passed"\]=\(selector_path_ok\s+if OBSERVE_SELECTOR_PATH else None\)')
        self.assertIn('"pci_binding_changed":None', source)
        self.assertIn('"pci_binding_change_requested":False', source)
        self.assertIn('"firmware_or_vm_change":None', source)
        self.assertIn('"firmware_or_vm_change_requested":False', source)
        wrapper = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('"pci_binding_change_requested"', wrapper)
        self.assertIn('"firmware_or_vm_change_requested"', wrapper)

    def test_remote_deadline_exceeds_all_sequential_guest_command_deadlines(self):
        # Build (90), preflight GPU queries (40), both registrations/removals
        # (80), trigger (30), final inventory (20), plus SSH/sudo overhead.
        self.assertGreaterEqual(RUNNER.GUEST_SSH_TIMEOUT_SECONDS, 360)
        self.assertGreaterEqual(RUNNER.REMOTE_TIMEOUT_SECONDS,
                                RUNNER.GUEST_SSH_TIMEOUT_SECONDS + 60)

    def test_pinned_transport_timeout_is_extended_at_one_exact_anchor(self):
        original = "result = run(argv, timeout=100)"
        wrapper = "def x():\n    " + original + "\n"
        updated = RUNNER.set_guest_ssh_timeout(wrapper)
        self.assertEqual(updated.count(original), 0)
        self.assertIn(f"timeout={RUNNER.GUEST_SSH_TIMEOUT_SECONDS}", updated)
        with self.assertRaises(RuntimeError):
            RUNNER.set_guest_ssh_timeout(wrapper + wrapper)

    def test_guest_finally_retries_cleanup_and_checks_residual_probe(self):
        guest = ast.parse(RUNNER.guest_probe_script(True))
        terminal = next(
            node for node in guest.body
            if isinstance(node, ast.Try)
            and any(isinstance(child, ast.Expr) for child in node.finalbody)
            and any(isinstance(child, ast.Expr) for child in node.finalbody)
        )
        final_source = ast.unparse(terminal.finalbody)
        self.assertIn("unload('finally')", final_source)
        self.assertIn("observer_module_loaded_at_end", final_source)
        self.assertIn("target_probe_lines_at_end", final_source)
        self.assertIn("KEEP_WORK = True", final_source)
        self.assertIn("CANARY_STARTED", final_source)

    def test_preflight_never_unloads_a_preexisting_or_unowned_module(self):
        source = RUNNER.guest_probe_script(True)
        self.assertIn("CANARY_STARTED = False", source)
        self.assertIn('disabled_argv=["insmod",str(artifact),"owner_nonce="+str(OWNER_NONCE)]', source)
        self.assertIn("CANARY_STARTED=disabled_owned", source)
        self.assertIn('if not owns_module():', source)
        unload_start = source.index("def unload(stage):")
        unload_end = source.index("\ndef interrupted", unload_start)
        unload_source = source[unload_start:unload_end]
        self.assertLess(unload_source.index("if not owns_module():"),
                        unload_source.index('run(["rmmod",MODULE]'))
        final_cleanup = source.split("finally:", 1)[1]
        self.assertIn('if CANARY_STARTED and Path("/sys/module").joinpath(MODULE).exists() and owns_module():',
                      final_cleanup)

    def test_guest_lock_serializes_runner_invocations_and_is_private(self):
        guest = ast.parse(RUNNER.guest_probe_script(True))
        function = next(node for node in guest.body
                        if isinstance(node, ast.FunctionDef) and
                        node.name == "acquire_runner_lock")
        namespace = {"fcntl": fcntl, "os": os, "stat": stat}
        exec(compile(ast.Module(body=[function], type_ignores=[]),
                     "<guest acquire_runner_lock>", "exec"), namespace)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observer.lock"
            path.touch(mode=0o644)
            acquire = namespace["acquire_runner_lock"]
            first_fd = acquire(str(path), os.geteuid())
            try:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                with self.assertRaisesRegex(RuntimeError, "another PC3 observer runner"):
                    acquire(str(path), os.geteuid())
            finally:
                os.close(first_fd)
            second_fd = acquire(str(path), os.geteuid())
            os.close(second_fd)

    def test_guest_lock_rejects_symlinks_and_non_regular_files(self):
        guest = ast.parse(RUNNER.guest_probe_script(True))
        function = next(node for node in guest.body
                        if isinstance(node, ast.FunctionDef) and
                        node.name == "acquire_runner_lock")
        namespace = {"fcntl": fcntl, "os": os, "stat": stat}
        exec(compile(ast.Module(body=[function], type_ignores=[]),
                     "<guest acquire_runner_lock>", "exec"), namespace)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("target", encoding="utf-8")
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                namespace["acquire_runner_lock"](str(link), os.geteuid())
            non_regular = Path(directory) / "directory-lock"
            non_regular.mkdir()
            with self.assertRaises(OSError):
                namespace["acquire_runner_lock"](str(non_regular), os.geteuid())

    def test_runner_without_lock_reports_unknown_state_without_claiming_cleanup(self):
        guest = ast.parse(RUNNER.guest_probe_script(True))
        function = next(node for node in guest.body
                        if isinstance(node, ast.FunctionDef) and
                        node.name == "mark_runner_lock_unavailable")
        report = {}
        namespace = {"REPORT": report}
        exec(compile(ast.Module(body=[function], type_ignores=[]),
                     "<guest mark_runner_lock_unavailable>", "exec"),
             namespace)
        namespace["mark_runner_lock_unavailable"]()
        self.assertEqual(report["status"], "runner_lock_unavailable")
        for name in ("observer_module_loaded_at_end", "observer_module_owned_at_end",
                     "unowned_observer_module_at_end", "kprobe_attached_at_end",
                     "target_probe_lines_at_end", "target_probe_list_unchanged",
                     "kernel_taint_after", "kernel_taint_unchanged",
                     "gpu_identity_unchanged", "stock_driver_changed"):
            with self.subTest(name=name):
                self.assertIsNone(report[name])

        final = next(node for node in ast.walk(guest) if isinstance(node, ast.Try)
                     and node.finalbody and any(
                         isinstance(item, ast.If) and ast.unparse(item.test) == "LOCK_FD is None"
                         for item in node.finalbody))
        lock_guard = next(item for item in final.finalbody
                          if isinstance(item, ast.If) and
                          ast.unparse(item.test) == "LOCK_FD is None")
        self.assertIn("mark_runner_lock_unavailable", ast.unparse(lock_guard.body))
        self.assertNotIn("owns_module", ast.unparse(lock_guard.body))
        self.assertNotIn("target_lines", ast.unparse(lock_guard.body))
        self.assertIn("owns_module", ast.unparse(lock_guard.orelse))

    def test_reports_do_not_expose_process_ids_or_owner_nonce(self):
        source = RUNNER.guest_probe_script(True)
        self.assertIn('REPORT["compute_pids_before_count"]=len(pids)', source)
        self.assertIn('REPORT["compute_pids_before_active_count"]=', source)
        self.assertNotIn('REPORT["compute_pids_before"]=', source)
        self.assertNotIn('REPORT["compute_pids_before_active"]=', source)
        self.assertIn('REPORT["owner_nonce_sha256"]', source)
        self.assertNotIn('REPORT["owner_nonce"]', source)
        self.assertIn('REPORT["unowned_observer_module_at_end"]', source)
        self.assertIn('REPORT["kernel_taint_unchanged"]', source)

    def test_guest_catches_remote_termination_signals_for_finally_cleanup(self):
        source = RUNNER.guest_probe_script(True)
        self.assertIn("for _signal in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)", source)
        self.assertIn("signal.signal(_signal, interrupted)", source)

    def test_report_uses_guest_cleanup_state_not_wrapper_constant_defaults(self):
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('report["guest_" + key] = guest.get(key)', source)
        self.assertNotIn('"experimental_module_loaded", "stock_driver_changed", "pci_binding_changed"',
                         source)

    def test_successful_canary_requires_final_identity_taint_and_cleanup_integrity(self):
        guest = ast.parse(RUNNER.guest_probe_script(
            True, capture_state=True, observe_selector_path=True))
        functions = {node.name: node for node in guest.body
                     if isinstance(node, ast.FunctionDef)}
        self.assertIn("final_integrity_violations", functions,
                      "guest observer must validate final hardware and cleanup state")
        self.assertIn("final_status_after_cleanup", functions,
                      "guest observer must gate success on post-unload integrity")
        namespace = {}
        selected = [functions["final_integrity_violations"],
                    functions["final_status_after_cleanup"]]
        exec(compile(ast.Module(body=selected, type_ignores=[]),
                     "<guest final integrity>", "exec"), namespace)
        baseline = {
            "stock_driver_changed": False,
            "kernel_taint_unchanged": True,
            "gpu_identity_unchanged": True,
            "target_probe_list_unchanged": True,
            "observer_module_loaded_at_end": False,
            "kprobe_attached_at_end": False,
            "unowned_observer_module_at_end": False,
        }
        self.assertEqual(namespace["final_integrity_violations"](baseline), [])
        for field, unexpected in (
                ("stock_driver_changed", True),
                ("kernel_taint_unchanged", False),
                ("gpu_identity_unchanged", False),
                ("target_probe_list_unchanged", False),
                ("observer_module_loaded_at_end", True),
                ("kprobe_attached_at_end", True),
                ("unowned_observer_module_at_end", True),
                ("kernel_taint_unchanged", None)):
            with self.subTest(field=field, unexpected=unexpected):
                report = {**baseline, field: unexpected}
                self.assertIn(field,
                              namespace["final_integrity_violations"](report))
                report["status"] = "active_capture_passed"
                self.assertEqual(namespace["final_status_after_cleanup"](report, True),
                                 "cleanup_or_integrity_failed")
        self.assertEqual(namespace["final_status_after_cleanup"](
            {"status": "build_only_passed"}, False), "build_only_passed")

    def test_final_integrity_fields_use_a_new_guest_schema_without_dropping_legacy_reads(self):
        ordinary = RUNNER.guest_probe_script(False)
        selector = RUNNER.guest_probe_script(False, observe_selector_path=True)
        self.assertIn('nvidia-hybrid-pc3-r580-direct-kprobe-canary-v3', ordinary)
        self.assertIn('nvidia-hybrid-pc3-r580-direct-kprobe-canary-v4', selector)
        selector_capture = RUNNER.guest_probe_script(
            False, observe_selector_path=True, capture_selector=True)
        self.assertIn('nvidia-hybrid-pc3-r580-direct-kprobe-canary-v6', selector_capture)
        self.assertIn('"final_integrity_passed":None', ordinary)
        wrapper = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('"nvidia-hybrid-pc3-r580-direct-kprobe-canary-v4"', wrapper)
        self.assertIn('"nvidia-hybrid-pc3-r580-direct-kprobe-canary-v6"', wrapper)
        self.assertIn('"nvidia-hybrid-pc3-r580-direct-kprobe-canary-v2",', wrapper)

    def test_active_path_requires_explicit_opt_in_and_no_compute_pid(self):
        source = RUNNER.guest_probe_script(True)
        self.assertIn('"status":"skipped_gpu_busy"', source)
        self.assertIn('active_pids,active_pid_query=compute_pids()', source)
        self.assertIn('if active_pids is None:', source)
        self.assertIn('parser.add_argument("--active", action="store_true"',
                      RUNNER_PATH.read_text(encoding="utf-8"))

    def test_compute_pid_parser_fails_closed_on_unknown_or_invalid_output(self):
        guest = ast.parse(RUNNER.guest_probe_script(False))
        function = next(node for node in guest.body
                        if isinstance(node, ast.FunctionDef) and node.name == "compute_pids")

        def parse(output, returncode=0):
            namespace = {"run": lambda argv, timeout: {
                "returncode": returncode, "stdout": output,
            }}
            isolated = ast.Module(body=[function], type_ignores=[])
            exec(compile(isolated, "<guest compute_pids>", "exec"), namespace)
            return namespace["compute_pids"]()

        self.assertEqual(parse("\n \n")[0], [])
        self.assertEqual(parse("123\n456\n")[0], [123, 456])
        for output in ("N/A\n", "[Not Supported]\n", "0\n", "١٢٣\n", "123\nN/A\n"):
            with self.subTest(output=output):
                self.assertIsNone(parse(output)[0])
        self.assertIsNone(parse("", returncode=1)[0])

    def test_kprobe_list_redacts_kernel_address_before_reporting(self):
        guest = ast.parse(RUNNER.guest_probe_script(False))
        function = next(node for node in guest.body
                        if isinstance(node, ast.FunctionDef) and node.name == "target_lines")

        class FakePath:
            def __init__(self, path):
                self.path = path

            def is_file(self):
                return True

            def read_text(self, **kwargs):
                return "ffffffffc175e3c0  k  rm_init_adapter+0x0  nvidia [DISABLED]\n"

        namespace = {"Path": FakePath, "re": __import__("re"),
                     "TARGET": "nvidia:rm_init_adapter",
                     "SELECTOR_TARGETS": ("nvidia:_nv000790rm", "nvidia:_nv031399rm"),
                     "LOOKUP_CALLSITE_TARGET": "nvidia:_nv031364rm+0x92",
                     "LOOKUP_BRANCH_TARGET": "nvidia:_nv031364rm+0xd7e",
                     "LOOKUP_BRANCH_DECISION_TARGET": "nvidia:_nv031364rm+0xa81",
                     "LOOKUP_JOIN_PREDECESSOR_TARGETS": RUNNER.LOOKUP_JOIN_PREDECESSOR_TARGETS}
        exec(compile(ast.Module(body=[function], type_ignores=[]),
                     "<guest target_lines>", "exec"), namespace)
        lines = namespace["target_lines"]()
        self.assertEqual(len(lines), 1)
        self.assertNotIn("ffffffffc175e3c0", lines[0])
        self.assertIn("rm_init_adapter", lines[0])
        self.assertIn("[DISABLED]", lines[0])

    def test_active_trigger_is_redacted_to_hash_and_exit_status(self):
        source = RUNNER.guest_probe_script(True)
        self.assertIn('active_state["nvidia_smi_trigger"]={key:trigger.get(key)', source)
        self.assertIn('active_state["trigger_passed"]=(trigger.get("returncode")==0', source)
        self.assertIn('active_state.get("trigger_passed") is True', source)
        self.assertNotIn('"nvidia_smi_trigger":run(', source)


if __name__ == "__main__":
    unittest.main()
