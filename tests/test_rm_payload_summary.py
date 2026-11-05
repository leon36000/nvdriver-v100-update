# SPDX-License-Identifier: MIT
"""Typed observer report tests, never evidence of GPU execution."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PayloadSummary(unittest.TestCase):
    def load(self):
        path = ROOT / 'tools/summarize_rm_payloads.py'
        self.assertTrue(path.is_file(), 'typed payload summarizer is not implemented')
        spec = importlib.util.spec_from_file_location('payload_summary', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        return tool

    def report(self):
        entry = dict(hRoot=0, hObjectParent=0, hObjectNew=0, hClass=0x41,
                     pAllocParms=0, paramsSize=0, pRightsRequested=0, flags=0, status=0)
        return dict(schema='nvidia-hybrid-rm-ioctl-observer-v1', trace_complete=True,
                    child_exit_code=77, errors=[], control_path='/dev/nvidiactl', records=[
                        dict(tid=10, request=0xc030462b, packet_size=48, operation='alloc',
                             entry=entry, exit=dict(entry, hObjectNew=0x12340001), syscall_return=0)])

    def test_extracts_observer_from_v100_guest_runner_transport(self):
        tool = self.load()
        self.assertTrue(hasattr(tool, "extract_observation"),
                        "V100 guest transport reports are not supported")
        raw = self.report()
        transport = {"remote": {
            "schema": "nvidia-hybrid-pc3-v100-guest-reference-v1",
            "ioctl_observation": raw,
        }}
        self.assertEqual(tool.extract_observation(transport), raw)

    def test_extracts_observer_from_pc3_host_acceptance_transport(self):
        tool = self.load()
        self.assertTrue(hasattr(tool, "extract_observation"),
                        "PC3 host acceptance reports are not supported")
        raw = self.report()
        transport = {"remote": {"hardware_acceptance": {
            "ioctl_observation": {"report": raw},
        }}}
        self.assertEqual(tool.extract_observation(transport), raw)

    def test_root_slice_is_evaluated_from_entry_and_both_status_channels(self):
        result = self.load().summarize(self.report())
        self.assertEqual(result['root_allocations'], 1)
        self.assertEqual(result['confirmed_root_allocations'], 1)
        self.assertEqual(result['broker_compatible_root_inputs'], 1)
        self.assertEqual(result['unsupported_root_inputs'], [])
        self.assertFalse(result['hybrid_runtime_validated'])
        self.assertFalse(result['nested_parameter_contents_observed'])

    def test_real_nonnull_root_parameters_are_not_silently_supported(self):
        report = self.report()
        report['records'][0]['entry'].update(pAllocParms=0x11223344, paramsSize=8)
        result = self.load().summarize(report)
        self.assertEqual(result['broker_compatible_root_inputs'], 0)
        self.assertEqual(result['unsupported_root_inputs'][0]['reasons'], ['parameters'])

    def test_each_broker_input_boundary_is_distinguished(self):
        for changes, reason in [({'hRoot': 7}, 'requested-root'), ({'hObjectNew': 9}, 'requested-object'),
                                ({'pRightsRequested': 8}, 'rights'), ({'flags': 1}, 'flags')]:
            with self.subTest(changes=changes):
                report = self.report()
                report['records'][0]['entry'].update(changes)
                result = self.load().summarize(report)
                self.assertEqual(result['broker_compatible_root_inputs'], 0)
                self.assertEqual(result['unsupported_root_inputs'][0]['reasons'], [reason])

    def test_missing_root_and_unconfirmed_status_do_not_certify_coverage(self):
        tool = self.load()
        for changes in ({'syscall_return': -22}, {'exit': None},
                        {'exit': dict(self.report()['records'][0]['exit'], status=0x1f)},
                        {'exit': dict(self.report()['records'][0]['exit'], hObjectNew=0)}):
            with self.subTest(changes=changes):
                report = self.report(); report['records'][0].update(changes)
                if 'exit' in changes and changes['exit'] is None:
                    with self.assertRaises(ValueError): tool.summarize(report)
                else:
                    self.assertEqual(tool.summarize(report)['confirmed_root_allocations'], 0)
        report = self.report(); report['records'][0]['entry']['hClass'] = 0x2080
        result = tool.summarize(report)
        self.assertEqual(result['root_allocations'], 0)
        self.assertEqual(result['qualification'], 'no-root-allocation-observed')

    def test_partial_or_wrong_scope_cannot_be_interpreted_as_cuda_evidence(self):
        tool = self.load()
        for changes in ({'trace_complete': False}, {'errors': ['short read']},
                        {'control_path': '/dev/null'}, {'schema': 'metadata-only'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                tool.summarize(dict(self.report(), **changes))
        report = self.report(); del report['records'][0]['entry']['pRightsRequested']
        with self.assertRaises(ValueError):tool.summarize(report)

    def test_root_free_parent_alias_matches_observed_driver(self):
        report = self.report()
        report['records'] = [dict(operation='free', packet_size=16, request=0xc0104629,
            entry=dict(hRoot=0x12340001,hObjectParent=0x12340001,hObjectOld=0x12340001,status=0),
            exit=dict(hRoot=0x12340001,hObjectParent=0x12340001,hObjectOld=0x12340001,status=0),
            syscall_return=0)]
        self.assertEqual(self.load().summarize(report)['confirmed_root_frees'], 1)

    def test_nvos21_and_root_free_are_not_conflated(self):
        report = self.report(); alloc=report['records'][0]
        alloc.update(packet_size=32, request=0xc020462b)
        for key in ('pRightsRequested','flags'):
            del alloc['entry'][key]; del alloc['exit'][key]
        report['records'].append(dict(operation='free', packet_size=16, request=0xc0104629,
            entry=dict(hRoot=0x12340001,hObjectParent=0,hObjectOld=0x12340001,status=0),
            exit=dict(hRoot=0x12340001,hObjectParent=0,hObjectOld=0x12340001,status=0),syscall_return=0))
        result=self.load().summarize(report)
        self.assertEqual(result['confirmed_root_allocations'],1)
        self.assertEqual(result['confirmed_root_frees'],1)
        self.assertEqual(result['alloc_packet_sizes'],[{'bytes':32,'count':1}])
