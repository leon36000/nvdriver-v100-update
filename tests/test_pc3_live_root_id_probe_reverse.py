# SPDX-License-Identifier: MIT
"""Acceptance guards for the reverse simultaneous PC3 ROOT-ID experiment."""
from copy import deepcopy
import unittest

from tools.run_pc3_live_root_id_probe_reverse import (
    ROOT_REMOTE, V100_MIRROR_SCRIPT, validate_reverse_live_result,
)


def live_reverse_report():
    rtx = {'name': 'NVIDIA GeForce RTX 5080', 'uuid': 'GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77',
           'pci': '0000:02:00.0', 'driver_version': '595.99.02'}
    v100 = {'name': 'Tesla V100-SXM2-16GB', 'uuid': 'GPU-42d06a85-027a-75ea-7857-a8de27ad465e',
            'pci': '0000:00:05.0', 'driver_version': '580.178.04'}
    root_id = 0x1234ABCD
    free = {'passed': True}
    mirror = {'action': 'mirror-root-id', 'requested_id': root_id, 'allocated_id': root_id,
              'returned_requested_id': True, 'allocation': {'passed': True}, 'free': free,
              'control_close_succeeded': True, 'gpu_context_opened': False, 'success': True}
    guest = {'qualification': 'installed-R580-root-ID-mirror-request-and-free-passed', 'euid': 1000,
             'device_before': v100, 'device_after': v100, 'helper_removed': True,
             'helper_result': {'exit_code': 0, 'report': mirror}}
    holder = {'action': 'hold-root', 'release_received': True, 'allocated_id': root_id,
              'allocation': {'passed': True}, 'free': free,
              'control_close_succeeded': True, 'success': True}
    source = {'device': rtx, 'root_id': root_id,
              'holder_ready': {'event': 'root-held', 'allocated_id': root_id,
                               'gpu_context_opened': False},
              'final': holder, 'exit_code': 0}
    return {
        'schema': 'nvidia-hybrid-pc3-live-root-id-reverse-transport-v1',
        'qualification': 'V100-accepted-and-freed-RTX5080-root-ID-while-RTX5080-root-was-live',
        'host': 'pc3', 'guest_hostkey_fingerprint': 'SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts',
        'payload_file_cleanup_passed': True, 'probe_helper_removed': True,
        'probe_cleanup_passed': True,
        'execution_scope': {'driver_changed': False, 'module_loaded': False,
                            'vm_management_issued': False, 'pci_binding_changed': False,
                            'cuda_context_opened': False},
        'source_device_before': rtx, 'source_device_after': rtx,
        'source': source, 'target_guest': {'exit_code': 0, 'report': guest},
    }


class ReverseLiveRootIdProbeTests(unittest.TestCase):
    def test_remote_programs_are_syntactically_valid(self):
        compile(ROOT_REMOTE, '<pc3-root-reverse>', 'exec')
        compile(V100_MIRROR_SCRIPT, '<v100-r580-mirror>', 'exec')

    def test_accepts_live_rtx_source_and_clean_v100_mirror(self):
        self.assertTrue(validate_reverse_live_result(live_reverse_report(), 0))

    def test_rejects_identity_id_lifetime_and_cleanup_mismatches(self):
        mutations = (
            lambda r: r['source']['holder_ready'].update(allocated_id=9),
            lambda r: r['source']['final'].update(release_received=False),
            lambda r: r['source']['final']['free'].update(passed=False),
            lambda r: r['target_guest']['report']['helper_result']['report'].update(allocated_id=9),
            lambda r: r['target_guest']['report'].update(helper_removed=False),
            lambda r: r['target_guest']['report']['device_after'].update(driver_version='other'),
            lambda r: r['execution_scope'].update(module_loaded=True),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                report = live_reverse_report()
                mutate(report)
                self.assertFalse(validate_reverse_live_result(report, 0))

    def test_transport_failure_never_qualifies(self):
        self.assertFalse(validate_reverse_live_result(live_reverse_report(), 255))


if __name__ == '__main__':
    unittest.main()
