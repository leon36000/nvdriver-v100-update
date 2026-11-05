# SPDX-License-Identifier: MIT
"""Acceptance guards for the simultaneous PC3 ROOT-ID protocol experiment."""
from copy import deepcopy
import unittest

from tools.run_pc3_live_root_id_probe import GUEST_SCRIPT, ROOT_REMOTE, validate_live_result


def live_report():
    v100 = {'name': 'Tesla V100-SXM2-16GB', 'uuid': 'GPU-42d06a85-027a-75ea-7857-a8de27ad465e',
            'pci': '0000:00:05.0', 'driver_version': '580.178.04',
            'control_path': '/dev/nvidiactl', 'control_is_character_device': True,
            'control_rw_access': True}
    rtx = {'name': 'NVIDIA GeForce RTX 5080', 'uuid': 'GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77',
           'pci': '0000:02:00.0', 'driver_version': '595.99.02',
           'control_path': '/dev/nvidiactl', 'control_is_character_device': True,
           'control_rw_access': True}
    root_id = 0xC001CAFE
    free = {'passed': True}
    close = True
    holder_final = {'action': 'hold-root', 'release_received': True, 'allocated_id': root_id,
                    'free': free, 'control_close_succeeded': close, 'success': True}
    source_final = {'qualification': 'V100-root-held-and-freed', 'helper_removed': True,
                    'device_after': v100, 'holder_final': holder_final}
    target = {'exit_code': 0, 'report': {'action': 'mirror-root-id', 'requested_id': root_id,
              'allocated_id': root_id, 'returned_requested_id': True,
              'allocation': {'passed': True}, 'free': free,
              'control_close_succeeded': close, 'gpu_context_opened': False, 'success': True}}
    return {
        'schema': 'nvidia-hybrid-pc3-live-root-id-transport-v1',
        'qualification': 'RTX5080-accepted-and-freed-V100-root-ID-while-V100-root-was-live',
        'host': 'pc3', 'guest_hostkey_fingerprint': 'SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts',
        'payload_file_cleanup_passed': True,
        'probe_cleanup_passed': True, 'probe_helper_removed': True,
        'execution_scope': {'driver_changed': False, 'module_loaded': False,
                            'vm_management_issued': False, 'pci_binding_changed': False,
                            'cuda_context_opened': False},
        'target_device_before': rtx, 'target_device_after': rtx,
        'source': {'device': v100, 'root_id': root_id,
                   'holder_ready': {'event': 'root-held', 'allocated_id': root_id,
                                    'gpu_context_opened': False},
                   'final': source_final, 'exit_code': 0},
        'target': target,
    }


class LiveRootIdProbeTests(unittest.TestCase):
    def test_remote_protocol_programs_are_syntactically_valid(self):
        compile(GUEST_SCRIPT, '<pc3-v100-guest-script>', 'exec')
        compile(ROOT_REMOTE, '<pc3-root-script>', 'exec')

    def test_accepts_only_complete_live_id_mirror_and_cleanup(self):
        self.assertTrue(validate_live_result(live_report(), 0))

    def test_rejects_missing_liveness_or_cleanup_evidence(self):
        mutations = (
            lambda r: r['source']['final']['holder_final'].update(release_received=False),
            lambda r: r['source']['final']['holder_final']['free'].update(passed=False),
            lambda r: r['target']['report'].update(allocated_id=123),
            lambda r: r['target']['report']['free'].update(passed=False),
            lambda r: r.update(probe_helper_removed=False),
            lambda r: r['target_device_after'].update(driver_version='other'),
            lambda r: r['execution_scope'].update(module_loaded=True),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                report = live_report()
                mutate(report)
                self.assertFalse(validate_live_result(report, 0))

    def test_nonzero_transport_status_never_qualifies(self):
        self.assertFalse(validate_live_result(live_report(), 255))


if __name__ == '__main__':
    unittest.main()
