# SPDX-License-Identifier: MIT
"""Validate provenance gates for the installed-driver mirror probe."""
import unittest

from tools.run_pc3_rm_root_id_probe import extract_v100_root_id


def source_report():
    record = {
        'operation': 'alloc', 'syscall_return': 0,
        'entry': {'layout': 'NVOS64', 'hClass': 0, 'hRoot': 0, 'hObjectParent': 0,
                  'pAllocParms': 0, 'pRightsRequested': 0, 'paramsSize': 0, 'flags': 0},
        'exit': {'status': 0, 'hClass': 0x41, 'hObjectNew': 0x12345678},
    }
    return {
        'schema': 'nvidia-hybrid-pc3-v100-reference-transport-v1',
        'observed_at_utc': '2026-10-20T00:00:00Z',
        'remote': {
            'schema': 'nvidia-hybrid-pc3-v100-guest-reference-v1',
            'guest': {'name': 'Tesla V100-SXM2-32GB', 'driver_version': '580.178.04',
                      'pci': '0000:00:05.0'},
            'ioctl_observation': {'trace_complete': True, 'errors': [],
                                  'control_path': '/dev/nvidiactl', 'records': [record]},
        },
    }


class RootIdSourceTests(unittest.TestCase):
    def test_uses_only_confirmed_ordinary_v100_root_output(self):
        root_id, source = extract_v100_root_id(source_report())
        self.assertEqual(root_id, 0x12345678)
        self.assertEqual(source['record_index'], 0)
        self.assertEqual(source['guest']['driver_version'], '580.178.04')

    def test_rejects_incomplete_or_wrong_guest_source(self):
        for mutate in (
            lambda r: r.update(schema='wrong'),
            lambda r: r['remote']['ioctl_observation'].update(trace_complete=False),
            lambda r: r['remote']['guest'].update(driver_version='595.99.02'),
            lambda r: r['remote']['guest'].update(pci='0000:05:00.0'),
        ):
            with self.subTest(mutate=mutate):
                report = source_report()
                mutate(report)
                with self.assertRaises(ValueError):
                    extract_v100_root_id(report)

    def test_rejects_root_record_with_nonzero_input_root_or_bad_status(self):
        for field, value in (('hRoot', 3), ('hClass', 0x41), ('status', 7)):
            with self.subTest(field=field):
                report = source_report()
                target = report['remote']['ioctl_observation']['records'][0]['entry' if field != 'status' else 'exit']
                target[field] = value
                with self.assertRaises(ValueError):
                    extract_v100_root_id(report)


if __name__ == '__main__':
    unittest.main()
