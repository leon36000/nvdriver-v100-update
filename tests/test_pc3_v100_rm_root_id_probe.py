# SPDX-License-Identifier: MIT
"""Source-identity guards for the reverse PC3 root-ID boundary test."""
import unittest

from tools.run_pc3_v100_rm_root_id_probe import extract_rtx_root_id


def rtx_report():
    record = {
        'operation': 'alloc', 'syscall_return': 0,
        'entry': {'layout': 'NVOS64', 'hClass': 0, 'hRoot': 0, 'hObjectParent': 0,
                  'pAllocParms': 0, 'pRightsRequested': 0, 'paramsSize': 0, 'flags': 0},
        'exit': {'status': 0, 'hClass': 0x41, 'hObjectNew': 0x12345678},
    }
    return {
        'schema': 'nvidia-hybrid-remote-selected-gpu-transport-v1',
        'remote': {
            'schema': 'nvidia-hybrid-remote-selected-gpu-v1',
            'selected_nvidia_smi': {'name': 'NVIDIA GeForce RTX 5080',
                                    'uuid': 'GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77',
                                    'pci': '0000:02:00.0', 'driver': '595.99.02'},
            'hardware_acceptance': {'ioctl_observation': {'report': {
                'trace_complete': True, 'errors': [], 'control_path': '/dev/nvidiactl',
                'records': [record],
            }}},
        },
    }


class ReverseRootIdSourceTests(unittest.TestCase):
    def test_extracts_only_successful_typed_rtx_root_output(self):
        root_id, source = extract_rtx_root_id(rtx_report())
        self.assertEqual(root_id, 0x12345678)
        self.assertEqual(source['record_index'], 0)
        self.assertEqual(source['device']['driver'], '595.99.02')

    def test_rejects_wrong_target_or_incomplete_trace(self):
        for mutate in (
            lambda r: r.update(schema='wrong'),
            lambda r: r['remote']['selected_nvidia_smi'].update(uuid='GPU-other'),
            lambda r: r['remote']['hardware_acceptance']['ioctl_observation']['report'].update(trace_complete=False),
            lambda r: r['remote']['hardware_acceptance']['ioctl_observation']['report'].update(errors=['partial']),
        ):
            with self.subTest(mutate=mutate):
                report = rtx_report()
                mutate(report)
                with self.assertRaises(ValueError):
                    extract_rtx_root_id(report)

    def test_rejects_nonordinary_root_input_and_bad_output(self):
        for field, value in (('hRoot', 4), ('hClass', 0x41), ('status', 9)):
            with self.subTest(field=field):
                report = rtx_report()
                trace = report['remote']['hardware_acceptance']['ioctl_observation']['report']
                record = trace['records'][0]
                record['exit' if field == 'status' else 'entry'][field] = value
                with self.assertRaises(ValueError):
                    extract_rtx_root_id(report)


if __name__ == '__main__':
    unittest.main()
