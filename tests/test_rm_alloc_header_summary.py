# SPDX-License-Identifier: MIT
"""Contracts for privacy-preserving summaries of observed RM_ALLOC headers."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / 'tools/summarize_rm_alloc_headers.py'


def load_tool():
    spec = importlib.util.spec_from_file_location('rm_alloc_header_summary', TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def alloc_row(klass, object_id, parent_id, *, root_id=0, params=0, size=0,
              status=0, root_class=False, syscall_return=0):
    header = dict(layout='NVOS64', hRoot=root_id, hObjectParent=parent_id,
                  hObjectNew=object_id, hClass=klass, root_class=root_class,
                  pAllocParms=params, paramsSize=size, pRightsRequested=0,
                  flags=0, status=status)
    return dict(operation='alloc', request=0xc030462b, packet_size=48,
                syscall_return=syscall_return, fd=8, tid=90,
                entry=dict(header), exit=dict(header))


def observer(records):
    return dict(schema='nvidia-hybrid-rm-ioctl-observer-v6',
                trace_complete=True, errors=[], control_path='/dev/nvidiactl',
                architecture='x86_64', pointer_bits=64, nested_pointers_read=True,
                payload_scope='RM_CONTROL headers plus selected metadata; other nested parameters omitted',
                nested_pointer_scope='selected fixed metadata only; addresses omitted',
                records=records)


def transport(role, records):
    observation = observer(records)
    if role == 'rtx5080':
        return dict(schema='nvidia-hybrid-remote-selected-gpu-transport-v1',
                    rm_control_capture_requested=True,
                    remote=dict(qualification='rtx5080-report-contract-valid-hybrid-incomplete',
                                rm_control_capture_requested=True,
                                rm_control_records_seen=True,
                                hardware_acceptance=dict(
                                    qualification='incomplete-hardware-missing', exit_code=77,
                                    validation_errors=[],
                                    probe=dict(missing_sm=[70], hybrid_validated=False),
                                    ioctl_observation=dict(report=observation))))
    return dict(schema='nvidia-hybrid-pc3-v100-reference-transport-v1',
                exit_code=0, qualification='v100-reference-report-contract-valid',
                rm_control_capture_requested=True,
                remote=dict(exit_code=0, qualification='v100-reference-report-contract-valid',
                            rm_control_capture_requested=True,
                            rm_control_records_seen=True, probe_exit_code=0,
                            observer_exit_code=0, guest_cleanup_passed=True,
                            payload_file_cleanup_passed=True,
                            ioctl_observation=observation))


class RmAllocHeaderSummaryTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool()

    def test_summarizes_parent_class_edges_without_handles_or_pointer_values(self):
        records = [
            alloc_row(0, 0, 0, root_class=True),
            alloc_row(0x80, 0x12000001, 0x90000001,
                      root_id=0x90000001, params=0xDEADBEEF, size=0),
            alloc_row(0xCB13, 0x12000002, 0x90000001,
                      root_id=0x90000001, params=0xDEADBEEF, size=12),
        ]
        # The output-side root allocation returns the public root-client class/handle.
        records[0]['exit'].update(hClass=65, hObjectNew=0x90000001)
        report = self.tool.summarize_allocations(
            'rtx5080', transport('rtx5080', records))

        self.assertEqual(report['alloc_records'], 3)
        self.assertEqual(report['syscall_failures'], 0)
        edges = report['parent_class_edges']
        self.assertIn({'parent_class': '0x00000041', 'child_class': '0x00000080', 'count': 1}, edges)
        self.assertIn({'parent_class': '0x00000041', 'child_class': '0x0000cb13', 'count': 1}, edges)
        device = next(x for x in report['classes'] if x['class_id'] == '0x00000080')
        self.assertEqual(device['non_null_alloc_parameter_pointer_count'], 1)
        self.assertEqual(device['parameter_size_counts'], [{'bytes': 0, 'count': 1}])
        encoded = json.dumps(report)
        for secret in ('0x90000001', '0x12000001', '0xdeadbeef', 'hObjectNew', 'pAllocParms'):
            self.assertNotIn(secret, encoded)
        self.assertFalse(report['nested_alloc_parameters_read'])

    def test_rejects_malformed_record_and_cross_device_packet_layout(self):
        bad = alloc_row(0x80, 2, 1, root_id=1)
        bad['request'] = 0xc030462a
        with self.assertRaisesRegex(ValueError, 'NVOS64 RM_ALLOC'):
            self.tool.summarize_allocations('v100', transport('v100', [bad]))

        bad = alloc_row(0x80, 2, 1, root_id=1)
        bad['entry']['pAllocParms'] = -1
        with self.assertRaisesRegex(ValueError, 'pointer metadata'):
            self.tool.summarize_allocations('v100', transport('v100', [bad]))

    def test_rejects_unvalidated_hardware_reference(self):
        source = transport('v100', [alloc_row(65, 1, 0, root_class=True)])
        source['remote']['guest_cleanup_passed'] = False
        with self.assertRaisesRegex(ValueError, 'successful installed-driver reference'):
            self.tool.summarize_allocations('v100', source)

    def test_private_writer_is_create_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'summary.json'
            self.tool.write_private_report(path, {'schema': 'test'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                self.tool.write_private_report(path, {'schema': 'overwrite'})
            self.assertEqual(json.loads(path.read_text()), {'schema': 'test'})


if __name__ == '__main__':
    unittest.main()
