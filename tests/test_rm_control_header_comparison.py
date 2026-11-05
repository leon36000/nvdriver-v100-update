# SPDX-License-Identifier: MIT
"""Metadata-only comparison contracts for installed-driver RM_CONTROL traces."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / 'tools/compare_rm_control_headers.py'


def load_tool():
    spec = importlib.util.spec_from_file_location('rm_control_header_comparison', TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def row(command, size, status=0, syscall_return=0):
    fields = dict(command=command, flags=0, hClient=0x10001, hObject=0x10002,
                  params_size=size, status=status,
                  client_object_equal=False, object_matches_prior_root_allocation=False,
                  client_matches_prior_root_allocation=True)
    return dict(operation='rm_control_header', request=0xc020462a, packet_size=32,
                syscall_return=syscall_return, fd=8, tid=90,
                entry=dict(fields), exit=dict(fields))


def observer(records, *, complete=True, errors=None, extra_row_fields=None):
    return dict(schema='nvidia-hybrid-rm-ioctl-observer-v6',
                trace_complete=complete, errors=[] if errors is None else errors,
                control_path='/dev/nvidiactl', architecture='x86_64', pointer_bits=64,
                nested_pointers_read=True,
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
                exit_code=0,
                qualification='v100-reference-report-contract-valid',
                rm_control_capture_requested=True,
                remote=dict(exit_code=0, qualification='v100-reference-report-contract-valid',
                            rm_control_capture_requested=True,
                            rm_control_records_seen=True,
                            probe_exit_code=0, observer_exit_code=0,
                            guest_cleanup_passed=True, payload_file_cleanup_passed=True,
                            ioctl_observation=observation))


def redacted_row(command, size, status=0, syscall_return=0):
    fields = dict(command=command, flags=0, params_size=size, status=status,
                   hClientPresent=True, hObjectPresent=True,
                   client_object_equal=False,
                   client_matches_prior_root_allocation=True,
                   object_matches_prior_root_allocation=False)
    return dict(operation='rm_control_header', request=0xc020462a, packet_size=32,
                syscall_return=syscall_return, fd=8, tid=90, fd_role='control',
                entry=dict(fields), exit=dict(fields))


def observer_v23(records):
    return dict(schema='nvidia-hybrid-rm-ioctl-observer-v23',
                trace_complete=True, errors=[], control_path='/dev/nvidiactl',
                architecture='x86_64', pointer_bits=64,
                nested_pointers_read=False, fd_identity_tracking=False,
                payload_scope=('fixed NVOS54 RM_CONTROL headers only; handles redacted; '
                               'nested parameter payloads omitted'),
                child_exit_code=0, records=records)


def transport_v23(role, records):
    observation = observer_v23(records)
    probe = {'bytes': 167888, 'sha256': 'a' * 64}
    module = {'bytes': 19016, 'sha256': 'b' * 64}
    common_phase = dict(schema='nvidia-cuda-driver-phase-v1', status='phase-passed',
        phase='enumerate', driver_api=13000, driver_library_path='/usr/lib/libcuda.so.1',
        completed_operations=['cuInit', 'cuDriverGetVersion', 'cuDeviceGetCount',
            'cuDeviceGet', 'cuDeviceGetName', 'cuDeviceGetPCIBusId',
            'cuDeviceGetAttribute.major', 'cuDeviceGetAttribute.minor',
            'cuDeviceGetAttribute.concurrent_managed_access',
            'cuDeviceGetAttribute.pageable_memory_access',
            'cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables'],
        cleanup_passed=True, cleanup_errors=[], error='',
        selected_device={'name': 'Tesla V100', 'pci_bus_id': '0000:00:05.0',
                         'sm': 70, 'compute_capability': '7.0',
                         'concurrent_managed_access': True,
                         'pageable_memory_access': False,
                         'pageable_memory_access_uses_host_page_tables': False})
    if role == 'rtx5080':
        phase = dict(common_phase, driver_api=13020,
            driver_library_path='/usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02',
            selected_device={'name': 'NVIDIA GeForce RTX 5080', 'pci_bus_id': '0000:02:00.0',
                             'sm': 120, 'compute_capability': '12.0',
                             'concurrent_managed_access': True,
                             'pageable_memory_access': True,
                             'pageable_memory_access_uses_host_page_tables': False})
        acceptance = dict(schema='nvidia-hybrid-hardware-acceptance-v2',
            qualification='phase-report-contract-pass', exit_code=0, validation_errors=[],
            ioctl_observation={'report': observation})
        return dict(schema='nvidia-hybrid-remote-selected-gpu-transport-v1',
            phase='enumerate', exit_code=0, rm_control_headers_capture_requested=True,
            local_artifacts={'probe': probe, 'module': module},
            rm_control_headers_records_seen=True,
            remote=dict(phase='enumerate', exit_code=0,
                qualification='rtx5080-cuda-phase-report-contract-valid',
                rm_control_headers_capture_requested=True,
                rm_control_headers_records_seen=True,
                rm_control_headers_record_count=len(records),
                remote_work_cleanup={'passed': True, 'removed': True},
                phase_report=phase, hardware_acceptance=acceptance,
                kernel_release='7.0.0-38-generic'))
    return dict(schema='nvidia-hybrid-pc3-v100-reference-transport-v1',
        phase='enumerate', exit_code=0, qualification='v100-cuda-phase-report-contract-valid',
        probe=probe, module=module,
        rm_control_headers_capture_requested=True,
        remote=dict(phase='enumerate', exit_code=0,
            qualification='v100-cuda-phase-report-contract-valid',
            rm_control_headers_capture_requested=True,
            rm_control_headers_records_seen=True,
            rm_control_headers_record_count=len(records),
            probe=common_phase, probe_exit_code=0, observer_exit_code=0,
            guest_cleanup_passed=True, payload_file_cleanup_passed=True,
            ioctl_observation=observation,
            guest={'driver_version': '580.178.04', 'kernel_release': '6.8.0-147-generic'}))


class RmControlHeaderComparisonTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool()

    def test_compares_counts_statuses_and_size_drift_without_payloads(self):
        result = self.tool.compare_observations(
            ('rtx5080', transport('rtx5080', [row(0x2080012f, 1664, status=0x56),
                                               row(0x20800102, 564)])),
            ('v100', transport('v100', [row(0x2080012f, 1464), row(0x20800102, 564)])))

        drift = result['comparison']['shared_command_size_drift']
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0]['command'], '0x2080012f')
        self.assertEqual(drift[0]['rtx5080'], [{'bytes': 1664, 'count': 1}])
        self.assertEqual(drift[0]['v100'], [{'bytes': 1464, 'count': 1}])
        ecc = next(x for x in result['reports'][0]['commands']
                   if x['command'] == '0x2080012f')
        self.assertEqual(ecc['embedded_statuses'], [{'status': '0x00000056', 'count': 1}])
        self.assertFalse(result['comparison']['rm_control_payloads_read'])
        self.assertFalse(result['comparison']['hybrid_runtime_validated'])
        self.assertNotIn('hClient', json.dumps(result))
        self.assertNotIn('hObject', json.dumps(result))

    def test_call_frequency_does_not_masquerade_as_parameter_size_drift(self):
        result = self.tool.compare_observations(
            ('rtx5080', transport('rtx5080', [row(0x20800102, 564),
                                               row(0x20800102, 564)])),
            ('v100', transport('v100', [row(0x20800102, 564)])))
        self.assertEqual(result['comparison']['shared_command_size_drift'], [])
        self.assertEqual(result['comparison']['shared_command_call_count_drift'], [
            {'command': '0x20800102', 'params_size': [564],
             'rtx5080_calls': 2, 'v100_calls': 1}])

    def test_rejects_incomplete_or_unselected_observation(self):
        bad = transport('rtx5080', [row(1, 0)])
        bad['remote']['hardware_acceptance']['ioctl_observation']['report']['trace_complete'] = False
        with self.assertRaisesRegex(ValueError, 'complete'):
            self.tool.summarize_transport('rtx5080', bad)

        bad = transport('v100', [row(1, 0)])
        bad['remote']['rm_control_capture_requested'] = False
        with self.assertRaisesRegex(ValueError, 'capture was not requested'):
            self.tool.summarize_transport('v100', bad)

    def test_rejects_wrong_envelope_missing_fields_and_pointer_bearing_rows(self):
        for mutation, message in (
            (lambda r: r.update(request=0xc020462b), 'RM_CONTROL ioctl envelope'),
            (lambda r: r['exit'].pop('params_size'), 'typed fixed header'),
            (lambda r: r.update(pParams=0xdeadbeef), 'unexpected pointer-bearing field'),
        ):
            r = row(7, 4)
            mutation(r)
            report = transport('v100', [r])
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.tool.summarize_transport('v100', report)

    def test_writer_is_private_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'comparison.json'
            result = {'schema': 'test'}
            self.tool.write_private_report(path, result)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                self.tool.write_private_report(path, {'schema': 'replacement'})
            self.assertEqual(json.loads(path.read_text()), result)

    def test_compares_current_v23_redacted_hardware_captures(self):
        rtx_rows = [redacted_row(0x20800102, 564),
                    redacted_row(0x2080220c, 0, status=0x56)]
        v100_rows = [redacted_row(0x20800102, 564),
                     redacted_row(0x2080220c, 0, status=0)]
        result = self.tool.compare_observations(
            ('rtx5080', transport_v23('rtx5080', rtx_rows)),
            ('v100', transport_v23('v100', v100_rows)))
        self.assertEqual(result['schema'], 'nvidia-hybrid-rm-control-header-comparison-v3')
        self.assertEqual(result['reports'][0]['observer_schema'],
                         'nvidia-hybrid-rm-ioctl-observer-v23')
        self.assertEqual(result['reports'][0]['probe_sha256'], 'a' * 64)
        self.assertEqual(result['reports'][1]['cuda_fatbin_sha256'], 'b' * 64)
        self.assertTrue(result['comparison']['same_probe_binary'])
        self.assertTrue(result['comparison']['same_cuda_fatbin'])
        self.assertEqual(result['reports'][0]['driver']['api'], 13020)
        self.assertEqual(result['reports'][1]['driver']['api'], 13000)
        self.assertEqual(result['reports'][0]['params_size_zero_records'], 1)
        self.assertEqual(result['reports'][0]['client_handle_present_records'], 2)
        drift = result['comparison']['shared_command_status_code_drift']
        self.assertEqual(drift, [{'command': '0x2080220c', 'params_size': 0,
            'rtx5080_status_codes': ['0x00000056'],
            'v100_status_codes': ['0x00000000']}])
        self.assertNotIn('hClient"', json.dumps(result))
        self.assertNotIn('hObject"', json.dumps(result))
        self.assertFalse(result['comparison']['hybrid_runtime_validated'])

    def test_v23_pair_rejects_different_probe_or_fatbin(self):
        rtx = transport_v23('rtx5080', [redacted_row(0x20800102, 564)])
        v100 = transport_v23('v100', [redacted_row(0x20800102, 564)])
        v100['probe']['sha256'] = 'c' * 64
        with self.assertRaisesRegex(ValueError, 'same CUDA probe'):
            self.tool.compare_observations(('rtx5080', rtx), ('v100', v100))

        v100 = transport_v23('v100', [redacted_row(0x20800102, 564)])
        v100['module']['sha256'] = 'd' * 64
        with self.assertRaisesRegex(ValueError, 'same CUDA fatbin'):
            self.tool.compare_observations(('rtx5080', rtx), ('v100', v100))

        v100 = transport_v23('v100', [redacted_row(0x20800102, 564)])
        v100['probe']['bytes'] += 1
        with self.assertRaisesRegex(ValueError, 'same CUDA probe'):
            self.tool.compare_observations(('rtx5080', rtx), ('v100', v100))

    def test_v23_pair_rejects_missing_or_malformed_artifact_identity(self):
        for mutate in (
                lambda report: report['local_artifacts'].pop('probe'),
                lambda report: report['local_artifacts']['module'].update(sha256='bad'),
                lambda report: report['local_artifacts']['module'].update(bytes=True)):
            rtx = transport_v23('rtx5080', [redacted_row(0x20800102, 564)])
            v100 = transport_v23('v100', [redacted_row(0x20800102, 564)])
            mutate(rtx)
            with self.assertRaisesRegex(ValueError, 'artifact identity is malformed or missing'):
                self.tool.compare_observations(('rtx5080', rtx), ('v100', v100))

    def test_v23_rejects_unredacted_fields_and_wrong_generation(self):
        observation = transport_v23('rtx5080', [redacted_row(1, 0)])
        observation['remote']['hardware_acceptance']['ioctl_observation']['report']['records'][0]['entry']['hClient'] = 0x1234
        with self.assertRaisesRegex(ValueError, 'unexpected|unredacted|fixed header'):
            self.tool.summarize_transport('rtx5080', observation)

        wrong_gpu = transport_v23('rtx5080', [redacted_row(1, 0)])
        wrong_gpu['remote']['phase_report']['selected_device']['sm'] = 70
        with self.assertRaisesRegex(ValueError, 'SM120|Blackwell|selected'):
            self.tool.summarize_transport('rtx5080', wrong_gpu)


if __name__ == '__main__':
    unittest.main()
