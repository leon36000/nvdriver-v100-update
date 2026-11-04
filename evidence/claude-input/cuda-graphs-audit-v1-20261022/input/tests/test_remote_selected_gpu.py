#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU-only safety contracts: no SSH and no real NVIDIA/CUDA calls."""
import base64
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location('selected_remote', ROOT / 'tools/run_remote_selected_gpu.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
UUID = 'GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77'
PCI = '0000:02:00.0'
DEVICE = {'pci_bus_id': PCI, 'sm': 120, 'name': 'NVIDIA GeForce RTX 5080'}
PROBE_CONTRACT = {
    'schema': 'nvidia-hybrid-probe-contract-v1',
    'contract_version': 2,
    'probe_report_schema': 'nvidia-hybrid-probe-v2',
    'probe_report_fields': ['memory_mode', 'managed_prefetch_requested',
                            'managed_prefetch_api', 'devices', 'cuda_graphs_requested',
                            'cuda_graph_api'],
    'device_report_fields': ['managed_memory_passed', 'managed_prefetch_passed',
                             'cuda_graphs_passed', 'cuda_graph_launches'],
}


class RemoteSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.proc = self.root / 'proc'
        self.sys = self.root / 'sys'
        info = self.proc / 'driver/nvidia/gpus/00000000:02:00.0/information'
        info.parent.mkdir(parents=True)
        info.write_text(f'Model: NVIDIA GeForce RTX 5080\nGPU UUID: {UUID}\n')
        driver = self.sys / 'bus/pci/drivers/nvidia'
        driver.mkdir(parents=True)
        link = self.sys / 'bus/pci/devices' / PCI / 'driver'
        link.parent.mkdir(parents=True)
        link.symlink_to(driver)
        self.payload = {'pci': PCI, 'uuid': UUID, 'remote_script_sha256': 'script-sha', 'artifacts': {}}
        for name in ('probe', 'module', 'runner'):
            data = ('fixture-' + name).encode()
            self.payload['artifacts'][name] = {'base64': base64.b64encode(data).decode(),
                                            'sha256': hashlib.sha256(data).hexdigest()}
        self.commands = []
        namespace = {'__name__': 'remote_contract'}
        exec(tool.REMOTE_SCRIPT, namespace)
        self.run_remote = namespace['run']
        self.namespace = namespace
        self.preflight_device = dict(DEVICE)
        self.preflight_devices = None
        self.acceptance_code = 77
        self.managed_result = False
        self.prefetch_result = False
        self.graph_result = False
        self.mutate = False
        self.phase_report = None
        self.phase_observation = None

    def tearDown(self):
        self.tmp.cleanup()

    def test_transport_exit_code_preserves_only_phase_success(self):
        self.assertEqual(tool.transport_exit_code(0, phase_requested=True), 0)
        self.assertEqual(tool.transport_exit_code(77, phase_requested=True), 77)
        self.assertEqual(tool.transport_exit_code(0, phase_requested=False), 2)
        self.assertEqual(tool.transport_exit_code(77, phase_requested=False), 77)
        self.assertEqual(tool.transport_exit_code(3, phase_requested=True), 2)

    def invoke(self, argv, **kwargs):
        self.commands.append(argv)
        env = kwargs['env']
        self.assertEqual(env['CUDA_VISIBLE_DEVICES'], UUID)
        self.assertFalse(any(key.startswith(('LD_', 'PYTHON', 'NVIDIA_')) for key in env))
        if argv[0] == 'nvidia-smi':
            self.assertEqual(argv[1:3], ['-i', UUID])
            return subprocess.CompletedProcess(argv, 0, f'NVIDIA GeForce RTX 5080, {UUID}, 00000000:02:00.0, 595.99.02\n', '')
        if '--list' in argv:
            report = {'schema': 'nvidia-hybrid-probe-v2', 'status': 'inventory',
                      'devices': self.preflight_devices if self.preflight_devices is not None else [self.preflight_device]}
            return subprocess.CompletedProcess(argv, 0, json.dumps(report), '')
        self.assertEqual(argv[1].split('/')[-1], 'runner')
        self.assertIn('--expected-pci', argv)
        self.assertNotIn('--allow-incomplete', argv)
        self.assertEqual(argv[argv.index('--expected-pci') + 1], PCI)
        requested_phase = self.payload.get('phase')
        if requested_phase is not None:
            self.assertIn('--phase', argv)
            self.assertEqual(argv[argv.index('--phase') + 1], requested_phase)
            self.assertIn('--ioctl-observer', argv)
            if self.payload.get('device_alloc_capture'):
                self.assertIn('--device-alloc', argv)
                self.assertNotIn('--binapi-control', argv)
                self.assertNotIn('--rm-control', argv)
                self.assertIn('--gpu-path', argv)
            elif self.payload.get('subdevice_alloc_capture'):
                self.assertIn('--subdevice-alloc', argv)
                self.assertNotIn('--device-alloc', argv)
                self.assertNotIn('--binapi-control', argv)
                self.assertIn('--gpu-path', argv)
            elif self.payload.get('binapi_alloc_capture'):
                self.assertIn('--binapi-alloc', argv)
                self.assertNotIn('--device-alloc', argv)
                self.assertNotIn('--subdevice-alloc', argv)
                self.assertNotIn('--binapi-control', argv)
                self.assertIn('--gpu-path', argv)
            else:
                self.assertIn('--binapi-control', argv)
                self.assertIn('--rm-control', argv)
            result = {'probe': self.phase_report, 'phase_capture_requested': True,
                      'phase': requested_phase, 'exit_code': 0,
                      'qualification': 'phase-observed-on-hardware',
                      'validation_errors': []}
            if self.phase_observation is not None:
                result['ioctl_observation'] = {'report': self.phase_observation}
            if self.payload.get('device_alloc_capture'):
                result['device_alloc_records_seen'] = True
                result['device_alloc_payload_snapshots_read'] = 2
            if self.payload.get('subdevice_alloc_capture'):
                result['subdevice_alloc_records_seen'] = True
                result['subdevice_alloc_payload_snapshots_read'] = 2
            if self.payload.get('binapi_alloc_capture'):
                result['binapi_alloc_records_seen'] = True
                result['binapi_alloc_payload_snapshots_read'] = 2
            return subprocess.CompletedProcess(argv, 0, json.dumps(result), '')
        managed_requested = bool(self.payload.get('managed_memory'))
        prefetch_requested = bool(self.payload.get('managed_prefetch'))
        graphs_requested = bool(self.payload.get('cuda_graphs'))
        self.assertEqual('--managed-memory' in argv, managed_requested)
        self.assertEqual('--managed-prefetch' in argv, prefetch_requested)
        self.assertEqual('--cuda-graphs' in argv, graphs_requested)
        probe = {'devices': [dict(DEVICE, managed_memory_passed=self.managed_result,
                                  managed_prefetch_passed=self.prefetch_result,
                                  cuda_graphs_passed=self.graph_result,
                                  cuda_graph_launches=(2 if self.graph_result else 0))],
                 'memory_mode': 'managed' if managed_requested else 'device',
                 'managed_prefetch_requested': prefetch_requested,
                 'managed_prefetch_api': ('cuMemPrefetchAsync_v2' if prefetch_requested else 'not-requested'),
                 'cuda_graphs_requested': graphs_requested,
                 'cuda_graph_api': ('cuGraphInstantiateWithFlags' if graphs_requested else 'not-requested'),
                 'hybrid_validated': False, 'missing_sm': [70], 'required_sm': [70, 120]}
        result = {'probe': probe, 'exit_code': self.acceptance_code,
                  'qualification': 'incomplete-hardware-missing', 'validation_errors': []}
        if self.mutate:
            Path(argv[argv.index('--probe') + 1]).write_bytes(b'mutated')
        return subprocess.CompletedProcess(argv, self.acceptance_code, json.dumps(result), '')

    def run_case(self, work_name='work'):
        work = self.root / work_name
        work.mkdir()
        with patch.dict(os.environ, {'LD_PRELOAD': 'bad', 'LD_LIBRARY_PATH': 'bad',
                                     'CUDA_INJECTION64_PATH': 'bad', 'CUDA_VISIBLE_DEVICES': '0,1',
                                     'PYTHONPATH': 'bad'}), patch.object(self.namespace['tempfile'], 'mkdtemp', return_value=str(work)):
            return self.run_remote(self.payload, self.proc, self.sys, self.invoke)

    @staticmethod
    def binapi_observation(records=True):
        zero_changed = '00' * 124
        changed = '01' + ('00' * 123)
        nonzero = '01' + ('00' * 30)
        common_payload = {'payloadBytes': 992, 'payloadValid': True,
                          'nonzeroU32Count': 1,
                          'nonzeroU32MaskLsbFirst': nonzero}
        entry = {'command': 0x20810108, 'flags': 0, 'params_size': 992,
                 'status': 0, 'hClientPresent': True, 'hObjectPresent': True,
                 'client_object_equal': False,
                 'client_matches_prior_root_allocation': False,
                 'object_matches_prior_root_allocation': False,
                 'objectClass': {'resolution': 'resolved', 'classId': 0x2081},
                 'binapiPayload': {**common_payload, 'changedByteCount': 0,
                                   'changedByteMaskLsbFirst': zero_changed,
                                   'entryExitPayloadEqual': None}}
        exit_phase = copy.deepcopy(entry)
        exit_phase['binapiPayload']['changedByteCount'] = 1
        exit_phase['binapiPayload']['changedByteMaskLsbFirst'] = changed
        exit_phase['binapiPayload']['entryExitPayloadEqual'] = False
        rows = ([{'tid': 77, 'fd': 6, 'fd_role': 'control',
                  'request': 0xc020462a, 'packet_size': 32,
                  'operation': 'binapi_control', 'entry': entry,
                  'exit': exit_phase, 'syscall_return': 0}] if records else [])
        observed = {'schema': 'nvidia-hybrid-rm-ioctl-observer-v18',
                    'trace_complete': True, 'child_exit_code': 77,
                    'control_path': '/dev/nvidiactl', 'gpu_path': '/dev/nvidia0',
                    'architecture': 'x86_64', 'pointer_bits': 64,
                    'nested_pointers_read': bool(records),
                    'fd_identity_tracking': False,
                    'object_class_resolution_scope': (
                        'successful prior RM_ALLOC and RM_FREE packets observed on the explicitly '
                        'selected control and GPU paths; keyed by root and handle; unresolved means '
                        'no unique live object was observed'),
                    'binapi_payload_snapshots_read': 2 if records else 0,
                    'payload_scope': ('RM_CONTROL headers plus exact 992-byte NV2081_BINAPI '
                                      'payload-shape metadata; contained pointers are never followed; '
                                      'raw bytes, addresses, and handles omitted'),
                    'errors': [], 'records': rows}
        if records:
            observed['nested_pointer_scope'] = (
                'exact 992-byte top-level NV2081_BINAPI control payload for command 0x20810108; '
                'no contained pointer is followed; raw bytes, addresses, and handles omitted')
        return observed

    @staticmethod
    def device_alloc_observation():
        payload = {'classPayloadBytes': 56, 'deviceId': 0,
                   'hClientShare': 'same-as-root', 'targetClientZero': True,
                   'targetDeviceZero': True, 'flags': 0x403, 'vaSpaceSize': 0x123000,
                   'vaStartInternalZero': False, 'vaLimitInternalZero': False,
                   'vaMode': 2}
        packet = {'layout': 'NVOS64', 'hClass': 128, 'paramsSize': 56, 'flags': 0,
                  'status': 0, 'hRootPresent': True, 'hObjectParentPresent': True,
                  'hObjectNewPresent': True, 'pAllocParmsPresent': True,
                  'pRightsRequestedPresent': False, 'deviceAlloc': payload}
        scope = ('NV01_DEVICE_0 NV0080_ALLOC_PARAMETERS fixed 56-byte payload only; '
                 'client handles are relational booleans; internal VA addresses are omitted')
        row = {'tid': 77, 'fd': 6, 'fd_role': 'control', 'request': 0xc020462a,
               'packet_size': 64, 'operation': 'device_alloc', 'entry': packet,
               'exit': packet, 'syscall_return': 0}
        return {'schema': 'nvidia-hybrid-rm-ioctl-observer-v19', 'trace_complete': True,
                'child_exit_code': 0, 'control_path': '/dev/nvidiactl',
                'gpu_path': '/dev/nvidia0', 'architecture': 'x86_64', 'pointer_bits': 64,
                'nested_pointers_read': True, 'nested_pointer_scope': scope,
                'payload_scope': ('NV01_DEVICE_0 fixed class parameters only; handles are redacted '
                                  'and internal VA addresses are omitted'),
                'fd_identity_tracking': False, 'device_alloc_payload_snapshots_read': 2,
                'errors': [], 'records': [row]}

    @staticmethod
    def subdevice_alloc_observation():
        payload = {'classPayloadBytes': 4, 'subDeviceId': 0}
        packet = {'layout': 'NVOS64', 'hClass': 0x2080, 'paramsSize': 0,
                  'flags': 0, 'status': 0, 'hRootPresent': True,
                  'hObjectParentPresent': True, 'hObjectNewPresent': True,
                  'pAllocParmsPresent': True, 'pRightsRequestedPresent': False,
                  'subdeviceAlloc': payload}
        return {'schema': 'nvidia-hybrid-rm-ioctl-observer-v20',
                'trace_complete': True, 'child_exit_code': 0,
                'control_path': '/dev/nvidiactl', 'gpu_path': '/dev/nvidia0',
                'architecture': 'x86_64', 'pointer_bits': 64,
                'nested_pointers_read': True,
                'nested_pointer_scope': ('NV20_SUBDEVICE_0 NV2080_ALLOC_PARAMETERS fixed '
                                         '4-byte subDeviceId only; handles omitted'),
                'payload_scope': 'NV20_SUBDEVICE_0 fixed class parameters only; handles omitted',
                'fd_identity_tracking': False, 'subdevice_alloc_payload_snapshots_read': 2,
                'errors': [], 'records': [{'tid': 77, 'fd': 6, 'fd_role': 'control',
                    'request': 0xc030462b, 'packet_size': 48,
                    'operation': 'subdevice_alloc', 'entry': packet,
                    'exit': packet, 'syscall_return': 0}]}

    @staticmethod
    def binapi_alloc_observation():
        payload = {'classPayloadBytes': 4, 'reservedZero': True}
        packet = {'layout': 'NVOS64', 'hClass': 0x2081, 'paramsSize': 0,
                  'flags': 0, 'status': 0, 'hRootPresent': True,
                  'hObjectParentPresent': True, 'hObjectNewPresent': True,
                  'pAllocParmsPresent': True, 'pRightsRequestedPresent': False,
                  'binapiAlloc': payload}
        return {'schema': 'nvidia-hybrid-rm-ioctl-observer-v21',
                'trace_complete': True, 'child_exit_code': 0,
                'control_path': '/dev/nvidiactl', 'gpu_path': '/dev/nvidia0',
                'architecture': 'x86_64', 'pointer_bits': 64,
                'nested_pointers_read': True,
                'nested_pointer_scope': ('NV2081_BINAPI NV2081_ALLOC_PARAMETERS fixed '
                                         '4-byte reserved zero predicate only; handles omitted'),
                'payload_scope': ('NV2081_BINAPI fixed class parameters only; raw reserved '
                                  'value, handles omitted'),
                'fd_identity_tracking': False, 'binapi_alloc_payload_snapshots_read': 2,
                'errors': [], 'records': [{'tid': 77, 'fd': 6, 'fd_role': 'control',
                    'request': 0xc030462b, 'packet_size': 48,
                    'operation': 'binapi_alloc', 'entry': packet,
                    'exit': packet, 'syscall_return': 0}]}

    def test_selected_reference_is_truthfully_incomplete(self):
        report, code = self.run_case()
        self.assertEqual(code, 77)
        self.assertEqual(report['memory_mode'], 'device')
        self.assertEqual(len(self.commands), 3)
        self.assertEqual(report['artifacts_before'], report['artifacts_after'])
        self.assertFalse(report['hardware_acceptance']['probe']['hybrid_validated'])
        for key in ('vm_management_commands_issued', 'v100_test_requested',
                    'experimental_driver_change_requested'):
            self.assertIs(report['execution_scope'][key], False)
        self.assertIsNone(report['execution_scope']['official_module_autoload_observed'])

    def test_phase_capture_is_forwarded_and_qualified_separately_from_hybrid(self):
        observer_data = b"CPU observer fixture"
        self.payload['phase'] = 'initialize'
        self.payload['binapi_control_capture'] = True
        self.payload['rm_control_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(observer_data).decode(),
            'sha256': hashlib.sha256(observer_data).hexdigest(),
        }
        self.phase_report = {
            'schema': 'nvidia-cuda-driver-phase-v1', 'status': 'phase-passed',
            'phase': 'initialize', 'expected_pci': '00000000:02:00.0',
            'driver_library_path': '/usr/lib/x86_64-linux-gnu/libcuda.so.1',
            'driver_api': None, 'selected_device': None,
            'completed_operations': ['cuInit'], 'numeric_result_passed': False,
            'result_value': None, 'expected_result': None, 'cleanup_passed': True,
            'cleanup_errors': [], 'error': '',
        }
        self.phase_observation = self.binapi_observation(records=False)
        self.phase_observation['child_exit_code'] = 0
        report, code = self.run_case()
        self.assertEqual(code, 0, report.get('error'))
        self.assertEqual(report['qualification'], 'rtx5080-cuda-phase-validated')
        self.assertEqual(report['phase'], 'initialize')
        acceptance = report['hardware_acceptance']
        self.assertEqual(acceptance['qualification'], 'phase-observed-on-hardware')
        self.assertFalse(acceptance['probe'].get('hybrid_validated', False))
        self.assertEqual(report['binapi_payload_snapshots_read'], 0)

    def test_phase_capture_requires_the_isolated_binapi_observer(self):
        self.payload['phase'] = 'context'
        with self.assertRaisesRegex(ValueError, 'phase capture requires exactly one isolated BINAPI'):
            self.run_case()

    def test_device_alloc_phase_capture_is_forwarded_and_kept_separate(self):
        observer_data = b"CPU observer fixture"
        self.payload.update({'phase': 'context', 'device_alloc_capture': True})
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(observer_data).decode(),
            'sha256': hashlib.sha256(observer_data).hexdigest(),
        }
        self.phase_report = {
            'schema': 'nvidia-cuda-driver-phase-v1', 'status': 'phase-passed',
            'phase': 'context', 'expected_pci': '00000000:02:00.0',
            'driver_library_path': '/usr/lib/x86_64-linux-gnu/libcuda.so.1',
            'driver_api': 13020,
            'selected_device': {'name': DEVICE['name'], 'pci_bus_id': PCI,
                                'sm': 120, 'compute_capability': '12.0'},
            'completed_operations': ['cuInit', 'cuDriverGetVersion', 'cuDeviceGetCount',
                'cuDeviceGet', 'cuDeviceGetName', 'cuDeviceGetPCIBusId',
                'cuDeviceGetAttribute.major', 'cuDeviceGetAttribute.minor',
                'cuCtxCreate_v2', 'cuCtxSetCurrent', 'cuCtxGetDevice'],
            'numeric_result_passed': False, 'result_value': None, 'expected_result': None,
            'cleanup_passed': True, 'cleanup_errors': [], 'error': '',
        }
        self.phase_observation = self.device_alloc_observation()
        report, code = self.run_case()
        self.assertEqual(code, 0, report.get('error'))
        self.assertEqual(report['qualification'], 'rtx5080-cuda-phase-validated')
        self.assertTrue(report['device_alloc_capture_requested'])
        self.assertTrue(report['device_alloc_records_seen'])
        self.assertEqual(report['device_alloc_payload_snapshots_read'], 2)
        self.assertFalse(report['binapi_control_capture_requested'])

    def test_subdevice_alloc_phase_capture_is_forwarded_and_kept_separate(self):
        observer_data = b"CPU observer fixture"
        self.payload.update({'phase': 'context', 'subdevice_alloc_capture': True})
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(observer_data).decode(),
            'sha256': hashlib.sha256(observer_data).hexdigest(),
        }
        self.phase_report = {
            'schema': 'nvidia-cuda-driver-phase-v1', 'status': 'phase-passed',
            'phase': 'context', 'expected_pci': '00000000:02:00.0',
            'driver_library_path': '/usr/lib/x86_64-linux-gnu/libcuda.so.1',
            'driver_api': 13020,
            'selected_device': {'name': DEVICE['name'], 'pci_bus_id': PCI,
                                'sm': 120, 'compute_capability': '12.0'},
            'completed_operations': ['cuInit', 'cuCtxCreate_v2', 'cuCtxDestroy_v2'],
            'numeric_result_passed': False, 'result_value': None, 'expected_result': None,
            'cleanup_passed': True, 'cleanup_errors': [], 'error': '',
        }
        self.phase_observation = self.subdevice_alloc_observation()
        report, code = self.run_case()
        self.assertEqual(code, 0, report.get('error'))
        self.assertTrue(report['subdevice_alloc_capture_requested'])
        self.assertTrue(report['subdevice_alloc_records_seen'])
        self.assertEqual(report['subdevice_alloc_payload_snapshots_read'], 2)
        self.assertFalse(report['device_alloc_capture_requested'])
        self.assertFalse(report['binapi_control_capture_requested'])

    def test_binapi_alloc_phase_capture_is_forwarded_and_kept_separate(self):
        observer_data = b"CPU observer fixture"
        self.payload.update({'phase': 'context', 'binapi_alloc_capture': True})
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(observer_data).decode(),
            'sha256': hashlib.sha256(observer_data).hexdigest(),
        }
        self.phase_report = {
            'schema': 'nvidia-cuda-driver-phase-v1', 'status': 'phase-passed',
            'phase': 'context', 'expected_pci': '00000000:02:00.0',
            'driver_library_path': '/usr/lib/x86_64-linux-gnu/libcuda.so.1',
            'driver_api': 13020,
            'selected_device': {'name': DEVICE['name'], 'pci_bus_id': PCI,
                                'sm': 120, 'compute_capability': '12.0'},
            'completed_operations': ['cuInit', 'cuCtxCreate_v2', 'cuCtxDestroy_v2'],
            'numeric_result_passed': False, 'result_value': None, 'expected_result': None,
            'cleanup_passed': True, 'cleanup_errors': [], 'error': '',
        }
        self.phase_observation = self.binapi_alloc_observation()
        report, code = self.run_case()
        self.assertEqual(code, 0, report.get('error'))
        self.assertEqual(report['qualification'], 'rtx5080-cuda-phase-validated')
        self.assertTrue(report['binapi_alloc_capture_requested'])
        self.assertTrue(report['binapi_alloc_records_seen'])
        self.assertEqual(report['binapi_alloc_payload_snapshots_read'], 2)
        self.assertFalse(report['subdevice_alloc_capture_requested'])

    def test_managed_memory_is_forwarded_and_requires_a_real_probe_pass(self):
        self.payload['managed_memory'] = True
        self.managed_result = True
        report, code = self.run_case()
        self.assertEqual(code, 77, report.get('error'))
        self.assertEqual(report['memory_mode'], 'managed')
        self.assertIn('--managed-memory', self.commands[-1])
        self.assertTrue(report['hardware_acceptance']['probe']['devices'][0]['managed_memory_passed'])

    def test_managed_memory_failure_cannot_be_qualified(self):
        self.payload['managed_memory'] = True
        self.managed_result = False
        report, code = self.run_case()
        self.assertEqual(code, 2)
        self.assertIn('managed-memory', report['error'])

    def test_managed_prefetch_is_forwarded_and_requires_probe_confirmation(self):
        self.payload['managed_memory'] = True
        self.payload['managed_prefetch'] = True
        self.managed_result = True
        self.prefetch_result = True
        report, code = self.run_case()
        self.assertEqual(code, 77, report.get('error'))
        self.assertEqual(report['memory_mode'], 'managed')
        self.assertTrue(report['managed_prefetch_validated'])
        self.assertIn('--managed-prefetch', self.commands[-1])

    def test_managed_prefetch_failure_cannot_be_qualified(self):
        self.payload['managed_memory'] = True
        self.payload['managed_prefetch'] = True
        self.managed_result = True
        self.prefetch_result = False
        report, code = self.run_case()
        self.assertEqual(code, 2)
        self.assertIn('prefetch', report['error'])

    def test_cuda_graph_flag_is_forwarded_and_requires_two_replays(self):
        self.payload['cuda_graphs'] = True
        self.graph_result = True
        report, code = self.run_case()
        self.assertEqual(code, 77, report.get('error'))
        self.assertTrue(report['cuda_graphs_validated'])
        self.assertIn('--cuda-graphs', self.commands[-1])

        self.graph_result = False
        report, code = self.run_case('graph-fails')
        self.assertEqual(code, 2)
        self.assertIn('CUDA Graph', report['error'])

    def test_observer_is_uploaded_guarded_and_evidence_required(self):
        data = b"CPU observer fixture"
        self.payload['artifacts']['observer'] = {'base64': base64.b64encode(data).decode(),
                                                'sha256': hashlib.sha256(data).hexdigest()}
        original = self.invoke
        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                self.assertIn('--ioctl-observer', argv)
                observed_path = Path(argv[argv.index('--ioctl-observer') + 1])
                self.assertEqual(observed_path.read_bytes(), data)
                self.assertEqual(observed_path.stat().st_mode & 0o777, 0o700)
                report = json.loads(result.stdout)
                capture_id_info = bool(self.payload.get('gpu_id_info_capture'))
                if capture_id_info:
                    self.assertIn('--gpu-id-info', argv)
                report['ioctl_observation'] = {'report': {
                    'schema': ('nvidia-hybrid-rm-ioctl-observer-v3' if capture_id_info else
                               'nvidia-hybrid-rm-ioctl-observer-v1'),
                    'trace_complete': True,
                    'nested_pointers_read': capture_id_info,
                    'nested_pointer_scope': (
                        'exact NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 payload only; addresses omitted'
                        if capture_id_info else None),
                    'errors': [], 'child_exit_code': 77, 'control_path': '/dev/nvidiactl', 'records': []}}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result
        self.invoke = invoke
        report, code = self.run_case()
        self.assertEqual(code, 77, report.get('error'))
        self.assertIn('observer', report['artifacts_before'])
        self.assertEqual(report['artifacts_before'], report['artifacts_after'])

    def test_gpu_id_info_capture_is_explicitly_forwarded_and_version_checked(self):
        data = b"CPU observer fixture"
        self.payload['gpu_id_info_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        original = self.invoke

        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                self.assertIn('--gpu-id-info', argv)
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': {
                    'schema': 'nvidia-hybrid-rm-ioctl-observer-v3', 'trace_complete': True,
                    'nested_pointers_read': True,
                    'nested_pointer_scope': 'exact NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 payload only; addresses omitted',
                    'errors': [], 'child_exit_code': 77, 'control_path': '/dev/nvidiactl', 'records': []}}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result

        self.invoke = invoke
        report, code = self.run_case()
        self.assertEqual(code, 77, report.get('error'))
        self.assertTrue(report['hardware_acceptance']['ioctl_observation']['report']['nested_pointers_read'])

        # A v1 report cannot satisfy an explicitly requested v2 capture.
        self.invoke = original
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        self.payload['gpu_id_info_capture'] = True

        def stale_invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': {
                    'schema': 'nvidia-hybrid-rm-ioctl-observer-v1', 'trace_complete': True,
                    'nested_pointers_read': False,
                    'errors': [], 'child_exit_code': 77, 'control_path': '/dev/nvidiactl', 'records': []}}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result

        self.invoke = stale_invoke
        report, code = self.run_case(work_name='work-stale-schema')
        self.assertEqual(code, 2)
        self.assertIn('observation', report['error'])

    def test_attached_ids_capture_is_explicitly_forwarded_and_scope_checked(self):
        data = b"CPU observer fixture"
        self.payload['attached_ids_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        original = self.invoke

        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                self.assertIn('--attached-ids', argv)
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': {
                    'schema': 'nvidia-hybrid-rm-ioctl-observer-v4', 'trace_complete': True,
                    'nested_pointers_read': True,
                    'nested_pointer_scope': 'exact NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS payload only; addresses omitted',
                    'errors': [], 'child_exit_code': 77, 'control_path': '/dev/nvidiactl', 'records': []}}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result

        self.invoke = invoke
        report, code = self.run_case()
        self.assertEqual(code, 77, report.get('error'))
        self.assertTrue(report['attached_ids_capture_requested'])
        self.assertTrue(report['hardware_acceptance']['ioctl_observation']['report']['nested_pointers_read'])

        self.invoke = original
        def stale_invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': {
                    'schema': 'nvidia-hybrid-rm-ioctl-observer-v1', 'trace_complete': True,
                    'nested_pointers_read': False, 'errors': [], 'child_exit_code': 77,
                    'control_path': '/dev/nvidiactl', 'records': []}}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result
        self.invoke = stale_invoke
        report, code = self.run_case(work_name='work-stale-attached-schema')
        self.assertEqual(code, 2)
        self.assertIn('observation', report['error'])

    def test_rm_control_capture_is_explicitly_forwarded_and_payload_bounded(self):
        data = b"CPU observer fixture"
        self.payload['rm_control_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        original = self.invoke

        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                self.assertIn('--rm-control', argv)
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': {
                    'schema': 'nvidia-hybrid-rm-ioctl-observer-v5',
                    'trace_complete': True, 'nested_pointers_read': False,
                    'payload_scope': 'fixed NVOS54 RM_CONTROL headers only; nested parameter payloads omitted',
                    'errors': [], 'child_exit_code': 77, 'control_path': '/dev/nvidiactl',
                    'records': [{'operation': 'rm_control_header'}]}}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result

        self.invoke = invoke
        report, code = self.run_case()
        self.assertEqual(code, 77, report.get('error'))
        self.assertTrue(report['rm_control_capture_requested'])
        self.assertTrue(report['rm_control_records_seen'])
        self.assertEqual(report['artifacts_before'], report['artifacts_after'])

        self.invoke = original
        def wide_scope_invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                observed = {'schema': 'nvidia-hybrid-rm-ioctl-observer-v5',
                            'trace_complete': True, 'nested_pointers_read': False,
                            'payload_scope': 'all RM payloads', 'errors': [],
                            'child_exit_code': 77, 'control_path': '/dev/nvidiactl',
                            'records': [{'operation': 'rm_control_header'}]}
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': observed}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result
        self.invoke = wide_scope_invoke
        report, code = self.run_case(work_name='work-wide-rm-control')
        self.assertEqual(code, 2)
        self.assertIn('observation', report['error'])

    def test_p2p_control_capture_allows_a_complete_blackwell_trace_with_no_p2p_controls(self):
        data = b"CPU observer fixture"
        self.payload['rm_control_capture'] = True
        self.payload['p2p_control_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        original = self.invoke

        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                self.assertIn('--rm-control', argv)
                self.assertIn('--p2p-control', argv)
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': {
                    'schema': 'nvidia-hybrid-rm-ioctl-observer-v17',
                    'trace_complete': True, 'nested_pointers_read': False,
                    'payload_scope': ('RM_CONTROL headers plus exact NV503C P2P control payloads; '
                                      'raw addresses, handles, and VA-space tokens omitted; '
                                      'other nested parameter payloads omitted'),
                    'p2p_control_payload_snapshots_read': 0,
                    'errors': [], 'child_exit_code': 77,
                    'control_path': '/dev/nvidiactl',
                    'records': [{'operation': 'rm_control_header'}]}}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result

        self.invoke = invoke
        report, code = self.run_case(work_name='work-p2p-control-empty')
        self.assertEqual(code, 77, report.get('error'))
        self.assertTrue(report['p2p_control_capture_requested'])
        self.assertTrue(report['rm_control_records_seen'])
        self.assertFalse(report['p2p_control_records_seen'])
        self.assertEqual(report['p2p_control_payload_snapshots_read'], 0)

    def test_p2p_control_capture_validates_a_resolved_successful_nested_control(self):
        data = b"CPU observer fixture"
        self.payload['rm_control_capture'] = True
        self.payload['p2p_control_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        command = 0x503c0105
        nested = {'command': command, 'payloadBytes': 4, 'payloadValid': True,
                  'inputHandlePresent': True}
        outer = {'command': command, 'flags': 0, 'params_size': 4, 'status': 0,
                 'hClientPresent': True, 'hObjectPresent': True,
                 'client_object_equal': False, 'client_matches_prior_root_allocation': True,
                 'object_matches_prior_root_allocation': False,
                 'objectClass': {'resolution': 'resolved', 'classId': 0x503c},
                 'p2pControl': nested}
        row = {'tid': 77, 'fd': 6, 'fd_role': 'control', 'request': 0xc020462a,
               'packet_size': 32, 'operation': 'rm_control_header', 'entry': outer,
               'exit': dict(outer), 'syscall_return': 0}
        observed = {'schema': 'nvidia-hybrid-rm-ioctl-observer-v17',
                    'trace_complete': True, 'nested_pointers_read': True,
                    'nested_pointer_scope': ('exact NV503C register/unregister VA-space, '
                                             'register/unregister vidmem, and register-PID fixed '
                                             'parameter structures; raw addresses, handles, and '
                                             'VA-space tokens omitted'),
                    'payload_scope': ('RM_CONTROL headers plus exact NV503C P2P control payloads; '
                                      'raw addresses, handles, and VA-space tokens omitted; '
                                      'other nested parameter payloads omitted'),
                    'p2p_control_payload_snapshots_read': 2,
                    'errors': [], 'child_exit_code': 77, 'control_path': '/dev/nvidiactl',
                    'records': [row]}
        original = self.invoke

        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                self.assertIn('--p2p-control', argv)
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': observed}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result

        self.invoke = invoke
        report, code = self.run_case(work_name='work-p2p-control-positive')
        self.assertEqual(code, 77, report.get('error'))
        self.assertTrue(report['p2p_control_records_seen'])
        self.assertEqual(report['p2p_control_payload_snapshots_read'], 2)

        observed['records'][0]['entry']['objectClass']['classId'] = 0x80
        report, code = self.run_case(work_name='work-p2p-control-wrong-class')
        self.assertEqual(code, 2)
        self.assertIn('P2P control', report['error'])

    def test_p2p_control_capture_requires_rm_control_and_observer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / 'probe', root / 'module', root / 'observer'
            probe.write_bytes(b'CPU fixture')
            module.write_bytes(b'CPU fixture module')
            observer.write_bytes(b'CPU observer')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--p2p-control', '--evidence', str(root / 'no-observer.json')]
            with self.assertRaises(SystemExit) as missing_observer:
                tool.parse_args(argv)
            self.assertEqual(missing_observer.exception.code, 2)
            argv[argv.index('--evidence'):argv.index('--evidence')] = [
                '--ioctl-observer', str(observer)]
            with self.assertRaises(SystemExit) as missing_rm_control:
                tool.parse_args(argv)
            self.assertEqual(missing_rm_control.exception.code, 2)
            argv.insert(argv.index('--p2p-control'), '--rm-control')
            self.assertTrue(tool.parse_args(argv).p2p_control)

    def test_binapi_control_capture_forwards_gpu_path_and_validates_redacted_shape(self):
        data = b"CPU observer fixture"
        self.payload['rm_control_capture'] = True
        self.payload['binapi_control_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        observed = self.binapi_observation()
        original = self.invoke

        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                self.assertIn('--rm-control', argv)
                self.assertIn('--binapi-control', argv)
                self.assertEqual(argv[argv.index('--gpu-path') + 1], '/dev/nvidia0')
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': observed}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result

        self.invoke = invoke
        report, code = self.run_case(work_name='work-binapi-control-valid')
        self.assertEqual(code, 77, report.get('error'))
        self.assertTrue(report['binapi_control_records_seen'])
        self.assertEqual(report['binapi_payload_snapshots_read'], 2)

        observed['records'][0]['entry']['objectClass']['classId'] = 0x80
        report, code = self.run_case(work_name='work-binapi-control-wrong-class')
        self.assertEqual(code, 2)
        self.assertIn('NV2081_BINAPI', report['error'])

        observed = self.binapi_observation()
        observed['records'][0]['exit']['binapiPayload']['changedByteCount'] = 2
        report, code = self.run_case(work_name='work-binapi-control-wrong-mask-count')
        self.assertEqual(code, 2)
        self.assertIn('mask counts', report['error'])

    def test_binapi_control_capture_accepts_complete_trace_with_no_target_command(self):
        data = b"CPU observer fixture"
        self.payload['rm_control_capture'] = True
        self.payload['binapi_control_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        observed = self.binapi_observation(records=False)
        original = self.invoke

        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': observed}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result

        self.invoke = invoke
        report, code = self.run_case(work_name='work-binapi-control-empty')
        self.assertEqual(code, 77, report.get('error'))
        self.assertFalse(report['binapi_control_records_seen'])
        self.assertEqual(report['binapi_payload_snapshots_read'], 0)

    def test_binapi_control_capture_requires_rm_control_and_observer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / 'probe', root / 'module', root / 'observer'
            probe.write_bytes(b'CPU fixture')
            module.write_bytes(b'CPU fixture module')
            observer.write_bytes(b'CPU observer')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--binapi-control', '--evidence', str(root / 'capture.json')]
            with self.assertRaises(SystemExit) as missing_observer:
                tool.parse_args(argv)
            self.assertEqual(missing_observer.exception.code, 2)
            argv[argv.index('--evidence'):argv.index('--evidence')] = [
                '--ioctl-observer', str(observer)]
            with self.assertRaises(SystemExit) as missing_rm:
                tool.parse_args(argv)
            self.assertEqual(missing_rm.exception.code, 2)
            argv.insert(argv.index('--binapi-control'), '--rm-control')
            self.assertTrue(tool.parse_args(argv).binapi_control)

    def test_device_alloc_capture_cli_is_observer_guarded_and_phase_compatible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / 'probe', root / 'module', root / 'observer'
            probe.write_bytes(b'CPU fixture')
            module.write_bytes(b'CPU fixture module')
            observer.write_bytes(b'CPU observer')
            base = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--phase', 'context']
            with self.assertRaises(SystemExit) as missing:
                tool.parse_args([*base, '--device-alloc-capture',
                                 '--evidence', str(root / 'missing-observer.json')])
            self.assertEqual(missing.exception.code, 2)
            args = tool.parse_args([*base, '--ioctl-observer', str(observer),
                '--device-alloc-capture', '--evidence', str(root / 'device-alloc.json')])
            self.assertTrue(args.device_alloc_capture)
            with self.assertRaises(SystemExit) as combined:
                tool.parse_args([*base, '--ioctl-observer', str(observer),
                    '--device-alloc-capture', '--rm-control', '--binapi-control',
                    '--evidence', str(root / 'combined.json')])
            self.assertEqual(combined.exception.code, 2)

    def test_subdevice_alloc_capture_cli_is_guarded_and_phase_compatible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / 'probe', root / 'module', root / 'observer'
            probe.write_bytes(b'CPU fixture')
            module.write_bytes(b'CPU fixture module')
            observer.write_bytes(b'CPU observer')
            base = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--phase', 'context']
            with self.assertRaises(SystemExit) as missing:
                tool.parse_args([*base, '--subdevice-alloc-capture',
                                 '--evidence', str(root / 'missing-observer.json')])
            self.assertEqual(missing.exception.code, 2)
            args = tool.parse_args([*base, '--ioctl-observer', str(observer),
                '--subdevice-alloc-capture', '--evidence', str(root / 'subdevice-alloc.json')])
            self.assertTrue(args.subdevice_alloc_capture)
            with self.assertRaises(SystemExit) as combined:
                tool.parse_args([*base, '--ioctl-observer', str(observer),
                    '--subdevice-alloc-capture', '--device-alloc-capture',
                    '--evidence', str(root / 'combined.json')])
            self.assertEqual(combined.exception.code, 2)

    def test_binapi_alloc_capture_cli_is_guarded_and_phase_compatible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / 'probe', root / 'module', root / 'observer'
            for path, content in ((probe, b'CPU fixture'), (module, b'CPU module'),
                                  (observer, b'CPU observer')):
                path.write_bytes(content)
            base = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--phase', 'context']
            with self.assertRaises(SystemExit):
                tool.parse_args([*base, '--binapi-alloc-capture', '--evidence',
                                 str(root / 'missing.json')])
            args = tool.parse_args([*base, '--ioctl-observer', str(observer),
                                    '--binapi-alloc-capture', '--evidence',
                                    str(root / 'binapi-alloc.json')])
            self.assertTrue(args.binapi_alloc_capture)
            with self.assertRaises(SystemExit):
                tool.parse_args([*base, '--ioctl-observer', str(observer),
                    '--binapi-alloc-capture', '--subdevice-alloc-capture',
                    '--evidence', str(root / 'combined.json')])

    def test_probed_ids_capture_is_explicitly_forwarded_and_requires_the_record(self):
        data = b"CPU observer fixture"
        self.payload['probed_ids_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        original = self.invoke

        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                self.assertIn('--probed-ids', argv)
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': {
                    'schema': 'nvidia-hybrid-rm-ioctl-observer-v6',
                    'trace_complete': True, 'nested_pointers_read': True,
                    'nested_pointer_scope': 'exact NV0000_CTRL_CMD_GPU_GET_PROBED_IDS payload only; addresses omitted',
                    'errors': [], 'child_exit_code': 77, 'control_path': '/dev/nvidiactl',
                    'records': [{'operation': 'gpu_probed_ids'}]}}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result

        self.invoke = invoke
        report, code = self.run_case()
        self.assertEqual(code, 77, report.get('error'))
        self.assertTrue(report['probed_ids_capture_requested'])
        self.assertTrue(report['probed_ids_records_seen'])

        self.invoke = original
        def missing_record(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                observed = {'schema': 'nvidia-hybrid-rm-ioctl-observer-v6',
                            'trace_complete': True, 'nested_pointers_read': True,
                            'nested_pointer_scope': 'exact NV0000_CTRL_CMD_GPU_GET_PROBED_IDS payload only; addresses omitted',
                            'errors': [], 'child_exit_code': 77, 'control_path': '/dev/nvidiactl',
                            'records': [{'operation': 'rm_control_header'}]}
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': observed}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result
        self.invoke = missing_record
        report, code = self.run_case(work_name='work-no-probed-record')
        self.assertEqual(code, 2)
        self.assertIn('probed-ID capture', report['error'])

    def test_missing_observation_cannot_pass_selected_run(self):
        data = b"CPU observer fixture"
        self.payload['artifacts']['observer'] = {'base64': base64.b64encode(data).decode(),
                                                'sha256': hashlib.sha256(data).hexdigest()}
        report, code = self.run_case()
        self.assertEqual(code, 2)
        self.assertIn('observation', report['error'])

    def test_channel_alloc_capture_is_explicitly_forwarded_redacted_and_required(self):
        data = b"CPU observer fixture"
        self.payload['channel_alloc_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        original = self.invoke

        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                self.assertIn('--channel-alloc', argv)
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': {
                    'schema': 'nvidia-hybrid-rm-ioctl-observer-v9',
                    'trace_complete': True, 'nested_pointers_read': True,
                    'nested_pointer_scope': (
                        'VOLTA_CHANNEL_GPFIFO_A and BLACKWELL_CHANNEL_GPFIFO_A class payloads parsed '
                        'using the byte-identical pinned R580.178.04/R595.99.02 '
                        'NV_CHANNEL_ALLOC_PARAMS layout; raw addresses and handles omitted'),
                    'channel_payload_snapshots_read': 2,
                    'gpu_path': '/dev/nvidia0',
                    'object_class_resolution_scope':
                        'successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed',
                    'errors': [], 'child_exit_code': 77,
                    'control_path': '/dev/nvidiactl',
                    'records': [{'operation': 'channel_alloc', 'fd_role': 'control'}]}}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result

        self.invoke = invoke
        report, code = self.run_case()
        self.assertEqual(code, 77, report.get('error'))
        self.assertTrue(report['channel_alloc_capture_requested'])
        self.assertTrue(report['channel_alloc_records_seen'])

        self.invoke = original
        def missing_channel_invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                observed = {'schema': 'nvidia-hybrid-rm-ioctl-observer-v9',
                            'trace_complete': True, 'nested_pointers_read': False,
                            'nested_pointer_scope': (
                                'VOLTA_CHANNEL_GPFIFO_A and BLACKWELL_CHANNEL_GPFIFO_A class payloads parsed '
                                'using the byte-identical pinned R580.178.04/R595.99.02 '
                                'NV_CHANNEL_ALLOC_PARAMS layout; raw addresses and handles omitted'),
                            'channel_payload_snapshots_read': 0,
                            'gpu_path': '/dev/nvidia0',
                            'object_class_resolution_scope':
                                'successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed',
                            'errors': [], 'child_exit_code': 77,
                            'control_path': '/dev/nvidiactl', 'records': []}
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': observed}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(report), '')
            return result
        self.invoke = missing_channel_invoke
        report, code = self.run_case(work_name='work-missing-channel-record')
        self.assertEqual(code, 2)
        self.assertIn('channel allocation', report['error'])

    def test_rusd_capture_forwards_only_typed_mask_and_accepts_observed_allocation(self):
        data = b"CPU observer fixture"
        self.payload['rusd_alloc_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        original = self.invoke
        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                self.assertIn('--rusd-alloc', argv)
                self.assertNotIn('--gpu-path', argv)
                packet = {'layout': 'NVOS64', 'hClass': 0xde, 'paramsSize': 0,
                          'flags': 0, 'status': 0, 'hRootPresent': True,
                          'hObjectParentPresent': True, 'hObjectNewPresent': True,
                          'pAllocParmsPresent': True, 'pRightsRequestedPresent': False,
                          'rusdPayloadState': 'r580-r595-class-layout-parsed',
                          'rusd': {'classPayloadBytes': 8, 'polledDataMask': 5}}
                row = {'tid': 77, 'fd': 6, 'fd_role': 'control',
                       'request': 0xc030462b, 'packet_size': 48,
                       'operation': 'rusd_alloc', 'entry': packet, 'exit': dict(packet),
                       'syscall_return': 0}
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': {
                    'schema': 'nvidia-hybrid-rm-ioctl-observer-v14',
                    'trace_complete': True, 'nested_pointers_read': True,
                    'nested_pointer_scope': (
                        'RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS only, parsed as the pinned '
                        '8-byte polledDataMask; raw addresses and handles omitted'),
                    'rusd_payload_snapshots_read': 2, 'gpu_path': '/dev/nvidia0',
                    'errors': [], 'child_exit_code': 77, 'control_path': '/dev/nvidiactl',
                    'records': [row]}}
                return subprocess.CompletedProcess(argv, result.returncode,
                                                    json.dumps(report), '')
            return result
        self.invoke = invoke
        report, code = self.run_case()
        self.assertEqual(code, 77, report.get('error'))
        self.assertTrue(report['rusd_alloc_capture_requested'])
        self.assertTrue(report['rusd_alloc_records_seen'])
        self.assertEqual(report['rusd_polled_data_masks'], [5])

    def test_rusd_capture_accepts_complete_zero_class_trace_and_rejects_bad_snapshot_count(self):
        data = b"CPU observer fixture"
        self.payload['rusd_alloc_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        original = self.invoke
        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                self.assertIn('--rusd-alloc', argv)
                report = json.loads(result.stdout)
                report['ioctl_observation'] = {'report': {
                    'schema': 'nvidia-hybrid-rm-ioctl-observer-v14',
                    'trace_complete': True, 'nested_pointers_read': True,
                    'nested_pointer_scope': (
                        'RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS only, parsed as the pinned '
                        '8-byte polledDataMask; raw addresses and handles omitted'),
                    'rusd_payload_snapshots_read': 0, 'gpu_path': '/dev/nvidia0',
                    'errors': [], 'child_exit_code': 77, 'control_path': '/dev/nvidiactl',
                    'records': []}}
                return subprocess.CompletedProcess(argv, result.returncode,
                                                    json.dumps(report), '')
            return result
        self.invoke = invoke
        report, code = self.run_case()
        self.assertEqual(code, 77, report.get('error'))
        self.assertFalse(report['rusd_alloc_records_seen'])
        self.assertEqual(report['rusd_polled_data_masks'], [])

        def bad_count(argv, **kwargs):
            result = invoke(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                outer = json.loads(result.stdout)
                outer['ioctl_observation']['report']['rusd_payload_snapshots_read'] = 1
                return subprocess.CompletedProcess(argv, result.returncode,
                                                    json.dumps(outer), '')
            return result
        self.invoke = bad_count
        report, code = self.run_case(work_name='work-rusd-bad-count')
        self.assertEqual(code, 2)
        self.assertIn('snapshot', report['error'])

    def test_map_memory_capture_requires_successful_redacted_map_and_unmap_status(self):
        data = b"CPU observer fixture"
        self.payload['map_memory_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        original = self.invoke

        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                self.assertIn('--map-memory', argv)
                report = json.loads(result.stdout)
                observed = {
                    'schema': 'nvidia-hybrid-rm-ioctl-observer-v15',
                    'trace_complete': True, 'nested_pointers_read': False,
                    'payload_scope': ('exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device '
                                      'open/dup/close/mmap metadata, and transient RM_ALLOC/RM_FREE class resolution; '
                                      'no allocation payloads emitted; addresses, paths, and handles omitted'),
                    'object_class_resolution_scope': ('successful prior RM_ALLOC and RM_FREE packets observed on the '
                                      'explicitly selected control and GPU paths; keyed by root and handle; unresolved '
                                      'means no unique live object was observed'),
                    'fd_lifecycle_scope': ('opaque file IDs assigned at observed open/openat/openat2 and dup/dup2/dup3/'
                                           'fcntl(F_DUPFD*) calls; close() removes an ID; close_range invalidates affected IDs; '
                                           'exec invalidates inherited IDs; io_uring and external fd injection are not tracked; '
                                           'VMA file references remain kernel-owned'),
                    'fd_identity_capture_complete': True,
                    'gpu_path': '/dev/nvidia0', 'errors': [], 'child_exit_code': 77,
                    'control_path': '/dev/nvidiactl',
                    'records': [
                        {'operation': 'fd_open', 'request': 257, 'packet_size': 0,
                         'tid': 77, 'fd': 6, 'fd_role': 'control', 'fd_file_id': 1,
                         'entry': None, 'exit': None, 'syscall_return': 6},
                        {'operation': 'fd_open', 'request': 257, 'packet_size': 0,
                         'tid': 77, 'fd': 7, 'fd_role': 'gpu', 'fd_file_id': 2,
                         'entry': None, 'exit': None, 'syscall_return': 7},
                        {'operation': 'map_memory', 'fd_role': 'control',
                         'fd': 6, 'fd_file_id': 1, 'syscall_return': 0,
                         'entry': {'backendFd': 7, 'backendFdRole': 'gpu',
                                   'backendFileId': 2, 'length': 4096,
                                   'memoryObjectClass': {'resolution': 'resolved',
                                                         'classId': 0xc661}},
                         'exit': {'status': 0, 'backendFd': 7, 'backendFdRole': 'gpu',
                                  'backendFileId': 2, 'length': 4096, 'linearAddressPresent': True,
                                  'memoryObjectClass': {'resolution': 'resolved',
                                                        'classId': 0xc661}}},
                        {'operation': 'mmap', 'request': 9, 'packet_size': 0,
                         'fd': 7, 'fd_file_id': 2, 'fd_role': 'gpu',
                         'entry': {'length': 4096, 'prot': 1, 'flags': 1, 'offsetZero': True},
                         'exit': None, 'syscall_return': None, 'mmap_succeeded': True},
                        {'operation': 'unmap_memory', 'fd': 6, 'fd_file_id': 1,
                         'fd_role': 'control',
                         'syscall_return': 0, 'exit': {'status': 0}},
                        {'operation': 'close', 'request': 3, 'packet_size': 0,
                         'fd': 7, 'fd_file_id': 2, 'fd_role': 'gpu', 'entry': None, 'exit': None,
                         'syscall_return': 0, 'close_succeeded': True},
                    ]}
                report['ioctl_observation'] = {'report': observed}
                return subprocess.CompletedProcess(argv, result.returncode,
                                                    json.dumps(report), '')
            return result

        self.invoke = invoke
        report, code = self.run_case()
        self.assertEqual(code, 77, report.get('error'))
        self.assertTrue(report['map_memory_capture_requested'])
        self.assertTrue(report['map_memory_records_seen'])
        self.assertEqual(report['map_memory_success_count'], 1)
        self.assertEqual(report['unmap_memory_success_count'], 1)
        self.assertEqual(report['map_memory_mmap_success_count'], 1)
        self.assertEqual(report['map_memory_gpu_fd_close_count'], 1)
        self.assertEqual(report['map_memory_class_resolution_counts'], {'resolved': 1})
        self.assertEqual(report['map_memory_class_ids'], [0xc661])

        def failed_rm_status(argv, **kwargs):
            result = invoke(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                outer = json.loads(result.stdout)
                observed = outer['ioctl_observation']['report']
                mapped = next(row for row in observed['records']
                              if row.get('operation') == 'map_memory')
                mapped['exit']['status'] = 0x1
                return subprocess.CompletedProcess(argv, result.returncode,
                                                    json.dumps(outer), '')
            return result

        self.invoke = failed_rm_status
        report, code = self.run_case(work_name='work-rm-map-failure')
        self.assertEqual(code, 2)
        self.assertIn('successful control-to-GPU mapping pair', report['error'])

        def malformed_class(argv, **kwargs):
            result = invoke(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                outer = json.loads(result.stdout)
                observed = outer['ioctl_observation']['report']
                mapped = next(row for row in observed['records']
                              if row.get('operation') == 'map_memory')
                mapped['entry']['memoryObjectClass'] = {
                    'resolution': 'resolved', 'classId': None}
                return subprocess.CompletedProcess(argv, result.returncode,
                                                    json.dumps(outer), '')
            return result
        self.invoke = malformed_class
        report, code = self.run_case(work_name='work-rm-map-bad-class')
        self.assertEqual(code, 2)
        self.assertIn('memory-object class', report['error'])

    def test_combined_rusd_map_capture_reports_the_resolved_class(self):
        data = b"CPU observer fixture"
        self.payload['map_memory_capture'] = True
        self.payload['rusd_alloc_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        original = self.invoke

        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if '--list' not in argv and argv[0] != 'nvidia-smi':
                self.assertIn('--map-memory', argv)
                self.assertIn('--rusd-alloc', argv)
                outer = json.loads(result.stdout)
                rusd_packet = {'layout': 'NVOS64', 'hClass': 0xde, 'paramsSize': 0,
                    'flags': 0, 'status': 0, 'hRootPresent': True,
                    'hObjectParentPresent': True, 'hObjectNewPresent': True,
                    'pAllocParmsPresent': True, 'pRightsRequestedPresent': False,
                    'rusdPayloadState': 'r580-r595-class-layout-parsed',
                    'rusd': {'classPayloadBytes': 8, 'polledDataMask': 0}}
                class_ref = {'resolution': 'resolved', 'classId': 0xde}
                records = [
                    {'tid': 77, 'fd': 6, 'fd_role': 'control', 'request': 257,
                     'packet_size': 0, 'operation': 'fd_open', 'fd_file_id': 1,
                     'entry': None, 'exit': None, 'syscall_return': 6},
                    {'tid': 77, 'fd': 7, 'fd_role': 'gpu', 'request': 257,
                     'packet_size': 0, 'operation': 'fd_open', 'fd_file_id': 2,
                     'entry': None, 'exit': None, 'syscall_return': 7},
                    {'tid': 77, 'fd': 6, 'fd_role': 'control', 'request': 0xc030462b,
                     'packet_size': 48, 'operation': 'rusd_alloc', 'fd_file_id': 1,
                     'entry': rusd_packet, 'exit': dict(rusd_packet), 'syscall_return': 0},
                    {'tid': 77, 'fd': 6, 'fd_file_id': 1, 'fd_role': 'control',
                     'request': 0xc038464e, 'packet_size': 56, 'operation': 'map_memory',
                     'entry': {'backendFd': 7, 'backendFdRole': 'gpu', 'backendFileId': 2,
                               'flags': 0, 'hClientPresent': True, 'hDevicePresent': True,
                               'hMemoryPresent': True, 'length': 4096,
                               'linearAddressPresent': True, 'memoryObjectClass': class_ref,
                               'offsetNonzero': False, 'status': 0},
                     'exit': {'backendFd': 7, 'backendFdRole': 'gpu', 'backendFileId': 2,
                              'flags': 0, 'hClientPresent': True, 'hDevicePresent': True,
                              'hMemoryPresent': True, 'length': 4096,
                              'linearAddressPresent': True, 'memoryObjectClass': class_ref,
                              'offsetNonzero': False, 'status': 0}, 'syscall_return': 0},
                    {'tid': 77, 'fd': 7, 'fd_file_id': 2, 'fd_role': 'gpu',
                     'request': 9, 'packet_size': 0, 'operation': 'mmap',
                     'entry': {'length': 4096, 'prot': 1, 'flags': 1, 'offsetZero': True},
                     'exit': None, 'syscall_return': None, 'mmap_succeeded': True},
                    {'tid': 77, 'fd': 6, 'fd_file_id': 1, 'fd_role': 'control',
                     'request': 0xc020464f, 'packet_size': 32, 'operation': 'unmap_memory',
                     'entry': {'status': 0, 'flags': 0, 'hClientPresent': True,
                               'hDevicePresent': True, 'hMemoryPresent': True,
                               'linearAddressPresent': True},
                     'exit': {'status': 0, 'flags': 0, 'hClientPresent': True,
                              'hDevicePresent': True, 'hMemoryPresent': True,
                              'linearAddressPresent': True}, 'syscall_return': 0},
                    {'tid': 77, 'fd': 7, 'fd_file_id': 2, 'fd_role': 'gpu',
                     'request': 3, 'packet_size': 0, 'operation': 'close',
                     'entry': None, 'exit': None, 'syscall_return': 0,
                     'close_succeeded': True},
                ]
                outer['ioctl_observation'] = {'report': {
                    'schema': 'nvidia-hybrid-rm-ioctl-observer-v22',
                    'trace_complete': True, 'nested_pointers_read': True,
                    'nested_pointer_scope': (
                        'RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS fixed 8-byte polledDataMask only, '
                        'plus exact pinned R580 NVOS33/NVOS34 map packets and selected-file lifecycle '
                        'metadata; other allocation payloads and raw addresses/handles omitted'),
                    'rusd_payload_snapshots_read': 2,
                    'payload_scope': (
                        'exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device '
                        'open/dup/close/mmap metadata, transient RM_ALLOC/RM_FREE class resolution, and '
                        'fixed RM_USER_SHARED_DATA 8-byte polling-mask snapshots only; addresses, paths, '
                        'and handles omitted'),
                    'object_class_resolution_scope': (
                        'successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected '
                        'control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed'),
                    'fd_lifecycle_scope': (
                        'opaque file IDs assigned at observed open/openat/openat2 and dup/dup2/dup3/'
                        'fcntl(F_DUPFD*) calls; close() removes an ID; close_range invalidates affected IDs; '
                        'exec invalidates inherited IDs; io_uring and external fd injection are not tracked; '
                        'VMA file references remain kernel-owned'),
                    'fd_identity_capture_complete': True, 'gpu_path': '/dev/nvidia0',
                    'errors': [], 'child_exit_code': 77, 'control_path': '/dev/nvidiactl',
                    'records': records}}
                return subprocess.CompletedProcess(argv, result.returncode, json.dumps(outer), '')
            return result

        self.invoke = invoke
        report, code = self.run_case(work_name='work-rusd-map')
        self.assertEqual(code, 77, report.get('error'))
        self.assertTrue(report['map_memory_capture_requested'])
        self.assertTrue(report['rusd_alloc_capture_requested'])
        self.assertTrue(report['rusd_alloc_records_seen'])
        self.assertEqual(report['rusd_polled_data_masks'], [0])
        self.assertEqual(report['map_memory_class_ids'], [0xde])
        self.assertEqual(report['map_memory_success_count'], 1)
        self.assertEqual(report['map_memory_mmap_success_count'], 1)

    def test_metadata_mismatch_prevents_nvml_and_cuda(self):
        self.payload['uuid'] = 'GPU-other'
        report, code = self.run_case()
        self.assertEqual(code, 2)
        self.assertEqual(self.commands, [])
        self.assertIn('UUID/model/driver', report['error'])

    def test_preflight_wrong_pci_prevents_kernel_runner(self):
        self.preflight_device['pci_bus_id'] = '0000:03:00.0'
        report, code = self.run_case()
        self.assertEqual(code, 2)
        self.assertEqual(len(self.commands), 2)
        self.assertIsNone(report['hardware_acceptance'])

    def test_preflight_second_gpu_prevents_kernel_runner(self):
        self.preflight_devices = [dict(DEVICE), dict(DEVICE, sm=70, name='V100')]
        report, code = self.run_case()
        self.assertEqual(code, 2)
        self.assertEqual(len(self.commands), 2)

    def test_artifact_mutation_cannot_pass(self):
        self.mutate = True
        report, code = self.run_case()
        self.assertEqual(code, 2)
        self.assertEqual(report['error'], 'artifacts changed during execution')

    def test_unexpected_success_cannot_be_hybrid_validation(self):
        self.acceptance_code = 0
        report, code = self.run_case()
        self.assertEqual(code, 2)
        self.assertIn('truthful incomplete', report['error'])

    def test_uploaded_hash_mismatch_prevents_driver_calls(self):
        self.payload['artifacts']['probe']['sha256'] = '0' * 64
        report, code = self.run_case()
        self.assertEqual(code, 2)
        self.assertEqual(self.commands, [])

    def test_strace_capture_is_guarded_summarized_and_transported_compressed(self):
        from tools import summarize_rm_ioctl_trace
        data = b"CPU trace helper fixture"
        self.payload['ioctl_trace'] = True
        self.payload['artifacts']['trace-helper'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        raw = b'7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0x123) = 0\n'
        summary = summarize_rm_ioctl_trace.summarize(raw)
        original = self.invoke
        def invoke(argv, **kwargs):
            result = original(argv, **kwargs)
            if argv[0] == sys.executable and argv[1].endswith('/runner'):
                self.assertIn('--ioctl-trace', argv)
                helper = Path(argv[argv.index('--trace-helper') + 1])
                self.assertEqual(helper.read_bytes(), data)
                trace_path = Path(argv[argv.index('--ioctl-trace-output') + 1])
                trace_path.write_bytes(raw)
                result_report = json.loads(result.stdout)
                result_report['ioctl_trace'] = {'trace': {
                    'path': str(trace_path), 'trace_complete': True, 'size_limit_exceeded': False,
                    'summary': summary}}
                return subprocess.CompletedProcess(argv, result.returncode,
                                                    json.dumps(result_report), '')
            return result
        self.invoke = invoke
        report, code = self.run_case()
        self.assertEqual(code, 77, report.get('error'))
        self.assertTrue(report['hardware_acceptance']['ioctl_trace']['trace']['trace_complete'])
        compressed = base64.b64decode(report['ioctl_trace_transport']['gzip_base64'], validate=True)
        self.assertEqual(gzip.decompress(compressed), raw)
        self.assertEqual(report['artifacts_before'], report['artifacts_after'])


class LocalArguments(unittest.TestCase):
    def test_new_evidence_destination_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'already.json'
            path.write_text('{}')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', '/tmp/probe', '--module', '/tmp/module', '--evidence', str(path)]
            with self.assertRaises(SystemExit) as error:
                tool.parse_args(argv)
            self.assertEqual(error.exception.code, 2)

    def test_gpu_id_info_requires_observer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module = root / 'probe', root / 'module'
            probe.write_bytes(b'CPU fixture')
            module.write_bytes(b'CPU fixture module')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--gpu-id-info', '--evidence', str(root / 'new.json')]
            with self.assertRaises(SystemExit) as error:
                tool.parse_args(argv)
            self.assertEqual(error.exception.code, 2)

    def test_cuda_graphs_cannot_be_combined_with_phase_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / 'probe', root / 'module', root / 'observer'
            for path, data in ((probe, b'CPU probe'), (module, b'CPU module'),
                               (observer, b'CPU observer')):
                path.write_bytes(data)
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--ioctl-observer', str(observer), '--phase', 'kernel',
                    '--device-alloc-capture', '--cuda-graphs',
                    '--evidence', str(root / 'new.json')]
            with self.assertRaises(SystemExit) as error:
                tool.parse_args(argv)
            self.assertEqual(error.exception.code, 2)

    def test_attached_ids_requires_observer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module = root / 'probe', root / 'module'
            probe.write_bytes(b'CPU fixture')
            module.write_bytes(b'CPU fixture module')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--attached-ids', '--evidence', str(root / 'new.json')]
            with self.assertRaises(SystemExit) as error:
                tool.parse_args(argv)
            self.assertEqual(error.exception.code, 2)

    def test_probed_ids_requires_observer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module = root / 'probe', root / 'module'
            probe.write_bytes(b'CPU fixture')
            module.write_bytes(b'CPU fixture module')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--probed-ids', '--evidence', str(root / 'new.json')]
            with self.assertRaises(SystemExit) as error:
                tool.parse_args(argv)
            self.assertEqual(error.exception.code, 2)

    def test_rusd_alloc_requires_observer_and_isolated_default_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / 'probe', root / 'module', root / 'observer'
            for path, data in ((probe, b'CPU probe'), (module, b'CPU module'),
                               (observer, b'CPU observer')):
                path.write_bytes(data)
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--rusd-alloc', '--evidence', str(root / 'missing.json')]
            with self.assertRaises(SystemExit) as error:
                tool.parse_args(argv)
            self.assertEqual(error.exception.code, 2)
            argv[argv.index('--evidence'):argv.index('--evidence')] = [
                '--ioctl-observer', str(observer)]
            args = tool.parse_args(argv)
            self.assertTrue(args.rusd_alloc)
            combined = argv[:-2] + ['--map-memory', '--evidence',
                                     str(root / 'combined.json')]
            combined_args = tool.parse_args(combined)
            self.assertTrue(combined_args.rusd_alloc)
            self.assertTrue(combined_args.map_memory)
            for conflict in ('--gpu-id-info', '--channel-alloc',
                             '--managed-memory', '--ioctl-trace'):
                with self.subTest(conflict=conflict):
                    with self.assertRaises(SystemExit) as rejected:
                        tool.parse_args(argv[:-2] + [conflict, '--evidence',
                                                     str(root / (conflict[2:] + '.json'))])
                    self.assertEqual(rejected.exception.code, 2)

    def test_rm_control_requires_observer_and_is_forwarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / 'probe', root / 'module', root / 'observer'
            probe.write_bytes(b'CPU fixture')
            module.write_bytes(b'CPU fixture module')
            observer.write_bytes(b'CPU observer')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--rm-control', '--evidence', str(root / 'missing-observer.json')]
            with self.assertRaises(SystemExit) as error:
                tool.parse_args(argv)
            self.assertEqual(error.exception.code, 2)
            argv[argv.index('--evidence'):argv.index('--evidence')] = ['--ioctl-observer', str(observer)]
            args = tool.parse_args(argv)
            self.assertTrue(args.rm_control)

    def test_transport_arguments_and_evidence_are_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'new.json'
            probe.write_bytes(b'CPU fixture')
            probe.chmod(0o700)
            module.write_bytes(b'CPU fixture module')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module), '--managed-memory',
                    '--managed-prefetch', '--evidence', str(evidence)]
            def fake_ssh(command, **kwargs):
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(command, 0,
                                                       json.dumps(PROBE_CONTRACT), '')
                self.assertTrue(evidence.exists())
                self.assertIn('StrictHostKeyChecking=yes', command)
                self.assertIn('BatchMode=yes', command)
                self.assertIn('HostKeyAlias=pc3', command)
                self.assertEqual(command[-2], 'pc3@pc3')
                self.assertEqual(command[-3], '--')
                payload = json.loads(kwargs['input'])
                self.assertEqual(payload['uuid'], UUID)
                self.assertIs(payload['managed_memory'], True)
                self.assertIs(payload['managed_prefetch'], True)
                self.assertEqual(set(payload['artifacts']), {'probe', 'module', 'runner'})
                result = {'remote_script_sha256': payload['remote_script_sha256'], 'exit_code': 77}
                return subprocess.CompletedProcess(command, 77, json.dumps(result), '')
            with patch.object(tool.subprocess, 'run', side_effect=fake_ssh):
                self.assertEqual(tool.main(argv), 77)
            report = json.loads(evidence.read_text())
            self.assertEqual(report['local_artifacts'], report['local_artifacts_after'])
            self.assertEqual(report['ssh_exit_code'], 77)

    def test_stale_probe_contract_is_rejected_before_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
            probe.write_bytes(b'old CUDA probe')
            probe.chmod(0o700)
            module.write_bytes(b'fatbin')
            calls = []
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3',
                    '--gpu-uuid', UUID, '--pci', PCI, '--probe', str(probe),
                    '--module', str(module), '--evidence', str(evidence)]

            def fake_run(command, **kwargs):
                calls.append(command)
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(
                        command, 2, '', 'unknown or incomplete argument: --contract')
                payload = json.loads(kwargs['input'])
                remote = {'remote_script_sha256': payload['remote_script_sha256'],
                          'exit_code': 0}
                return subprocess.CompletedProcess(command, 0, json.dumps(remote), '')

            with patch.object(tool.subprocess, 'run', side_effect=fake_run):
                result = tool.main(argv)

            self.assertEqual(result, 2)
            self.assertEqual(calls, [[str(probe.resolve()), '--contract']])
            report = json.loads(evidence.read_text())
            self.assertIn('probe report contract', report['error'].lower())
            self.assertNotIn('remote', report)

    def test_trace_transport_is_hash_checked_and_saved_as_a_private_sidecar(self):
        import gzip
        import hashlib
        from tools import summarize_rm_ioctl_trace as trace_summary
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
            for path, data in ((probe, b'CPU fixture'), (module, b'CPU fixture module')):
                path.write_bytes(data)
            probe.chmod(0o700)
            raw = b'7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0x123) = 0\n'
            compressed = gzip.compress(raw, mtime=0)
            trace = trace_summary.summarize(raw)
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--evidence', str(evidence), '--ioctl-trace']
            def fake_ssh(command, **kwargs):
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(command, 0,
                                                       json.dumps(PROBE_CONTRACT), '')
                payload = json.loads(kwargs['input'])
                self.assertTrue(payload['ioctl_trace'])
                self.assertIn('trace-helper', payload['artifacts'])
                transport = {'gzip_base64': base64.b64encode(compressed).decode(),
                             'gzip_bytes': len(compressed),
                             'gzip_sha256': hashlib.sha256(compressed).hexdigest(),
                             'raw_bytes': len(raw), 'raw_sha256': hashlib.sha256(raw).hexdigest()}
                remote = {'remote_script_sha256': payload['remote_script_sha256'], 'exit_code': 77,
                          'hardware_acceptance': {'ioctl_trace': {'trace': {
                              'trace_complete': True, 'summary': trace}}},
                          'ioctl_trace_transport': transport}
                return subprocess.CompletedProcess(command, 77, json.dumps(remote), '')
            with patch.object(tool.subprocess, 'run', side_effect=fake_ssh):
                self.assertEqual(tool.main(argv), 77)
            sidecar = evidence.with_suffix('.json.strace.gz')
            self.assertEqual(sidecar.read_bytes(), compressed)
            self.assertEqual(sidecar.stat().st_mode & 0o777, 0o600)
            report = json.loads(evidence.read_text())
            self.assertEqual(report['remote']['ioctl_trace_artifact']['raw_sha256'],
                             hashlib.sha256(raw).hexdigest())
            self.assertNotIn('ioctl_trace_transport', report['remote'])
            self.assertEqual(report['ssh_stdout'], '')

    def test_trace_mode_is_mutually_exclusive_with_packet_observer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = []
            for name in ('probe', 'module', 'observer'):
                path = root / name
                path.write_bytes(b'fixture')
                files.append(path)
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(files[0]), '--module', str(files[1]),
                    '--ioctl-observer', str(files[2]), '--ioctl-trace',
                    '--evidence', str(root / 'report.json')]
            with self.assertRaises(SystemExit) as error:
                tool.parse_args(argv)
            self.assertEqual(error.exception.code, 2)

    def test_pci_normalization_and_environment(self):
        self.assertEqual(tool.canonical_pci('00000000:02:00.0'), PCI)
        with self.assertRaises(ValueError):
            tool.canonical_pci('0000:02:ff.0')
        env = tool.clean_environment({'LD_PRELOAD': 'x', 'CUDA_INJECTION64_PATH': 'x', 'HOME': '/fixture'}, UUID)
        self.assertEqual(env['CUDA_VISIBLE_DEVICES'], UUID)
        self.assertNotIn('LD_PRELOAD', env)
        self.assertNotIn('CUDA_INJECTION64_PATH', env)

if __name__ == '__main__':
    unittest.main()
