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
import shlex
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
acceptance_spec = importlib.util.spec_from_file_location(
    'hybrid_acceptance', ROOT / 'tests/run_hybrid_acceptance.py')
acceptance = importlib.util.module_from_spec(acceptance_spec)
acceptance_spec.loader.exec_module(acceptance)
UUID = 'GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77'
PCI = '0000:02:00.0'
DEVICE = {'pci_bus_id': PCI, 'sm': 120, 'name': 'NVIDIA GeForce RTX 5080'}
PROBE_CONTRACT = {
    'schema': 'nvidia-hybrid-probe-contract-v1',
    'contract_version': 6,
    'probe_report_schema': 'nvidia-hybrid-probe-v2',
    'probe_report_fields': ['expected_device_pci_by_sm', 'memory_mode', 'managed_prefetch_requested',
                            'managed_prefetch_api', 'devices', 'cuda_graphs_requested',
                            'cuda_graph_api', 'performance_benchmark_requested'],
    'device_report_fields': ['concurrent_managed_access', 'pageable_memory_access',
                             'pageable_memory_access_uses_host_page_tables',
                             'managed_memory_passed', 'managed_prefetch_passed',
                             'cuda_graphs_passed', 'cuda_graph_launches',
                             'performance_benchmark_passed', 'performance_benchmark'],
}


def system_pageable_report():
    return {
        'schema': 'nvidia-cuda-system-pageable-memory-v1', 'status': 'validated',
        'phase': 'system-pageable-memory', 'expected_pci': '00000000:02:00.0',
        'driver_library_path': '/usr/lib/x86_64-linux-gnu/libcuda.so.1',
        'driver_api': 13020,
        'selected_device': {**DEVICE, 'compute_capability': '12.0',
            'concurrent_managed_access': True, 'pageable_memory_access': True,
            'pageable_memory_access_uses_host_page_tables': False,
            'unified_addressing': True},
        'allocators': {
            'malloc': {'tested': True, 'passed': True,
                       'execution_mode': 'context-synchronized',
                       'sizes': [1, 31, 256, 4096, 65537]},
            'mmap': {'tested': True, 'passed': True,
                     'execution_mode': 'stream-synchronized',
                     'sizes': [1, 31, 256, 4096, 65537]},
        },
        'cleanup_passed': True, 'cleanup_errors': [], 'error': '',
    }


def managed_accessed_by_report():
    return {
        'schema': 'nvidia-cuda-driver-phase-v1', 'status': 'phase-passed',
        'phase': 'managed-accessed-by', 'expected_pci': '00000000:02:00.0',
        'driver_library_path': '/usr/lib/x86_64-linux-gnu/libcuda.so.1',
        'driver_api': 13020,
        'selected_device': {**DEVICE, 'compute_capability': '12.0',
            'concurrent_managed_access': True, 'pageable_memory_access': True,
            'pageable_memory_access_uses_host_page_tables': False},
        'completed_operations': ['cuInit', 'cuDriverGetVersion', 'cuDeviceGetCount',
            'cuDeviceGet', 'cuDeviceGetName', 'cuDeviceGetPCIBusId',
            'cuDeviceGetAttribute.major', 'cuDeviceGetAttribute.minor',
            'cuDeviceGetAttribute.concurrent_managed_access',
            'cuDeviceGetAttribute.pageable_memory_access',
            'cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables',
            'cuCtxCreate_v2', 'cuCtxSetCurrent', 'cuCtxGetDevice', 'cuMemAllocManaged',
            'cuMemAdvise(SET_ACCESSED_BY)', 'cuMemAdvise(UNSET_ACCESSED_BY)'],
        'numeric_result_passed': False, 'result_value': None, 'expected_result': None,
        'cleanup_passed': True, 'cleanup_errors': [], 'error': '',
    }


class RemoteScriptBootstrapTests(unittest.TestCase):
    def test_remote_script_command_is_bounded_and_executes_the_pinned_source(self):
        command = tool.remote_script_command()
        argv = shlex.split(command)
        self.assertEqual(argv[:2], ['python3', '-c'])
        self.assertLess(len(argv[2].encode('utf-8')), 65536)
        namespace = {'__name__': 'remote_contract'}
        exec(argv[2], namespace)
        self.assertTrue(callable(namespace.get('run')))

    def test_remote_script_command_detects_compressed_source_corruption(self):
        source = 'value = 7\n'
        command = tool.remote_script_command(source)
        bootstrap = shlex.split(command)[2]
        expected = hashlib.sha256(source.encode('utf-8')).hexdigest()
        changed = ('0' if expected[0] != '0' else '1') + expected[1:]
        corrupted = bootstrap.replace(expected, changed)
        namespace = {'__name__': 'remote_contract'}
        with self.assertRaises(AssertionError):
            exec(corrupted, namespace)

    def test_acceptance_runner_and_contract_module_match_independent_pins(self):
        for name, relative, expected in tool.PINNED_ACCEPTANCE_ARTIFACTS:
            with self.subTest(name=name):
                artifact = tool.pinned_acceptance_artifact(name, tool.ROOT / relative)
                self.assertEqual(artifact['sha256'], expected)

    def test_unpinned_acceptance_runner_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = Path(tmp) / 'run_hybrid_acceptance.py'
            runner.write_text("print('{\\\"qualification\\\":\\\"phase-report-contract-pass\\\"}')\\n")
            with self.assertRaisesRegex(ValueError, 'runner hash differs from its independent acceptance pin'):
                tool.pinned_acceptance_artifact('runner', runner)

    def test_cli_rejects_a_replaced_acceptance_runner_before_transport(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'tests').mkdir()
            (root / 'tools').mkdir()
            (root / 'tests/run_hybrid_acceptance.py').write_text('raise SystemExit(0)\n')
            (root / 'tools/cuda_probe_contract.py').write_text('')
            argv = [
                '--target', 'pc3@pc3', '--host-key-alias', 'pc3',
                '--gpu-uuid', UUID, '--pci', PCI,
                '--probe', str(root / 'probe'), '--module', str(root / 'module'),
                '--evidence', str(root / 'report.json'),
            ]
            with patch.object(tool, 'ROOT', root), self.assertRaises(SystemExit) as rejected:
                tool.parse_args(argv)
            self.assertEqual(rejected.exception.code, 2)

    def test_probe_build_trust_must_match_uploaded_probe_and_fatbin(self):
        artifacts = {
            'probe': {'sha256': tool.PINNED_PROBE_SHA256},
            'module': {'sha256': tool.PINNED_MODULE_SHA256},
        }
        identity = {
            'status': 'trusted-pinned-build',
            'probe_sha256': artifacts['probe']['sha256'],
            'module_sha256': artifacts['module']['sha256'],
            'provenance': 'pinned-probe-and-fatbin-sha256',
        }
        acceptance_report = {
            'probe_build_trust': {
                'status': 'trusted-pinned-build',
                'before_run': identity,
                'after_run': dict(identity),
            },
        }
        tool.validate_probe_build_trust(acceptance_report, artifacts)
        acceptance_report['probe_build_trust']['after_run']['module_sha256'] = 'c' * 64
        with self.assertRaisesRegex(ValueError, 'changed during execution'):
            tool.validate_probe_build_trust(acceptance_report, artifacts)

    def test_probe_build_trust_rejects_unverifiable_manifest_provenance(self):
        artifacts = {
            'probe': {'sha256': tool.PINNED_PROBE_SHA256},
            'module': {'sha256': tool.PINNED_MODULE_SHA256},
        }
        identity = {
            'status': 'trusted-pinned-build',
            'probe_sha256': tool.PINNED_PROBE_SHA256,
            'module_sha256': tool.PINNED_MODULE_SHA256,
            'provenance': 'source-verified-manifest-and-pinned-artifacts',
        }
        acceptance_report = {'probe_build_trust': {
            'status': 'trusted-pinned-build', 'before_run': identity,
            'after_run': dict(identity)}}
        with self.assertRaisesRegex(ValueError, 'provenance is unsupported'):
            tool.validate_probe_build_trust(acceptance_report, artifacts)

    def test_probe_build_trust_rejects_unpinned_uploaded_artifacts(self):
        artifacts = {
            'probe': {'sha256': 'a' * 64},
            'module': {'sha256': 'b' * 64},
        }
        identity = {
            'status': 'trusted-pinned-build',
            'probe_sha256': '0' * 64,
            'module_sha256': artifacts['module']['sha256'],
            'provenance': 'pinned-probe-and-fatbin-sha256',
        }
        acceptance_report = {
            'probe_build_trust': {
                'status': 'trusted-pinned-build',
                'before_run': identity,
                'after_run': dict(identity),
            },
        }
        with self.assertRaisesRegex(ValueError, 'uploaded probe hash'):
            tool.validate_probe_build_trust(acceptance_report, artifacts)
        with self.assertRaisesRegex(ValueError, 'trusted pinned probe build'):
            tool.validate_probe_build_trust({}, artifacts)


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
        self.expected_libcuda_path = None
        self.expected_libcuda_loader_output = None
        self.mutate_libcuda = False
        for name in ('probe', 'module', 'runner'):
            data = ('fixture-' + name).encode()
            self.payload['artifacts'][name] = {'base64': base64.b64encode(data).decode(),
                                            'sha256': hashlib.sha256(data).hexdigest()}
        self.commands = []
        probe_sha = self.payload['artifacts']['probe']['sha256']
        module_sha = self.payload['artifacts']['module']['sha256']
        remote_source = (tool.REMOTE_SCRIPT
                         .replace(tool.PINNED_PROBE_SHA256, probe_sha)
                         .replace(tool.PINNED_MODULE_SHA256, module_sha))
        namespace = {'__name__': 'remote_contract'}
        exec(remote_source, namespace)
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
        self.phase_result_in_stdout = False
        self.phase_observation = None
        self.managed_trace_raw = (
            b'123 ioctl(4</dev/nvidia-uvm<char 511:0>>, 0x2e, 0x7fff0000) = 0\n'
            b'123 ioctl(4</dev/nvidia-uvm<char 511:0>>, 0x2f, 0x7fff0000) = 0\n')

    def probe_build_trust(self):
        identity = {
            'status': 'trusted-pinned-build',
            'probe_sha256': self.payload['artifacts']['probe']['sha256'],
            'module_sha256': self.payload['artifacts']['module']['sha256'],
            'provenance': 'pinned-probe-and-fatbin-sha256',
        }
        return {'status': 'trusted-pinned-build', 'before_run': identity,
                'after_run': dict(identity)}

    def tearDown(self):
        self.tmp.cleanup()

    def test_transport_pins_match_acceptance_runner_and_software_suite(self):
        runner = (tool.ROOT / 'tests/run_hybrid_acceptance.py').read_text()
        suite = (tool.ROOT / 'tools/run_software_test_suite.py').read_text()
        self.assertIn(f'PINNED_PROBE_SHA256 = "{tool.PINNED_PROBE_SHA256}"', runner)
        self.assertIn(f'PINNED_MODULE_SHA256 = "{tool.PINNED_MODULE_SHA256}"', runner)
        self.assertIn(f'PINNED_PROBE_SHA256 = "{tool.PINNED_PROBE_SHA256}"', suite)
        self.assertIn(f'PINNED_PROBE_FATBIN_SHA256 = "{tool.PINNED_MODULE_SHA256}"', suite)

    def test_transport_exit_code_preserves_only_phase_success(self):
        self.assertEqual(tool.transport_exit_code(0, phase_requested=True), 0)
        self.assertEqual(tool.transport_exit_code(77, phase_requested=True), 77)
        self.assertEqual(tool.transport_exit_code(0, phase_requested=False), 2)
        self.assertEqual(tool.transport_exit_code(77, phase_requested=False), 77)
        self.assertEqual(tool.transport_exit_code(3, phase_requested=True), 2)

    def test_expected_system_libcuda_is_hash_checked_before_cuda_preflight(self):
        library = self.root / 'libcuda.so.595.99.02'
        library.write_bytes(b'pinned R595 library')
        self.expected_libcuda_path = str(library)
        expected = hashlib.sha256(library.read_bytes()).hexdigest()
        self.payload['expected_libcuda_sha256'] = expected
        self.expected_libcuda_loader_output = (
            'libssl.so.3 (libc6,x86-64) => /usr/lib/libssl.so.3\n'
            f'libcuda.so.1 (libc6,x86-64) => {library}\n')
        report, code = self.run_case('pinned-libcuda')
        self.assertEqual(code, 77)
        self.assertEqual(report['system_libcuda_before']['sha256'], expected)
        self.assertEqual(report['system_libcuda_after'], report['system_libcuda_before'])
        commands = [entry['argv'] for entry in report['commands']]
        self.assertLess(commands.index(['/sbin/ldconfig', '-p']),
                        next(i for i, argv in enumerate(commands) if '--list' in argv))
        self.assertEqual(report['preflight']['driver_library_path'],
                         str(library.resolve(strict=True)))
        self.assertEqual(report['hardware_acceptance']['probe']['driver_library_path'],
                         str(library.resolve(strict=True)))
        ldconfig_row = next(row for row in report['commands']
                            if row['argv'] == ['/sbin/ldconfig', '-p'])
        self.assertEqual(ldconfig_row['stdout'],
                         f'libcuda.so.1 (libc6,x86-64) => {library}\n')

    def test_expected_system_libcuda_hash_mismatch_stops_before_cuda(self):
        library = self.root / 'libcuda.so.595.99.02'
        library.write_bytes(b'other R595 library')
        self.expected_libcuda_path = str(library)
        self.payload['expected_libcuda_sha256'] = '0' * 64
        report, code = self.run_case('wrong-libcuda')
        self.assertEqual(code, 2)
        self.assertIn('system libcuda hash differs', report['error'])
        self.assertFalse(any('--list' in entry['argv'] for entry in report['commands']))
        self.assertEqual(report['system_libcuda_before']['sha256'],
                         hashlib.sha256(library.read_bytes()).hexdigest())

    def test_ambiguous_system_libcuda_resolution_stops_before_cuda(self):
        library = self.root / 'libcuda.so.595.99.02'
        duplicate = self.root / 'other/libcuda.so.595.99.02'
        library.write_bytes(b'pinned R595 library')
        duplicate.parent.mkdir()
        duplicate.write_bytes(b'another R595 library')
        self.expected_libcuda_path = str(library)
        self.expected_libcuda_loader_output = (
            f'libcuda.so.1 (libc6,x86-64) => {library}\n'
            f'libcuda.so.1 (libc6,x86-64) => {duplicate}\n')
        self.payload['expected_libcuda_sha256'] = hashlib.sha256(library.read_bytes()).hexdigest()
        report, code = self.run_case('ambiguous-libcuda')
        self.assertEqual(code, 2)
        self.assertIn('system libcuda loader resolution is ambiguous', report['error'])
        self.assertFalse(any('--list' in entry['argv'] for entry in report['commands']))

    def test_system_libcuda_change_during_probe_fails_closed(self):
        library = self.root / 'libcuda.so.595.99.02'
        library.write_bytes(b'pinned R595 library')
        self.expected_libcuda_path = str(library)
        self.payload['expected_libcuda_sha256'] = hashlib.sha256(library.read_bytes()).hexdigest()
        self.mutate_libcuda = True
        report, code = self.run_case('mutated-libcuda')
        self.assertEqual(code, 2)
        self.assertIn('system libcuda changed during the selected-GPU probe', report['error'])
        self.assertNotEqual(report['system_libcuda_after']['sha256'],
                            report['system_libcuda_before']['sha256'])

    def invoke(self, argv, **kwargs):
        self.commands.append(argv)
        env = kwargs['env']
        self.assertEqual(env['CUDA_VISIBLE_DEVICES'], UUID)
        self.assertFalse(any(key.startswith(('LD_', 'PYTHON', 'NVIDIA_')) for key in env))
        if argv[0] == 'nvidia-smi':
            self.assertEqual(argv[1:3], ['-i', UUID])
            return subprocess.CompletedProcess(argv, 0, f'NVIDIA GeForce RTX 5080, {UUID}, 00000000:02:00.0, 595.99.02\n', '')
        if argv[0] == '/sbin/ldconfig':
            self.assertEqual(argv[1:], ['-p'])
            if self.expected_libcuda_path is None:
                return subprocess.CompletedProcess(argv, 1, '', 'unexpected ldconfig')
            if self.expected_libcuda_loader_output is not None:
                return subprocess.CompletedProcess(argv, 0, self.expected_libcuda_loader_output, '')
            return subprocess.CompletedProcess(
                argv, 0,
                f'libcuda.so.1 (libc6,x86-64) => {self.expected_libcuda_path}\n', '')
        if '--list' in argv:
            report = {'schema': 'nvidia-hybrid-probe-v2', 'status': 'inventory',
                      'devices': self.preflight_devices if self.preflight_devices is not None else [self.preflight_device]}
            if self.payload.get('expected_libcuda_sha256'):
                report['driver_library_path'] = str(Path(self.expected_libcuda_path).resolve(strict=True))
            return subprocess.CompletedProcess(argv, 0, json.dumps(report), '')
        self.assertEqual(argv[1].split('/')[-1], 'runner')
        self.assertIn('--expected-pci', argv)
        self.assertNotIn('--allow-incomplete', argv)
        self.assertEqual(argv[argv.index('--expected-pci') + 1], PCI)
        requested_phase = self.payload.get('phase')
        if requested_phase is not None:
            self.assertIn('--phase', argv)
            self.assertEqual(argv[argv.index('--phase') + 1], requested_phase)
            if requested_phase == 'system-pageable-memory':
                self.assertNotIn('--ioctl-observer', argv)
                self.assertIn('--expected-pci', argv)
                self.assertEqual(argv[argv.index('--expected-pci') + 1], PCI)
                phase_qualification = ('system-pageable-memory-report-contract-pass'
                                       if self.phase_report.get('status') == 'validated'
                                       else 'system-pageable-memory-unsupported-report-contract-valid')
                result = {'probe': self.phase_report,
                          'phase_capture_requested': True,
                          'phase': requested_phase,
                          'exit_code': self.acceptance_code,
                          'qualification': phase_qualification,
                          'validation_errors': []}
                result['probe_build_trust'] = self.probe_build_trust()
                return subprocess.CompletedProcess(argv, self.acceptance_code,
                                                   json.dumps(result), '')
            node_trace = (requested_phase == 'enumerate' and self.payload.get('ioctl_trace') is True)
            managed_accessed_by_trace = (requested_phase == 'managed-accessed-by' and
                                         self.payload.get('ioctl_trace') is True)
            phase_trace = node_trace or managed_accessed_by_trace
            if phase_trace:
                self.assertNotIn('--ioctl-observer', argv)
                self.assertIn('--ioctl-trace', argv)
                self.assertIn('--trace-helper', argv)
            else:
                self.assertIn('--ioctl-observer', argv)
            if not phase_trace:
                if self.payload.get('rm_control_headers_capture'):
                    self.assertIn('--rm-control-headers', argv)
                    self.assertNotIn('--rm-control', argv)
                    self.assertNotIn('--binapi-control', argv)
                elif self.payload.get('device_alloc_capture'):
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
                elif self.payload.get('gt200_debugger_alloc_capture'):
                    self.assertIn('--gt200-debugger-alloc', argv)
                    self.assertNotIn('--device-alloc', argv)
                    self.assertNotIn('--subdevice-alloc', argv)
                    self.assertNotIn('--binapi-alloc', argv)
                    self.assertNotIn('--binapi-control', argv)
                    self.assertIn('--gpu-path', argv)
                elif self.payload.get('gt200_debugger_lifecycle_capture'):
                    self.assertIn('--gt200-debugger-lifecycle', argv)
                    self.assertNotIn('--gt200-debugger-alloc', argv)
                    self.assertNotIn('--rm-control', argv)
                    self.assertIn('--gpu-path', argv)
                else:
                    self.assertIn('--binapi-control', argv)
                    self.assertIn('--rm-control', argv)
            result = {'probe': self.phase_report, 'phase_capture_requested': True,
                      'phase': requested_phase, 'exit_code': 0,
                      'qualification': 'phase-report-contract-pass',
                      'validation_errors': []}
            result['probe_build_trust'] = self.probe_build_trust()
            if self.phase_result_in_stdout:
                result['probe'] = None
                result['stdout'] = json.dumps(self.phase_report)
            if node_trace:
                from tools.summarize_rm_ioctl_trace import summarize_node_open_trace
                trace_path = Path(argv[argv.index('--ioctl-trace-output') + 1])
                raw = (b'123 openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3</dev/nvidiactl<char 195:255>>\n'
                       b'123 ioctl(3</dev/nvidiactl<char 195:255>>, 0xc01046d3, 0x7ffe1234) = 0\n')
                trace_path.write_bytes(raw)
                result['ioctl_trace'] = {'trace': {
                    'path': str(trace_path), 'trace_complete': True, 'size_limit_exceeded': False,
                    'summary': summarize_node_open_trace(raw)}}
            elif managed_accessed_by_trace:
                from tools.summarize_rm_ioctl_trace import summarize
                trace_path = Path(argv[argv.index('--ioctl-trace-output') + 1])
                trace_path.write_bytes(self.managed_trace_raw)
                result['ioctl_trace'] = {'trace': {
                    'path': str(trace_path), 'trace_complete': True, 'size_limit_exceeded': False,
                    'summary': summarize(self.managed_trace_raw)}}
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
            if self.payload.get('gt200_debugger_alloc_capture'):
                result['gt200_debugger_alloc_records_seen'] = True
                result['gt200_debugger_alloc_payload_snapshots_read'] = 2
            if self.payload.get('gt200_debugger_lifecycle_capture'):
                result['gt200_debugger_lifecycle_capture_requested'] = True
                result['gt200_debugger_lifecycle'] = self.namespace[
                    'validate_gt200_debugger_lifecycle_capture'](self.phase_observation)
            return subprocess.CompletedProcess(argv, 0, json.dumps(result), '')
        managed_requested = bool(self.payload.get('managed_memory'))
        prefetch_requested = bool(self.payload.get('managed_prefetch'))
        graphs_requested = bool(self.payload.get('cuda_graphs'))
        benchmark_requested = bool(self.payload.get('performance_benchmark'))
        benchmark_samples = self.payload.get('benchmark_samples', 9)
        benchmark_transfer_samples = self.payload.get('benchmark_samples', 7)
        self.assertEqual('--managed-memory' in argv, managed_requested)
        self.assertEqual('--managed-prefetch' in argv, prefetch_requested)
        self.assertEqual('--cuda-graphs' in argv, graphs_requested)
        self.assertEqual('--benchmark' in argv, benchmark_requested)
        if benchmark_requested:
            self.assertEqual(argv[argv.index('--benchmark-samples') + 1],
                             str(benchmark_samples))
        device = dict(DEVICE, concurrent_managed_access=True,
                                  pageable_memory_access=True,
                                  pageable_memory_access_uses_host_page_tables=True,
                                  managed_memory_passed=self.managed_result,
                                  managed_prefetch_passed=self.prefetch_result,
                                  cuda_graphs_passed=self.graph_result,
                                  cuda_graph_launches=(2 if self.graph_result else 0))
        if benchmark_requested:
            device['performance_benchmark_passed'] = True
            device['performance_benchmark'] = {
                'samples': benchmark_samples,
                'transfer_samples': benchmark_transfer_samples,
                'transfers': [{'samples': benchmark_transfer_samples} for _ in range(5)]}
        probe = {'devices': [device],
                 'memory_mode': 'managed' if managed_requested else 'device',
                 'managed_prefetch_requested': prefetch_requested,
                 'managed_prefetch_api': ('cuMemPrefetchAsync_v2' if prefetch_requested else 'not-requested'),
                 'cuda_graphs_requested': graphs_requested,
                 'performance_benchmark_requested': benchmark_requested,
                 'cuda_graph_api': ('cuGraphInstantiateWithFlags' if graphs_requested else 'not-requested'),
                 'hybrid_validated': False, 'missing_sm': [70], 'required_sm': [70, 120]}
        if self.payload.get('expected_libcuda_sha256'):
            probe['driver_library_path'] = str(Path(self.expected_libcuda_path).resolve(strict=True))
        result = {'probe': probe, 'exit_code': self.acceptance_code,
                  'qualification': 'incomplete-hardware-missing', 'validation_errors': []}
        result['probe_build_trust'] = self.probe_build_trust()
        if self.mutate:
            Path(argv[argv.index('--probe') + 1]).write_bytes(b'mutated')
        if self.mutate_libcuda:
            Path(self.expected_libcuda_path).write_bytes(b'changed during acceptance')
        return subprocess.CompletedProcess(argv, self.acceptance_code, json.dumps(result), '')

    def test_benchmark_sample_count_is_forwarded_and_verified(self):
        self.payload['performance_benchmark'] = True
        self.payload['benchmark_samples'] = 21

        report, code = self.run_case('benchmark-samples')

        self.assertEqual(code, 77, report)
        self.assertEqual(report['qualification'],
                         'rtx5080-report-contract-valid-hybrid-incomplete')
        self.assertTrue(report['performance_benchmark_report_contract_passed'])
        self.assertEqual(report['cuda_execution_validation_state'],
                         'probe/fatbin identity is pinned; CUDA execution is not independently attested')

    def test_remote_script_rejects_out_of_range_benchmark_samples_before_commands(self):
        self.payload['performance_benchmark'] = True
        self.payload['benchmark_samples'] = 1002
        calls = []

        with self.assertRaisesRegex(ValueError, 'benchmark sample count'):
            self.run_remote(self.payload, self.proc, self.sys,
                            lambda *args, **kwargs: calls.append(args))
        self.assertEqual(calls, [])

    def run_case(self, work_name='hybrid-rtx5080-work'):
        if not work_name.startswith('hybrid-rtx5080-'):
            work_name = 'hybrid-rtx5080-' + work_name
        work = self.root / work_name
        work.mkdir()
        work.chmod(0o700)
        with patch.dict(os.environ, {'LD_PRELOAD': 'bad', 'LD_LIBRARY_PATH': 'bad',
                                     'CUDA_INJECTION64_PATH': 'bad', 'CUDA_VISIBLE_DEVICES': '0,1',
                                     'PYTHONPATH': 'bad'}), patch.object(self.namespace['tempfile'], 'mkdtemp', return_value=str(work)), \
                patch.object(self.namespace['tempfile'], 'gettempdir', return_value=str(self.root)):
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

    @staticmethod
    def gt200_debugger_alloc_observation():
        payload = {'classPayloadBytes': 12, 'obsoleteClientZero': True,
                   'appClientPresent': True, 'appClientMatchesRoot': False,
                   'appClientMatchesParent': True, 'appClientEqualsDebuggee': False,
                   'debuggee3dHandlePresent': True,
                   'appClientClassWithinRoot': {'resolution': 'resolved', 'classId': 0x41},
                   'debuggee3dClassWithinRoot': {'resolution': 'resolved', 'classId': 0x97},
                   'debuggee3dParentClassWithinRoot': {'resolution': 'resolved', 'classId': 0x80},
                   'parentClassWithinRoot': {'resolution': 'resolved', 'classId': 0x41}}
        packet = {'layout': 'NVOS64', 'hClass': 0x83de, 'paramsSize': 0,
                  'flags': 0, 'status': 0, 'hRootPresent': True,
                  'hObjectParentPresent': True, 'hObjectNewPresent': True,
                  'pAllocParmsPresent': True, 'pRightsRequestedPresent': False,
                  'debuggerAlloc': payload}
        return {'schema': 'nvidia-hybrid-rm-ioctl-observer-v34',
                'trace_complete': True, 'child_exit_code': 0,
                'control_path': '/dev/nvidiactl', 'gpu_path': '/dev/nvidia0',
                'architecture': 'x86_64', 'pointer_bits': 64,
                'nested_pointers_read': True,
                'nested_pointer_scope': ('exact NV83DE_ALLOC_PARAMETERS 12-byte payload for GT200_DEBUGGER only; '
                    'emits handle presence and within-root class relations including the debuggee direct-parent class; '
                    'raw handles and addresses omitted'),
                'payload_scope': ('NV83DE_ALLOC_PARAMETERS exact 12-byte fixed payload on GT200_DEBUGGER allocations only; '
                    'raw handles, pointers, and payload bytes omitted'),
                'object_class_resolution_scope': ('successful prior RM_ALLOC and RM_FREE packets observed on the explicitly '
                    'selected control and GPU paths; lookup is keyed by NVOS64 root and handle and emits only '
                    'object and direct-parent class IDs/presence; '
                    'unresolved means no unique live object was observed'),
                'fd_identity_tracking': False,
                'debugger_alloc_payload_snapshots_read': 2, 'errors': [],
                'records': [{'tid': 77, 'fd': 6, 'fd_role': 'control',
                    'request': 0xc030462b, 'packet_size': 48,
                    'operation': 'gt200_debugger_alloc', 'entry': copy.deepcopy(packet),
                    'exit': copy.deepcopy(packet), 'syscall_return': 0}]}

    def test_selected_reference_is_truthfully_incomplete(self):
        report, code = self.run_case()
        self.assertEqual(code, 77)
        self.assertEqual(report['memory_mode'], 'device')
        self.assertEqual(len(self.commands), 3)
        self.assertEqual(report['artifacts_before'], report['artifacts_after'])
        self.assertFalse(report['hardware_acceptance']['probe']['hybrid_validated'])
        self.assertEqual(report['remote_work_cleanup'], {
            'attempted': True, 'passed': True, 'removed': True,
            'retained_for_inspection': False,
        })
        self.assertFalse(Path(report['remote_work_directory']).exists())
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
        self.assertEqual(report['qualification'], 'rtx5080-cuda-phase-report-contract-valid')
        self.assertTrue(report['report_contract_validated'])
        self.assertFalse(report['cuda_execution_validated'])
        self.assertEqual(report['cuda_execution_validation_state'],
                         'isolated initialize CUDA phase passed; '
                         'same-process multi-GPU execution is not validated')
        self.assertEqual(report['phase'], 'initialize')
        acceptance = report['hardware_acceptance']
        self.assertEqual(acceptance['qualification'], 'phase-report-contract-pass')
        self.assertFalse(acceptance['probe'].get('hybrid_validated', False))
        self.assertEqual(report['binapi_payload_snapshots_read'], 0)

    def test_system_pageable_phase_runs_without_observer_and_validates_both_allocators(self):
        self.payload['phase'] = 'system-pageable-memory'
        self.phase_report = system_pageable_report()
        self.acceptance_code = 0
        report, code = self.run_case()
        self.assertEqual(code, 0, report.get('error'))
        self.assertEqual(report['qualification'], 'rtx5080-system-pageable-memory-report-contract-valid')
        self.assertTrue(report['report_contract_validated'])
        self.assertFalse(report['cuda_execution_validated'])
        self.assertEqual(report['cuda_execution_validation_state'],
                         'isolated system-pageable-memory CUDA phase passed; '
                         'same-process multi-GPU execution is not validated')
        self.assertEqual(report['phase_report']['allocators']['malloc']['sizes'],
                         [1, 31, 256, 4096, 65537])
        self.assertNotIn('--ioctl-observer', ' '.join(self.commands[-1]))

    def test_system_pageable_remote_rejects_boolean_size_and_mismatched_unsupported_reason(self):
        self.payload['phase'] = 'system-pageable-memory'
        self.phase_report = system_pageable_report()
        self.phase_report['allocators']['malloc']['sizes'][0] = True
        self.acceptance_code = 0
        report, code = self.run_case('pageable-bool-size')
        self.assertEqual(code, 2)
        self.assertEqual(report['qualification'], 'failed')

        self.phase_report = system_pageable_report()
        self.phase_report['status'] = 'unsupported'
        self.phase_report['selected_device']['pageable_memory_access'] = True
        self.phase_report['allocators'] = {'malloc': None, 'mmap': None}
        self.phase_report['error'] = 'device does not report pageable memory access'
        self.acceptance_code = 77
        report, code = self.run_case('pageable-inconsistent-unsupported')
        self.assertEqual(code, 2)
        self.assertEqual(report['qualification'], 'failed')

    def test_managed_accessed_by_phase_validates_selected_rtx_and_same_process_uvm_pair(self):
        self.payload['phase'] = 'managed-accessed-by'
        self.payload['ioctl_trace'] = True
        helper = b'CPU trace helper fixture'
        self.payload['artifacts']['trace-helper'] = {
            'base64': base64.b64encode(helper).decode(),
            'sha256': hashlib.sha256(helper).hexdigest(),
        }
        self.phase_report = managed_accessed_by_report()
        self.acceptance_code = 0
        report, code = self.run_case('managed-accessed-by')
        self.assertEqual(code, 0, report.get('error'))
        self.assertEqual(report['qualification'], 'rtx5080-managed-accessed-by-report-contract-valid')
        self.assertTrue(report['managed_accessed_by_report_contract_passed'])
        self.assertFalse(report['managed_accessed_by_validated'])
        self.assertFalse(report['cuda_execution_validated'])
        self.assertEqual(report['phase'], 'managed-accessed-by')
        command = self.commands[-1]
        self.assertIn('--ioctl-trace', command)
        self.assertIn('--trace-helper', command)
        summary = report['hardware_acceptance']['ioctl_trace']['trace']['summary']
        pair = [row for row in summary['calls']
                if row['node'] == '/dev/nvidia-uvm' and row['request'] in ('0x2e', '0x2f')]
        self.assertEqual([(row['request'], row['pid'], row['syscall_return']) for row in pair],
                         [('0x2e', 123, 0), ('0x2f', 123, 0)])

    def test_managed_accessed_by_rejects_unpaired_or_cross_process_uvm_trace(self):
        self.payload['phase'] = 'managed-accessed-by'
        self.payload['ioctl_trace'] = True
        helper = b'CPU trace helper fixture'
        self.payload['artifacts']['trace-helper'] = {
            'base64': base64.b64encode(helper).decode(),
            'sha256': hashlib.sha256(helper).hexdigest(),
        }
        self.phase_report = managed_accessed_by_report()
        self.acceptance_code = 0
        self.managed_trace_raw = (
            b'123 ioctl(4</dev/nvidia-uvm<char 511:0>>, 0x2e, 0x7fff0000) = 0\n'
            b'124 ioctl(4</dev/nvidia-uvm<char 511:0>>, 0x2f, 0x7fff0000) = 0\n')
        report, code = self.run_case('managed-accessed-by-cross-process')
        self.assertEqual(code, 2)
        self.assertEqual(report['qualification'], 'failed')

    def test_enumeration_rm_control_headers_are_redacted_and_qualified(self):
        observer_data = b'CPU observer fixture'
        self.payload['phase'] = 'enumerate'
        self.payload['rm_control_headers_capture'] = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(observer_data).decode(),
            'sha256': hashlib.sha256(observer_data).hexdigest(),
        }
        self.phase_report = {
            'schema': 'nvidia-cuda-driver-phase-v1', 'status': 'phase-passed',
            'phase': 'enumerate', 'expected_pci': '00000000:02:00.0',
            'driver_library_path': '/usr/lib/libcuda.so.1', 'driver_api': 13020,
            'selected_device': {'name': DEVICE['name'], 'pci_bus_id': PCI,
                                'sm': 120, 'compute_capability': '12.0',
                                'concurrent_managed_access': True,
                                'pageable_memory_access': True,
                                'pageable_memory_access_uses_host_page_tables': True},
            'completed_operations': ['cuInit', 'cuDriverGetVersion', 'cuDeviceGetCount',
                                     'cuDeviceGet', 'cuDeviceGetName', 'cuDeviceGetPCIBusId',
                                     'cuDeviceGetAttribute.major', 'cuDeviceGetAttribute.minor',
                                     'cuDeviceGetAttribute.concurrent_managed_access',
                                     'cuDeviceGetAttribute.pageable_memory_access',
                                     'cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables'],
            'numeric_result_passed': False, 'result_value': None, 'expected_result': None,
            'cleanup_passed': True, 'cleanup_errors': [], 'error': '',
        }
        packet = {'command': 0x205, 'flags': 3, 'params_size': 0, 'status': 0,
                  'hClientPresent': True, 'hObjectPresent': True,
                  'client_object_equal': False,
                  'client_matches_prior_root_allocation': False,
                  'object_matches_prior_root_allocation': False}
        self.phase_observation = {
            'schema': 'nvidia-hybrid-rm-ioctl-observer-v23', 'trace_complete': True,
            'child_exit_code': 0, 'control_path': '/dev/nvidiactl',
            'architecture': 'x86_64', 'pointer_bits': 64,
            'nested_pointers_read': False, 'fd_identity_tracking': False,
            'payload_scope': ('fixed NVOS54 RM_CONTROL headers only; handles redacted; '
                              'nested parameter payloads omitted'),
            'errors': [], 'records': [{'tid': 77, 'fd': 6, 'fd_role': 'control',
                'request': 0xc020462a, 'packet_size': 32,
                'operation': 'rm_control_header', 'entry': packet,
                'exit': packet, 'syscall_return': 0}],
        }
        report, code = self.run_case('enumeration-rm-control-headers')
        self.assertEqual(code, 0, report.get('error'))
        self.assertTrue(report['rm_control_headers_capture_requested'])
        self.assertTrue(report['rm_control_headers_records_seen'])
        self.assertEqual(report['rm_control_headers_record_count'], 1)
        self.assertEqual(report['qualification'], 'rtx5080-cuda-phase-report-contract-valid')
        self.assertEqual(report['phase'], 'enumerate')
        valid_observation = copy.deepcopy(self.phase_observation)
        self.phase_observation['records'][0]['entry'] = None
        rejected, rejected_code = self.run_case('enumeration-rm-control-headers-missing-entry')
        self.assertNotEqual(rejected_code, 0)
        self.assertEqual(rejected['qualification'], 'failed')

        self.phase_observation = copy.deepcopy(valid_observation)
        allocation = {'layout': 'NVOS21', 'hRoot': 7, 'hObjectParent': 17,
                      'hObjectNew': 18, 'pAllocParms': 0x123456789abcdef0}
        self.phase_observation['records'].append({
            'tid': 77, 'fd': 6, 'fd_role': 'control', 'request': 0xc030462b,
            'packet_size': 48, 'operation': 'alloc', 'entry': allocation,
            'exit': allocation, 'syscall_return': 0})
        rejected, rejected_code = self.run_case(
            'enumeration-rm-control-headers-unexpected-alloc')
        self.assertNotEqual(rejected_code, 0)
        self.assertEqual(rejected['qualification'], 'failed')
        self.assertRegex(rejected['error'], 'invalid envelope')

    def test_enumeration_node_trace_is_forwarded_without_observer_or_context_creation(self):
        helper_data = b'CPU trace helper fixture'
        self.payload.update({'phase': 'enumerate', 'ioctl_trace': True})
        self.payload['artifacts']['trace-helper'] = {
            'base64': base64.b64encode(helper_data).decode(),
            'sha256': hashlib.sha256(helper_data).hexdigest(),
        }
        self.phase_report = {
            'schema': 'nvidia-cuda-driver-phase-v1', 'status': 'phase-passed',
            'phase': 'enumerate', 'expected_pci': '00000000:02:00.0',
            'driver_library_path': '/usr/lib/x86_64-linux-gnu/libcuda.so.1',
            'driver_api': 13020,
            'selected_device': {'name': DEVICE['name'], 'pci_bus_id': PCI,
                                'sm': 120, 'compute_capability': '12.0',
                                'concurrent_managed_access': True,
                                'pageable_memory_access': True,
                                'pageable_memory_access_uses_host_page_tables': True},
            'completed_operations': ['cuInit', 'cuDriverGetVersion', 'cuDeviceGetCount',
                'cuDeviceGet', 'cuDeviceGetName', 'cuDeviceGetPCIBusId',
                'cuDeviceGetAttribute.major', 'cuDeviceGetAttribute.minor',
                'cuDeviceGetAttribute.concurrent_managed_access',
                'cuDeviceGetAttribute.pageable_memory_access',
                'cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables'],
            'numeric_result_passed': False, 'result_value': None, 'expected_result': None,
            'cleanup_passed': True, 'cleanup_errors': [], 'error': '',
        }
        report, code = self.run_case()
        self.assertEqual(code, 0, report.get('error'))
        acceptance = report['hardware_acceptance']
        summary = acceptance['ioctl_trace']['trace']['summary']
        self.assertEqual(summary['schema'], 'nvidia-hybrid-node-open-trace-v1')
        self.assertEqual(summary['successful_selected_node_open_count'], 1)
        self.assertEqual(summary['ioctl_counts_by_node'], {'nvidiactl': 1})
        self.assertEqual(report['qualification'], 'rtx5080-cuda-phase-report-contract-valid')
        self.assertTrue(acceptance['ioctl_trace']['trace']['trace_complete'])
        self.assertTrue(report['ioctl_trace_transport']['gzip_base64'])
        self.assertFalse(any(operation.startswith('cuCtx')
                             for operation in acceptance['probe']['completed_operations']))
        self.assertNotIn('ioctl-observer', ' '.join(self.commands[-1]))

    def test_phase_capture_requires_the_isolated_binapi_observer(self):
        self.payload['phase'] = 'context'
        with self.assertRaisesRegex(ValueError, 'phase capture requires exactly one isolated allocation/control'):
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
                                'sm': 120, 'compute_capability': '12.0',
                                'concurrent_managed_access': True,
                                'pageable_memory_access': True,
                                'pageable_memory_access_uses_host_page_tables': True},
            'completed_operations': ['cuInit', 'cuDriverGetVersion', 'cuDeviceGetCount',
                'cuDeviceGet', 'cuDeviceGetName', 'cuDeviceGetPCIBusId',
                'cuDeviceGetAttribute.major', 'cuDeviceGetAttribute.minor',
                'cuDeviceGetAttribute.concurrent_managed_access',
                'cuDeviceGetAttribute.pageable_memory_access',
                'cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables',
                'cuCtxCreate_v2', 'cuCtxSetCurrent', 'cuCtxGetDevice'],
            'numeric_result_passed': False, 'result_value': None, 'expected_result': None,
            'cleanup_passed': True, 'cleanup_errors': [], 'error': '',
        }
        self.phase_observation = self.device_alloc_observation()
        report, code = self.run_case()
        self.assertEqual(code, 0, report.get('error'))
        self.assertEqual(report['qualification'], 'rtx5080-cuda-phase-report-contract-valid')
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
                                'sm': 120, 'compute_capability': '12.0',
                                'concurrent_managed_access': True,
                                'pageable_memory_access': True,
                                'pageable_memory_access_uses_host_page_tables': True},
            'completed_operations': ['cuInit', 'cuDriverGetVersion', 'cuDeviceGetCount',
                'cuDeviceGet', 'cuDeviceGetName', 'cuDeviceGetPCIBusId',
                'cuDeviceGetAttribute.major', 'cuDeviceGetAttribute.minor',
                'cuDeviceGetAttribute.concurrent_managed_access',
                'cuDeviceGetAttribute.pageable_memory_access',
                'cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables',
                'cuCtxCreate_v2', 'cuCtxSetCurrent', 'cuCtxGetDevice'],
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
                                'sm': 120, 'compute_capability': '12.0',
                                'concurrent_managed_access': True,
                                'pageable_memory_access': True,
                                'pageable_memory_access_uses_host_page_tables': True},
            'completed_operations': ['cuInit', 'cuDriverGetVersion', 'cuDeviceGetCount',
                'cuDeviceGet', 'cuDeviceGetName', 'cuDeviceGetPCIBusId',
                'cuDeviceGetAttribute.major', 'cuDeviceGetAttribute.minor',
                'cuDeviceGetAttribute.concurrent_managed_access',
                'cuDeviceGetAttribute.pageable_memory_access',
                'cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables',
                'cuCtxCreate_v2', 'cuCtxSetCurrent', 'cuCtxGetDevice'],
            'numeric_result_passed': False, 'result_value': None, 'expected_result': None,
            'cleanup_passed': True, 'cleanup_errors': [], 'error': '',
        }
        self.phase_observation = self.binapi_alloc_observation()
        report, code = self.run_case()
        self.assertEqual(code, 0, report.get('error'))
        self.assertEqual(report['qualification'], 'rtx5080-cuda-phase-report-contract-valid')
        self.assertTrue(report['binapi_alloc_capture_requested'])
        self.assertTrue(report['binapi_alloc_records_seen'])
        self.assertEqual(report['binapi_alloc_payload_snapshots_read'], 2)
        self.assertFalse(report['subdevice_alloc_capture_requested'])

    def test_gt200_debugger_allocation_capture_is_forwarded_and_validated(self):
        observer_data = b"CPU observer fixture"
        self.payload.update({'phase': 'context', 'gt200_debugger_alloc_capture': True})
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
                                'sm': 120, 'compute_capability': '12.0',
                                'concurrent_managed_access': True,
                                'pageable_memory_access': True,
                                'pageable_memory_access_uses_host_page_tables': True},
            'completed_operations': ['cuInit', 'cuDriverGetVersion', 'cuDeviceGetCount',
                'cuDeviceGet', 'cuDeviceGetName', 'cuDeviceGetPCIBusId',
                'cuDeviceGetAttribute.major', 'cuDeviceGetAttribute.minor',
                'cuDeviceGetAttribute.concurrent_managed_access',
                'cuDeviceGetAttribute.pageable_memory_access',
                'cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables',
                'cuCtxCreate_v2', 'cuCtxSetCurrent', 'cuCtxGetDevice'],
            'numeric_result_passed': False, 'result_value': None, 'expected_result': None,
            'cleanup_passed': True, 'cleanup_errors': [], 'error': '',
        }
        self.phase_observation = self.gt200_debugger_alloc_observation()
        report, code = self.run_case('gt200-debugger-allocation')
        self.assertEqual(code, 0, report.get('error'))
        self.assertEqual(report['qualification'], 'rtx5080-cuda-phase-report-contract-valid')
        self.assertEqual(report['cuda_execution_validation_state'],
                         'isolated context CUDA phase passed; '
                         'same-process multi-GPU execution is not validated')
        self.assertTrue(report['gt200_debugger_alloc_capture_requested'])
        self.assertEqual(report['gt200_debugger_alloc_records_seen'], 1)
        self.assertEqual(report['gt200_debugger_alloc_payload_snapshots_read'], 2)
        self.assertFalse(report['device_alloc_capture_requested'])
        self.assertIn('--gt200-debugger-alloc', self.commands[-1])

    @staticmethod
    def gt200_debugger_lifecycle_observation():
        return {
            'schema': 'nvidia-hybrid-rm-ioctl-observer-v39',
            'trace_complete': True, 'child_exit_code': 0,
            'control_path': '/dev/nvidiactl', 'gpu_path': '/dev/nvidia0',
            'architecture': 'x86_64', 'pointer_bits': 64,
            'nested_pointers_read': False, 'fd_identity_tracking': False,
            'object_class_resolution_scope': (
                'successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU '
                'paths; debugger control hClient is resolved to one observed root before resolving hObject; '
                'a redacted hObject equality against prior successful GT200_DEBUGGER allocations is recorded; unresolved free classes and debugger-command candidates emit redacted fixed headers; raw handles are omitted'),
            'debugger_alloc_payload_snapshots_read': 0,
            'debugger_free_unresolved_class_count': 0,
            'debugger_control_unresolved_candidate_count': 0,
            'debugger_exception_mask_payload_snapshots_read': 0,
            'payload_scope': (
                'GT200_DEBUGGER allocations, class-resolved GT200_DEBUGGER frees, fixed NVOS54 headers plus a redacted hObject-to-prior-debugger-allocation equality, and exact 4-byte exceptionMask snapshots for resolved 0x83de0309 controls only; null pointers, size mismatch, and undocumented bits fail closed; unresolved command candidates are never dereferenced; raw handles and addresses omitted'),
            'nested_pointer_scope': (
                'exact NV83DE allocation parameters plus fixed NVOS54 headers for resolved GT200_DEBUGGER controls and unresolved 0x83de command candidates; only exact 4-byte exceptionMask for resolved 0x83de0309 controls is followed after fixed-size, non-null-pointer, and documented-bit checks; RM_FREE class resolution is root-scoped; a redacted hObject-to-prior-GT200_DEBUGGER-allocation equality is emitted; raw handles and addresses omitted'),
            'errors': [], 'records': [],
        }

    def test_gt200_debugger_lifecycle_acceptance_gate_matches_v39_payload_scope(self):
        observed = self.gt200_debugger_lifecycle_observation()
        self.assertTrue(acceptance.gt200_debugger_lifecycle_payload_scope_matches(observed))
        stale = copy.deepcopy(observed)
        stale['payload_scope'] = (
            'GT200_DEBUGGER allocations, class-resolved GT200_DEBUGGER frees, and fixed NVOS54 headers '
            'for resolved debugger controls and unresolved 0x83de command candidates; no control parameter '
            'payloads are followed; raw handles and addresses omitted')
        self.assertFalse(acceptance.gt200_debugger_lifecycle_payload_scope_matches(stale))

    def test_gt200_debugger_lifecycle_capture_is_forwarded_and_validated(self):
        observer_data = b'CPU observer fixture'
        self.payload.update({'phase': 'context', 'gt200_debugger_lifecycle_capture': True})
        library = self.root / 'libcuda.so.595.99.02'
        library.write_bytes(b'pinned R595 library')
        self.expected_libcuda_path = str(library)
        expected_library_hash = hashlib.sha256(library.read_bytes()).hexdigest()
        self.payload['expected_libcuda_sha256'] = expected_library_hash
        self.phase_result_in_stdout = True
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(observer_data).decode(),
            'sha256': hashlib.sha256(observer_data).hexdigest(),
        }
        self.phase_report = {
            'schema': 'nvidia-cuda-driver-phase-v1', 'status': 'phase-passed',
            'phase': 'context', 'expected_pci': '00000000:02:00.0',
            'driver_library_path': str(library.resolve()),
            'driver_api': 13020,
            'selected_device': {'name': DEVICE['name'], 'pci_bus_id': PCI,
                                'sm': 120, 'compute_capability': '12.0',
                                'concurrent_managed_access': True,
                                'pageable_memory_access': True,
                                'pageable_memory_access_uses_host_page_tables': True},
            'completed_operations': ['cuInit', 'cuDriverGetVersion', 'cuDeviceGetCount',
                'cuDeviceGet', 'cuDeviceGetName', 'cuDeviceGetPCIBusId',
                'cuDeviceGetAttribute.major', 'cuDeviceGetAttribute.minor',
                'cuDeviceGetAttribute.concurrent_managed_access',
                'cuDeviceGetAttribute.pageable_memory_access',
                'cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables',
                'cuCtxCreate_v2', 'cuCtxSetCurrent', 'cuCtxGetDevice'],
            'numeric_result_passed': False, 'result_value': None, 'expected_result': None,
            'cleanup_passed': True, 'cleanup_errors': [], 'error': '',
        }
        self.phase_observation = self.gt200_debugger_lifecycle_observation()
        report, code = self.run_case('gt200-debugger-lifecycle')
        self.assertEqual(code, 0, report.get('error'))
        self.assertTrue(report['gt200_debugger_lifecycle_capture_requested'])
        self.assertEqual(report['gt200_debugger_lifecycle']['records'], 0)
        self.assertFalse(report['cuda_execution_validated'])
        self.assertEqual(report['system_libcuda_before']['sha256'], expected_library_hash)
        self.assertEqual(report['system_libcuda_after'], report['system_libcuda_before'])
        self.assertEqual(report['phase_report'], self.phase_report)
        self.assertIsNone(report['hardware_acceptance']['probe'])
        self.assertIn('--gt200-debugger-lifecycle', self.commands[-1])

    def test_gt200_debugger_lifecycle_rejects_raw_control_handles(self):
        observer_data = b'CPU observer fixture'
        self.payload.update({'phase': 'context', 'gt200_debugger_lifecycle_capture': True})
        self.payload['artifacts']['observer'] = {
            'base64': base64.b64encode(observer_data).decode(),
            'sha256': hashlib.sha256(observer_data).hexdigest(),
        }
        self.phase_report = {
            'schema': 'nvidia-cuda-driver-phase-v1', 'status': 'phase-passed',
            'phase': 'context', 'expected_pci': '00000000:02:00.0',
            'driver_library_path': '/usr/lib/libcuda.so.1', 'driver_api': 13020,
            'selected_device': {'name': DEVICE['name'], 'pci_bus_id': PCI,
                                'sm': 120, 'compute_capability': '12.0',
                                'concurrent_managed_access': True,
                                'pageable_memory_access': True,
                                'pageable_memory_access_uses_host_page_tables': True},
            'completed_operations': ['cuInit', 'cuDriverGetVersion', 'cuDeviceGetCount',
                'cuDeviceGet', 'cuDeviceGetName', 'cuDeviceGetPCIBusId',
                'cuDeviceGetAttribute.major', 'cuDeviceGetAttribute.minor',
                'cuDeviceGetAttribute.concurrent_managed_access',
                'cuDeviceGetAttribute.pageable_memory_access',
                'cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables',
                'cuCtxCreate_v2', 'cuCtxSetCurrent', 'cuCtxGetDevice'],
            'numeric_result_passed': False, 'result_value': None, 'expected_result': None,
            'cleanup_passed': True, 'cleanup_errors': [], 'error': '',
        }
        observed = self.gt200_debugger_lifecycle_observation()
        control = {'command': 0x83de0301, 'flags': 0, 'params_size': 0, 'status': 0,
                   'hClientPresent': True, 'hObjectPresent': True,
                   'client_object_equal': False,
                   'client_matches_prior_root_allocation': True,
                   'object_matches_prior_root_allocation': True,
                   'object_handle_matches_prior_debugger_allocation': True}
        observed['records'] = [{
            'tid': 77, 'fd': 6, 'fd_role': 'control', 'request': 0xc020462a,
            'packet_size': 32, 'operation': 'gt200_debugger_control',
            'debuggerTargetObjectClassWithinRoot': {'resolution': 'resolved', 'classId': 0x83de},
            'entry': {**control, 'hClient': 19}, 'exit': control, 'syscall_return': 0,
        }]
        self.phase_observation = observed
        report, code = self.run_case('gt200-debugger-lifecycle-unredacted')
        self.assertEqual(code, 2)
        self.assertIn('unredacted', report.get('error', ''))

    def test_gt200_debugger_lifecycle_validates_alloc_free_control_status_transitions(self):
        observed = self.gt200_debugger_lifecycle_observation()
        allocation = self.gt200_debugger_alloc_observation()['records'][0]
        free_packet = {'layout': 'NVOS00', 'status': 0, 'hRootPresent': True,
                       'hObjectParentPresent': False, 'hObjectOldPresent': True,
                       'objectClassWithinRoot': 0x83de}
        free_exit = {**free_packet, 'status': 1}
        free = {'tid': 77, 'fd': 6, 'fd_role': 'control', 'request': 0xc0104629,
                'packet_size': 16, 'operation': 'gt200_debugger_free',
                'entry': free_packet, 'exit': free_exit, 'syscall_return': 0}
        header = {'command': 0x83de0301, 'flags': 0, 'params_size': 0, 'status': 0,
                  'hClientPresent': True, 'hObjectPresent': True,
                  'client_object_equal': False,
                  'client_matches_prior_root_allocation': True,
                  'object_matches_prior_root_allocation': True,
                  'object_handle_matches_prior_debugger_allocation': True}
        header_exit = {**header, 'status': 1}
        control = {'tid': 77, 'fd': 6, 'fd_role': 'control', 'request': 0xc020462a,
                   'packet_size': 32, 'operation': 'gt200_debugger_control',
                   'debuggerTargetObjectClassWithinRoot': {'resolution': 'resolved',
                                                            'classId': 0x83de},
                   'entry': header, 'exit': header_exit, 'syscall_return': 0}
        observed['nested_pointers_read'] = True
        observed['debugger_alloc_payload_snapshots_read'] = 2
        observed['records'] = [allocation, free, control]
        expected = {'records': 3, 'allocations': 1, 'frees': 1, 'controls': 1,
                    'allocation_payload_snapshots': 2, 'unresolved_free_classes': 0,
                    'exception_mask_payload_snapshots': 0,
                    'resolved_exception_mask_controls': 0,
                    'unresolved_exception_mask_candidates': 0,
                    'unresolved_exception_mask_rm_statuses': [],
                    'unresolved_control_candidates': 0}
        self.assertEqual(acceptance.validate_gt200_debugger_lifecycle_observation(observed), expected)
        self.assertEqual(self.namespace['validate_gt200_debugger_lifecycle_capture'](observed), expected)

    def test_gt200_debugger_lifecycle_validates_only_documented_exception_mask_payload(self):
        observed = self.gt200_debugger_lifecycle_observation()
        allocation = self.gt200_debugger_alloc_observation()['records'][0]
        header = {'command': 0x83de0309, 'flags': 0, 'params_size': 4, 'status': 0,
                  'hClientPresent': True, 'hObjectPresent': True,
                  'client_object_equal': False,
                  'client_matches_prior_root_allocation': True,
                  'object_matches_prior_root_allocation': True,
                  'object_handle_matches_prior_debugger_allocation': True,
                  'exceptionMask': 0x21}
        header_exit = {**header, 'status': 1, 'exceptionMaskUserBufferEntryExitEqual': True}
        control = {'tid': 77, 'fd': 6, 'fd_role': 'control', 'request': 0xc020462a,
                   'packet_size': 32, 'operation': 'gt200_debugger_control',
                   'debuggerTargetObjectClassWithinRoot': {'resolution': 'resolved',
                                                            'classId': 0x83de},
                   'entry': header, 'exit': header_exit, 'syscall_return': 0}
        observed['nested_pointers_read'] = True
        observed['debugger_alloc_payload_snapshots_read'] = 2
        observed['debugger_exception_mask_payload_snapshots_read'] = 2
        observed['records'] = [allocation, control]
        expected = {'records': 2, 'allocations': 1, 'frees': 0, 'controls': 1,
                    'allocation_payload_snapshots': 2,
                    'exception_mask_payload_snapshots': 2,
                    'resolved_exception_mask_controls': 1,
                    'unresolved_exception_mask_candidates': 0,
                    'unresolved_exception_mask_rm_statuses': [],
                    'unresolved_free_classes': 0, 'unresolved_control_candidates': 0}
        self.assertEqual(acceptance.validate_gt200_debugger_lifecycle_observation(observed), expected)
        self.assertEqual(tool.validate_gt200_debugger_lifecycle_capture(observed), expected)

        for field, value in (('exceptionMask', 0x40),
                             ('exceptionMaskUserBufferEntryExitEqual', False)):
            malformed = copy.deepcopy(observed)
            malformed['records'][1]['exit' if field.endswith('Equal') else 'entry'][field] = value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    acceptance.validate_gt200_debugger_lifecycle_observation(malformed)
                with self.assertRaises(ValueError):
                    tool.validate_gt200_debugger_lifecycle_capture(malformed)

    def test_gt200_debugger_lifecycle_rejects_missing_fixed_payload_and_invalid_u32(self):
        observed = self.gt200_debugger_lifecycle_observation()
        observed['nested_pointers_read'] = True
        observed['debugger_alloc_payload_snapshots_read'] = 2
        observed['records'] = [self.gt200_debugger_alloc_observation()['records'][0]]
        mutations = []
        missing_payload = copy.deepcopy(observed)
        missing_payload['records'][0]['entry']['debuggerAlloc'] = None
        mutations.append(missing_payload)
        inconsistent_pointer = copy.deepcopy(observed)
        inconsistent_pointer['records'][0]['exit']['pAllocParmsPresent'] = False
        mutations.append(inconsistent_pointer)
        out_of_range = copy.deepcopy(observed)
        out_of_range['records'][0]['entry']['status'] = 1 << 32
        mutations.append(out_of_range)
        wide_tid = copy.deepcopy(observed)
        wide_tid['records'][0]['tid'] = 1 << 31
        mutations.append(wide_tid)
        wide_return = copy.deepcopy(observed)
        wide_return['records'][0]['syscall_return'] = 1 << 63
        mutations.append(wide_return)
        changed_header = copy.deepcopy(observed)
        changed_header['records'][0]['exit']['flags'] = 1
        mutations.append(changed_header)
        for candidate in mutations:
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    acceptance.validate_gt200_debugger_lifecycle_observation(candidate)
                with self.assertRaises(ValueError):
                    tool.validate_gt200_debugger_lifecycle_capture(candidate)

    def test_gt200_debugger_lifecycle_rejects_control_without_resolved_handle_presence(self):
        observed = self.gt200_debugger_lifecycle_observation()
        control = {'command': 0x83de0301, 'flags': 0, 'params_size': 0, 'status': 0,
                   'hClientPresent': True, 'hObjectPresent': True,
                   'client_object_equal': False,
                   'client_matches_prior_root_allocation': True,
                   'object_matches_prior_root_allocation': True,
                   'object_handle_matches_prior_debugger_allocation': True}
        observed['records'] = [{
            'tid': 77, 'fd': 6, 'fd_role': 'control', 'request': 0xc020462a,
            'packet_size': 32, 'operation': 'gt200_debugger_control',
            'debuggerTargetObjectClassWithinRoot': {'resolution': 'resolved', 'classId': 0x83de},
            'entry': dict(control), 'exit': dict(control), 'syscall_return': 0,
        }]
        self.assertEqual(acceptance.validate_gt200_debugger_lifecycle_observation(observed)['controls'], 1)
        self.assertEqual(tool.validate_gt200_debugger_lifecycle_capture(observed)['controls'], 1)
        observed['records'][0]['entry']['hClientPresent'] = False
        with self.assertRaises(ValueError):
            acceptance.validate_gt200_debugger_lifecycle_observation(observed)
        with self.assertRaises(ValueError):
            tool.validate_gt200_debugger_lifecycle_capture(observed)

    def test_gt200_debugger_lifecycle_preserves_redacted_unresolved_command_identity(self):
        observed = self.gt200_debugger_lifecycle_observation()
        header = {'command': 0x83de0309, 'flags': 7, 'params_size': 4, 'status': 0,
                  'hClientPresent': True, 'hObjectPresent': False,
                  'client_object_equal': False,
                  'client_matches_prior_root_allocation': False,
                  'object_matches_prior_root_allocation': False,
                  'object_handle_matches_prior_debugger_allocation': False}
        exit_header = {**header, 'status': 1}
        observed['debugger_control_unresolved_candidate_count'] = 1
        observed['records'] = [{
            'tid': 77, 'fd': 6, 'fd_role': 'control', 'request': 0xc020462a,
            'packet_size': 32, 'operation': 'gt200_debugger_control_candidate',
            'debuggerTargetObjectClassWithinRoot': {
                'resolution': 'not-observed-live-object', 'classId': None},
            'entry': header, 'exit': exit_header, 'syscall_return': 0,
        }]
        expected = {'records': 1, 'allocations': 0, 'frees': 0, 'controls': 0,
                    'allocation_payload_snapshots': 0, 'unresolved_free_classes': 0,
                    'exception_mask_payload_snapshots': 0,
                    'resolved_exception_mask_controls': 0,
                    'unresolved_exception_mask_candidates': 1,
                    'unresolved_exception_mask_rm_statuses': [1],
                    'unresolved_control_candidates': 1}
        self.assertEqual(acceptance.validate_gt200_debugger_lifecycle_observation(observed), expected)
        self.assertEqual(tool.validate_gt200_debugger_lifecycle_capture(observed), expected)
        non_mask = copy.deepcopy(observed)
        non_mask['records'][0]['entry']['command'] = 0x83de030a
        non_mask['records'][0]['exit']['command'] = 0x83de030a
        non_mask_expected = {**expected,
                             'unresolved_exception_mask_candidates': 0,
                             'unresolved_exception_mask_rm_statuses': []}
        self.assertEqual(
            acceptance.validate_gt200_debugger_lifecycle_observation(non_mask),
            non_mask_expected)
        self.assertEqual(tool.validate_gt200_debugger_lifecycle_capture(non_mask),
                         non_mask_expected)
        for bad in ('raw_handle', 'non_debugger_command', 'wrong_relation'):
            candidate = copy.deepcopy(observed)
            if bad == 'raw_handle':
                candidate['records'][0]['entry']['hClient'] = 0x12345678
            elif bad == 'non_debugger_command':
                candidate['records'][0]['exit']['command'] = 0x20800001
            else:
                candidate['records'][0]['debuggerTargetObjectClassWithinRoot'] = {
                    'resolution': 'resolved', 'classId': 0x83de}
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    acceptance.validate_gt200_debugger_lifecycle_observation(candidate)
                with self.assertRaises(ValueError):
                    tool.validate_gt200_debugger_lifecycle_capture(candidate)

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
        self.assertTrue(report['managed_prefetch_report_contract_passed'])
        self.assertFalse(report['managed_prefetch_validated'])
        self.assertFalse(report['cuda_execution_validated'])
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
        self.assertTrue(report['cuda_graphs_report_contract_passed'])
        self.assertFalse(report['cuda_graphs_validated'])
        self.assertFalse(report['cuda_execution_validated'])
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

    def test_gt200_debugger_capture_cli_is_isolated_and_context_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / 'probe', root / 'module', root / 'observer'
            for path, content in ((probe, b'CPU fixture'), (module, b'CPU module'),
                                  (observer, b'CPU observer')):
                path.write_bytes(content)
            base = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--phase', 'context']
            with self.assertRaises(SystemExit) as missing:
                tool.parse_args([*base, '--gt200-debugger-alloc-capture',
                                 '--evidence', str(root / 'missing-observer.json')])
            self.assertEqual(missing.exception.code, 2)
            args = tool.parse_args([*base, '--ioctl-observer', str(observer),
                '--gt200-debugger-alloc-capture', '--evidence', str(root / 'debugger.json')])
            self.assertTrue(args.gt200_debugger_alloc_capture)
            wrong_phase = [*base]
            wrong_phase[wrong_phase.index('context')] = 'enumerate'
            with self.assertRaises(SystemExit) as wrong:
                tool.parse_args([*wrong_phase, '--ioctl-observer', str(observer),
                    '--gt200-debugger-alloc-capture', '--evidence', str(root / 'wrong-phase.json')])
            self.assertEqual(wrong.exception.code, 2)
            with self.assertRaises(SystemExit) as combined:
                tool.parse_args([*base, '--ioctl-observer', str(observer),
                    '--gt200-debugger-alloc-capture', '--device-alloc-capture',
                    '--evidence', str(root / 'combined.json')])
            self.assertEqual(combined.exception.code, 2)

    def test_gt200_debugger_lifecycle_cli_is_isolated_and_context_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / 'probe', root / 'module', root / 'observer'
            for path, content in ((probe, b'CPU fixture'), (module, b'CPU module'),
                                  (observer, b'CPU observer')):
                path.write_bytes(content)
            base = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--phase', 'context']
            with self.assertRaises(SystemExit) as missing:
                tool.parse_args([*base, '--gt200-debugger-lifecycle-capture',
                                 '--evidence', str(root / 'missing-observer.json')])
            self.assertEqual(missing.exception.code, 2)
            args = tool.parse_args([*base, '--ioctl-observer', str(observer),
                '--gt200-debugger-lifecycle-capture', '--evidence', str(root / 'lifecycle.json')])
            self.assertTrue(args.gt200_debugger_lifecycle_capture)
            wrong_phase = [*base]
            wrong_phase[wrong_phase.index('context')] = 'enumerate'
            with self.assertRaises(SystemExit) as wrong:
                tool.parse_args([*wrong_phase, '--ioctl-observer', str(observer),
                    '--gt200-debugger-lifecycle-capture', '--evidence', str(root / 'wrong-phase.json')])
            self.assertEqual(wrong.exception.code, 2)
            with self.assertRaises(SystemExit) as combined:
                tool.parse_args([*base, '--ioctl-observer', str(observer),
                    '--gt200-debugger-lifecycle-capture', '--gt200-debugger-alloc-capture',
                    '--evidence', str(root / 'combined.json')])
            self.assertEqual(combined.exception.code, 2)

    def test_hybrid_acceptance_cli_exposes_lifecycle_mode(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / 'tests/run_hybrid_acceptance.py'), '--help'],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--gt200-debugger-lifecycle', result.stdout)

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
        report, code = self.run_case(work_name='hybrid-rtx5080-work-rusd-map')
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
        self.assertEqual(report['remote_work_cleanup'], {
            'attempted': False, 'passed': False, 'removed': False,
            'retained_for_inspection': True,
        })
        self.assertTrue(Path(report['remote_work_directory']).is_dir())

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

    def test_unpinned_probe_is_rejected_before_any_driver_or_probe_command(self):
        data = b'unreviewed executable fixture'
        self.payload['artifacts']['probe'] = {
            'base64': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        report, code = self.run_case('unpinned-probe')
        self.assertEqual(code, 2)
        self.assertIn('reviewed pinned artifacts', report['error'])
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
    def main_with_fixture_pins(self, argv):
        probe = Path(argv[argv.index('--probe') + 1])
        module = Path(argv[argv.index('--module') + 1])
        with (patch.object(tool, 'PINNED_PROBE_SHA256',
                           hashlib.sha256(probe.read_bytes()).hexdigest()),
              patch.object(tool, 'PINNED_MODULE_SHA256',
                           hashlib.sha256(module.read_bytes()).hexdigest())):
            return tool.main(argv)

    def test_unpinned_probe_is_rejected_before_local_contract_execution_or_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
            probe.write_bytes(b'unreviewed executable fixture')
            probe.chmod(0o700)
            module.write_bytes(b'fixture fatbin')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--evidence', str(evidence)]
            calls = []
            with patch.object(tool.subprocess, 'run', side_effect=lambda *args, **kwargs:
                              calls.append(args)):
                self.assertEqual(tool.main(argv), 2)
            self.assertEqual(calls, [])
            report = json.loads(evidence.read_text())
            self.assertIn('reviewed pinned artifacts', report['error'])

    def test_remote_success_without_validated_qualification_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
            probe.write_bytes(b'CPU fixture probe')
            probe.chmod(0o700)
            module.write_bytes(b'CPU fixture module')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--evidence', str(evidence)]

            def fake_run(command, **kwargs):
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(command, 0, json.dumps(PROBE_CONTRACT), '')
                payload = json.loads(kwargs['input'])
                remote = {
                    'remote_script_sha256': payload['remote_script_sha256'],
                    'exit_code': 0,
                    'report_contract_validated': True,
                    'qualification': 'unrecognized-success',
                    'cuda_execution_validated': True,
                    'cuda_execution_validation_state': 'same-process hybrid CUDA validated',
                }
                return subprocess.CompletedProcess(command, 0, json.dumps(remote), '')

            with patch.object(tool.subprocess, 'run', side_effect=fake_run):
                self.assertEqual(self.main_with_fixture_pins(argv), 2)

            report = json.loads(evidence.read_text())
            self.assertEqual(report['qualification'], 'failed')
            self.assertFalse(report['report_contract_validated'])
            self.assertFalse(report['cuda_execution_validated'])
            self.assertEqual(report['cuda_execution_validation_state'],
                             tool.LOCAL_CUDA_EXECUTION_VALIDATION_STATE)
            self.assertEqual(report['remote']['cuda_execution_validation_state'],
                             'same-process hybrid CUDA validated')
            self.assertIn('supported, validated report qualification', report['error'])

    def test_phase_success_without_validated_qualification_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
            probe.write_bytes(b'CPU fixture probe')
            probe.chmod(0o700)
            module.write_bytes(b'CPU fixture module')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--phase', 'system-pageable-memory', '--evidence', str(evidence)]

            def fake_run(command, **kwargs):
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(command, 0, json.dumps(PROBE_CONTRACT), '')
                payload = json.loads(kwargs['input'])
                remote = {'remote_script_sha256': payload['remote_script_sha256'], 'exit_code': 0}
                return subprocess.CompletedProcess(command, 0, json.dumps(remote), '')

            with patch.object(tool.subprocess, 'run', side_effect=fake_run):
                self.assertEqual(self.main_with_fixture_pins(argv), 2)

            report = json.loads(evidence.read_text())
            self.assertFalse(report['report_contract_validated'])
            self.assertFalse(report['cuda_execution_validated'])
            self.assertEqual(report['qualification'], 'failed')
            self.assertIn('supported, validated report qualification', report['error'])

    def test_remote_qualification_must_match_requested_phase_and_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
            probe.write_bytes(b'CPU fixture probe')
            probe.chmod(0o700)
            module.write_bytes(b'CPU fixture module')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--phase', 'system-pageable-memory', '--evidence', str(evidence)]

            def fake_run(command, **kwargs):
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(command, 0, json.dumps(PROBE_CONTRACT), '')
                payload = json.loads(kwargs['input'])
                remote = {
                    'remote_script_sha256': payload['remote_script_sha256'],
                    'exit_code': 77,
                    'report_contract_validated': True,
                    'qualification': 'rtx5080-report-contract-valid-hybrid-incomplete',
                }
                return subprocess.CompletedProcess(command, 77, json.dumps(remote), '')

            with patch.object(tool.subprocess, 'run', side_effect=fake_run):
                self.assertEqual(self.main_with_fixture_pins(argv), 2)

            report = json.loads(evidence.read_text())
            self.assertFalse(report['report_contract_validated'])
            self.assertFalse(report['cuda_execution_validated'])
            self.assertEqual(report['qualification'], 'failed')
            self.assertIn('supported, validated report qualification', report['error'])

    def test_unpinned_fatbin_is_rejected_before_local_contract_execution_or_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
            probe.write_bytes(b'fixture probe that matches its supplied test pin')
            probe.chmod(0o700)
            module.write_bytes(b'unpinned fixture fatbin')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--evidence', str(evidence)]
            calls = []
            with (patch.object(tool, 'PINNED_PROBE_SHA256',
                               hashlib.sha256(probe.read_bytes()).hexdigest()),
                  patch.object(tool, 'PINNED_MODULE_SHA256', '0' * 64),
                  patch.object(tool.subprocess, 'run', side_effect=lambda *args, **kwargs:
                               calls.append(args))):
                self.assertEqual(tool.main(argv), 2)

            self.assertEqual(calls, [])
            report = json.loads(evidence.read_text())
            self.assertIn('reviewed pinned artifacts', report['error'])

    def test_remote_contract_claim_is_cleared_when_script_identity_mismatches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
            probe.write_bytes(b'CPU fixture probe')
            probe.chmod(0o700)
            module.write_bytes(b'CPU fixture module')
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--evidence', str(evidence)]

            def fake_run(command, **kwargs):
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(command, 0, json.dumps(PROBE_CONTRACT), '')
                remote = {
                    'remote_script_sha256': '0' * 64,
                    'exit_code': 77,
                    'report_contract_validated': True,
                    'qualification': 'rtx5080-report-contract-valid-hybrid-incomplete',
                }
                return subprocess.CompletedProcess(command, 77, json.dumps(remote), '')

            with patch.object(tool.subprocess, 'run', side_effect=fake_run):
                self.assertEqual(self.main_with_fixture_pins(argv), 2)

            report = json.loads(evidence.read_text())
            self.assertFalse(report['report_contract_validated'])
            self.assertFalse(report['cuda_execution_validated'])
            self.assertEqual(report['qualification'], 'failed')
            self.assertIn('remote script identity or exit status mismatch', report['error'])
            self.assertTrue(report['remote']['report_contract_validated'])

    def test_remote_response_requires_object_and_exact_integer_exit_status(self):
        cases = (
            ('array', [], 'remote result must be a JSON object'),
            ('boolean-exit', {'exit_code': False}, 'remote exit status must be an integer'),
        )
        for suffix, response, expected_error in cases:
            with self.subTest(response=suffix), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
                probe.write_bytes(b'CPU fixture probe')
                probe.chmod(0o700)
                module.write_bytes(b'CPU fixture module')
                argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                        '--pci', PCI, '--probe', str(probe), '--module', str(module),
                        '--evidence', str(evidence)]

                def fake_run(command, **kwargs):
                    if command == [str(probe.resolve()), '--contract']:
                        return subprocess.CompletedProcess(command, 0,
                                                           json.dumps(PROBE_CONTRACT), '')
                    payload = json.loads(kwargs['input'])
                    if isinstance(response, dict):
                        response['remote_script_sha256'] = payload['remote_script_sha256']
                    return subprocess.CompletedProcess(command, 0, json.dumps(response), '')

                with patch.object(tool.subprocess, 'run', side_effect=fake_run):
                    self.assertEqual(self.main_with_fixture_pins(argv), 2)
                report = json.loads(evidence.read_text())
                self.assertFalse(report['report_contract_validated'])
                self.assertFalse(report['cuda_execution_validated'])
                self.assertIn(expected_error, report['error'])

    def test_managed_accessed_by_phase_requires_an_isolated_ioctl_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module = root / 'probe', root / 'module'
            probe.write_bytes(b'CPU fixture')
            module.write_bytes(b'CPU fixture module')
            base = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--phase', 'managed-accessed-by']
            args = tool.parse_args(base + ['--ioctl-trace', '--evidence', str(root / 'new.json')])
            self.assertEqual(args.phase, 'managed-accessed-by')
            self.assertTrue(args.ioctl_trace)
            for extra in (None, '--managed-memory', '--device-alloc-capture'):
                with self.subTest(extra=extra), self.assertRaises(SystemExit):
                    argv = list(base)
                    if extra:
                        argv.append(extra)
                    argv += ['--evidence', str(root / f'{extra or "no-trace"}.json')]
                    tool.parse_args(argv)

    def test_system_pageable_phase_is_isolated_and_needs_no_ioctl_observer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module = root / 'probe', root / 'module'
            probe.write_bytes(b'CPU fixture')
            module.write_bytes(b'CPU fixture module')
            base = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--phase', 'system-pageable-memory']
            args = tool.parse_args(base + ['--evidence', str(root / 'new.json')])
            self.assertEqual(args.phase, 'system-pageable-memory')
            for extra in ('--managed-memory', '--ioctl-trace', '--device-alloc-capture'):
                with self.subTest(extra=extra), self.assertRaises(SystemExit) as error:
                    tool.parse_args(base + [extra, '--evidence', str(root / f'{extra[2:]}.json')])
                self.assertEqual(error.exception.code, 2)

    def test_system_pageable_phase_selection_reaches_remote_without_observer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
            probe.write_bytes(b'CPU fixture')
            module.write_bytes(b'CPU module fixture')
            probe.chmod(0o700)
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--phase', 'system-pageable-memory', '--evidence', str(evidence)]
            seen_payload = []

            def fake_ssh(command, **kwargs):
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(command, 0, json.dumps(PROBE_CONTRACT), '')
                payload = json.loads(kwargs['input'])
                seen_payload.append(payload)
                self.assertEqual(payload['phase'], 'system-pageable-memory')
                self.assertNotIn('observer', payload['artifacts'])
                remote = {'remote_script_sha256': payload['remote_script_sha256'], 'exit_code': 0,
                          'report_contract_validated': True,
                          'qualification': 'rtx5080-system-pageable-memory-report-contract-valid'}
                return subprocess.CompletedProcess(command, 0, json.dumps(remote), '')

            with patch.object(tool.subprocess, 'run', side_effect=fake_ssh):
                self.assertEqual(self.main_with_fixture_pins(argv), 0)
            self.assertEqual(len(seen_payload), 1)
            report = json.loads(evidence.read_text())
            self.assertTrue(report['phase_capture_requested'])
            self.assertEqual(report['phase'], 'system-pageable-memory')
            self.assertEqual(report['qualification'],
                             'rtx5080-system-pageable-memory-report-contract-valid')

    def test_stale_probe_without_exact_pci_map_stops_before_remote(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
            probe.write_bytes(b'CPU fixture probe')
            probe.chmod(0o700)
            module.write_bytes(b'CPU fixture module')
            legacy_contract = dict(PROBE_CONTRACT)
            legacy_contract['contract_version'] = 5
            legacy_contract['probe_report_fields'] = [
                field for field in PROBE_CONTRACT['probe_report_fields']
                if field != 'expected_device_pci_by_sm']
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--evidence', str(evidence)]
            remote_calls = []

            def fake_run(command, **kwargs):
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(command, 0,
                                                       json.dumps(legacy_contract), '')
                remote_calls.append(command)
                return subprocess.CompletedProcess(command, 0, '{}', '')

            with patch.object(tool.subprocess, 'run', side_effect=fake_run):
                result = self.main_with_fixture_pins(argv)

            self.assertEqual(result, 2)
            self.assertEqual(remote_calls, [])
            report = json.loads(evidence.read_text())
            self.assertIn('probe report contract is incompatible', report['error'].lower())
            self.assertNotIn('ssh_exit_code', report)

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
            expected_libcuda_sha256 = 'a' * 64
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module), '--managed-memory',
                    '--managed-prefetch', '--expected-libcuda-sha256', expected_libcuda_sha256,
                    '--identity-file', str(root / 'identity'),
                    '--evidence', str(evidence)]
            for invalid_hash in ('A' * 64, 'a' * 63):
                invalid_argv = list(argv)
                invalid_argv[invalid_argv.index('--expected-libcuda-sha256') + 1] = invalid_hash
                invalid_argv[invalid_argv.index('--evidence') + 1] = str(root / 'invalid.json')
                with self.subTest(invalid_hash=invalid_hash), self.assertRaises(SystemExit) as error:
                    tool.parse_args(invalid_argv)
                self.assertEqual(error.exception.code, 2)
            def fake_ssh(command, **kwargs):
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(command, 0,
                                                       json.dumps(PROBE_CONTRACT), '')
                self.assertTrue(evidence.exists())
                self.assertIn('StrictHostKeyChecking=yes', command)
                self.assertIn('BatchMode=yes', command)
                self.assertIn('HostKeyAlias=pc3', command)
                self.assertIn('IdentitiesOnly=yes', command)
                self.assertIn('/home/pc1/.ssh/fixture-key', command)
                self.assertEqual(command[-2], 'pc3@pc3')
                self.assertEqual(command[-3], '--')
                payload = json.loads(kwargs['input'])
                self.assertEqual(payload['uuid'], UUID)
                self.assertIs(payload['managed_memory'], True)
                self.assertIs(payload['managed_prefetch'], True)
                self.assertEqual(payload['expected_libcuda_sha256'], expected_libcuda_sha256)
                self.assertEqual(set(payload['artifacts']), {
                    'probe', 'module', 'runner', 'cuda_probe_contract.py'})
                self.assertEqual(payload['artifacts']['cuda_probe_contract.py']['sha256'],
                                 tool.identity(tool.ROOT / 'tools/cuda_probe_contract.py')['sha256'])
                result = {'remote_script_sha256': payload['remote_script_sha256'], 'exit_code': 77,
                          'report_contract_validated': True,
                          'qualification': 'rtx5080-report-contract-valid-hybrid-incomplete'}
                return subprocess.CompletedProcess(command, 77, json.dumps(result), '')
            with (patch.object(tool, 'validate_direct_identity_file',
                               return_value=Path('/home/pc1/.ssh/fixture-key')),
                  patch.object(tool.subprocess, 'run', side_effect=fake_ssh)):
                self.assertEqual(self.main_with_fixture_pins(argv), 77)
            report = json.loads(evidence.read_text())
            self.assertEqual(report['local_artifacts'], report['local_artifacts_after'])
            self.assertEqual(report['ssh_exit_code'], 77)
            self.assertEqual(report['ssh_identity_file_basename'], 'fixture-key')

            wrong_route = list(argv)
            wrong_route[wrong_route.index('--target') + 1] = 'pc6@pc6'
            wrong_route[wrong_route.index('--host-key-alias') + 1] = 'pc6'
            wrong_route[wrong_route.index('--evidence') + 1] = str(root / 'wrong-route.json')
            with self.assertRaises(SystemExit) as error:
                tool.parse_args(wrong_route)
            self.assertEqual(error.exception.code, 2)

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
                result = self.main_with_fixture_pins(argv)

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
                          'report_contract_validated': True,
                          'qualification': 'rtx5080-report-contract-valid-hybrid-incomplete',
                          'hardware_acceptance': {'ioctl_trace': {'trace': {
                              'trace_complete': True, 'summary': trace}}},
                          'ioctl_trace_transport': transport}
                return subprocess.CompletedProcess(command, 77, json.dumps(remote), '')
            with patch.object(tool.subprocess, 'run', side_effect=fake_ssh):
                self.assertEqual(self.main_with_fixture_pins(argv), 77)
            sidecar = evidence.with_suffix('.json.strace.gz')
            self.assertEqual(sidecar.read_bytes(), compressed)
            self.assertEqual(sidecar.stat().st_mode & 0o777, 0o600)
            report = json.loads(evidence.read_text())
            self.assertEqual(report['remote']['ioctl_trace_artifact']['raw_sha256'],
                             hashlib.sha256(raw).hexdigest())
            self.assertNotIn('ioctl_trace_transport', report['remote'])
            self.assertEqual(report['ssh_stdout'], '')

    def test_node_open_trace_transport_is_recomputed_and_saved_privately(self):
        import gzip
        import hashlib
        from tools import summarize_rm_ioctl_trace as trace_summary
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
            for path, data in ((probe, b'CPU fixture'), (module, b'CPU fixture module')):
                path.write_bytes(data)
            probe.chmod(0o700)
            raw = (b'7 openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3</dev/nvidiactl<char 195:255>>\n'
                   b'7 ioctl(3</dev/nvidiactl<char 195:255>>, 0xc01046d3, 0x123) = 0\n')
            compressed = gzip.compress(raw, mtime=0)
            summary = trace_summary.summarize_node_open_trace(raw)
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--evidence', str(evidence), '--phase', 'enumerate', '--ioctl-trace']
            def fake_ssh(command, **kwargs):
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(command, 0,
                                                       json.dumps(PROBE_CONTRACT), '')
                payload = json.loads(kwargs['input'])
                self.assertTrue(payload['ioctl_trace'])
                self.assertEqual(payload['phase'], 'enumerate')
                transport = {'gzip_base64': base64.b64encode(compressed).decode(),
                             'gzip_bytes': len(compressed),
                             'gzip_sha256': hashlib.sha256(compressed).hexdigest(),
                             'raw_bytes': len(raw), 'raw_sha256': hashlib.sha256(raw).hexdigest()}
                remote = {'remote_script_sha256': payload['remote_script_sha256'], 'exit_code': 0,
                          'report_contract_validated': True,
                          'qualification': 'rtx5080-cuda-phase-report-contract-valid',
                          'hardware_acceptance': {'phase': 'enumerate', 'ioctl_trace': {'trace': {
                              'trace_complete': True, 'summary': summary}}},
                          'ioctl_trace_transport': transport}
                return subprocess.CompletedProcess(command, 0, json.dumps(remote), '')
            with patch.object(tool.subprocess, 'run', side_effect=fake_ssh):
                self.assertEqual(self.main_with_fixture_pins(argv), 0)
            sidecar = evidence.with_suffix('.json.strace.gz')
            self.assertEqual(sidecar.read_bytes(), compressed)
            self.assertEqual(sidecar.stat().st_mode & 0o777, 0o600)
            report = json.loads(evidence.read_text())
            self.assertEqual(report['remote']['ioctl_trace_artifact']['summary']['schema'],
                             'nvidia-hybrid-node-open-trace-v1')
            self.assertNotIn('ioctl_trace_transport', report['remote'])

    def test_node_open_trace_rejects_remote_complete_claim_when_local_summary_is_incomplete(self):
        import gzip
        from tools import summarize_rm_ioctl_trace as trace_summary
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
            for path, data in ((probe, b'CPU fixture'), (module, b'CPU fixture module')):
                path.write_bytes(data)
            probe.chmod(0o700)
            raw = (b'7 openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3</dev/nvidiactl<char 195:255>>\n'
                   b'7 ioctl(3</dev/nvidiactl<char 195:255>>, 0xc01046d3, 0x123) = 0\n'
                   b'7 openat(4</dev>, "nvidia0", O_RDWR) = 9</dev/nvidia0<char 195:0>>\n')
            compressed = gzip.compress(raw, mtime=0)
            summary = trace_summary.summarize_node_open_trace(raw)
            self.assertFalse(summary['trace_complete'])
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--evidence', str(evidence), '--phase', 'enumerate', '--ioctl-trace']

            def fake_ssh(command, **kwargs):
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(command, 0, json.dumps(PROBE_CONTRACT), '')
                payload = json.loads(kwargs['input'])
                transport = {'gzip_base64': base64.b64encode(compressed).decode(),
                             'gzip_bytes': len(compressed),
                             'gzip_sha256': hashlib.sha256(compressed).hexdigest(),
                             'raw_bytes': len(raw), 'raw_sha256': hashlib.sha256(raw).hexdigest()}
                remote = {'remote_script_sha256': payload['remote_script_sha256'], 'exit_code': 0,
                          'report_contract_validated': True,
                          'qualification': 'rtx5080-cuda-phase-report-contract-valid',
                          'hardware_acceptance': {'phase': 'enumerate', 'ioctl_trace': {'trace': {
                              'trace_complete': True, 'summary': summary}}},
                          'ioctl_trace_transport': transport}
                return subprocess.CompletedProcess(command, 0, json.dumps(remote), '')

            with patch.object(tool.subprocess, 'run', side_effect=fake_ssh):
                self.assertEqual(self.main_with_fixture_pins(argv), 2)
            report = json.loads(evidence.read_text())
            self.assertIn('captured ioctl trace is incomplete', report['ioctl_trace_error'])

    def test_malformed_trace_transport_stdout_is_never_saved_raw(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, evidence = root / 'probe', root / 'module', root / 'report.json'
            for path, data in ((probe, b'CPU fixture'), (module, b'CPU fixture module')):
                path.write_bytes(data)
            probe.chmod(0o700)
            raw_response = 'MALFORMED_TRACE_RESPONSE_SECRET'
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--evidence', str(evidence), '--phase', 'enumerate', '--ioctl-trace']

            def fake_ssh(command, **kwargs):
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(command, 0, json.dumps(PROBE_CONTRACT), '')
                return subprocess.CompletedProcess(command, 0, raw_response, '')

            with patch.object(tool.subprocess, 'run', side_effect=fake_ssh):
                self.assertEqual(self.main_with_fixture_pins(argv), 2)
            report = json.loads(evidence.read_text())
            self.assertEqual(report['ssh_stdout'], '')
            self.assertEqual(report['ssh_stdout_bytes'], len(raw_response.encode()))
            self.assertEqual(report['ssh_stdout_sha256'], hashlib.sha256(raw_response.encode()).hexdigest())
            self.assertNotIn(raw_response, evidence.read_text())

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

    def test_enumeration_node_trace_is_an_isolated_remote_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module = root / 'probe', root / 'module'
            probe.write_bytes(b'CPU fixture')
            module.write_bytes(b'CPU fixture module')
            base = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--phase', 'enumerate', '--ioctl-trace']
            args = tool.parse_args(base + ['--evidence', str(root / 'new.json')])
            self.assertEqual(args.phase, 'enumerate')
            self.assertTrue(args.ioctl_trace)
            for extra in ('--managed-memory', '--map-memory'):
                with self.subTest(extra=extra), self.assertRaises(SystemExit) as error:
                    tool.parse_args(base + [extra, '--evidence', str(root / f'{extra[2:]}.json')])
                self.assertEqual(error.exception.code, 2)

    def test_enumeration_rm_control_headers_are_an_isolated_observer_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / 'probe', root / 'module', root / 'observer'
            for path in (probe, module, observer):
                path.write_bytes(b'CPU fixture')
            base = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--ioctl-observer', str(observer), '--phase', 'enumerate',
                    '--rm-control-headers']
            args = tool.parse_args(base + ['--evidence', str(root / 'new.json')])
            self.assertEqual(args.phase, 'enumerate')
            self.assertTrue(args.rm_control_headers)
            for extra in ('--ioctl-trace', '--managed-memory', '--binapi-control'):
                with self.subTest(extra=extra), self.assertRaises(SystemExit) as error:
                    tool.parse_args(base + [extra, '--evidence', str(root / (extra[2:] + '.json'))])
                self.assertEqual(error.exception.code, 2)

    def test_enumeration_rm_control_headers_selection_reaches_remote_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer, evidence = (root / 'probe', root / 'module',
                                                  root / 'observer', root / 'report.json')
            for path, data in ((probe, b'CPU probe'), (module, b'CPU module'),
                               (observer, b'CPU observer')):
                path.write_bytes(data)
            probe.chmod(0o700)
            argv = ['--target', 'pc3@pc3', '--host-key-alias', 'pc3', '--gpu-uuid', UUID,
                    '--pci', PCI, '--probe', str(probe), '--module', str(module),
                    '--ioctl-observer', str(observer), '--phase', 'enumerate',
                    '--rm-control-headers', '--evidence', str(evidence)]

            def fake_ssh(command, **kwargs):
                if command == [str(probe.resolve()), '--contract']:
                    return subprocess.CompletedProcess(command, 0, json.dumps(PROBE_CONTRACT), '')
                payload = json.loads(kwargs['input'])
                self.assertTrue(payload['rm_control_headers_capture'])
                self.assertEqual(payload['phase'], 'enumerate')
                self.assertIn('observer', payload['artifacts'])
                remote = {'remote_script_sha256': payload['remote_script_sha256'], 'exit_code': 0,
                          'report_contract_validated': True,
                          'qualification': 'rtx5080-cuda-phase-report-contract-valid'}
                return subprocess.CompletedProcess(command, 0, json.dumps(remote), '')

            with patch.object(tool.subprocess, 'run', side_effect=fake_ssh):
                self.assertEqual(self.main_with_fixture_pins(argv), 0)
            report = json.loads(evidence.read_text())
            self.assertTrue(report['rm_control_headers_capture_requested'])
            self.assertEqual(report['remote_script_sha256'], report['remote']['remote_script_sha256'])

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
