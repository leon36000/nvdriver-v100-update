# SPDX-License-Identifier: MIT
"""Real ptrace integration on CPU-only /dev/null synthetic packets."""
import hashlib
import json
from pathlib import Path
import subprocess
import signal
import time
import tempfile
import unittest
import importlib.util
import uuid

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04'
R595_SOURCE = ROOT / 'build/research/open-gpu-kernel-modules-595.99.02/source/open-gpu-kernel-modules-595.99.02'
spec = importlib.util.spec_from_file_location('rm_ioctl_observer_builder',
                                              ROOT / 'tools/build_rm_ioctl_observer.py')
observer_builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer_builder)

class RmIoctlObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.observer = Path(cls.tmp.name) / 'observer'
        cls.child = Path(cls.tmp.name) / 'child'
        cls.uvm_child = Path(cls.tmp.name) / 'uvm-child'
        flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-DNVRM=1']
        flags += ['-I' + str(SOURCE / p) for p in (
            'src/common/sdk/nvidia/inc', 'src/common/inc',
            'src/nvidia/arch/nvalloc/unix/include', 'kernel-open/common/inc',
            'kernel-open/nvidia-uvm')]
        for source, binary in ((ROOT / 'src/rm_ioctl_observer.c', cls.observer),
                               (ROOT / 'tests/fixtures/rm_ioctl_observer_child.c', cls.child),
                               (ROOT / 'tests/fixtures/uvm_vaspace_observer_child.c', cls.uvm_child)):
            result = subprocess.run(['cc', *flags, str(source), '-pthread', '-o', str(binary)],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode:
                cls.tmp.cleanup()
                raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def observe(self, mode, selected=True, seconds=10, gpu_id_info=False, attached_ids=False,
                rm_control=False, probed_ids=False, channel_alloc=False, map_memory=False,
                rusd_alloc=False, p2p_alloc=False, p2p_control=False, gpu_path=None,
                binapi_control=False, device_alloc=False, rm_control_headers=False,
                fabric_status=False, system_features=False, uvm_vaspace_fd=False,
                sync_boost_groups=False, debugger_alloc=False,
                debugger_lifecycle=False):
        output = Path(self.tmp.name) / ('report-' + uuid.uuid4().hex + '-' + mode + '-' + str(selected) + '-' +
                                        str(gpu_id_info) + '-' + str(attached_ids) + '-' +
                                        str(rm_control) + '-' + str(probed_ids) + '-' +
                                        str(map_memory) + '-' + str(rusd_alloc) + '-' +
                                        str(p2p_alloc) + '-' + str(p2p_control) + '-' +
                                        str(binapi_control) + '-' + str(rm_control_headers) +
                                        '-' + str(fabric_status) + '-' + str(system_features) +
                                        '-' + str(uvm_vaspace_fd) + '-' +
                                        str(sync_boost_groups) + '-' +
                                        str(debugger_lifecycle) + '.json')
        args = [str(self.observer), '--output', str(output), '--timeout-seconds', str(seconds)]
        if selected:
            args += ['--control-path', '/dev/null']
        if gpu_id_info:
            args += ['--gpu-id-info']
        if attached_ids:
            args += ['--attached-ids']
        if rm_control:
            args += ['--rm-control']
        if rm_control_headers:
            args += ['--rm-control-headers']
        if fabric_status:
            args += ['--fabric-status']
        if system_features:
            args += ['--system-features']
        if sync_boost_groups:
            args += ['--sync-boost-groups']
        if debugger_alloc:
            args += ['--gt200-debugger-alloc']
        if debugger_lifecycle:
            args += ['--gt200-debugger-lifecycle']
        if uvm_vaspace_fd:
            args += ['--uvm-vaspace-fd', '--uvm-path', '/dev/null']
        if probed_ids:
            args += ['--probed-ids']
        if channel_alloc:
            args += ['--channel-alloc']
        if map_memory:
            args += ['--map-memory']
        if rusd_alloc:
            args += ['--rusd-alloc']
        if p2p_alloc:
            args += ['--p2p-alloc']
        if p2p_control:
            args += ['--p2p-control']
        if binapi_control:
            args += ['--binapi-control']
        if device_alloc:
            args += ['--device-alloc']
        if gpu_path is not None:
            args += ['--gpu-path', gpu_path]
        child = self.uvm_child if uvm_vaspace_fd else self.child
        result = subprocess.run([*args, '--', str(child), mode], capture_output=True,
                                text=True, timeout=seconds + 5)
        return result, json.loads(output.read_text()) if output.exists() else {}

    def assert_redacted_numeric_values(self, report, forbidden_values):
        """Check typed report leaves without matching volatile ptrace TIDs."""
        forbidden = set(forbidden_values)

        def visit(value, path=()):
            if isinstance(value, dict):
                for key, child in value.items():
                    # TIDs are kernel-assigned process metadata and can contain
                    # arbitrary decimal substrings unrelated to captured data.
                    if key == 'tid':
                        continue
                    visit(child, path + (str(key),))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, path + (str(index),))
            elif type(value) is int:
                self.assertNotIn(value, forbidden,
                                 'forbidden raw numeric value at ' + '/'.join(path))
            elif isinstance(value, str):
                for secret in forbidden:
                    self.assertNotIn(str(secret), value,
                                     'forbidden raw numeric text at ' + '/'.join(path))

    def test_pinned_layouts_and_entry_exit_fields(self):
        # SDK payload size/offset checks are compiled by the observer, not re-created
        # locally. Exact hashes pin the headers from the recorded R580 baseline.
        pinned = {
            'src/common/sdk/nvidia/inc/nvos.h': '07f9f453afbf080750663abc9e04e2d3b55500887303ba03bd6855916d2405bd',
            'src/common/sdk/nvidia/inc/nvtypes.h': '57bf6ee0fc9f604e7d6f224a3b861521526bb0b115e99a33e5704d881daca708',
            'src/nvidia/arch/nvalloc/unix/include/nv-ioctl-numbers.h': '7f449a019521f2f858a2d485eed1ee0fa4a8ffc82c9aecd484be5d3f6821f87d',
            'src/nvidia/arch/nvalloc/unix/include/nv_escape.h': '12850ee7368dbfeba1e2392f9ff7fb44563d88ed12cbf478d0c0f61a03763570',
        }
        for name, expected in pinned.items():
            self.assertEqual(hashlib.sha256((SOURCE / name).read_bytes()).hexdigest(), expected)
        channel_header_sha = 'f0211fbc8bf3f80841f699bf4ccb776d32517308782dfb3c8e99c7652986b5ab'
        self.assertIn('NVIDIA_VERSION = 580.178.04',
                      (SOURCE / 'version.mk').read_text(encoding='utf-8'))
        self.assertIn('NVIDIA_VERSION = 595.99.02',
                      (R595_SOURCE / 'version.mk').read_text(encoding='utf-8'))
        for tree in (SOURCE, R595_SOURCE):
            self.assertEqual(hashlib.sha256((tree / 'src/common/sdk/nvidia/inc/alloc/alloc_channel.h').read_bytes()).hexdigest(),
                             channel_header_sha)
            classes = (tree / 'src/nvidia/src/kernel/rmapi/resource_list.h').read_text(encoding='utf-8')
            for klass in ('VOLTA_CHANNEL_GPFIFO_A', 'BLACKWELL_CHANNEL_GPFIFO_A'):
                marker = '/* External Class         */ ' + klass
                position = classes.index(marker)
                next_entry = classes.index('RS_ENTRY(', position + len(marker))
                self.assertIn('RS_REQUIRED(NV_CHANNEL_ALLOC_PARAMS)', classes[position:next_entry])
        result, report = self.observe('basic')
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertTrue(report['trace_complete'])
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v1')
        self.assertEqual(report['architecture'], 'x86_64')
        self.assertEqual(report['pointer_bits'], 64)
        self.assertFalse(report['nested_pointers_read'])
        self.assertFalse(report['fd_identity_tracking'])
        self.assertEqual(report['errors'], [])
        self.assertIn('child stdout passed', result.stdout)
        self.assertIn('child stderr passed', result.stderr)
        records = report['records']
        self.assertEqual([r['packet_size'] for r in records], [32, 48, 16])
        self.assertEqual([r['request'] for r in records], [0xc020462b, 0xc030462b, 0xc0104629])
        for record in records:
            self.assertIsInstance(record['fd'], int)
            self.assertGreaterEqual(record['fd'], 0)
            self.assertEqual(record['entry'], record['exit'])
            self.assertEqual(record['syscall_return'], -25) # ENOTTY, not RM execution
        self.assertEqual(len({r['fd'] for r in records}), 1)
        p21, p64, freep = [r['entry'] for r in records]
        self.assertEqual(p21, dict(layout='NVOS21', hRoot=7, hObjectParent=17,
            hObjectNew=18, hClass=65, root_class=True, pAllocParms=0x123456789abcdef0,
            paramsSize=23, status=0xfedcba98))
        self.assertEqual(p64, dict(layout='NVOS64', hRoot=8, hObjectParent=0,
            hObjectNew=0, hClass=0, root_class=True, pAllocParms=0,
            pRightsRequested=0xfedcba9876543210, paramsSize=99, flags=1, status=0xabcdef01))
        self.assertEqual(freep, dict(layout='NVOS00', hRoot=9, hObjectParent=33,
            hObjectOld=44, status=0x11223344))

    def test_uvm_vaspace_fd_observer_reads_only_field_and_redacts_identifiers(self):
        result, report = self.observe('matches-control', uvm_vaspace_fd=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertTrue(report['trace_complete'])
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v31')
        self.assertTrue(report['fd_identity_tracking'])
        self.assertTrue(report['fd_identity_capture_complete'])
        self.assertEqual(report['uvm_vaspace_records_seen'], 1)
        self.assertEqual(report['uvm_map_external_records_seen'], 1)
        record = report['records'][0]
        self.assertEqual(record['operation'], 'uvm_register_gpu_vaspace')
        self.assertEqual(record['request'], 25)
        self.assertTrue(record['uvm_fd_matches_selected_node_at_entry'])
        self.assertTrue(record['rm_ctrl_fd_matches_control_node_at_entry'])
        self.assertTrue(record['rm_ctrl_fd_matches_control_node_at_exit'])
        self.assertTrue(record['rm_ctrl_fd_identity_tracked_at_entry'])
        self.assertTrue(record['rm_ctrl_fd_same_file_identity_at_exit'])
        self.assertTrue(record['rm_ctrl_fd_field_unchanged_at_exit'])
        self.assertTrue(record['rm_ctrl_fd_no_mutation_pending_at_entry'])
        self.assertTrue(record['rm_ctrl_fd_no_mutation_pending_at_exit'])
        self.assertFalse(record['rm_ctrl_fd_is_negative'])
        self.assertEqual(record['syscall_return'], -25)  # ptrace syscall rval is -ENOTTY
        map_record = report['records'][1]
        self.assertEqual(map_record['operation'], 'uvm_map_external_allocation')
        self.assertEqual(map_record['request'], 33)
        self.assertTrue(map_record['field_read_at_entry'])
        self.assertTrue(map_record['rm_ctrl_fd_matches_control_node_at_entry'])
        self.assertTrue(map_record['rm_ctrl_fd_matches_control_node_at_exit'])
        self.assertTrue(map_record['rm_ctrl_fd_same_file_identity_at_exit'])
        self.assertTrue(map_record['rm_ctrl_fd_field_unchanged_at_exit'])
        self.assertEqual(map_record['syscall_return'], -25)
        encoded = json.dumps(report)
        for field in ('"tid"', '"fd"', '"rmCtrlFd"', '"pointer"', '"address"'):
            self.assertNotIn(field, encoded)

    def test_uvm_vaspace_fd_observer_reports_unmatched_control_descriptor(self):
        result, report = self.observe('negative-control', uvm_vaspace_fd=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['uvm_vaspace_records_seen'], 1)
        record = report['records'][0]
        self.assertTrue(record['uvm_fd_matches_selected_node_at_entry'])
        self.assertFalse(record['rm_ctrl_fd_matches_control_node_at_entry'])
        self.assertFalse(record['rm_ctrl_fd_matches_control_node_at_exit'])
        self.assertTrue(record['rm_ctrl_fd_is_negative'])
        self.assertFalse(record['rm_ctrl_fd_identity_tracked_at_entry'])
        self.assertFalse(record['rm_ctrl_fd_same_file_identity_at_exit'])
        self.assertTrue(record['rm_ctrl_fd_field_unchanged_at_exit'])
        map_record = report['records'][1]
        self.assertEqual(map_record['operation'], 'uvm_map_external_allocation')
        self.assertTrue(map_record['rm_ctrl_fd_is_negative'])

    def test_uvm_fd_identity_survives_threaded_and_reopened_control_lifecycle(self):
        result, report = self.observe('threaded-control-reopen', uvm_vaspace_fd=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertTrue(report['trace_complete'])
        self.assertTrue(report['fd_identity_capture_complete'])
        self.assertEqual(report['uvm_vaspace_records_seen'], 1)
        self.assertEqual(report['uvm_map_external_records_seen'], 1)
        record = report['records'][0]
        self.assertTrue(record['rm_ctrl_fd_identity_tracked_at_entry'])
        self.assertTrue(record['rm_ctrl_fd_same_file_identity_at_exit'])
        self.assertTrue(record['rm_ctrl_fd_field_unchanged_at_exit'])
        self.assertTrue(report['records'][1]['rm_ctrl_fd_same_file_identity_at_exit'])
        encoded = json.dumps(report)
        for raw_key in ('"file_id":', '"raw_fd":', '"rmCtrlFd":',
                        '"tid":', '"fd":'):
            self.assertNotIn(raw_key, encoded)

    def test_uvm_fd_identity_capture_fails_closed_after_file_table_unshare(self):
        result, report = self.observe('unshare-control-table', uvm_vaspace_fd=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertTrue(report['trace_complete'])
        self.assertFalse(report['fd_identity_capture_complete'])
        self.assertTrue(report['records'][0]['rm_ctrl_fd_identity_tracked_at_entry'])

    def test_uvm_fd_tracker_checks_pending_close_dup_and_close_range_mutations(self):
        source = (ROOT / 'src/rm_ioctl_observer.c').read_text()
        self.assertIn('static int fd_identity_transition_pending(int fd)', source)
        helper = source.split('static int fd_identity_transition_pending(int fd)', 1)[1]
        helper = helper.split('static int snapshot_map_memory', 1)[0]
        for token in ('r->is_close', 'FD_OP_DUP',
                      'task->fd_op_target==fd', 'FD_OP_CLOSE_RANGE',
                      'task->fd_op_arg0', 'task->fd_op_arg1'):
            self.assertIn(token, helper)
        self.assertGreaterEqual(source.count('fd_identity_transition_pending('), 3)

    def test_rusd_payload_abi_and_required_class_metadata_match_r580_r595(self):
        evidence = observer_builder.rusd_payload_abi_evidence()
        self.assertTrue(evidence['byte_identical'], evidence)
        self.assertEqual(evidence['measurements'], {
            'R580': {'size_bytes': 8, 'polled_data_mask_offset': 0},
            'R595': {'size_bytes': 8, 'polled_data_mask_offset': 0}})
        self.assertEqual(evidence['required_classes'], {'R580': True, 'R595': True})
        self.assertEqual(evidence['poll_mask_constants'], {
            'R580': {'CLOCK': 1, 'PERF': 2, 'MEMORY': 4, 'POWER': 8,
                     'THERMAL': 16, 'PCI': 32, 'FAN': 64},
            'R595': {'CLOCK': 1, 'PERF': 2, 'MEMORY': 4, 'POWER': 8,
                     'THERMAL': 16, 'PCI': 32, 'FAN': 64}})

    def test_p2p_payload_abi_and_optional_class_metadata_match_r580_r595(self):
        evidence = observer_builder.p2p_payload_abi_evidence()
        self.assertTrue(evidence['byte_identical'], evidence)
        self.assertEqual(evidence['measurements'], {
            'R580': {'size_bytes': 4, 'flags_offset': 0},
            'R595': {'size_bytes': 4, 'flags_offset': 0}})
        self.assertEqual(evidence['optional_classes'], {'R580': True, 'R595': True})
        self.assertEqual(evidence['type_constants'], {
            'R580': {'PROPRIETARY': 0, 'BAR1': 1, 'NVLINK': 2},
            'R595': {'PROPRIETARY': 0, 'BAR1': 1, 'NVLINK': 2}})

    def test_p2p_control_payload_abi_matches_r580_r595(self):
        evidence = observer_builder.p2p_control_payload_abi_evidence()
        self.assertTrue(evidence['byte_identical'], evidence)
        expected = {
            'commands': {'register_va_space': 0x503c0102,
                         'unregister_va_space': 0x503c0103,
                         'register_vidmem': 0x503c0104,
                         'unregister_vidmem': 0x503c0105,
                         'register_pid': 0x503c0106},
            'register_va_space': {'size_bytes': 16, 'hVASpace_offset': 0,
                                  'vaSpaceToken_offset': 8},
            'unregister_va_space_bytes': 4,
            'register_vidmem': {'size_bytes': 32, 'hMemory_offset': 0,
                                'address_offset': 8, 'size_offset': 16,
                                'offset_offset': 24},
            'unregister_vidmem_and_register_pid_bytes': 8,
        }
        self.assertEqual(evidence['measurements'], {'R580': expected, 'R595': expected})

    def test_threads_and_signal_delivery_keep_pairing(self):
        result, report = self.observe('threads')
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertTrue(report['trace_complete'])
        self.assertEqual(len(report['records']), 18)
        self.assertEqual(len({r['tid'] for r in report['records']}), 2)
        for record in report['records']:
            self.assertEqual(record['entry'], record['exit'])
            self.assertEqual(record['syscall_return'], -25)
        result, report = self.observe('signal')
        self.assertEqual(result.returncode, 0, str(report))
        self.assertEqual(len(report['records']), 3)

    def test_default_target_ignores_other_devices(self):
        result, report = self.observe('basic', selected=False)
        self.assertEqual(result.returncode, 0, str(report))
        self.assertEqual(report['control_path'], '/dev/nvidiactl')
        self.assertEqual(report['records'], [])

    def test_gpu_id_info_capture_is_command_bounded_and_redacts_pointers(self):
        result, report = self.observe('id-info', gpu_id_info=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v3')
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['nested_pointer_scope'],
                         'exact NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 payload only; addresses omitted')
        self.assertEqual(report['errors'], [])
        self.assertEqual([row['operation'] for row in report['records']],
                         ['alloc', 'alloc', 'free', 'gpu_id_info_v2', 'gpu_id_info_v2'])
        direct, xfer = report['records'][-2:]
        for row in (direct, xfer):
            self.assertEqual(row['syscall_return'], -25)  # /dev/null: no RM execution
            self.assertEqual(row['entry']['command'], 0x205)
            self.assertEqual(row['entry']['params_size'], 32)
            self.assertTrue(row['entry']['client_handle_present'])
            self.assertTrue(row['entry']['object_handle_present'])
            self.assertFalse(row['entry']['client_matches_prior_root_allocation'])
            self.assertFalse(row['entry']['object_matches_prior_root_allocation'])
            self.assertFalse(row['entry']['client_object_equal'])
            self.assertNotIn('params_address', row)
            self.assertNotIn('xfer_payload_address', row)
        self.assertEqual(direct['request'], 0xc020462a)
        self.assertEqual(direct['entry']['gpuId'], 77)
        self.assertEqual(direct['exit']['gpuId'], 77)
        self.assertEqual(direct['entry']['numaId'], 8)
        self.assertEqual(xfer['request'], 0xc01046d3)
        self.assertEqual(xfer['entry']['gpuId'], 88)
        self.assertEqual(xfer['exit']['gpuInstance'], 17)

        # The default mode keeps its prior no-nested-pointer boundary.
        plain, old = self.observe('id-info')
        self.assertEqual(plain.returncode, 0, str(old))
        self.assertEqual(old['schema'], 'nvidia-hybrid-rm-ioctl-observer-v1')
        self.assertFalse(old['nested_pointers_read'])
        self.assertEqual([row['operation'] for row in old['records']], ['alloc', 'alloc', 'free'])

    def test_gpu_id_info_bad_pointer_fails_without_leaking_address(self):
        result, report = self.observe('id-info-bad-pointer', gpu_id_info=True)
        self.assertEqual(result.returncode, 2, str(report))
        self.assertFalse(report['trace_complete'])
        self.assertIn('cannot read GPU ID-info payload', report['errors'][0])
        self.assertEqual(len(report['records']), 4)
        self.assertIsNone(report['records'][-1]['entry'])
        self.assertNotIn('params_address', report['records'][-1])
        self.assertNotIn('xfer_payload_address', report['records'][-1])

    def test_attached_ids_capture_is_command_bounded_and_redacts_pointers(self):
        result, report = self.observe('attached-ids', attached_ids=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v4')
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['nested_pointer_scope'],
                         'exact NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS payload only; addresses omitted')
        self.assertEqual(report['errors'], [])
        self.assertEqual([row['operation'] for row in report['records']],
                         ['alloc', 'alloc', 'free', 'gpu_attached_ids', 'gpu_attached_ids'])
        direct, xfer = report['records'][-2:]
        for row in (direct, xfer):
            self.assertEqual(row['syscall_return'], -25)
            self.assertEqual(row['entry']['command'], 0x201)
            self.assertEqual(row['entry']['params_size'], 128)
            self.assertTrue(row['entry']['client_handle_present'])
            self.assertTrue(row['entry']['object_handle_present'])
            self.assertTrue(row['entry']['client_object_equal'])
            self.assertNotIn('params_address', row)
            self.assertNotIn('xfer_payload_address', row)
        self.assertEqual(direct['request'], 0xc020462a)
        self.assertEqual(direct['entry']['gpuIds'][:3], [7, 11, 0xffffffff])
        self.assertEqual(direct['entry'], direct['exit'])
        self.assertEqual(xfer['request'], 0xc01046d3)
        self.assertEqual(xfer['entry']['gpuIds'][:2], [22, 0xffffffff])
        self.assertEqual(xfer['entry'], xfer['exit'])

    def test_attached_ids_bad_pointer_fails_without_leaking_address(self):
        result, report = self.observe('attached-ids-bad-pointer', attached_ids=True)
        self.assertEqual(result.returncode, 2, str(report))
        self.assertFalse(report['trace_complete'])
        self.assertIn('cannot read attached-ID payload', report['errors'][0])
        self.assertEqual(len(report['records']), 4)
        self.assertIsNone(report['records'][-1]['entry'])
        self.assertNotIn('params_address', report['records'][-1])
        self.assertNotIn('xfer_payload_address', report['records'][-1])

    def test_probed_ids_capture_reads_only_the_exact_fixed_payload(self):
        result, report = self.observe('probed-ids', probed_ids=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v6')
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['nested_pointer_scope'],
                         'exact NV0000_CTRL_CMD_GPU_GET_PROBED_IDS payload only; addresses omitted')
        self.assertNotIn('payload_scope', report)
        self.assertEqual(report['errors'], [])
        self.assertEqual([row['operation'] for row in report['records']],
                         ['alloc', 'alloc', 'free', 'gpu_probed_ids', 'gpu_probed_ids'])
        direct, xfer = report['records'][-2:]
        for row in (direct, xfer):
            self.assertEqual(row['syscall_return'], -25)
            self.assertEqual(row['entry']['command'], 0x214)
            self.assertEqual(row['entry']['params_size'], 384)
            self.assertTrue(row['entry']['client_object_equal'])
            self.assertNotIn('params_address', row)
            self.assertNotIn('xfer_payload_address', row)
        self.assertEqual(direct['entry']['gpuIds'][:2], [7, 0xffffffff])
        self.assertEqual(direct['entry']['excludedGpuIds'][:2], [13, 0xffffffff])
        self.assertEqual(direct['entry']['gpuFlags'][:2], [1, 0])
        self.assertEqual(direct['entry'], direct['exit'])
        self.assertEqual(xfer['entry']['gpuIds'][:2], [22, 0xffffffff])
        self.assertEqual(xfer['entry']['excludedGpuIds'][:2], [0xffffffff, 0xffffffff])
        self.assertEqual(xfer['entry'], xfer['exit'])

    def test_probed_ids_bad_pointer_and_size_fail_closed_without_leaking(self):
        for mode in ('probed-ids-bad-pointer', 'probed-ids-bad-size'):
            with self.subTest(mode=mode):
                result, report = self.observe(mode, probed_ids=True)
                self.assertEqual(result.returncode, 2, str(report))
                self.assertFalse(report['trace_complete'])
                self.assertIn('probed-ID payload', report['errors'][0])
                self.assertIsNone(report['records'][-1]['entry'])
                self.assertNotIn('params_address', report['records'][-1])
                self.assertNotIn('xfer_payload_address', report['records'][-1])

    def test_probed_ids_combined_capture_declares_only_the_three_fixed_metadata_payloads(self):
        result, report = self.observe('probed-ids', gpu_id_info=True,
                                      attached_ids=True, rm_control=True,
                                      probed_ids=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v6')
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['nested_pointer_scope'],
                         'exact NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2, '
                         'NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS, and '
                         'NV0000_CTRL_CMD_GPU_GET_PROBED_IDS payloads only; addresses omitted')
        self.assertEqual(report['payload_scope'],
                         'RM_CONTROL headers plus explicitly selected fixed metadata payloads; '
                         'other nested parameters omitted')
        self.assertEqual([row['operation'] for row in report['records'][-2:]],
                         ['gpu_probed_ids', 'gpu_probed_ids'])

    def test_unrelated_rm_control_is_ignored_without_nested_read(self):
        result, report = self.observe('other-control', gpu_id_info=True)
        self.assertEqual(result.returncode, 0, str(report))
        self.assertEqual([row['operation'] for row in report['records']], ['alloc', 'alloc', 'free'])
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['errors'], [])

    def test_rm_control_headers_are_captured_without_dereferencing_nested_parameters(self):
        result, report = self.observe('rm-control', rm_control=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v5')
        self.assertFalse(report['nested_pointers_read'])
        self.assertEqual(report['payload_scope'],
                         'fixed NVOS54 RM_CONTROL headers only; nested parameter payloads omitted')
        self.assertEqual(report['errors'], [])
        self.assertEqual([row['operation'] for row in report['records']],
                         ['alloc', 'alloc', 'free', 'rm_control_header', 'rm_control_header'])
        direct, xfer = report['records'][-2:]
        self.assertEqual(direct['request'], 0xc020462a)
        self.assertEqual(xfer['request'], 0xc01046d3)
        for record in (direct, xfer):
            self.assertEqual(record['syscall_return'], -25)
            self.assertEqual(record['entry'], record['exit'])
            self.assertNotIn('params_address', record)
            self.assertNotIn('xfer_payload_address', record)
            self.assertNotIn('params', record['entry'])
        self.assertEqual(direct['entry'], {
            'command': 0x205, 'flags': 3, 'params_size': 4096, 'status': 41,
            'hClient': 71, 'hObject': 72, 'client_object_equal': False,
            'client_matches_prior_root_allocation': False,
            'object_matches_prior_root_allocation': False,
        })
        self.assertEqual(xfer['entry'], {
            'command': 0x12345678, 'flags': 5, 'params_size': 8192, 'status': 51,
            'hClient': 81, 'hObject': 82, 'client_object_equal': False,
            'client_matches_prior_root_allocation': False,
            'object_matches_prior_root_allocation': False,
        })

        plain, default = self.observe('rm-control')
        self.assertEqual(plain.returncode, 0, str(default))
        self.assertEqual(default['schema'], 'nvidia-hybrid-rm-ioctl-observer-v1')
        self.assertEqual([row['operation'] for row in default['records']], ['alloc', 'alloc', 'free'])

    def test_sync_boost_group_capture_omits_stale_input_after_failed_ioctl(self):
        result, report = self.observe('sync-boost-groups', sync_boost_groups=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertTrue(report['trace_complete'])
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v32')
        # The synthetic fixture uses /dev/null, so both RM_CONTROL ioctls fail
        # with ENOTTY. Their seeded input counts must not be reported as output.
        self.assertFalse(report['nested_pointers_read'])
        self.assertEqual(report['sync_boost_group_payload_snapshots_read'], 0)
        self.assertEqual(report['payload_scope'],
                         'exact root-global SYNC_GPU_BOOST_GROUP_INFO groupCount field only; '
                         'inline GPU IDs and group payloads omitted; raw addresses and handles omitted')
        rows = report['records']
        self.assertEqual([row['request'] for row in rows],
                         [0xc020462a, 0xc01046d3])
        self.assertEqual([row['entry']['command'] for row in rows], [0xa04, 0xa04])
        self.assertEqual([row['exit']['command'] for row in rows], [0xa04, 0xa04])
        self.assertEqual([row['operation'] for row in rows],
                         ['rm_control_sync_boost_groups'] * 2)
        self.assertTrue(all(row['syscall_return'] == -25 for row in rows))
        self.assertTrue(all(row['exit']['status'] == 0xabcdef01 for row in rows))
        self.assertTrue(all('syncBoostGroupCount' not in row['exit'] for row in rows))
        serialized = json.dumps(report)
        for forbidden in ('"gpuIds"', '"boostGroupId"', '"bBridgeless"',
                          '"params_address"', '"xfer_payload_address"'):
            self.assertNotIn(forbidden, serialized)

    def test_sync_boost_failed_observer_record_passes_the_production_summarizer(self):
        result, report = self.observe('sync-boost-groups', sync_boost_groups=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['control_path'], '/dev/null')
        spec = importlib.util.spec_from_file_location(
            'pc3_rtx5080_ioctl_shape_reference',
            ROOT / 'tools/run_pc3_rtx5080_ioctl_shape_reference.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)

        summary = runner.summarize_sync_boost_observation(
            report, 0, expected_control_path='/dev/null')

        self.assertEqual(summary['failed_record_count'], 2)
        self.assertEqual(summary['successful_record_count'], 0)
        self.assertEqual(summary['sync_boost_group_payload_snapshots_read'], 0)
        self.assertEqual(summary['group_counts'], [])
        self.assertTrue(all('syncBoostGroupCount' not in row['exit']
                            for row in summary['records']))

    def test_sync_boost_group_capture_rejects_wrong_size_bad_pointer_and_overflow(self):
        for mode in ('sync-boost-groups-bad-size',
                     'sync-boost-groups-bad-pointer',
                     'sync-boost-groups-bad-count'):
            with self.subTest(mode=mode):
                result, report = self.observe(mode, sync_boost_groups=True)
                self.assertEqual(result.returncode, 0, str(report))
                self.assertTrue(report['trace_complete'])
                self.assertEqual(report['sync_boost_group_payload_snapshots_read'], 0)
                self.assertEqual(report['records'][0]['syscall_return'], -25)
                self.assertNotIn('syncBoostGroupCount', report['records'][0]['exit'])
                self.assertNotIn('params_address', json.dumps(report))
                self.assertNotIn('xfer_payload_address', json.dumps(report))

    def test_enumeration_rm_control_headers_redact_handles_and_omit_nested_payloads(self):
        result, report = self.observe('rm-control', rm_control_headers=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v23')
        self.assertFalse(report['nested_pointers_read'])
        self.assertEqual(report['payload_scope'],
                         'fixed NVOS54 RM_CONTROL headers only; handles redacted; nested parameter payloads omitted')
        rows = [row for row in report['records'] if row['operation'] == 'rm_control_header']
        self.assertEqual(len(rows), 2)
        self.assertEqual([row['operation'] for row in report['records']],
                         ['rm_control_header', 'rm_control_header'])
        serialized = json.dumps(report)
        for field in ('"hRoot"', '"hObjectParent"', '"hObjectNew"',
                      '"hObjectOld"', '"pAllocParms"', '"pRightsRequested"'):
            self.assertNotIn(field, serialized)
        for row in rows:
            for phase in ('entry', 'exit'):
                packet = row[phase]
                self.assertNotIn('hClient', packet)
                self.assertNotIn('hObject', packet)
                self.assertTrue(packet['hClientPresent'])
                self.assertTrue(packet['hObjectPresent'])
                self.assertNotIn('params', packet)
                self.assertNotIn('params_address', packet)

    def test_fabric_status_capture_reads_only_fixed_enum_for_direct_and_xfer(self):
        result, report = self.observe('fabric-status', fabric_status=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v24')
        self.assertTrue(report['trace_complete'])
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['fabric_status_payload_snapshots_read'], 4)
        self.assertEqual(report['nested_pointer_scope'],
                         'exact NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS 4-byte enum only; '
                         'raw addresses and handles omitted')
        self.assertEqual(report['payload_scope'],
                         'exact root-global Fabric Manager status enum plus fixed RM_CONTROL '
                         'headers; raw addresses and handles omitted')
        rows = report['records']
        self.assertEqual(len(rows), 2)
        self.assertEqual([row['request'] for row in rows], [0xc020462a, 0xc01046d3])
        self.assertEqual([row['packet_size'] for row in rows], [32, 16])
        self.assertEqual([row['entry']['command'] for row in rows], [0x136, 0x136])
        self.assertEqual([row['entry']['fabricStatus'] for row in rows], [4, 3])
        self.assertEqual([row['exit']['fabricStatus'] for row in rows], [4, 3])
        for row in rows:
            self.assertEqual(row['operation'], 'rm_control_fabric_status')
            self.assertEqual(row['syscall_return'], -25)  # /dev/null: no RM execution
            for phase in ('entry', 'exit'):
                self.assertEqual(row[phase]['params_size'], 4)
                self.assertEqual(row[phase]['flags'], 0)
                self.assertNotIn('hClient', row[phase])
                self.assertNotIn('hObject', row[phase])
                self.assertTrue(row[phase]['hClientPresent'])
                self.assertTrue(row[phase]['hObjectPresent'])
                self.assertNotIn('params_address', row[phase])
                self.assertNotIn('params', row[phase])
            self.assertNotIn('xfer_payload_address', row)

    def test_fabric_status_rejects_wrong_fixed_size_without_reading_pointer(self):
        result, report = self.observe('fabric-status-bad-size', fabric_status=True)
        self.assertEqual(result.returncode, 2, str(report))
        self.assertFalse(report['trace_complete'])
        self.assertIn('invalid Fabric Status RM_CONTROL shape', report['errors'][0])
        self.assertFalse(report['nested_pointers_read'])
        self.assertEqual(len(report['records']), 1)
        self.assertIsNone(report['records'][0]['entry'])
        self.assertNotIn('params_address', json.dumps(report))
        self.assertNotIn('xfer_payload_address', json.dumps(report))

    def test_fabric_status_rejects_bad_nested_pointer_without_leaking_it(self):
        result, report = self.observe('fabric-status-bad-pointer', fabric_status=True)
        self.assertEqual(result.returncode, 2, str(report))
        self.assertFalse(report['trace_complete'])
        self.assertIn('cannot read Fabric Status payload', report['errors'][0])
        self.assertFalse(report['nested_pointers_read'])
        self.assertEqual(len(report['records']), 1)
        self.assertIsNone(report['records'][0]['entry'])

    def test_system_features_captures_only_fixed_mask_on_direct_and_xfer(self):
        result, report = self.observe('system-features', system_features=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v25')
        self.assertTrue(report['trace_complete'])
        self.assertEqual(report['system_features_payload_snapshots_read'], 4)
        self.assertEqual(report['payload_scope'],
                         'exact root-global SYSTEM_GET_FEATURES 4-byte mask plus fixed RM_CONTROL headers; raw addresses and handles omitted')
        rows = report['records']
        self.assertEqual(len(rows), 2)
        self.assertEqual([row['operation'] for row in rows],
                         ['rm_control_system_features'] * 2)
        self.assertEqual([row['entry']['featuresMask'] for row in rows],
                         [0xA5A55A5A, 0x13579BDF])
        self.assertEqual([row['exit']['featuresMask'] for row in rows],
                         [0xA5A55A5A, 0x13579BDF])
        self.assertEqual([row['syscall_return'] for row in rows], [-25, -25])
        encoded = json.dumps(report)
        for forbidden in ('params_address', 'xfer_payload_address', '"hClient":', '"hObject":'):
            self.assertNotIn(forbidden, encoded)

    def test_system_features_rejects_wrong_payload_size(self):
        result, report = self.observe('system-features-bad-size', system_features=True)
        self.assertEqual(result.returncode, 2, str(report))
        self.assertFalse(report['trace_complete'])
        self.assertIn('invalid SYSTEM_GET_FEATURES RM_CONTROL shape', report['errors'][0])
        self.assertEqual(report['system_features_payload_snapshots_read'], 0)
        self.assertEqual(len(report['records']), 1)
        self.assertIsNone(report['records'][0]['entry'])
        self.assertNotIn('params_address', json.dumps(report))

    def test_system_features_rejects_bad_nested_pointer_without_leaking_it(self):
        result, report = self.observe('system-features-bad-pointer', system_features=True)
        self.assertEqual(result.returncode, 2, str(report))
        self.assertFalse(report['trace_complete'])
        self.assertIn('cannot read SYSTEM_GET_FEATURES payload', report['errors'][0])
        self.assertEqual(report['system_features_payload_snapshots_read'], 0)
        self.assertEqual(len(report['records']), 1)
        self.assertIsNone(report['records'][0]['entry'])
        self.assertNotIn('params_address', json.dumps(report))

    def test_system_features_mode_cannot_be_combined_with_other_capture(self):
        output = Path(self.tmp.name) / 'system-features-conflict.json'
        result = subprocess.run([
            str(self.observer), '--output', str(output), '--system-features',
            '--fabric-status', '--', str(self.child), 'system-features'
        ], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())
        self.assertNotIn('xfer_payload_address', result.stderr)

    def test_fabric_status_flag_is_an_isolated_observer_mode(self):
        result = subprocess.run([str(self.observer), '--output',
                                 str(Path(self.tmp.name) / 'mixed-fabric-status.json'),
                                 '--rm-control', '--fabric-status', '--',
                                 str(self.child), 'fabric-status'],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2)

    def test_rm_control_xfer_header_bad_pointer_fails_without_address_leak(self):
        result, report = self.observe('rm-control-xfer-bad-pointer', rm_control=True)
        self.assertEqual(result.returncode, 2, str(report))
        self.assertFalse(report['trace_complete'])
        self.assertIn('cannot read RM_CONTROL header', report['errors'][0])
        self.assertEqual(len(report['records']), 4)
        self.assertIsNone(report['records'][-1]['entry'])
        self.assertNotIn('xfer_payload_address', report['records'][-1])

    def test_rm_control_metadata_mode_keeps_both_exact_scope_contracts(self):
        result, report = self.observe('rm-control-mixed', gpu_id_info=True,
                                      attached_ids=True, rm_control=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v5')
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['nested_pointer_scope'],
                         'exact NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 and '
                         'NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS payloads only; addresses omitted')
        self.assertEqual(report['payload_scope'],
                         'RM_CONTROL headers plus explicitly selected fixed metadata payloads; '
                         'other nested parameters omitted')
        operations = [row['operation'] for row in report['records']]
        self.assertEqual(operations,
                         ['alloc', 'alloc', 'free', 'gpu_id_info_v2', 'gpu_attached_ids',
                          'rm_control_header', 'rm_control_header'])
        self.assertEqual(report['records'][4]['entry']['gpuIds'][:2], [22, 0xffffffff])
        for row in report['records'][3:]:
            for phase in ('entry', 'exit'):
                self.assertNotIn('params', row[phase])
                self.assertNotIn('params_address', row[phase])
                self.assertNotIn('xfer_payload_address', row[phase])

    def test_p2p_controls_capture_only_exact_fixed_payload_metadata(self):
        result, report = self.observe('p2p-control', rm_control=True,
                                      p2p_control=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v17')
        self.assertTrue(report['trace_complete'])
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['p2p_control_payload_snapshots_read'], 10)
        self.assertEqual(report['nested_pointer_scope'],
            'exact NV503C register/unregister VA-space, register/unregister vidmem, and '
            'register-PID fixed parameter structures; raw addresses, handles, and VA-space tokens omitted')
        self.assertEqual(report['payload_scope'],
            'RM_CONTROL headers plus exact NV503C P2P control payloads; raw addresses, handles, '
            'and VA-space tokens omitted; other nested parameter payloads omitted')
        self.assertEqual(report['errors'], [])
        records = report['records']
        self.assertEqual(len(records), 8)
        rows = records[-5:]
        commands = [0x503c0102, 0x503c0103, 0x503c0104, 0x503c0105, 0x503c0106]
        self.assertEqual([row['entry']['command'] for row in rows], commands)
        self.assertEqual([row['request'] for row in rows],
                         [0xc020462a, 0xc020462a, 0xc01046d3,
                          0xc020462a, 0xc020462a])
        for row, command in zip(rows, commands):
            self.assertEqual(row['syscall_return'], -25)
            for phase in ('entry', 'exit'):
                outer = row[phase]
                self.assertNotIn('hClient', outer)
                self.assertNotIn('hObject', outer)
                self.assertTrue(outer['hClientPresent'])
                self.assertTrue(outer['hObjectPresent'])
                self.assertEqual(outer['objectClass'], {
                    'resolution': 'not-observed-live-object', 'classId': None})
                nested = outer['p2pControl']
                self.assertEqual(nested['command'], command)
                self.assertTrue(nested['payloadValid'])
                self.assertTrue(nested['inputHandlePresent'])
                self.assertNotIn('params_address', outer)
                self.assertNotIn('params', outer)
        self.assertTrue(rows[0]['entry']['p2pControl']['vaSpaceTokenNonzeroAtSnapshot'])
        vidmem = rows[2]['entry']['p2pControl']
        self.assertEqual(vidmem['payloadBytes'], 32)
        for key in ('addressAligned64K', 'sizeNonzero', 'sizeAligned64K',
                    'offsetAligned64K', 'offsetAndSizeDoNotOverflow',
                    'addressAndSizeDoNotOverflow'):
            self.assertTrue(vidmem[key], key)
        self.assert_redacted_numeric_values(
            report, (19088743, 305419896, 1985229328, 129394765414400))
        encoded = json.dumps(report)
        for secret in ('params_address', 'xfer_payload_address'):
            self.assertNotIn(secret, encoded)

    def test_p2p_control_unknown_commands_do_not_read_nested_payloads(self):
        result, report = self.observe('p2p-control-unrelated', rm_control=True,
                                      p2p_control=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertFalse(report['nested_pointers_read'])
        self.assertEqual(report['p2p_control_payload_snapshots_read'], 0)
        record = report['records'][-1]
        self.assertIsNone(record['entry']['p2pControl'])
        self.assertIsNone(record['exit']['p2pControl'])
        self.assertNotIn('params_address', json.dumps(report))

    def test_p2p_control_fixed_size_and_pointer_fail_closed(self):
        result, report = self.observe('p2p-control-bad-size', rm_control=True,
                                      p2p_control=True)
        self.assertEqual(result.returncode, 2, str(report))
        self.assertFalse(report['trace_complete'])
        self.assertEqual(report['errors'],
            ['NV503C P2P RM_CONTROL has an unexpected fixed payload size'])
        result, report = self.observe('p2p-control-bad-pointer', rm_control=True,
                                      p2p_control=True)
        self.assertEqual(result.returncode, 2, str(report))
        self.assertFalse(report['trace_complete'])
        self.assertEqual(report['errors'],
            ['cannot read NV503C register-vidmem payload'])
        self.assertNotIn('params_address', json.dumps(report))

    def test_p2p_control_requires_rm_control_and_isolated_capture(self):
        output = Path(self.tmp.name) / 'report-p2p-control-requires-rm.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
                                  '--control-path', '/dev/null', '--p2p-control', '--',
                                  str(self.child), 'p2p-control'], capture_output=True,
                                 text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

    def test_binapi_control_denies_unresolved_object_before_reading_payload_pointer(self):
        result, report = self.observe('binapi-control-unresolved', rm_control=True,
                                      binapi_control=True, gpu_path='/dev/zero')
        self.assertEqual(result.returncode, 2, str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v18')
        self.assertFalse(report['trace_complete'])
        self.assertFalse(report['nested_pointers_read'])
        self.assertEqual(report['binapi_payload_snapshots_read'], 0)
        self.assertEqual(report['gpu_path'], '/dev/zero')
        self.assertIn('object_class_resolution_scope', report)
        self.assertEqual(report['errors'],
                         ['BINAPI RM_CONTROL object class is not a live NV2081_BINAPI'])
        self.assertEqual(len(report['records']), 1)
        record = report['records'][0]
        self.assertEqual(record['operation'], 'binapi_control')
        self.assertEqual(record['entry']['command'], 0x20810108)
        self.assertEqual(record['entry']['params_size'], 992)
        self.assertEqual(record['entry']['objectClass'], {
            'resolution': 'not-observed-live-object', 'classId': None})
        self.assertFalse(record['entry']['binapiPayload']['payloadValid'])
        encoded = json.dumps(report)
        self.assertNotIn('params_address', encoded)
        self.assertNotIn('xfer_payload_address', encoded)
        self.assertNotIn('0x1', encoded)

    def test_binapi_control_capture_requires_isolated_rm_control_mode(self):
        output = Path(self.tmp.name) / 'report-binapi-control-requires-rm.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
                                 '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
                                 '--binapi-control', '--',
                                 str(self.child), 'binapi-control-unresolved'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

    def test_binapi_control_capture_requires_an_explicit_gpu_descriptor(self):
        output = Path(self.tmp.name) / 'report-binapi-control-requires-gpu.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
                                 '--control-path', '/dev/null', '--rm-control',
                                 '--binapi-control', '--', str(self.child),
                                 'binapi-control-unresolved'], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

    def test_bad_pointer_and_unsupported_size_fail_closed(self):
        for mode in ('bad-pointer', 'bad-size'):
            with self.subTest(mode=mode):
                result, report = self.observe(mode)
                self.assertEqual(result.returncode, 2, str(report))
                self.assertFalse(report['trace_complete'])
                self.assertTrue(report['errors'])
                self.assertEqual(len(report['records']), 1)
                self.assertIsNone(report['records'][0]['entry'])

    def test_x32_and_unresolvable_descriptor_fail_closed(self):
        for mode, error in (('x32', 'x32 tracee ABI unsupported'),
                            ('invalid-fd', 'cannot resolve matching ioctl descriptor')):
            with self.subTest(mode=mode):
                result, report = self.observe(mode)
                self.assertEqual(result.returncode, 2, str(report))
                self.assertFalse(report['trace_complete'])
                self.assertEqual(report['records'], [])
                self.assertEqual(report['errors'], [error])

    def test_fork_is_rejected_and_timeout_bounded(self):
        for mode in ('fork', 'timeout'):
            with self.subTest(mode=mode):
                result, report = self.observe(mode, seconds=1)
                self.assertEqual(result.returncode, 2, str(report))
                self.assertFalse(report['trace_complete'])
                self.assertTrue(report['errors'])
        self.assertEqual(report['errors'], ['trace timeout'])

    def test_observer_termination_cleans_owned_child(self):
        output = Path(self.tmp.name) / 'interrupt.json'
        process = subprocess.Popen([str(self.observer), '--output', str(output), '--',
                                    str(self.child), 'timeout'], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            # Wait for an owned tracee to exist; no arbitrary process signalling.
            children = Path('/proc') / str(process.pid) / 'task' / str(process.pid) / 'children'
            deadline = time.monotonic() + 3
            owned = []
            while time.monotonic() < deadline and process.poll() is None:
                owned = children.read_text().split()
                if owned:
                    break
                time.sleep(0.01)
            self.assertTrue(owned)
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=5)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(json.loads(output.read_text())['errors'], ['observer interrupted'])
            for pid in owned:
                self.assertFalse((Path('/proc') / pid).exists())
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)

    def test_child_exit_and_new_output_requirement(self):
        result, report = self.observe('nonzero')
        self.assertEqual(result.returncode, 77)
        self.assertEqual(report['child_exit_code'], 77)
        self.assertTrue(report['trace_complete'])
        output = Path(self.tmp.name) / 'existing.json'
        output.write_text('preserve')
        result = subprocess.run([str(self.observer), '--output', str(output), '--', '/bin/true'],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(output.read_text(), 'preserve')

    def test_channel_alloc_capture_is_opt_in_and_redacts_handles_and_gpu_addresses(self):
        result, report = self.observe('channel-alloc', channel_alloc=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v9')
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['nested_pointer_scope'],
            'VOLTA_CHANNEL_GPFIFO_A and BLACKWELL_CHANNEL_GPFIFO_A class payloads parsed using the byte-identical pinned R580.178.04/R595.99.02 NV_CHANNEL_ALLOC_PARAMS layout; raw addresses and handles omitted')
        self.assertEqual(report['errors'], [])
        self.assertIn('successful prior RM_ALLOC and RM_FREE',
                      report['object_class_resolution_scope'])
        self.assertEqual(len(report['records']), 1)
        row = report['records'][0]
        self.assertEqual(row['operation'], 'channel_alloc')
        self.assertEqual(row['request'], 0xc030462b)
        self.assertEqual(row['syscall_return'], -25)
        for side in ('entry', 'exit'):
            packet = row[side]
            self.assertEqual(packet['hClass'], 0xc36f)
            self.assertTrue(packet['hRootPresent'])
            self.assertTrue(packet['hObjectParentPresent'])
            self.assertTrue(packet['hObjectNewPresent'])
            self.assertTrue(packet['pAllocParmsPresent'])
            self.assertEqual(packet['paramsSize'], 0)
            self.assertEqual(packet['channelPayloadState'], 'r580-r595-class-layout-parsed')
            self.assertEqual(packet['channel']['classPayloadBytes'], 368)
            channel = packet['channel']
            self.assertTrue(channel['hObjectErrorPresent'])
            self.assertTrue(channel['hObjectBufferPresent'])
            self.assertTrue(channel['gpFifoOffsetNonzero'])
            self.assertEqual(channel['gpFifoEntries'], 64)
            self.assertEqual(channel['flags'], 5)
            self.assertTrue(channel['hContextSharePresent'])
            self.assertTrue(channel['hVASpacePresent'])
            self.assertEqual(channel['hUserdMemoryPresentCount'], 1)
            self.assertEqual(channel['userdOffsetNonzeroCount'], 1)
            self.assertEqual(channel['engineType'], 0x31)
            self.assertTrue(channel['cidPresent'])
            self.assertEqual(channel['subDeviceId'], 1)
            self.assertTrue(channel['hObjectEccErrorPresent'])
            self.assertEqual(channel['memoryDescriptors']['instanceMem'],
                             {'basePresent': True, 'size': 4096,
                              'addressSpace': 2, 'cacheAttrib': 3})
            refs = channel['objectClasses']
            self.assertEqual(refs['parent'],
                             {'resolution': 'not-observed-live-object', 'classId': None})
            self.assertEqual(refs['hContextShare'],
                             {'resolution': 'not-observed-live-object', 'classId': None})
            self.assertEqual(refs['hUserdMemory'][0],
                             {'resolution': 'not-observed-live-object', 'classId': None})
            self.assertEqual(refs['hUserdMemory'][1],
                             {'resolution': 'absent', 'classId': None})
        secret_values = (991, 882, 773, 0x01020304, 0x11223344, 0x1234abc,
                         0xdeadbeef, 0x1122334455667788, 0x8877665544332211,
                         0x0101010102020202)
        self.assert_redacted_numeric_values(report, secret_values)

    def test_channel_alloc_captures_both_explicit_descriptor_paths(self):
        result, report = self.observe('channel-alloc-two-paths', channel_alloc=True,
                                      gpu_path='/dev/zero')
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v9')
        self.assertEqual(report['gpu_path'], '/dev/zero')
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(report['records']), 2)
        self.assertEqual([row['fd_role'] for row in report['records']],
                         ['control', 'gpu'])
        self.assertEqual([row['entry']['hClass'] for row in report['records']],
                         [0xc36f, 0xc96f])
        self.assert_redacted_numeric_values(
            report, (991, 882, 773, 0x01020304, 0x11223344, 0x1234abc, 0xdeadbeef))
        for row in report['records']:
            for packet in (row['entry'], row['exit']):
                self.assertNotIn('pAllocParms', packet)
                self.assertNotIn('params_address', packet)

    def test_channel_alloc_bad_nested_pointer_fails_closed_without_emitting_address(self):
        result, report = self.observe('channel-alloc-bad-pointer', channel_alloc=True)
        self.assertEqual(result.returncode, 2, str(report))
        self.assertFalse(report['trace_complete'])
        self.assertEqual(report['errors'], ['cannot read channel allocation payload'])
        self.assertNotIn('params_address', json.dumps(report))

    def test_channel_alloc_outer_size_does_not_override_required_class_payload(self):
        result, report = self.observe('channel-alloc-bad-size', channel_alloc=True)
        self.assertEqual(result.returncode, 0, str(report))
        self.assertTrue(report['trace_complete'])
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(report['records']), 1)
        packet = report['records'][0]['entry']
        self.assertEqual(packet['paramsSize'], 360)
        self.assertEqual(packet['channel']['classPayloadBytes'], 368)
        self.assertEqual(packet['channelPayloadState'], 'r580-r595-class-layout-parsed')
        self.assert_redacted_numeric_values(report, (991, 882, 773))
        self.assertNotIn('pAllocParms', packet)

    def test_blackwell_zero_outer_size_uses_pinned_class_payload_layout(self):
        result, report = self.observe('channel-alloc-blackwell', channel_alloc=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertTrue(report['trace_complete'])
        self.assertEqual(report['errors'], [])
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['nested_pointer_scope'],
            'VOLTA_CHANNEL_GPFIFO_A and BLACKWELL_CHANNEL_GPFIFO_A class payloads parsed using the byte-identical pinned R580.178.04/R595.99.02 NV_CHANNEL_ALLOC_PARAMS layout; raw addresses and handles omitted')
        self.assertEqual(len(report['records']), 1)
        row = report['records'][0]
        self.assertEqual(row['entry']['hClass'], 0xc96f)
        self.assertEqual(row['entry']['paramsSize'], 0)
        self.assertEqual(row['entry']['channel']['classPayloadBytes'], 368)
        self.assertEqual(row['entry']['channelPayloadState'], 'r580-r595-class-layout-parsed')
        self.assertEqual(row['exit']['paramsSize'], 0)
        self.assertEqual(row['exit']['channel']['classPayloadBytes'], 368)
        self.assertEqual(row['syscall_return'], -25)
        self.assert_redacted_numeric_values(report, (991, 882, 773))
        for packet in (row['entry'], row['exit']):
            self.assertNotIn('pAllocParms', packet)

    def test_required_channel_payload_with_null_pointer_fails_closed_even_when_outer_size_zero(self):
        result, report = self.observe('channel-alloc-blackwell-no-params',
                                      channel_alloc=True)
        self.assertEqual(result.returncode, 2, str(report))
        self.assertFalse(report['trace_complete'])
        self.assertEqual(report['errors'], ['cannot read channel allocation payload'])
        self.assertFalse(report['records'][0]['entry']['pAllocParmsPresent'])
        self.assertEqual(report['records'][0]['entry']['paramsSize'], 0)
        self.assertNotIn('params_address', json.dumps(report))

    def test_rusd_alloc_capture_reads_only_the_typed_64_bit_mask(self):
        result, report = self.observe('rusd-alloc', rusd_alloc=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v14')
        self.assertTrue(report['trace_complete'])
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['nested_pointer_scope'],
            'RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS only, parsed as the pinned '
            '8-byte polledDataMask; raw addresses and handles omitted')
        self.assertEqual(report['rusd_payload_snapshots_read'], 2)
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(report['records']), 1)
        row = report['records'][0]
        self.assertEqual(row['operation'], 'rusd_alloc')
        self.assertEqual(row['syscall_return'], -25)
        for packet in (row['entry'], row['exit']):
            self.assertEqual(packet['hClass'], 0xde)
            self.assertEqual(packet['paramsSize'], 0)
            self.assertTrue(packet['pAllocParmsPresent'])
            self.assertEqual(packet['rusdPayloadState'],
                             'r580-r595-class-layout-parsed')
            self.assertEqual(packet['rusd'],
                             {'classPayloadBytes': 8, 'polledDataMask': 3})
        self.assert_redacted_numeric_values(report, (270544960, 540033104, 810549600))
        encoded = json.dumps(report)
        self.assertNotIn('params_address', encoded)
        for observed_packet in (row['entry'], row['exit']):
            self.assertNotIn('pAllocParms', observed_packet)

    def test_rusd_alloc_reads_control_and_selected_gpu_paths_without_leaking_handles(self):
        result, report = self.observe('rusd-alloc-two-paths', rusd_alloc=True,
                                      gpu_path='/dev/zero')
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['errors'], [])
        self.assertEqual([row['fd_role'] for row in report['records']],
                         ['control', 'gpu'])
        self.assertEqual([row['entry']['rusd']['polledDataMask']
                          for row in report['records']], [0, 4])
        self.assert_redacted_numeric_values(report, (270544960, 540033104, 810549600))
        encoded = json.dumps(report)
        self.assertNotIn('params_address', encoded)
        for observed_row in report['records']:
            for observed_packet in (observed_row['entry'], observed_row['exit']):
                self.assertNotIn('pAllocParms', observed_packet)

    def test_rusd_map_lifecycle_capture_keeps_typed_alloc_and_map_class_resolution(self):
        result, report = self.observe('rusd-map-memory', map_memory=True,
                                      rusd_alloc=True, gpu_path='/dev/zero')
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v22')
        self.assertTrue(report['trace_complete'])
        self.assertTrue(report['nested_pointers_read'])
        self.assertTrue(report['fd_identity_capture_complete'])
        self.assertEqual(report['rusd_payload_snapshots_read'], 2)
        self.assertEqual(report['nested_pointer_scope'],
            'RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS fixed 8-byte polledDataMask only, '
            'plus exact pinned R580 NVOS33/NVOS34 map packets and selected-file lifecycle '
            'metadata; other allocation payloads and raw addresses/handles omitted')
        self.assertEqual(report['payload_scope'],
            'exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device '
            'open/dup/close/mmap metadata, transient RM_ALLOC/RM_FREE class resolution, and '
            'fixed RM_USER_SHARED_DATA 8-byte polling-mask snapshots only; addresses, paths, '
            'and handles omitted')
        self.assertEqual(report['errors'], [])
        records = report['records']
        allocation = next(row for row in records if row['operation'] == 'rusd_alloc')
        mapping = next(row for row in records if row['operation'] == 'map_memory')
        unmapping = next(row for row in records if row['operation'] == 'unmap_memory')
        self.assertEqual(allocation['entry']['rusd'],
                         {'classPayloadBytes': 8, 'polledDataMask': 0})
        self.assertEqual(allocation['exit']['rusd'], allocation['entry']['rusd'])
        self.assertEqual(allocation['syscall_return'], -25)
        self.assertEqual(mapping['entry']['memoryObjectClass'], {
            'resolution': 'not-observed-live-object', 'classId': None})
        self.assertEqual(mapping['entry']['memoryObjectClass'],
                         mapping['exit']['memoryObjectClass'])
        self.assertEqual(unmapping['operation'], 'unmap_memory')
        self.assertEqual([row['operation'] for row in records],
                         ['fd_open', 'fd_open', 'rusd_alloc', 'map_memory',
                          'unmap_memory', 'close', 'close'])
        self.assert_redacted_numeric_values(
            report, (0x10203040, 0x20304050, 0x30405060, 0x24681357,
                     0x13572468, 0xdeadbeef, 0xfedcba9876543210,
                     0x123456789abcdef0))
        encoded = json.dumps(report)
        for forbidden in ('params_address', 'linear_address', 'hMemory":',
                          'hClient":', 'hObjectNew":'):
            self.assertNotIn(forbidden, encoded)

    def test_rusd_alloc_bad_or_null_nested_pointer_fails_closed_and_redacts_address(self):
        for mode in ('rusd-alloc-bad-pointer', 'rusd-alloc-null-pointer'):
            with self.subTest(mode=mode):
                result, report = self.observe(mode, rusd_alloc=True)
                self.assertEqual(result.returncode, 2, str(report))
                self.assertFalse(report['trace_complete'])
                self.assertEqual(report['errors'],
                                 ['cannot read RM_USER_SHARED_DATA allocation payload'])
                self.assertIsNone(report['records'][0]['entry'])
                self.assertNotIn('params_address', json.dumps(report))
                self.assertNotIn('pAllocParms":', json.dumps(report))

    def test_rusd_alloc_is_opt_in_and_unknown_alloc_payloads_stay_unread(self):
        result, report = self.observe('rusd-alloc')
        self.assertEqual(result.returncode, 0, str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v1')
        self.assertFalse(report['nested_pointers_read'])
        self.assertEqual(len(report['records']), 1)
        self.assertEqual(report['records'][0]['entry']['hClass'], 0xde)
        self.assertNotIn('polledDataMask', json.dumps(report))

    def test_p2p_alloc_capture_reads_only_fixed_class_flags_and_redacts_addresses(self):
        result, report = self.observe('p2p-alloc', p2p_alloc=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v16')
        self.assertTrue(report['trace_complete'])
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['nested_pointer_scope'],
            'NV50_THIRD_PARTY_P2P NV503C_ALLOC_PARAMETERS only, parsed as the pinned '
            '4-byte flags word; raw addresses and handles omitted')
        self.assertEqual(report['p2p_payload_snapshots_read'], 2)
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(report['records']), 1)
        row = report['records'][0]
        self.assertEqual(row['operation'], 'p2p_alloc')
        self.assertEqual(row['syscall_return'], -25)
        for packet in (row['entry'], row['exit']):
            self.assertEqual(packet['hClass'], 0x503c)
            self.assertEqual(packet['paramsSize'], 0)
            self.assertTrue(packet['pAllocParmsPresent'])
            self.assertEqual(packet['p2pPayloadState'], 'r580-r595-class-layout-parsed')
            self.assertEqual(packet['p2p'], {
                'classPayloadBytes': 4, 'flags': 0xa2, 'type': 2,
                'typeName': 'nvlink', 'unknownFlagBits': 0xa0})
        self.assert_redacted_numeric_values(report, (270544960, 540033104, 810549600))
        encoded = json.dumps(report)
        self.assertNotIn('params_address', encoded)
        for observed_packet in (row['entry'], row['exit']):
            self.assertNotIn('pAllocParms', observed_packet)

    def test_p2p_optional_missing_payload_and_bad_pointer_are_distinguished(self):
        result, report = self.observe('p2p-alloc-no-params', p2p_alloc=True)
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['p2p_payload_snapshots_read'], 0)
        packet = report['records'][0]['entry']
        self.assertFalse(packet['pAllocParmsPresent'])
        self.assertEqual(packet['p2pPayloadState'], 'optional-payload-omitted')
        self.assertIsNone(packet['p2p'])
        result, report = self.observe('p2p-alloc-bad-pointer', p2p_alloc=True)
        self.assertEqual(result.returncode, 2, str(report))
        self.assertFalse(report['trace_complete'])
        self.assertEqual(report['errors'], ['cannot read NV50_THIRD_PARTY_P2P allocation payload'])
        self.assertNotIn('params_address', json.dumps(report))

    def test_device_alloc_capture_reads_fixed_payload_and_redacts_handles(self):
        result, report = self.observe('device-alloc', device_alloc=True,
                                      gpu_path='/dev/zero')
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v19')
        self.assertTrue(report['trace_complete'])
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['device_alloc_payload_snapshots_read'], 2)
        self.assertEqual(report['nested_pointer_scope'],
            'NV01_DEVICE_0 NV0080_ALLOC_PARAMETERS fixed 56-byte payload only; '
            'client handles are relational booleans; internal VA addresses are omitted')
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(report['records']), 1)
        row = report['records'][0]
        self.assertEqual(row['operation'], 'device_alloc')
        self.assertEqual(row['syscall_return'], -25)
        for packet in (row['entry'], row['exit']):
            self.assertEqual(packet['layout'], 'NVOS64')
            self.assertEqual(packet['hClass'], 0x80)
            self.assertEqual(packet['paramsSize'], 0)
            self.assertTrue(packet['pAllocParmsPresent'])
            self.assertNotIn('hRoot', packet)
            self.assertNotIn('hObjectParent', packet)
            self.assertNotIn('hObjectNew', packet)
            self.assertNotIn('pAllocParms', packet)
            self.assertNotIn('params_address', packet)
            self.assertEqual(packet['deviceAlloc'], {
                'classPayloadBytes': 56,
                'deviceId': 13,
                'hClientShare': 'same-as-root',
                'targetClientZero': False,
                'targetDeviceZero': False,
                'flags': 0x403,
                'vaSpaceSize': 0x123000,
                'vaStartInternalZero': False,
                'vaLimitInternalZero': False,
                'vaMode': 2,
            })
        self.assertEqual(row['entry'], row['exit'])
        self.assert_redacted_numeric_values(report, (0xaabbccdd, 0xccddeeff,
            0x13579bdf, 0x2468ace0, 0x444000, 0x888000))
        encoded = json.dumps(report)
        for secret in ('params_address', 'xfer_payload_address', '"vaStartInternal":',
                       '"vaLimitInternal":', 'hClientShareValue'):
            self.assertNotIn(secret, encoded)

    def test_subdevice_alloc_capture_reads_only_fixed_subdevice_id(self):
        output = Path(self.tmp.name) / 'report-subdevice-alloc.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
            '--subdevice-alloc', '--', str(self.child), 'subdevice-alloc'],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(output.read_text())
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v20')
        self.assertTrue(report['trace_complete'])
        self.assertEqual(report['subdevice_alloc_payload_snapshots_read'], 2)
        self.assertEqual(report['nested_pointer_scope'],
            'NV20_SUBDEVICE_0 NV2080_ALLOC_PARAMETERS fixed 4-byte subDeviceId only; handles omitted')
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(report['records']), 1)
        row = report['records'][0]
        self.assertEqual(row['operation'], 'subdevice_alloc')
        self.assertEqual(row['request'], 0xc030462b)
        self.assertEqual(row['packet_size'], 48)
        self.assertEqual(row['syscall_return'], -25)
        for packet in (row['entry'], row['exit']):
            self.assertEqual(packet['layout'], 'NVOS64')
            self.assertEqual(packet['hClass'], 0x2080)
            self.assertEqual(packet['paramsSize'], 0)
            self.assertTrue(packet['pAllocParmsPresent'])
            self.assertEqual(packet['subdeviceAlloc'], {
                'classPayloadBytes': 4, 'subDeviceId': 0})
            for name in ('hRoot', 'hObjectParent', 'hObjectNew', 'pAllocParms',
                         'params_address', 'rawHandle'):
                self.assertNotIn(name, packet)
        self.assertEqual(row['entry'], row['exit'])
        self.assert_redacted_numeric_values(report, (0xaabbccdd, 0x11223344,
                                                       0xccddeeff))

    def test_subdevice_alloc_nonzero_class_payload_value_is_observed_safely(self):
        output = Path(self.tmp.name) / 'report-subdevice-alloc-nonzero.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
            '--subdevice-alloc', '--', str(self.child), 'subdevice-alloc-nonzero'],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(output.read_text())
        self.assertEqual(report['subdevice_alloc_payload_snapshots_read'], 2)
        self.assertEqual(report['records'][0]['exit']['subdeviceAlloc'], {
            'classPayloadBytes': 4, 'subDeviceId': 7})

    def test_binapi_alloc_capture_emits_only_reserved_zero_predicate(self):
        output = Path(self.tmp.name) / 'report-binapi-alloc.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
            '--binapi-alloc', '--', str(self.child), 'binapi-alloc'],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(output.read_text())
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v21')
        self.assertTrue(report['trace_complete'])
        self.assertEqual(report['binapi_alloc_payload_snapshots_read'], 2)
        self.assertEqual(report['nested_pointer_scope'],
            'NV2081_BINAPI NV2081_ALLOC_PARAMETERS fixed 4-byte reserved zero predicate only; handles omitted')
        self.assertEqual(report['payload_scope'],
            'NV2081_BINAPI fixed class parameters only; raw reserved value, handles omitted')
        self.assertEqual(report['errors'], [])
        self.assertEqual(len(report['records']), 1)
        row = report['records'][0]
        self.assertEqual(row['operation'], 'binapi_alloc')
        self.assertEqual(row['request'], 0xc030462b)
        self.assertEqual(row['packet_size'], 48)
        self.assertEqual(row['syscall_return'], -25)
        for packet in (row['entry'], row['exit']):
            self.assertEqual(packet['layout'], 'NVOS64')
            self.assertEqual(packet['hClass'], 0x2081)
            self.assertEqual(packet['paramsSize'], 0)
            self.assertTrue(packet['pAllocParmsPresent'])
            self.assertEqual(packet['binapiAlloc'], {
                'classPayloadBytes': 4, 'reservedZero': True})
            for name in ('hRoot', 'hObjectParent', 'hObjectNew', 'pAllocParms',
                         'params_address', 'reserved'):
                self.assertNotIn(name, packet)
        self.assertEqual(row['entry'], row['exit'])
        self.assert_redacted_numeric_values(report, (0xaabbccdd, 0x11223344,
                                                       0xccddeeff, 0x12345678))

    def test_binapi_alloc_nonzero_reserved_is_emitted_only_as_predicate(self):
        output = Path(self.tmp.name) / 'report-binapi-alloc-nonzero.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
            '--binapi-alloc', '--', str(self.child), 'binapi-alloc-nonzero'],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(output.read_text())
        self.assertEqual(report['binapi_alloc_payload_snapshots_read'], 2)
        payload = report['records'][0]['exit']['binapiAlloc']
        self.assertEqual(payload, {'classPayloadBytes': 4, 'reservedZero': False})
        self.assertNotIn('"reserved":', json.dumps(report))

    def test_binapi_alloc_optional_payload_and_bad_pointer(self):
        output = Path(self.tmp.name) / 'report-binapi-alloc-optional.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
            '--binapi-alloc', '--', str(self.child), 'binapi-alloc-no-params'],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(output.read_text())
        self.assertEqual(report['binapi_alloc_payload_snapshots_read'], 0)
        self.assertFalse(report['nested_pointers_read'])
        self.assertIsNone(report['records'][0]['entry']['binapiAlloc'])

        output = Path(self.tmp.name) / 'report-binapi-alloc-bad-pointer.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
            '--binapi-alloc', '--', str(self.child), 'binapi-alloc-bad-pointer'],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(output.read_text())
        self.assertFalse(report['trace_complete'])
        self.assertIn('cannot read NV2081 allocation payload', report['errors'][0])
        self.assertNotIn('params_address', json.dumps(report))

    def test_binapi_alloc_capture_requires_selected_gpu_and_exclusive_mode(self):
        output = Path(self.tmp.name) / 'report-binapi-alloc-requires-gpu.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--binapi-alloc', '--',
            str(self.child), 'binapi-alloc'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)

        output = Path(self.tmp.name) / 'report-binapi-alloc-exclusive.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--gpu-path', '/dev/zero', '--binapi-alloc',
            '--subdevice-alloc', '--', str(self.child), 'binapi-alloc'],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)

    def test_device_alloc_optional_payload_and_bad_pointer_fail_closed(self):
        result, report = self.observe('device-alloc-no-params', device_alloc=True,
                                      gpu_path='/dev/zero')
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['device_alloc_payload_snapshots_read'], 0)
        self.assertEqual(len(report['records']), 1)
        self.assertIsNone(report['records'][0]['entry']['deviceAlloc'])

        result, report = self.observe('device-alloc-bad-pointer', device_alloc=True,
                                      gpu_path='/dev/zero')
        self.assertEqual(result.returncode, 2, str(report))
        self.assertFalse(report['trace_complete'])
        self.assertIn('cannot read NV0080 allocation payload', report['errors'][0])
        self.assertNotIn('params_address', json.dumps(report))

    def test_device_alloc_capture_requires_selected_gpu_and_exclusive_mode(self):
        output = Path(self.tmp.name) / 'report-device-alloc-requires-gpu.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--device-alloc', '--',
            str(self.child), 'device-alloc'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

    def test_gt200_debugger_capture_redacts_handles_and_reports_within_root_relations(self):
        result, report = self.observe('gt200-debugger-alloc', debugger_alloc=True,
                                     gpu_path='/dev/zero')
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v34')
        self.assertTrue(report['trace_complete'])
        self.assertTrue(report['nested_pointers_read'])
        self.assertEqual(report['debugger_alloc_payload_snapshots_read'], 2)
        self.assertEqual(report['nested_pointer_scope'],
            'exact NV83DE_ALLOC_PARAMETERS 12-byte payload for GT200_DEBUGGER only; emits handle presence and within-root class relations including the debuggee direct-parent class; raw handles and addresses omitted')
        self.assertEqual(report['payload_scope'],
            'NV83DE_ALLOC_PARAMETERS exact 12-byte fixed payload on GT200_DEBUGGER allocations only; raw handles, pointers, and payload bytes omitted')
        self.assertEqual(len(report['records']), 1)
        row = report['records'][0]
        self.assertEqual(row['operation'], 'gt200_debugger_alloc')
        self.assertEqual(row['request'], 0xc030462b)
        self.assertEqual(row['syscall_return'], -25)
        expected_payload = {
            'classPayloadBytes': 12,
            'obsoleteClientZero': True,
            'appClientPresent': True,
            'appClientMatchesRoot': True,
            'appClientMatchesParent': False,
            'appClientEqualsDebuggee': False,
            'debuggee3dHandlePresent': True,
            'appClientClassWithinRoot': {'resolution': 'not-observed-live-object', 'classId': None},
            'debuggee3dClassWithinRoot': {'resolution': 'not-observed-live-object', 'classId': None},
            'debuggee3dParentClassWithinRoot': {'resolution': 'not-observed-live-object', 'classId': None},
            'parentClassWithinRoot': {'resolution': 'not-observed-live-object', 'classId': None},
        }
        self.assertEqual(row['entry']['debuggerAlloc'], expected_payload)
        self.assertTrue(all(value['resolution'] == 'not-observed-live-object'
                            for value in expected_payload.values()
                            if isinstance(value, dict)),
                        'the /dev/null fixture cannot prove successful live RM object resolution')
        self.assertEqual(row['entry'], row['exit'])
        encoded = json.dumps(report)
        for key in ('hRoot', 'hObjectParent', 'hObjectNew', 'pAllocParms',
                    'hAppClient', 'hClass3dObject', 'params_address'):
            self.assertNotIn('"' + key + '":', encoded)
        self.assert_redacted_numeric_values(report, (0xaabbccdd, 0x11223344,
            0x55667788, 0xccddeeff))

    def test_gt200_debugger_required_payload_fails_closed(self):
        for mode in ('gt200-debugger-alloc-null-payload',
                     'gt200-debugger-alloc-bad-pointer',
                     'gt200-debugger-alloc-bad-size'):
            with self.subTest(mode=mode):
                result, report = self.observe(mode, debugger_alloc=True,
                                              gpu_path='/dev/zero')
                self.assertEqual(result.returncode, 2, str(report))
                self.assertFalse(report['trace_complete'])
                expected_error = ('unexpected GT200_DEBUGGER allocation parameter size'
                                  if mode.endswith('bad-size') else
                                  'cannot read required GT200_DEBUGGER allocation payload')
                self.assertIn(expected_error, report['errors'][0])
                self.assertNotIn('params_address', json.dumps(report))

    def test_gt200_debugger_nested_payload_is_not_read_without_opt_in(self):
        result, report = self.observe('gt200-debugger-alloc-bad-pointer')
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertFalse(report['nested_pointers_read'])
        self.assertEqual(report['errors'], [])
        self.assertFalse(any(row.get('operation') == 'gt200_debugger_alloc'
                             for row in report['records']))

    def test_gt200_debugger_capture_requires_selected_gpu_and_exclusive_mode(self):
        output = Path(self.tmp.name) / 'report-debugger-alloc-requires-gpu.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--gt200-debugger-alloc', '--',
            str(self.child), 'gt200-debugger-alloc'], capture_output=True,
            text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

        output = Path(self.tmp.name) / 'report-debugger-lifecycle-requires-gpu.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--gt200-debugger-lifecycle', '--',
            str(self.child), 'gt200-debugger-lifecycle-unresolved'],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

        output = Path(self.tmp.name) / 'report-debugger-lifecycle-exclusive.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
            '--gt200-debugger-lifecycle', '--rm-control', '--', str(self.child),
            'gt200-debugger-lifecycle-unresolved'], capture_output=True,
            text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

    def test_gt200_debugger_lifecycle_omits_unresolved_free_and_control_handles(self):
        result, report = self.observe('gt200-debugger-lifecycle-unresolved',
                                      debugger_lifecycle=True,
                                      gpu_path='/dev/zero')
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v39')
        self.assertTrue(report['trace_complete'])
        self.assertFalse(report['nested_pointers_read'])
        self.assertEqual(report['debugger_free_unresolved_class_count'], 1)
        self.assertEqual(report['debugger_control_unresolved_candidate_count'], 2)
        self.assertEqual(report['debugger_exception_mask_payload_snapshots_read'], 0)
        self.assertEqual(len(report['records']), 2)
        self.assertEqual([row['operation'] for row in report['records']],
                         ['gt200_debugger_control_candidate',
                          'gt200_debugger_control_candidate'])
        self.assertEqual([row['entry']['command'] for row in report['records']],
                         [0x83DE0301, 0x83DE0301])
        self.assertTrue(all(row['entry']['hClientPresent'] for row in report['records']))
        self.assertEqual([row['entry']['hObjectPresent'] for row in report['records']],
                         [False, True])
        self.assertTrue(all(row['entry']['object_handle_matches_prior_debugger_allocation'] is False and
                            row['exit']['object_handle_matches_prior_debugger_allocation'] is False
                            for row in report['records']))
        self.assertIn('unresolved command candidates are never dereferenced',
                      report['payload_scope'])
        encoded = json.dumps(report)
        for forbidden in ('11223344', '55667788', '99aabbcc', '10203040',
                          '30405060', 'params_address', 'xfer_payload_address',
                          '"hClient":', '"hObject":'):
            self.assertNotIn(forbidden, encoded)

        output = Path(self.tmp.name) / 'report-debugger-alloc-exclusive.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
            '--gt200-debugger-alloc', '--device-alloc', '--', str(self.child),
            'gt200-debugger-alloc'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

        output = Path(self.tmp.name) / 'report-device-alloc-combined.json'
        result = subprocess.run([str(self.observer), '--output', str(output),
            '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
            '--device-alloc', '--binapi-control', '--rm-control', '--',
            str(self.child), 'device-alloc'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

    def test_p2p_alloc_capture_is_opt_in(self):
        result, report = self.observe('p2p-alloc')
        self.assertEqual(result.returncode, 0, str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v1')
        self.assertFalse(report['nested_pointers_read'])
        self.assertEqual(report['records'][0]['entry']['hClass'], 0x503c)
        self.assertNotIn('unknownFlagBits', json.dumps(report))

    def test_map_memory_capture_reads_only_pinned_fixed_packets_and_redacts_identity(self):
        result, report = self.observe('map-memory', map_memory=True,
                                      gpu_path='/dev/zero')
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v15')
        self.assertTrue(report['trace_complete'])
        self.assertFalse(report['nested_pointers_read'])
        self.assertEqual(report['payload_scope'],
            'exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device '
            'open/dup/close/mmap metadata, and transient RM_ALLOC/RM_FREE class resolution; '
            'no allocation payloads emitted; addresses, paths, and handles omitted')
        self.assertEqual(report['fd_lifecycle_scope'],
            'opaque file IDs assigned at observed open/openat/openat2 and dup/dup2/dup3/'
            'fcntl(F_DUPFD*) calls; close() removes an ID; close_range invalidates affected IDs; '
            'exec invalidates inherited IDs; io_uring and external fd injection are not tracked; '
            'VMA file references remain kernel-owned')
        self.assertTrue(report['fd_identity_capture_complete'])
        self.assertEqual(report['errors'], [])
        self.assertEqual([row['operation'] for row in report['records']],
                         ['fd_open', 'fd_open', 'map_memory', 'unmap_memory', 'close', 'close'])
        control_open, gpu_open, mapping, unmapping, gpu_close, control_close = report['records']
        self.assertEqual(control_open['fd_role'], 'control')
        self.assertEqual(gpu_open['fd_role'], 'gpu')
        self.assertNotEqual(control_open['fd_file_id'], gpu_open['fd_file_id'])
        self.assertEqual(mapping['fd_role'], 'control')
        self.assertEqual(mapping['request'], 0xc038464e)
        self.assertEqual(mapping['packet_size'], 56)
        self.assertEqual(mapping['syscall_return'], -25)
        self.assertEqual({key: value for key, value in mapping['entry'].items()
                          if key != 'backendFd'}, {
            'length': 0x1000000, 'status': 0x10203040, 'flags': 0x55667788,
            'hClientPresent': True, 'hDevicePresent': True, 'hMemoryPresent': True,
            'offsetNonzero': True, 'linearAddressPresent': True,
            'memoryObjectClass': {'resolution': 'not-observed-live-object',
                                  'classId': None},
            'backendFdRole': 'gpu', 'backendFileId': 2})
        self.assertIsInstance(mapping['entry']['backendFd'], int)
        self.assertEqual(mapping['entry']['backendFileId'], gpu_open['fd_file_id'])
        self.assertEqual(mapping['entry']['memoryObjectClass'], {
            'resolution': 'not-observed-live-object', 'classId': None})
        self.assertEqual(mapping['entry'], mapping['exit'])
        self.assertEqual(unmapping['request'], 0xc020464f)
        self.assertEqual(unmapping['packet_size'], 32)
        self.assertEqual(unmapping['syscall_return'], -25)
        self.assertEqual(unmapping['entry'], {
            'status': 0x89abcdef, 'flags': 0x778899aa,
            'hClientPresent': True, 'hDevicePresent': True,
            'hMemoryPresent': True, 'linearAddressPresent': True})
        self.assertEqual(unmapping['entry'], unmapping['exit'])
        self.assertEqual(gpu_close['fd_role'], 'gpu')
        self.assertEqual(gpu_close['fd_file_id'], gpu_open['fd_file_id'])
        self.assertTrue(gpu_close['close_succeeded'])
        self.assertEqual(control_close['fd_role'], 'control')
        self.assertEqual(control_close['fd_file_id'], control_open['fd_file_id'])
        self.assertTrue(control_close['close_succeeded'])
        encoded = json.dumps(report)
        self.assert_redacted_numeric_values(
            report, (0x13572468, 0x24681357, 0xdeadbeef,
                     0xfedcba9876543210, 0x123456789abcdef0,
                     0x11112222, 0x33334444, 0x55556666,
                     0x0fedcba987654321))

    def test_map_memory_capture_correlates_backend_fd_to_mmap_without_virtual_addresses(self):
        result, report = self.observe('map-memory-mmap', map_memory=True,
                                      gpu_path='/dev/zero')
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        records = report['records']
        mapping = next(row for row in records if row['operation'] == 'map_memory')
        mappings = [row for row in records if row['operation'] == 'mmap']
        opens = [row for row in records if row['operation'] == 'fd_open']
        self.assertEqual(len(opens), 2)
        self.assertEqual([row['fd_role'] for row in opens], ['control', 'gpu'])
        for row in opens:
            self.assertIsInstance(row['fd_file_id'], int)
            self.assertGreater(row['fd_file_id'], 0)
            self.assertIsNone(row['entry'])
            self.assertIsNone(row['exit'])
            self.assertNotIn('path', row)
        self.assertEqual(len(mappings), 1)
        self.assertEqual([row['operation'] for row in records],
                         ['fd_open', 'fd_open', 'map_memory', 'mmap',
                          'unmap_memory', 'close', 'close'])
        self.assertEqual(mapping['entry']['backendFd'], mappings[0]['fd'])
        self.assertEqual(mapping['entry']['backendFileId'], opens[1]['fd_file_id'])
        self.assertEqual(mappings[0]['fd_file_id'], opens[1]['fd_file_id'])
        self.assertEqual(mappings[0]['fd_role'], 'gpu')
        self.assertEqual(mappings[0]['entry'], {
            'length': 4096, 'prot': 1, 'flags': 2,
            'offsetZero': True})
        self.assertTrue(mappings[0]['mmap_succeeded'])
        self.assertIsNone(mappings[0]['syscall_return'])
        close = records[-2]
        self.assertEqual(close['fd'], mapping['entry']['backendFd'])
        self.assertEqual(close['fd_role'], 'gpu')
        self.assertEqual(close['fd_file_id'], opens[1]['fd_file_id'])
        self.assertTrue(close['close_succeeded'])
        self.assertEqual(close['syscall_return'], 0)
        encoded = json.dumps(report)
        self.assertNotIn('returned_address', encoded)
        self.assertNotIn('requested_address', encoded)
        for forbidden in ('params_address', 'linear_address', 'hMemory":', 'offset":'):
            self.assertNotIn(forbidden, encoded)

    def test_map_memory_file_identity_follows_dup_not_numeric_fd_generation(self):
        result, report = self.observe('map-memory-dup', map_memory=True,
                                      gpu_path='/dev/zero')
        self.assertEqual(result.returncode, 0, result.stderr + str(report))
        self.assertTrue(report['fd_identity_capture_complete'])
        records = report['records']
        gpu_open = next(row for row in records if row['operation'] == 'fd_open' and
                        row['fd_role'] == 'gpu')
        duplicate = next(row for row in records if row['operation'] == 'fd_dup')
        mappings = [row for row in records if row['operation'] == 'map_memory']
        closes = [row for row in records if row['operation'] == 'close' and
                  row['fd_role'] == 'gpu']
        self.assertEqual(len(mappings), 2)
        self.assertEqual(duplicate['fd_file_id'], gpu_open['fd_file_id'])
        self.assertEqual([row['entry']['backendFileId'] for row in mappings],
                         [gpu_open['fd_file_id'], gpu_open['fd_file_id']])
        self.assertEqual([row['fd_file_id'] for row in closes],
                         [gpu_open['fd_file_id'], gpu_open['fd_file_id']])

    def test_map_memory_bad_pointer_and_wrapper_size_fail_closed_without_leaking(self):
        cases = {
            'map-memory-bad-pointer': 'cannot read fixed NVOS33 map wrapper',
            'map-memory-bad-size': 'cannot read fixed NVOS33 map wrapper',
        }
        for mode, error_prefix in cases.items():
            with self.subTest(mode=mode):
                result, report = self.observe(mode, map_memory=True)
                self.assertEqual(result.returncode, 2, str(report))
                self.assertFalse(report['trace_complete'])
                self.assertTrue(report['errors'][0].startswith(error_prefix))
                self.assertIsNone(report['records'][0]['entry'])
                self.assertNotIn('params_address', json.dumps(report))
                self.assertNotIn('123456789abcdef0', json.dumps(report))

    def test_unmap_memory_bad_pointer_and_packet_size_fail_closed(self):
        cases = {
            'unmap-memory-bad-pointer': 'cannot read fixed NVOS34 unmap packet',
            'unmap-memory-bad-size': 'cannot read fixed NVOS34 unmap packet',
        }
        for mode, error_prefix in cases.items():
            with self.subTest(mode=mode):
                result, report = self.observe(mode, map_memory=True)
                self.assertEqual(result.returncode, 2, str(report))
                self.assertFalse(report['trace_complete'])
                self.assertTrue(report['errors'][0].startswith(error_prefix))
                self.assertIsNone(report['records'][0]['entry'])
                self.assertNotIn('linear_address', json.dumps(report))

    def test_map_memory_capture_cannot_be_combined_with_other_payload_modes(self):
        output = Path(self.tmp.name) / 'map-conflict.json'
        result = subprocess.run([
            str(self.observer), '--output', str(output), '--control-path', '/dev/null',
            '--map-memory', '--rm-control', '--', str(self.child), 'map-memory'],
            capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

if __name__ == '__main__':
    unittest.main()
