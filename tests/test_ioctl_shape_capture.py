# SPDX-License-Identifier: MIT
"""CPU-only regression coverage for redacted shapes of observed RM ioctls."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04'
OBSERVER_SOURCE = ROOT / 'src/rm_ioctl_observer.c'
CHILD_SOURCE = ROOT / 'tests/fixtures/ioctl_shape_child.c'
SIGNATURE_SOURCE = ROOT / 'tests/fixtures/ioctl_payload_shape_test.c'


class IoctlShapeCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ioctl-shape-tests-')
        cls.root = Path(cls.temp.name)
        cls.observer = cls.root / 'observer'
        cls.child = cls.root / 'child'
        cls.signature_test = cls.root / 'signature-test'
        includes = [
            'src/common/sdk/nvidia/inc', 'src/common/inc',
            'src/nvidia/arch/nvalloc/unix/include', 'kernel-open/common/inc',
            'kernel-open/nvidia-uvm',
        ]
        flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-DNVRM=1']
        flags.extend('-I' + str(SOURCE / item) for item in includes)
        for source, output, extra in (
                (OBSERVER_SOURCE, cls.observer, ['-pthread']),
                (CHILD_SOURCE, cls.child, ['-pthread'])):
            built = subprocess.run(['cc', *flags, str(source), *extra, '-o', str(output)],
                                   capture_output=True, text=True, timeout=30)
            if built.returncode:
                cls.temp.cleanup()
                raise AssertionError(built.stderr)
        built = subprocess.run(
            ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
             '-I' + str(ROOT / 'src'), str(SIGNATURE_SOURCE),
             '-o', str(cls.signature_test)],
            capture_output=True, text=True, timeout=30)
        if built.returncode:
            cls.temp.cleanup()
            raise AssertionError(built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_selected_direct_requests_emit_only_redacted_byte_shapes(self):
        output = self.root / 'shape-report.json'
        result = subprocess.run(
            [str(self.observer), '--output', str(output), '--timeout-seconds', '5',
             '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
             '--ioctl-shapes', '--', str(self.child)],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(output.read_text())
        self.assertTrue(report['trace_complete'])
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v26')
        self.assertEqual(set(report), {
            'schema', 'trace_complete', 'child_exit_code', 'control_path', 'gpu_path',
            'architecture', 'pointer_bits', 'nested_pointers_read',
            'snapshot_consistency', 'fd_identity_tracking', 'payload_scope',
            'records', 'errors',
        })
        records = [item for item in report['records']
                   if item['operation'] == 'selected_ioctl_payload_shape']
        self.assertEqual([item['request'] for item in records],
                         [0xc038464e, 0xc028465e, 0xc01046ce, 0xc01046cf])
        self.assertEqual([item['packet_size'] for item in records], [56, 40, 16, 16])
        self.assertEqual([item['fd_role'] for item in records],
                         ['control', 'control', 'gpu', 'gpu'])
        self.assertEqual(records[0]['entry_nonzero_offsets'], [0, 4, 16])
        self.assertEqual(records[0]['exit_nonzero_offsets'], [0, 4, 16])
        self.assertEqual(records[0]['changed_offsets'], [])
        self.assertEqual(records[1]['entry_nonzero_offsets'], [3])
        self.assertEqual(records[1]['exit_nonzero_offsets'], [3])
        self.assertEqual(records[1]['changed_offsets'], [])
        self.assertEqual(records[2]['entry_nonzero_offsets'], [8])
        self.assertEqual(records[2]['exit_nonzero_offsets'], [8])
        self.assertEqual(records[2]['changed_offsets'], [])
        self.assertEqual(records[3]['entry_nonzero_offsets'], [8])
        self.assertEqual(records[3]['exit_nonzero_offsets'], [8])
        self.assertEqual(records[3]['changed_offsets'], [])
        self.assertTrue(all(item['entry_snapshot_passed'] and
                            item['exit_snapshot_passed'] and
                            item['syscall_return'] == -25 for item in records))
        self.assertTrue(all(item['entry'] is None and item['exit'] is None
                            for item in records))
        self.assertFalse(any(item['request'] in (0xc00846d6, 0xc001464e)
                             for item in report['records']))
        expected_fields = {
            'tid', 'fd', 'fd_role', 'request', 'packet_size', 'operation',
            'entry_nonzero_offsets', 'exit_nonzero_offsets', 'changed_offsets',
            'entry_snapshot_passed', 'exit_snapshot_passed', 'entry', 'exit',
            'syscall_return',
        }
        self.assertTrue(all(set(item) == expected_fields for item in records))
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_shape_mode_requires_gpu_path_and_rejects_other_capture_modes(self):
        missing_gpu_path = self.root / 'missing-gpu-path.json'
        result = subprocess.run(
            [str(self.observer), '--output', str(missing_gpu_path),
             '--control-path', '/dev/null', '--ioctl-shapes', '--', str(self.child)],
            capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(missing_gpu_path.exists())

        mixed_mode = self.root / 'mixed-mode.json'
        result = subprocess.run(
            [str(self.observer), '--output', str(mixed_mode),
             '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
             '--ioctl-shapes', '--attached-ids', '--', str(self.child)],
            capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(mixed_mode.exists())

    def test_event_cleanup_mode_captures_only_root_predicates_and_descriptor_lifecycle(self):
        output = self.root / 'event-cleanup-report.json'
        result = subprocess.run(
            [str(self.observer), '--output', str(output), '--timeout-seconds', '5',
             '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
             '--ioctl-shapes', '--event-cleanup', '--', str(self.child), 'close-range'],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(output.read_text())
        self.assertTrue(report['trace_complete'])
        self.assertEqual(report['schema'], 'nvidia-hybrid-rm-ioctl-observer-v27')
        self.assertTrue(report['fd_identity_tracking'])
        self.assertIn('root-free equality predicate', report['payload_scope'])
        self.assertIn('selected descriptor lifecycle', report['payload_scope'])
        rows = report['records']
        root_frees = [row for row in rows if row['operation'] == 'root_free_predicate']
        self.assertEqual(len(root_frees), 2)
        self.assertEqual([row['root_free_candidate'] for row in root_frees], [True, False])
        self.assertEqual([row['root_free_succeeded'] for row in root_frees], [False, False])
        self.assertTrue(all(row['entry'] is None and row['exit'] is None for row in root_frees))
        self.assertTrue(all(type(row['fd_file_id']) is int and row['fd_file_id'] > 0
                            for row in root_frees))
        self.assertTrue(all(set(row) == {
            'tid', 'fd', 'fd_role', 'fd_file_id', 'request', 'packet_size', 'operation',
            'entry_nonzero_offsets', 'exit_nonzero_offsets', 'changed_offsets',
            'entry_snapshot_passed', 'exit_snapshot_passed', 'root_free_candidate',
            'root_free_succeeded', 'entry', 'exit', 'syscall_return',
        } for row in root_frees))
        self.assertEqual(sum(row['operation'] == 'fd_open' for row in rows), 2)
        close_rows = [row for row in rows if row['operation'] == 'close']
        self.assertEqual({row['fd_role'] for row in close_rows}, {'control'})
        self.assertTrue(all(row['close_succeeded'] for row in close_rows))
        ranges = [row for row in rows if row['operation'] == 'fd_close_range']
        self.assertEqual(len(ranges), 1)
        opens = [row for row in rows if row['operation'] == 'fd_open' and
                 row['fd_role'] == 'gpu']
        duplicates = [row for row in rows if row['operation'] == 'fd_dup' and
                      row['fd_role'] == 'gpu']
        self.assertEqual(len(opens), 1)
        self.assertEqual(len(duplicates), 1)
        descriptors = ranges[0]['fd_descriptors']
        self.assertEqual(len(descriptors), 2)
        self.assertEqual(len({item['fd'] for item in descriptors}), 2)
        self.assertEqual(len({item['file_id'] for item in descriptors}), 1)
        self.assertGreater(descriptors[0]['file_id'], 0)
        self.assertEqual(duplicates[0]['source_fd'], opens[0]['fd'])
        self.assertEqual(duplicates[0]['fd'],
                         next(item['fd'] for item in descriptors
                              if item['fd'] != opens[0]['fd']))
        self.assertEqual(opens[0]['fd_file_id'], duplicates[0]['fd_file_id'])
        self.assertIsNone(duplicates[0]['replaced_fd_file_id'])
        self.assertNotEqual(duplicates[0]['tid'], ranges[0]['tid'])
        self.assertTrue(report['fd_identity_capture_complete'])
        self.assertTrue(all(type(row['fd_file_id']) is int and row['fd_file_id'] > 0
                            for row in rows if row['operation'] in (
                                'fd_open', 'fd_dup', 'close',
                                'selected_ioctl_payload_shape', 'root_free_predicate')))
        serialized = json.dumps(report)
        self.assertNotIn('hRoot', serialized)
        self.assertNotIn('hObjectOld', serialized)
        self.assertNotIn('0x11223344', serialized)

    def test_event_cleanup_mode_requires_ioctl_shapes(self):
        output = self.root / 'event-cleanup-without-shapes.json'
        result = subprocess.run(
            [str(self.observer), '--output', str(output), '--timeout-seconds', '5',
             '--control-path', '/dev/null', '--gpu-path', '/dev/zero',
             '--event-cleanup', '--', str(self.child)],
            capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

    def test_byte_shape_reducer_marks_changes_and_rejects_unbounded_inputs(self):
        result = subprocess.run([str(self.signature_test)], capture_output=True,
                                text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
