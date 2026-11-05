# SPDX-License-Identifier: MIT
"""Contracts for reproducible SDK RM_CONTROL layout measurements."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / 'tools/probe_rm_ctrl_layouts.py'


def load_tool():
    spec = importlib.util.spec_from_file_location('rm_ctrl_layout_probe', TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reference_layout():
    return {
        'gpu_get_name_string_cmd': 0x20800110,
        'gpu_get_name_string_size': 132,
        'gpu_get_name_string_buffer_offset': 4,
        'gpu_get_name_string_buffer_size': 128,
        'gpu_query_ecc_status_cmd': 0x2080012F,
        'gpu_query_ecc_status_size': 1464,
        'gpu_ecc_unit_count': 36,
        'nvlink_get_status_cmd': 0x20803002,
        'nvlink_max_array_size': 64,
        'nvlink_link_status_info_size': 208,
        'nvlink_get_status_size': 13344,
        'nvlink_link_info_offset': 32,
        'nv01_device_class_id': 0x80,
        'nv0080_alloc_params_size': 56,
        'nv0080_device_id_offset': 0,
        'nv0080_flags_offset': 16,
        'nv0080_va_space_size_offset': 24,
        'nv0080_va_mode_offset': 48,
        'gpu_get_device_ids_cmd': 0x204,
        'gpu_get_device_ids_size': 4,
        'gpu_get_device_ids_value_offset': 0,
    }


class RmControlLayoutProbeTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool()

    def test_version_parser_requires_exact_release(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / 'version.mk').write_text(
                'NVIDIA_VERSION = 580.178.04\nNVIDIA_NVID_VERSION = 580.178.04\n')
            self.assertEqual(self.tool.read_source_version(source), '580.178.04')
            (source / 'version.mk').write_text('NVIDIA_VERSION = 580.178.05\n')
            with self.assertRaisesRegex(ValueError, '580.178.04'):
                self.tool.read_source_version(source, expected='580.178.04')

    def test_probe_output_requires_exact_numeric_schema(self):
        valid = {
            'gpu_get_name_string_cmd': 0x20800110,
            'gpu_get_name_string_size': 132,
            'gpu_get_name_string_buffer_offset': 4,
            'gpu_get_name_string_buffer_size': 128,
            'gpu_query_ecc_status_cmd': 0x2080012F,
            'gpu_query_ecc_status_size': 1464,
            'gpu_ecc_unit_count': 36,
            'nvlink_get_status_cmd': 0x20803002,
            'nvlink_max_array_size': 64,
            'nvlink_link_status_info_size': 208,
            'nvlink_get_status_size': 13344,
            'nvlink_link_info_offset': 32,
            'nv01_device_class_id': 0x80,
            'nv0080_alloc_params_size': 56,
            'nv0080_device_id_offset': 0,
            'nv0080_flags_offset': 16,
            'nv0080_va_space_size_offset': 24,
            'nv0080_va_mode_offset': 48,
            'gpu_get_device_ids_cmd': 0x204,
            'gpu_get_device_ids_size': 4,
            'gpu_get_device_ids_value_offset': 0,
        }
        self.assertEqual(self.tool.parse_probe_output(json.dumps(valid)), valid)
        with self.assertRaisesRegex(ValueError, 'schema'):
            self.tool.parse_probe_output(json.dumps({**valid, 'pParams': 123}))
        with self.assertRaisesRegex(ValueError, 'non-negative integer'):
            self.tool.parse_probe_output(json.dumps({**valid, 'gpu_get_name_string_size': True}))

    def test_layout_delta_distinguishes_size_and_invariant_changes(self):
        v100 = reference_layout()
        blackwell = {
            **v100,
            'gpu_get_name_string_size': 68,
            'gpu_get_name_string_buffer_size': 64,
            'gpu_query_ecc_status_size': 1664,
            'gpu_ecc_unit_count': 41,
            'nvlink_link_status_info_size': 216,
            'nvlink_get_status_size': 13864,
        }
        result = self.tool.compare_layouts(v100, blackwell)
        self.assertEqual(result['changed_parameter_sizes'], [
            {'command': '0x20800110', 'r580_bytes': 132, 'r595_bytes': 68},
            {'command': '0x2080012f', 'r580_bytes': 1464, 'r595_bytes': 1664},
            {'command': '0x20803002', 'r580_bytes': 13344, 'r595_bytes': 13864},
        ])
        self.assertEqual(result['unchanged'], {
            'gpu_get_name_string_cmd': True,
            'gpu_query_ecc_status_cmd': True,
            'nvlink_get_status_cmd': True,
            'gpu_get_device_ids_cmd': True,
            'nv01_device_class_id': True,
            'nvlink_max_array_size': True,
            'nvlink_link_info_offset': True,
        })
        self.assertEqual(result['changed_layout_fields'], [
            {'field': 'gpu_get_name_string_buffer_size', 'r580': 128, 'r595': 64},
            {'field': 'gpu_ecc_unit_count', 'r580': 36, 'r595': 41},
            {'field': 'nvlink_link_status_info_size', 'r580': 208, 'r595': 216},
        ])
        self.assertEqual(result['typed_allocation_contracts'], {
            'nv01_device_0': {
                'class_id': 0x80,
                'parameters_size_bytes': {'r580': 56, 'r595': 56},
                'field_offsets_bytes': {
                    'deviceId': {'r580': 0, 'r595': 0},
                    'flags': {'r580': 16, 'r595': 16},
                    'vaSpaceSize': {'r580': 24, 'r595': 24},
                    'vaMode': {'r580': 48, 'r595': 48},
                },
                'identical_layout': True,
            },
            'gpu_get_device_ids': {
                'command': {'r580': 0x204, 'r595': 0x204},
                'parameters_size_bytes': {'r580': 4, 'r595': 4},
                'deviceIds_offset_bytes': {'r580': 0, 'r595': 0},
                'identical_layout': True,
            },
        })

    def test_layout_comparison_rejects_unlike_command_ids(self):
        v100 = reference_layout()
        blackwell = reference_layout()
        blackwell['gpu_get_name_string_cmd'] = 2
        with self.assertRaisesRegex(ValueError, 'command IDs'):
            self.tool.compare_layouts(v100, blackwell)

    def test_private_report_is_create_only_and_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'layout.json'
            self.tool.write_private_report(target, {'schema': 'test'})
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                self.tool.write_private_report(target, {'schema': 'replacement'})
            self.assertEqual(json.loads(target.read_text()), {'schema': 'test'})


if __name__ == '__main__':
    unittest.main()
