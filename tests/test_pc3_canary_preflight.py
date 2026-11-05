# SPDX-License-Identifier: MIT
"""Static PC3 canary gates; these tests never load kernel modules."""
import importlib.util
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]


def load_preflight():
    path = ROOT / 'tools' / 'audit_pc3_canary_preflight.py'
    if not path.is_file():
        raise AssertionError('PC3 canary preflight implementation is missing')
    spec = importlib.util.spec_from_file_location('audit_pc3_canary_preflight', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_collector():
    path = ROOT / 'tools' / 'collect_pc3_canary_host_state.py'
    spec = importlib.util.spec_from_file_location('collect_pc3_canary_host_state', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def candidate_modules(signer=''):
    return {
        'open': {'name': 'hybrid580_open', 'version': '580.178.04',
                 'vermagic': '7.0.0-38-generic SMP preempt mod_unload modversions',
                 'signer': signer, 'sig_key': 'a001', 'sha256': '1' * 64,
                 'depends': ''},
        'legacy': {'name': 'hybrid580_legacy', 'version': '580.178.04',
                   'vermagic': '7.0.0-38-generic SMP preempt mod_unload modversions',
                   'signer': signer, 'sig_key': 'a002', 'sha256': '2' * 64,
                   'depends': ''},
        'frontend': {'name': 'hybrid580_frontend', 'version': '',
                     'vermagic': '7.0.0-38-generic SMP preempt mod_unload modversions',
                     'signer': signer, 'sig_key': 'a003', 'sha256': '3' * 64,
                     'depends': 'hybrid580_legacy,hybrid580_open'},
        'uvm': {'name': 'nvidia_uvm', 'version': '580.178.04',
                'vermagic': '7.0.0-38-generic SMP preempt mod_unload modversions',
                'signer': signer, 'sig_key': 'a004', 'sha256': '4' * 64,
                'depends': 'hybrid580_frontend'},
    }


def signature_trust_evidence(state, modules):
    boot_id = state['boot_id']
    keyring_sha256 = 'a' * 64
    state['module_signature_trust'] = {
        'schema': 'nvidia-module-signature-trust-v1',
        'kernel_release': state['kernel_release'],
        'boot_id': boot_id,
        'target_keyring_sha256': keyring_sha256,
        'evidence_sha256': 'b' * 64,
        'roles': {
            role: {
                'module_sha256': module['sha256'],
                'signer': module['signer'],
                'sig_key': module['sig_key'],
                'kernel_release': state['kernel_release'],
                'boot_id': boot_id,
                'target_keyring_sha256': keyring_sha256,
                'signature_valid': True,
                'key_trusted': True,
            }
            for role, module in modules.items()
        },
    }


def host_state():
    state = {
        'schema': 'nvidia-hybrid-canary-host-state-v2',
        'host': 'pc3',
        'observed_at_utc': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'boot_id': str(uuid.uuid4()),
        'kernel_release': '7.0.0-38-generic',
        'kernel_vermagic': '7.0.0-38-generic SMP preempt mod_unload modversions',
        'secure_boot_enabled': True,
        'lockdown': 'integrity',
        'module_sig_enforce': True,
        'active_modules_scope': 'all',
        'active_modules': [
            {'name': 'drm'},
            {'name': 'nvidia'}, {'name': 'nvidia_uvm'},
            {'name': 'nvidia_modeset'}, {'name': 'nvidia_drm'},
        ],
        'loaded_nvidia_modules': [
            'nvidia', 'nvidia_uvm', 'nvidia_modeset', 'nvidia_drm',
        ],
        'active_char_devices': [
            {'path': '/dev/nvidia0', 'major': 195, 'minor': 0},
            {'path': '/dev/nvidiactl', 'major': 195, 'minor': 255},
            {'path': '/dev/nvidia-uvm', 'major': 511, 'minor': 0},
        ],
        'char_device_major_names': [
            {'major': 195, 'name': 'nvidia'},
            {'major': 511, 'name': 'nvidia-uvm'},
        ],
        'gpu_ownership': [
            {'pci': '0000:02:00.0', 'vendor_id': '10de', 'device_id': '2c02',
             'driver': 'nvidia'},
        ],
        'installed_nvidia_module': {
            'version': '595.99.02', 'signer': 'Canonical Ltd.',
            'vermagic': '7.0.0-38-generic SMP preempt mod_unload modversions',
        },
        'loaded_nvidia_module_version': '595.99.02',
        'local_module_signing_key_metadata': {
            'certificate_present': True, 'certificate_enrolled': False,
            'mok_test_result': 'not_enrolled',
        },
    }
    return load_collector().make_report(state, 'pc3@pc3', 'gx10-e526')


def set_active_modules(state, modules):
    state['active_modules'] = modules
    state['loaded_nvidia_modules'] = [
        item['name'] for item in modules if item['name'].startswith('nvidia')
    ]
    return state


def clear_static_host(state):
    state.update(active_char_devices=[], active_modules=[],
                 loaded_nvidia_modules=[], char_device_major_names=[])
    return state


LAYOUT = {'major': 195, 'gpu_minor_first': 0, 'gpu_minor_last': 247,
          'control_minor': 255}


class Pc3CanaryPreflightTests(unittest.TestCase):
    def test_node_layout_parser_rejects_registration_text_only_in_comments(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 195\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                '/* register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0),\n'
                ' NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U);\n'
                ' register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER,\n'
                ' NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1); */\n',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'expected standard-node reservations'):
                tool.parse_standard_node_layout(header, source)

    def test_node_layout_parser_rejects_unregister_as_a_reservation(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 195\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                'unregister_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0),\n'
                ' NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U);\n'
                'unregister_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER,\n'
                ' NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1);\n',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'expected standard-node reservations'):
                tool.parse_standard_node_layout(header, source)

    def test_node_layout_parser_accepts_the_real_three_argument_registrations(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 195\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0),\n'
                ' NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, HYBRID580_NODE_NAME);\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER,\n'
                ' NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, HYBRID580_NODE_NAME);\n',
                encoding='utf-8')

            self.assertEqual(tool.parse_standard_node_layout(header, source), LAYOUT)

    def test_node_layout_parser_rejects_source_macro_override(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 195\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                '#undef NV_MAJOR_DEVICE_NUMBER\n'
                '#define NV_MAJOR_DEVICE_NUMBER 196\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'overrides audited standard-node macros'):
                tool.parse_standard_node_layout(header, source)

    def test_node_layout_parser_rejects_comment_separated_macro_override(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 195\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                '#undef/**/NV_MAJOR_DEVICE_NUMBER\n'
                '#define/**/NV_MAJOR_DEVICE_NUMBER 196\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'overrides audited standard-node macros'):
                tool.parse_standard_node_layout(header, source)

    def test_node_layout_parser_rejects_digraph_macro_override(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 195\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                '%:undef NV_MAJOR_DEVICE_NUMBER\n'
                '%:define NV_MAJOR_DEVICE_NUMBER 196\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'overrides audited standard-node macros'):
                tool.parse_standard_node_layout(header, source)

    def test_node_layout_parser_rejects_header_undefinition(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 195\n'
                '#undef NV_MAJOR_DEVICE_NUMBER\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'header undefines an audited'):
                tool.parse_standard_node_layout(header, source)

    def test_node_layout_parser_rejects_cr_only_source_directives(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 195\r'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\r'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\r',
                encoding='utf-8')
            source.write_text(
                '#define IRRELEVANT 0\r'
                '#undef NV_MAJOR_DEVICE_NUMBER\r'
                '#define NV_MAJOR_DEVICE_NUMBER 196\r'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\r'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\r',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'overrides audited standard-node macros'):
                tool.parse_standard_node_layout(header, source)

    def test_node_layout_parser_rejects_gcc_spaced_line_continuation(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 195\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                '#def' + '\\' + ' \n' + 'ine NV_MAJOR_DEVICE_NUMBER 196\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'spaced line continuation'):
                tool.parse_standard_node_layout(header, source)

    def test_node_layout_parser_accepts_digraph_header_definitions(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '%:define NV_MAJOR_DEVICE_NUMBER 195\n'
                '%:define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '%:define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            self.assertEqual(tool.parse_standard_node_layout(header, source), LAYOUT)

    def test_node_layout_parser_rejects_trigraph_preprocessor_input(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 195\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                '??=undef NV_MAJOR_DEVICE_NUMBER\n'
                '??=define NV_MAJOR_DEVICE_NUMBER 196\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'unsupported C trigraph'):
                tool.parse_standard_node_layout(header, source)

    def test_node_layout_parser_rejects_line_spliced_source_macro_override(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 195\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                '#' + '\\' + '\n' + 'define NV_MAJOR_DEVICE_NUMBER 196\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'overrides audited standard-node macros'):
                tool.parse_standard_node_layout(header, source)

    def test_node_layout_parser_ignores_macro_text_inside_comments(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '/*\n#define NV_MAJOR_DEVICE_NUMBER 196\n*/\n'
                '#define NV_MAJOR_DEVICE_NUMBER 195\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            self.assertEqual(tool.parse_standard_node_layout(header, source)['major'], 195)

    def test_node_layout_parser_rejects_expression_macros(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 196 - 1\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'single integer literal'):
                tool.parse_standard_node_layout(header, source)

    def test_node_layout_parser_rejects_duplicate_macro_definitions(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 195\n'
                '#define NV_MAJOR_DEVICE_NUMBER 196\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'exactly one definition'):
                tool.parse_standard_node_layout(header, source)

    def test_octal_c_device_major_detects_live_nvidia_node_conflict(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 0303\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 0367\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 0377\n',
                encoding='utf-8')
            source.write_text(
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            layout = tool.parse_standard_node_layout(header, source)
            state = host_state()
            state.update(secure_boot_enabled=False, lockdown='none',
                         module_sig_enforce=False,
                         active_char_devices=[
                             {'path': '/dev/nvidia0', 'major': 195, 'minor': 0}])
            result = tool.evaluate_preflight(
                state, candidate_modules(signer='test signer'), layout)

        self.assertEqual(layout['major'], 195)
        self.assertEqual(result['status'], 'blocked')
        self.assertIn('standard_device_numbers_in_use',
                      {item['code'] for item in result['blockers']})

    def test_invalid_octal_device_number_is_rejected(self):
        tool = load_preflight()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 08\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'single integer literal'):
                tool.parse_standard_node_layout(header, source)

    def test_current_pc3_state_blocks_unsigned_modules_and_owned_standard_nodes(self):
        result = load_preflight().evaluate_preflight(
            host_state(), candidate_modules(), LAYOUT)

        self.assertEqual(result['status'], 'blocked')
        blockers = {item['code'] for item in result['blockers']}
        self.assertIn('unsigned_modules_rejected_by_policy', blockers)
        self.assertIn('standard_device_numbers_in_use', blockers)
        self.assertFalse(result['tool_loaded_modules'])
        self.assertFalse(result['runtime_validated'])
        self.assertFalse(result['canary_ready'])

    def test_candidate_module_name_conflicts_with_loaded_stock_uvm(self):
        state = host_state()
        state['active_char_devices'] = []
        state['char_device_major_names'] = []
        set_active_modules(state, [{'name': 'nvidia'}, {'name': 'nvidia-uvm'}])

        result = load_preflight().evaluate_preflight(
            state, candidate_modules(signer='test signer'), LAYOUT)

        conflicts = [item for item in result['blockers']
                     if item['code'] == 'loaded_module_name_conflict']
        self.assertEqual(len(conflicts), 1)
        self.assertIn('nvidia_uvm', conflicts[0]['detail'])

    def test_standard_frontend_identity_matches_abi_but_conflicts_with_active_stack(self):
        state = host_state()
        modules = candidate_modules(signer='candidate signer')
        modules['frontend']['name'] = 'nvidia'
        modules['uvm']['depends'] = 'nvidia'

        result = load_preflight().evaluate_preflight(
            state, modules, LAYOUT, expected_frontend_module_name='nvidia')

        codes = {item['code'] for item in result['blockers']}
        self.assertNotIn('module_identity_mismatch', codes)
        self.assertNotIn('frontend_dependency_mismatch', codes)
        self.assertIn('loaded_module_name_conflict', codes)
        self.assertIn('standard_device_numbers_in_use', codes)
        self.assertIn('standard_device_major_in_use', codes)
        self.assertEqual(result['expected_module_names']['frontend'], 'nvidia')
        self.assertEqual(result['expected_module_names']['uvm'], 'nvidia_uvm')
        self.assertFalse(result['canary_ready'])

    def test_unsupported_frontend_module_identity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'frontend module name is unsupported'):
            load_preflight().evaluate_preflight(
                host_state(), candidate_modules(), LAYOUT,
                expected_frontend_module_name='nvidia_legacy')

    def test_private_uvm_module_name_removes_only_the_loaded_name_collision(self):
        state = host_state()
        modules = candidate_modules()
        modules['uvm']['name'] = 'hybrid580_uvm'

        result = load_preflight().evaluate_preflight(
            state, modules, LAYOUT, expected_uvm_module_name='hybrid580_uvm')

        codes = {item['code'] for item in result['blockers']}
        self.assertNotIn('module_identity_mismatch', codes)
        self.assertNotIn('loaded_module_name_conflict', codes)
        self.assertIn('unsigned_modules_rejected_by_policy', codes)
        self.assertIn('signature_trust_unverified', codes)
        self.assertIn('standard_device_numbers_in_use', codes)
        self.assertIn('standard_device_major_in_use', codes)
        self.assertEqual(
            result['candidate_chardev_name_conflicts'],
            [{'name': 'nvidia-uvm', 'major': 511}],
        )
        self.assertIn('character_device_name_in_use', codes)
        self.assertEqual(result['expected_module_names']['uvm'], 'hybrid580_uvm')
        self.assertFalse(result['canary_ready'])

    def test_private_uvm_module_still_conflicts_with_stock_chardev_registry_name(self):
        state = host_state()
        modules = candidate_modules()
        modules['uvm']['name'] = 'hybrid580_uvm'

        result = load_preflight().evaluate_preflight(
            state, modules, LAYOUT,
            expected_uvm_module_name='hybrid580_uvm',
            expected_uvm_chardev_name='nvidia-uvm',
        )

        self.assertEqual(
            result['candidate_chardev_name_conflicts'],
            [{'name': 'nvidia-uvm', 'major': 511}],
        )
        self.assertIn(
            'character_device_name_in_use',
            {item['code'] for item in result['blockers']},
        )

    def test_all_majors_with_the_expected_uvm_label_are_reported(self):
        state = host_state()
        state['char_device_major_names'].append(
            {'major': 512, 'name': 'nvidia-uvm'})
        modules = candidate_modules()
        modules['uvm']['name'] = 'hybrid580_uvm'

        result = load_preflight().evaluate_preflight(
            state, modules, LAYOUT,
            expected_uvm_module_name='hybrid580_uvm')

        self.assertEqual(
            result['candidate_chardev_name_conflicts'],
            [{'name': 'nvidia-uvm', 'major': 511},
             {'name': 'nvidia-uvm', 'major': 512}],
        )

    def test_cli_records_an_explicit_uvm_chardev_name(self):
        tool = load_preflight()
        state = host_state()
        modules = candidate_modules(signer='test signer')
        modules['uvm']['name'] = 'hybrid580_uvm'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / 'host-state.json'
            state_path.write_text(json.dumps(state), encoding='utf-8')
            header_path = root / 'nv-chardev-numbers.h'
            header_path.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 195\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source_path = root / 'hybrid580-standard-node-devices.c'
            source_path.write_text(
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')
            args = [
                '--host-state', str(state_path), '--open', 'unused-open.ko',
                '--legacy', 'unused-legacy.ko', '--frontend', 'unused-frontend.ko',
                '--uvm', 'unused-uvm.ko', '--uvm-module-name', 'hybrid580_uvm',
                '--uvm-chardev-name', 'hybrid580-uvm',
                '--node-header', str(header_path),
                '--frontend-source', str(source_path),
            ]
            stdout = io.StringIO()
            with mock.patch.object(
                    tool, '_module_metadata',
                    side_effect=lambda role, _path: modules[role]), \
                    mock.patch.object(tool.sys, 'stdout', stdout):
                exit_code = tool.main(args)

        self.assertEqual(exit_code, 1)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report['schema'], 'nvidia-hybrid-canary-preflight-v5')
        self.assertEqual(report['expected_uvm_chardev_name'], 'hybrid580-uvm')
        self.assertEqual(
            report['preflight_inputs']['expected_uvm_chardev_name'], 'hybrid580-uvm')
        self.assertEqual(report['candidate_chardev_name_conflicts'], [])

    def test_private_uvm_module_name_requires_an_explicit_matching_expectation(self):
        state = host_state()
        modules = candidate_modules(signer='test signer')
        modules['uvm']['name'] = 'hybrid580_uvm'

        result = load_preflight().evaluate_preflight(state, modules, LAYOUT)

        self.assertIn('module_identity_mismatch',
                      {item['code'] for item in result['blockers']})

    def test_expected_uvm_module_name_must_be_a_unique_kernel_name(self):
        tool = load_preflight()
        with self.assertRaisesRegex(ValueError, 'expected UVM module name'):
            tool.evaluate_preflight(
                host_state(), candidate_modules(), LAYOUT,
                expected_uvm_module_name='../nvidia_uvm')

    def test_expected_uvm_chardev_name_is_validated(self):
        tool = load_preflight()
        with self.assertRaisesRegex(ValueError, 'expected UVM character-device name'):
            tool.evaluate_preflight(
                host_state(), candidate_modules(), LAYOUT,
                expected_uvm_chardev_name='nvidia uvm')

    def test_distinct_private_uvm_chardev_label_avoids_only_registry_name_conflict(self):
        state = host_state()
        modules = candidate_modules()
        modules['uvm']['name'] = 'hybrid580_uvm'

        result = load_preflight().evaluate_preflight(
            state, modules, LAYOUT,
            expected_uvm_module_name='hybrid580_uvm',
            expected_uvm_chardev_name='hybrid580-uvm')

        self.assertEqual(result['candidate_chardev_name_conflicts'], [])
        self.assertNotIn(
            'character_device_name_in_use',
            {item['code'] for item in result['blockers']},
        )

    def test_malformed_character_device_major_inventory_fails_closed(self):
        state = host_state()
        state['char_device_major_names'] = [{'major': True, 'name': 'nvidia-uvm'}]

        with self.assertRaisesRegex(ValueError, 'character-device major record'):
            load_preflight().evaluate_preflight(state, candidate_modules(), LAYOUT)

    def test_every_candidate_name_in_complete_inventory_is_a_conflict(self):
        state = host_state()
        state['active_char_devices'] = []
        state['char_device_major_names'] = []
        set_active_modules(state, [
            {'name': 'hybrid580_open'}, {'name': 'hybrid580_legacy'},
            {'name': 'hybrid580_frontend'}, {'name': 'nvidia_uvm'},
        ])

        result = load_preflight().evaluate_preflight(
            state, candidate_modules(signer='test signer'), LAYOUT)

        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(
            {item['name'] for item in result['candidate_module_name_conflicts']},
            {'hybrid580_open', 'hybrid580_legacy', 'hybrid580_frontend', 'nvidia_uvm'},
        )

    def test_loaded_nvidia_subset_must_match_full_inventory(self):
        state = host_state()
        state['active_char_devices'] = []
        state['char_device_major_names'] = []
        state['active_modules'] = [
            item for item in state['active_modules'] if item['name'] != 'nvidia_uvm'
        ]

        with self.assertRaisesRegex(ValueError, 'loaded NVIDIA module inventory differs'):
            load_preflight().evaluate_preflight(
                state, candidate_modules(signer='test signer'), LAYOUT)

    def test_existing_character_major_blocks_even_when_no_nodes_exist(self):
        state = clear_static_host(host_state())
        state['char_device_major_names'] = [{'major': 195, 'name': 'unrelated'}]
        state.update(secure_boot_enabled=False, lockdown='none', module_sig_enforce=False)

        result = load_preflight().evaluate_preflight(
            state, candidate_modules(signer='test signer'), LAYOUT)

        self.assertEqual(result['status'], 'blocked')
        self.assertIn('standard_device_major_in_use',
                      {item['code'] for item in result['blockers']})

    def test_stale_and_future_host_snapshots_are_rejected(self):
        tool = load_preflight()
        state = clear_static_host(host_state())
        state.update(secure_boot_enabled=False, lockdown='none', module_sig_enforce=False)
        state['observed_at_utc'] = '2020-01-01T00:00:00Z'
        with self.assertRaisesRegex(ValueError, 'host-state snapshot is stale'):
            tool.evaluate_preflight(state, candidate_modules(signer='test signer'), LAYOUT)

        state = clear_static_host(host_state())
        state.update(secure_boot_enabled=False, lockdown='none', module_sig_enforce=False)
        state['observed_at_utc'] = '2999-01-01T00:00:00Z'
        with self.assertRaisesRegex(ValueError, 'observation timestamp is in the future'):
            tool.evaluate_preflight(state, candidate_modules(signer='test signer'), LAYOUT)

    def test_preflight_report_renames_operation_flags_as_tool_actions(self):
        state = clear_static_host(host_state())
        state.update(secure_boot_enabled=False, lockdown='none', module_sig_enforce=False)
        result = load_preflight().evaluate_preflight(
            state, candidate_modules(signer='test signer'), LAYOUT)
        self.assertFalse(result['tool_loaded_modules'])
        self.assertFalse(result['tool_installed_modules'])
        self.assertNotIn('modules_loaded', result)
        self.assertNotIn('modules_installed', result)

    def test_missing_loaded_module_inventory_fails_closed(self):
        state = host_state()
        del state['active_modules']

        with self.assertRaisesRegex(ValueError, 'active_modules must be a list'):
            load_preflight().evaluate_preflight(
                state, candidate_modules(signer='test signer'), LAYOUT)

    def test_clear_static_preflight_reports_new_schema_and_no_name_conflicts(self):
        state = clear_static_host(host_state())
        state.update(secure_boot_enabled=False, lockdown='none', module_sig_enforce=False)

        result = load_preflight().evaluate_preflight(
            state, candidate_modules(signer='test signer'), LAYOUT)

        self.assertEqual(result['schema'], 'nvidia-hybrid-canary-preflight-v5')
        self.assertEqual(result['candidate_module_name_conflicts'], [])

    def test_candidate_kernel_and_backend_versions_must_match(self):
        modules = candidate_modules(signer='test signer')
        modules['legacy']['vermagic'] = '6.8.0-147-generic SMP modversions'
        modules['uvm']['version'] = '615.71.10'
        state = host_state()
        state['active_char_devices'] = []
        state['char_device_major_names'] = []

        result = load_preflight().evaluate_preflight(state, modules, LAYOUT)
        blockers = {item['code'] for item in result['blockers']}
        self.assertIn('kernel_release_mismatch', blockers)
        self.assertIn('backend_version_mismatch', blockers)

    def test_candidate_must_match_the_audited_r580_release(self):
        modules = candidate_modules(signer='test signer')
        for module in modules.values():
            if module['version']:
                module['version'] = '595.99.02'
        state = host_state()
        state['active_char_devices'] = []
        state['char_device_major_names'] = []

        result = load_preflight().evaluate_preflight(state, modules, LAYOUT)

        self.assertIn('unsupported_candidate_version',
                      {item['code'] for item in result['blockers']})

    def test_pinned_hybrid_bundle_allows_its_audited_mixed_branch_versions(self):
        modules = candidate_modules(signer='test signer')
        modules['open']['version'] = '595.99.02'
        modules['legacy']['version'] = '580.178.04'
        modules['frontend']['name'] = 'nvidia'
        modules['uvm']['version'] = '595.99.02'
        modules['uvm']['depends'] = 'nvidia'
        state = host_state()
        state['active_char_devices'] = []
        state['char_device_major_names'] = []
        versions = {role: modules[role]['version'] for role in ('open', 'legacy', 'uvm')}

        result = load_preflight().evaluate_preflight(
            state, modules, LAYOUT, expected_frontend_module_name='nvidia',
            audited_candidate_versions=versions)

        blocker_codes = {item['code'] for item in result['blockers']}
        self.assertNotIn('unsupported_candidate_version', blocker_codes)
        self.assertNotIn('backend_version_mismatch', blocker_codes)
        self.assertNotIn('candidate_bundle_version_mismatch', blocker_codes)

    def test_vermagic_flags_must_match_target_not_only_release(self):
        modules = candidate_modules(signer='test signer')
        modules['open']['vermagic'] = '7.0.0-38-generic SMP preempt modversions'
        state = host_state()
        state['active_char_devices'] = []
        state['char_device_major_names'] = []

        result = load_preflight().evaluate_preflight(state, modules, LAYOUT)

        self.assertIn('kernel_vermagic_mismatch',
                      {item['code'] for item in result['blockers']})

    def test_integrity_lockdown_requires_signed_modules_without_secure_boot(self):
        state = host_state()
        state.update(secure_boot_enabled=False, module_sig_enforce=False,
                     active_char_devices=[])

        result = load_preflight().evaluate_preflight(state, candidate_modules(), LAYOUT)

        self.assertIn('unsigned_modules_rejected_by_policy',
                      {item['code'] for item in result['blockers']})

    def test_required_signature_policy_rejects_unverified_signer(self):
        state = host_state()
        state.update(active_char_devices=[], signature_trust_verified=True)

        result = load_preflight().evaluate_preflight(
            state, candidate_modules(signer='unverified signer'), LAYOUT)

        self.assertEqual(result['status'], 'blocked')
        self.assertIn('signature_trust_unverified',
                      {item['code'] for item in result['blockers']})

    def test_signature_trust_evidence_is_bound_to_exact_modules_and_boot(self):
        modules = candidate_modules(signer='verified signer')
        state = clear_static_host(host_state())
        signature_trust_evidence(state, modules)

        trusted = load_preflight().evaluate_preflight(state, modules, LAYOUT)
        self.assertTrue(trusted['signature_trust_verified'])
        self.assertEqual(trusted['status'], 'static-preflight-clear')

        changed = {role: dict(module) for role, module in modules.items()}
        changed['open']['sha256'] = 'f' * 64
        changed['legacy']['sig_key'] = 'ffff'
        stale = load_preflight().evaluate_preflight(state, changed, LAYOUT)
        self.assertFalse(stale['signature_trust_verified'])
        self.assertIn('signature_trust_unverified',
                      {item['code'] for item in stale['blockers']})

        stale_boot = dict(state)
        stale_boot['boot_id'] = str(uuid.uuid4())
        changed_boot = load_preflight().evaluate_preflight(stale_boot, modules, LAYOUT)
        self.assertIn('signature_trust_unverified',
                      {item['code'] for item in changed_boot['blockers']})

    def test_linux_dev_t_major_wrap_is_rejected(self):
        tool = load_preflight()
        self.assertEqual(((4291 << 20) & 0xffffffff) >> 20, 195)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'nv-chardev-numbers.h'
            source = root / 'hybrid580-standard-node-devices.c'
            header.write_text(
                '#define NV_MAJOR_DEVICE_NUMBER 4291U\n'
                '#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n'
                '#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n',
                encoding='utf-8')
            source.write_text(
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), '
                'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n'
                'register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, '
                'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n',
                encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'Linux dev_t'):
                tool.parse_standard_node_layout(header, source)

    def test_direct_preflight_rejects_linux_dev_t_overflow(self):
        state = host_state()
        state.update(secure_boot_enabled=False, lockdown='none',
                     module_sig_enforce=False, active_char_devices=[],
                     active_modules=[], loaded_nvidia_modules=[],
                     char_device_major_names=[])
        layout = dict(LAYOUT, major=4291)

        with self.assertRaisesRegex(ValueError, 'Linux dev_t'):
            load_preflight().evaluate_preflight(
                state, candidate_modules(signer='test signer'), layout)

    def test_invalid_host_device_number_is_rejected(self):
        state = host_state()
        state['active_char_devices'] = [
            {'path': '/dev/invalid', 'major': 4291, 'minor': 0}]

        with self.assertRaisesRegex(ValueError, 'active character-device number'):
            load_preflight().evaluate_preflight(
                state, candidate_modules(), LAYOUT)

    def test_unknown_lockdown_mode_is_rejected_closed(self):
        state = host_state()
        state['lockdown'] = 'maybe'
        with self.assertRaisesRegex(ValueError, 'unsupported lockdown mode'):
            load_preflight().evaluate_preflight(state, candidate_modules(), LAYOUT)

    def test_missing_full_kernel_vermagic_is_rejected_closed(self):
        state = host_state()
        del state['kernel_vermagic']

        with self.assertRaisesRegex(ValueError, 'kernel vermagic is required'):
            load_preflight().evaluate_preflight(state, candidate_modules(), LAYOUT)

    def test_module_dependency_graph_rejects_unreviewed_edges(self):
        modules = candidate_modules(signer='test signer')
        modules['frontend']['depends'] += ',unreviewed_provider'
        state = host_state()
        state.update(secure_boot_enabled=False, lockdown='none',
                     module_sig_enforce=False, active_char_devices=[],
                     active_modules=[], loaded_nvidia_modules=[],
                     char_device_major_names=[])

        result = load_preflight().evaluate_preflight(state, modules, LAYOUT)

        self.assertIn('frontend_dependency_mismatch',
                      {item['code'] for item in result['blockers']})

    def test_open_provider_dependency_cycle_is_rejected(self):
        modules = candidate_modules(signer='test signer')
        modules['open']['depends'] = 'hybrid580_frontend'
        state = host_state()
        state.update(secure_boot_enabled=False, lockdown='none',
                     module_sig_enforce=False, active_char_devices=[],
                     active_modules=[], loaded_nvidia_modules=[],
                     char_device_major_names=[])

        result = load_preflight().evaluate_preflight(state, modules, LAYOUT)

        self.assertIn('open_dependency_mismatch',
                      {item['code'] for item in result['blockers']})

    def test_legacy_provider_unknown_dependency_is_rejected(self):
        modules = candidate_modules(signer='test signer')
        modules['legacy']['depends'] = 'absent_module'
        state = host_state()
        state.update(secure_boot_enabled=False, lockdown='none',
                     module_sig_enforce=False, active_char_devices=[])

        result = load_preflight().evaluate_preflight(state, modules, LAYOUT)

        self.assertIn('legacy_dependency_mismatch',
                      {item['code'] for item in result['blockers']})

    def test_clear_static_checks_never_claim_runtime_canary_readiness(self):
        modules = candidate_modules(signer='unverified signer')
        state = clear_static_host(host_state())
        state.update(secure_boot_enabled=False, lockdown='none', module_sig_enforce=False)

        result = load_preflight().evaluate_preflight(state, modules, LAYOUT)

        self.assertEqual(result['status'], 'static-preflight-clear')
        self.assertEqual(result['qualification'], 'static-preflight-only')
        self.assertFalse(result['signature_trust_verified'])
        self.assertFalse(result['runtime_validated'])
        self.assertFalse(result['canary_ready'])

    def test_node_collision_uses_exact_major_minor_ranges(self):
        state = host_state()
        state.update(secure_boot_enabled=False, lockdown='none',
                     module_sig_enforce=False)
        state['active_char_devices'] = [
            {'path': '/dev/nvidia-unrelated', 'major': 195, 'minor': 254},
            {'path': '/dev/nvidia-other', 'major': 196, 'minor': 0},
        ]
        set_active_modules(state, [])
        state['char_device_major_names'] = []
        result = load_preflight().evaluate_preflight(
            state, candidate_modules(signer='unverified signer'), LAYOUT)

        self.assertEqual(result['status'], 'static-preflight-clear')
        self.assertNotIn('standard_device_numbers_in_use',
                         {item['code'] for item in result['blockers']})


if __name__ == '__main__':
    unittest.main()
