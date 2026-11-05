# SPDX-License-Identifier: MIT
"""Contracts for compile-only validation of the fully replayed R595 provider."""
from pathlib import Path
import importlib.util
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'build_replayed_r595_open', ROOT / 'tools/build_replayed_r595_open.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ReplayedR595OpenBuildTests(unittest.TestCase):
    def test_success_qualification_matches_the_debugger_provider_build(self):
        self.assertEqual(
            builder.BUILD_QUALIFICATION,
            'compiled-replayed-r595-private-open-debugger-provider')

    def test_replay_gate_requires_the_complete_unmodified_patch_replay(self):
        report = {
            'qualification': 'all-r580-open-patches-apply-to-r595-source',
            'source_version': '595.99.02',
            'patch_count': 45,
            'patches_attempted': 45,
            'source_tree_unchanged': True,
            'inputs_unchanged': True,
            'patch_inputs_unchanged': True,
            'baseline_symvers_unchanged': True,
            'build_version_api_header_unchanged': True,
            'pm_provider_api_headers_unchanged': True,
            'r595_source_modified': False,
            'module_compiled': False,
            'module_loaded': False,
            'hardware_tested': False,
            'patch_records': ([{'patch': f'{i:04d}-fixture.patch',
                                'exit_code': 0, 'offset_or_fuzz': False}
                              for i in range(1, 42)] +
                              [{'patch': '0047-private-open-client-share-policy.patch',
                                'exit_code': 0, 'offset_or_fuzz': False},
                               {'patch': '0048-private-open-sync-boost-groups.patch',
                                'exit_code': 0, 'offset_or_fuzz': False},
                              {'patch': '0049-private-open-control-export-prototypes.patch',
                               'exit_code': 0, 'offset_or_fuzz': False},
                              {'patch': '0050-private-open-debugger-bridge.patch',
                               'exit_code': 0, 'offset_or_fuzz': False}]),
        }
        builder.validate_replay_report(report)
        for key, value in (
            ('patch_count', 42),
            ('source_tree_unchanged', False),
            ('module_loaded', True),
        ):
            broken = dict(report)
            broken[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                builder.validate_replay_report(broken)
        broken = dict(report)
        broken['patch_records'] = list(report['patch_records'])
        broken['patch_records'][-2] = dict(broken['patch_records'][-2], offset_or_fuzz=True)
        with self.assertRaisesRegex(ValueError, '0049-private-open-control-export-prototypes'):
            builder.validate_replay_report(broken)

    def test_build_command_targets_provider_and_uvm_conftest_without_installing(self):
        command = builder.build_command(Path('/tmp/candidate-source'), jobs=4)
        self.assertEqual(command[:3], [
            'make', '-C', '/tmp/candidate-source/kernel-open'])
        self.assertIn('KERNEL_UNAME=' + builder.KERNEL_RELEASE, command)
        self.assertIn('NV_KERNEL_MODULES=nvidia nvidia-uvm', command)
        self.assertIn('KBUILD_EXTRA_SYMBOLS=' + str(
            ROOT / 'build/experiments/r595-syncboost-nvidia-frontend-v1/Module.symvers'),
            command)
        self.assertIn('-j4', command)
        self.assertEqual(command[-1], 'modules')
        self.assertNotIn('install', command)

    def test_build_command_generates_shared_uvm_conftest_for_open_provider(self):
        command = builder.build_command(Path('/tmp/candidate-source'), jobs=4)
        self.assertIn('NV_KERNEL_MODULES=nvidia nvidia-uvm', command)
        self.assertIn(
            'KBUILD_EXTRA_SYMBOLS=' + str(
                ROOT / 'build/experiments/r595-syncboost-nvidia-frontend-v1/Module.symvers'),
            command)

    def test_replay_source_path_is_bound_to_the_reported_work_directory(self):
        work = ROOT / 'build/experiments/replay-path-contract'
        report = {
            'work_dir': str(work),
            'source': str(builder.R595_UPSTREAM_SOURCE),
        }
        self.assertEqual(
            builder.source_from_replay_report(report),
            work / 'source')
        report['source'] = '/tmp/unrelated/source/open-gpu-kernel-modules-595.99.02'
        with self.assertRaises(ValueError):
            builder.source_from_replay_report(report)

    def test_candidate_export_requires_the_exact_private_flavor(self):
        symbol = builder.SHARE_POLICY_EXPORT
        builder.validate_share_policy_export(
            '0x12345678\t' + symbol + '\thybrid580_open' +
            '\tEXPORT_SYMBOL\t')
        for symvers in (
            '0x12345678\t' + symbol + '\thybrid580_open' +
            '\tEXPORT_SYMBOL_GPL\t',
            '0x12345678\t' + symbol + '\tnvidia\tEXPORT_SYMBOL\t',
            '',
        ):
            with self.subTest(symvers=symvers), self.assertRaises(ValueError):
                builder.validate_share_policy_export(symvers)

    def test_candidate_sync_boost_export_requires_the_exact_private_flavor(self):
        symbol = builder.SYNC_BOOST_EXPORT
        builder.validate_sync_boost_export(
            '0x12345678\t' + symbol + '\thybrid580_open' +
            '\tEXPORT_SYMBOL\t')
        for symvers in (
            '0x12345678\t' + symbol + '\thybrid580_open' +
            '\tEXPORT_SYMBOL_GPL\t',
            '0x12345678\t' + symbol + '\tnvidia\tEXPORT_SYMBOL\t',
            '',
        ):
            with self.subTest(symvers=symvers), self.assertRaises(ValueError):
                builder.validate_sync_boost_export(symvers)

    def test_debugger_bridge_exports_require_both_exact_private_symbols(self):
        valid = (
            '0x12345678\t' + builder.DEBUGGER_ALLOC_EXPORT +
            '\thybrid580_open\tEXPORT_SYMBOL\n' +
            '0x12345678\t' + builder.DEBUGGER_MASK_EXPORT +
            '\thybrid580_open\tEXPORT_SYMBOL\n')
        builder.validate_debugger_bridge_exports(valid)
        for broken in (
            valid.replace('hybrid580_open\tEXPORT_SYMBOL',
                          'hybrid580_open\tEXPORT_SYMBOL_GPL', 1),
            valid.splitlines()[0] + '\n',
            valid + valid.splitlines()[0] + '\n',
        ):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                builder.validate_debugger_bridge_exports(broken)

    def test_kmod_softdep_overlay_is_pinned_and_applies_to_a_private_copy(self):
        upstream = (ROOT / 'build/research/open-gpu-kernel-modules-595.99.02/source/'
                    'open-gpu-kernel-modules-595.99.02')
        with tempfile.TemporaryDirectory(prefix='r595-builder-softdep-') as tmp:
            source = Path(tmp) / 'source'
            source.mkdir()
            target = source / 'kernel-open/nvidia/libspdm_ecc.c'
            target.parent.mkdir(parents=True)
            shutil.copyfile(upstream / 'kernel-open/nvidia/libspdm_ecc.c', target)
            record = builder.apply_kmod_softdep_overlay(source)

            self.assertEqual(record['patch_sha256'], builder.KMOD_SOFTDEP_PATCH_SHA256)
            self.assertEqual(record['preimage_sha256'], builder.KMOD_SOFTDEP_SOURCE_SHA256)
            self.assertEqual(record['postimage_sha256'], builder.KMOD_SOFTDEP_PATCHED_SOURCE_SHA256)
            self.assertFalse(record['fuzz_used'])
            self.assertFalse(record['offset_used'])
            self.assertEqual(record['value'], 'pre: ecdh_generic ecdsa_generic')

    def test_kmod_softdep_overlay_fails_closed_on_a_changed_preimage(self):
        with tempfile.TemporaryDirectory(prefix='r595-builder-softdep-negative-') as tmp:
            source = Path(tmp) / 'source'
            target = source / 'kernel-open/nvidia/libspdm_ecc.c'
            target.parent.mkdir(parents=True)
            target.write_text('MODULE_SOFTDEP("pre: modified");\n')
            with self.assertRaisesRegex(ValueError, 'preimage hash mismatch'):
                builder.apply_kmod_softdep_overlay(source)

    def test_output_paths_must_be_new_and_below_project_roots(self):
        work = ROOT / 'build/experiments/test-only-candidate'
        report = ROOT / 'evidence/test-only-candidate.json'
        builder.validate_output_paths(work, report, check_exists=False)
        with self.assertRaises(ValueError):
            builder.validate_output_paths(ROOT / 'build/not-an-experiment', report,
                                          check_exists=False)
        with self.assertRaises(ValueError):
            builder.validate_output_paths(work, ROOT / 'docs/report.json',
                                          check_exists=False)


if __name__ == '__main__':
    unittest.main()
