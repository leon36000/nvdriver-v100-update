# SPDX-License-Identifier: MIT
"""Build-input and export boundaries; never compile or load a module here."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import json
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools/probe_private_backend_chardev.py'
spec = importlib.util.spec_from_file_location('private_chardev_build', TOOL)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
prop_spec = importlib.util.spec_from_file_location(
    'private_proprietary580_build', ROOT / 'tools/build_private_proprietary580.py')
prop_builder = importlib.util.module_from_spec(prop_spec)
prop_spec.loader.exec_module(prop_builder)


class PrivateBackendBuildContract(unittest.TestCase):
    def test_v100_master_routes_are_part_of_exact_legacy_export_abi(self):
        original = {'nv_vma_start_write': 'EXPORT_SYMBOL'}
        original.update({'vendor_' + str(index): 'EXPORT_SYMBOL' for index in range(93)})
        expected = prop_builder.expected_exports(original)
        self.assertEqual(len(expected), 150)
        self.assertEqual(expected['hybrid580_legacy_control_session_master_alloc_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected[
            'hybrid580_legacy_control_session_master_error_intr_offset_mask_v1'],
            'EXPORT_SYMBOL')

    def test_proprietary_gpu_id_route_is_in_exact_export_abi(self):
        original = {'nv_vma_start_write': 'EXPORT_SYMBOL'}
        original.update({'vendor_' + str(index): 'EXPORT_SYMBOL' for index in range(93)})
        expected = prop_builder.expected_exports(original)
        self.assertEqual(len(expected), 150)
        self.assertEqual(expected['hybrid580_legacy_control_session_gpu_name_string_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_client_share_policy_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_sync_boost_groups_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_gpu_session_register_control_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_gpu_id_info_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_attached_ids_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_probed_ids_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_device_ids_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_device_alloc_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_device_free_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_memory_alloc_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_object_free_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_vaspace_alloc_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_channel_group_alloc_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_context_share_alloc_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_channel_alloc_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_engine_alloc_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_subdevice_alloc_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_gr_tpc_mask_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_binapi_alloc_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_rusd_alloc_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_usermode_alloc_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_map_memory_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_unmap_memory_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected[
            'hybrid580_legacy_control_session_update_device_mapping_info_v1'],
            'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_sys_params_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_check_version_v1'],
                         'EXPORT_SYMBOL')
        self.assertEqual(expected['hybrid580_legacy_control_session_p2p_alloc_v1'],
                         'EXPORT_SYMBOL')
        for operation in ('register_va_space', 'unregister_va_space',
                          'register_vidmem', 'unregister_vidmem'):
            self.assertEqual(expected['hybrid580_legacy_control_session_p2p_' + operation + '_v1'],
                             'EXPORT_SYMBOL')
        for operation in ('begin', 'recover', 'end'):
            self.assertEqual(expected['hybrid580_legacy_pm_recovery_' + operation + '_v1'],
                             'EXPORT_SYMBOL')
        for operation in ('suspend', 'resume'):
            self.assertEqual(expected['hybrid580_legacy_pm_channels_' + operation + '_v1'],
                             'EXPORT_SYMBOL')
        builder_source = (ROOT / 'tools/build_private_proprietary580.py').read_text()
        self.assertIn("'new_device_mapping_update_export_exact'", builder_source)
        self.assertIn("'new_p2p_control_exports_exact'", builder_source)
        self.assertIn("'new_pm_recovery_exports_exact'", builder_source)
        self.assertIn("'new_pm_channels_exports_exact'", builder_source)
        self.assertIn("'new_sys_params_export_exact'", builder_source)
        self.assertIn('if actual != wanted:', builder_source)

    def test_target_conditional_vma_wrapper_is_derived_from_generated_conftest(self):
        original = {'nv_vma_start_write': 'EXPORT_SYMBOL'}
        original.update({'vendor_' + str(index): 'EXPORT_SYMBOL' for index in range(93)})
        feature = prop_builder.VMA_START_WRITE_FEATURE
        self.assertTrue(prop_builder.vma_start_write_is_gpl_only(
            '#define ' + feature + ' 1\n'))
        self.assertFalse(prop_builder.vma_start_write_is_gpl_only(
            '#define ' + feature + ' 0\n'))
        with self.assertRaises(ValueError):
            prop_builder.vma_start_write_is_gpl_only(
                '#define ' + feature + ' 0\n#define ' + feature + ' 1\n')
        with self.assertRaises(ValueError):
            prop_builder.vma_start_write_is_gpl_only('/* no conftest result */\n')

        wrapper = prop_builder.VMA_START_WRITE_WRAPPER
        with_wrapper = prop_builder.expected_exports(original, vma_start_write_wrapper=True)
        without_wrapper = prop_builder.expected_exports(original, vma_start_write_wrapper=False)
        self.assertEqual(len(with_wrapper), 150)
        self.assertEqual(len(without_wrapper), 149)
        self.assertIn(wrapper, with_wrapper)
        self.assertNotIn(wrapper, without_wrapper)
        self.assertEqual({**without_wrapper, wrapper: with_wrapper[wrapper]}, with_wrapper)

    def test_kernel_validation_config_requires_one_exact_setting(self):
        setting = prop_builder.kernel_config_setting
        self.assertEqual(setting('CONFIG_STACK_VALIDATION=y\n', 'CONFIG_STACK_VALIDATION'), 'y')
        self.assertEqual(setting('# CONFIG_STACK_VALIDATION is not set\n',
                                 'CONFIG_STACK_VALIDATION'), 'n')
        self.assertIsNone(setting('', 'CONFIG_STACK_VALIDATION'))
        with self.assertRaises(ValueError):
            setting('CONFIG_STACK_VALIDATION=y\n# CONFIG_STACK_VALIDATION is not set\n',
                    'CONFIG_STACK_VALIDATION')

    def test_objtool_warns_only_for_symbols_from_the_unchanged_vendor_core(self):
        classify = prop_builder.classify_objtool_output
        warning = ("/tmp/hybrid580_legacy.o: warning: objtool: _nv001234rm+0x4: "
                   "'naked' return found in MITIGATION_RETHUNK build\n")
        result = classify("$ objtool --module hybrid580_legacy.o\ncwd: /tmp\n" + warning,
                          {"_nv001234rm"}, 1)
        self.assertEqual(result["warning_count"], 1)
        self.assertEqual(result["warning_instances_from_unchanged_core"], 1)
        with self.assertRaisesRegex(ValueError, "outside the unchanged proprietary core"):
            classify(warning, {"_nv001235rm"}, 1)
        with self.assertRaisesRegex(ValueError, "unclassified diagnostic"):
            classify(warning + "objtool: error: unsupported instruction\n",
                     {"_nv001234rm"}, 1)
        with self.assertRaisesRegex(ValueError, "exit code"):
            classify(warning, {"_nv001234rm"}, 256)

    def test_sdk_overlay_reuses_wrapper_access_types(self):
        # Both vendor rs_access.h copies use pragma once. Including SDK nvos
        # in its original directory after the wrapper copy duplicates types.
        base = builder.private.BASE
        source = base.parent
        sdk = source / 'src/common/sdk/nvidia/inc'
        code = '#include <rs_access.h>\n#include <nvos.h>\n'
        code += '_Static_assert(sizeof(NVOS21_PARAMETERS)==32, "NVOS21");\n'
        code += '_Static_assert(sizeof(NVOS64_PARAMETERS)==48, "NVOS64");\n'
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            unit = directory / 'access-types.c'
            unit.write_text(code)
            includes = ['-I' + str(base / 'common/inc'), '-I' + str(sdk),
                '-I' + str(source / 'src/common/inc'), '-I' + str(source / 'src/common/inc/swref')]
            command = ['cc', '-std=gnu11', '-Werror', '-c', str(unit), '-o', str(directory / 'test.o')]
            original = subprocess.run(command + includes, capture_output=True, text=True)
            self.assertNotEqual(original.returncode, 0)
            self.assertIn('redefinition of', original.stderr)
            self.assertIn('RS_ACCESS_MASK', original.stderr)
            with tarfile.open(builder.private.ARCHIVE, 'r:xz') as archive:
                original_header = archive.extractfile(builder.private.TOP + '/src/common/sdk/nvidia/inc/nvos.h').read()
            self.assertEqual((sdk / 'nvos.h').read_bytes(), original_header)
            # Header copied verbatim; quoted rs_access now uses -I wrapper.
            (directory / 'nvos.h').write_bytes(original_header)
            fixed = subprocess.run(command + ['-I' + str(directory), *includes], capture_output=True, text=True)
            self.assertEqual(fixed.returncode, 0, fixed.stderr)

    def test_control_session_requires_projection(self):
        result = subprocess.run([sys.executable, '-B', str(TOOL), '--control-session'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('--control-session requires --file-projection', result.stderr)

    def test_gpu_session_requires_control_session(self):
        result = subprocess.run([sys.executable, '-B', str(TOOL), '--gpu-session'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('--gpu-session requires --control-session', result.stderr)

    def test_build_version_bridge_requires_gpu_session(self):
        result = subprocess.run([sys.executable, '-B', str(TOOL), '--hybrid-build-version'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('--hybrid-build-version requires --gpu-session', result.stderr)

    def test_build_version_bridge_has_one_pointer_free_open_export(self):
        original = {'nv_api': 'EXPORT_SYMBOL'}
        base = {'hybrid580_open_nv_api': 'EXPORT_SYMBOL'}
        builder.validate_backend_exports(original, base, False)
        expected = dict(base,
            hybrid580_open_control_session_build_version_v1='EXPORT_SYMBOL')
        builder.validate_backend_exports(original, expected, False, build_version=True)
        for bad in (base, dict(expected,
                    hybrid580_open_control_session_build_version_v1='EXPORT_SYMBOL_GPL'),
                    dict(expected, hybrid580_open_unexpected='EXPORT_SYMBOL')):
            with self.assertRaises(ValueError):
                builder.validate_backend_exports(original, bad, False, build_version=True)

    def test_build_version_provider_uses_only_fixed_v2_rm_packet(self):
        patch = builder.BUILD_VERSION_PATCH.read_text()
        header = builder.OPEN_BUILD_VERSION_HEADER.read_text()
        self.assertIn('NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION_V2', patch)
        self.assertIn('NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_V2_PARAMS', patch)
        self.assertIn('result = kzalloc(sizeof(*result), GFP_KERNEL)', patch)
        self.assertIn('paramsSize = sizeof(*result)', patch)
        self.assertIn('KERNEL_POINTER_TO_NvP64(result)', patch)
        self.assertIn('kfree(result)', patch)
        self.assertNotIn('GET_BUILD_VERSION_V2_PARAMS result = { 0 }', patch)
        self.assertIn('control.status == 0xffffffffU', patch)
        self.assertIn('EXPORT_SYMBOL(hybrid580_open_control_session_build_version_v1)', patch)
        self.assertNotIn('NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION,', patch)
        self.assertNotIn('copy_to_user', patch)
        self.assertNotIn('copy_from_user', patch)
        self.assertIn('NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_V2_PARAMS *params', header)
        self.assertNotIn('NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS *params', header)

    def test_gpu_session_export_contract_includes_bdf_routing(self):
        original = {'nv_api': 'EXPORT_SYMBOL_GPL'}
        expected = {'hybrid580_open_nv_api': 'EXPORT_SYMBOL_GPL'}
        expected.update({
            'hybrid580_open_register_file_projection_v1': 'EXPORT_SYMBOL',
            'hybrid580_open_unregister_file_projection_v1': 'EXPORT_SYMBOL'})
        for operation in ('create', 'get', 'put', 'file', 'attach'):
            expected['hybrid580_open_control_session_' + operation + '_v1'] = 'EXPORT_SYMBOL'
        for operation in ('create', 'create_by_bdf', 'get', 'put', 'file', 'ioctl',
                          'register_control'):
            expected['hybrid580_open_gpu_session_' + operation + '_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_gpu_inventory_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_gpu_card_info_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_gpu_id_info_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_attached_ids_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_probed_ids_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_device_ids_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_device_alloc_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_device_free_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_memory_alloc_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_object_free_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_vaspace_alloc_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_channel_group_alloc_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_context_share_alloc_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_channel_alloc_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_engine_alloc_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_subdevice_alloc_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_gr_tpc_mask_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_gpu_name_string_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_client_share_policy_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_binapi_alloc_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_rusd_alloc_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_usermode_alloc_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_map_memory_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_unmap_memory_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_sys_params_v1'] = 'EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_build_version_v1'] = 'EXPORT_SYMBOL'
        builder.validate_backend_exports(original, expected, True,
                                          control_session=True, gpu_session=True,
                                          sys_params=True, build_version=True,
                                          client_share_policy=True)
        del expected['hybrid580_open_gpu_session_create_by_bdf_v1']
        with self.assertRaises(ValueError):
            builder.validate_backend_exports(original, expected, True,
                                              control_session=True, gpu_session=True,
                                              sys_params=True, build_version=True)

    def test_map_memory_bridge_patches_keep_native_rm_dispatch(self):
        open_patch = builder.MAP_MEMORY_PATCH.read_text()
        legacy_patch = prop_builder.MAP_MEMORY_PATCH.read_text()
        for patch in (open_patch, legacy_patch):
            self.assertIn('NV_ESC_RM_MAP_MEMORY', patch)
            self.assertIn('NV_ESC_RM_UNMAP_MEMORY', patch)
            self.assertIn('rm_ioctl(', patch)
            self.assertIn('nv_ioctl_nvos33_parameters_with_fd', patch)
            self.assertIn('EXPORT_SYMBOL(', patch)
            self.assertNotIn('copy_from_user', patch)
        self.assertIn('hybrid580_open_control_session_map_memory_v1', open_patch)
        self.assertIn('hybrid580_legacy_control_session_map_memory_v1', legacy_patch)

    def test_sys_params_bridge_is_fixed_typed_and_backend_private(self):
        open_patch = builder.SYS_PARAMS_PATCH.read_text()
        legacy_patch = prop_builder.SYS_PARAMS_PATCH.read_text()
        for patch in (open_patch, legacy_patch):
            self.assertIn('NV_ESC_SYS_PARAMS', patch)
            self.assertIn('hybrid580_set_sys_params', patch)
            self.assertIn('numa_memblock_size', patch)
            self.assertIn('mutex_lock(&hybrid580_sys_params_lock)', patch)
            self.assertNotIn('NV_COPY_FROM_USER', patch)
            self.assertNotIn('copy_from_user', patch)
            self.assertIn('EXPORT_SYMBOL(', patch)
        self.assertIn('hybrid580_open_control_session_sys_params_v1', open_patch)
        self.assertIn('hybrid580_legacy_control_session_sys_params_v1', legacy_patch)
        self.assertIn('len(actual) != len(wanted)',
                      (ROOT / 'tools/build_private_proprietary580.py').read_text())

    def test_engine_object_provider_patches_are_generation_separated_and_payload_free(self):
        open_patch = builder.ENGINE_OBJECT_PATCH.read_text()
        legacy_patch = (prop_builder.PATCH_DIR / '0039-private-legacy-engine-object.patch').read_text()
        expected = (
            (open_patch, 'BLACKWELL_DMA_COPY_B', 'BLACKWELL_COMPUTE_B',
             'hybrid580_open_control_session_engine_alloc_v1', 'rm_kernel_rmapi_op(sp, &ops)'),
            (legacy_patch, 'VOLTA_DMA_COPY_A', 'VOLTA_COMPUTE_A',
             'hybrid580_legacy_control_session_engine_alloc_v1',
             'rm_ioctl(sp, nv, &nvlfp->nvfp, NV_ESC_RM_ALLOC'),
        )
        for patch, dma_class, compute_class, symbol, rm_call in expected:
            self.assertIn('hObjectParent = h_channel', patch)
            self.assertIn('hObjectNew = h_engine', patch)
            self.assertIn('class_id != ' + dma_class, patch)
            self.assertIn('class_id != ' + compute_class, patch)
            self.assertIn('.pAllocParms = NvP64_NULL', patch)
            self.assertIn('.paramsSize = 0', patch)
            self.assertIn('mutex_lock_interruptible(&session->lock)', patch)
            self.assertIn('nv_down_read_interruptible(&nv_system_pm_lock)', patch)
            self.assertIn('nv_check_gpu_state(nv)', patch)
            self.assertIn(rm_call, patch)
            self.assertIn('EXPORT_SYMBOL(' + symbol + ')', patch)
            self.assertNotIn('copy_from_user', patch)
            self.assertNotIn('NV_COPY_FROM_USER', patch)
        self.assertNotIn('BLACKWELL_', legacy_patch)
        self.assertNotIn('VOLTA_', open_patch)

    def test_control_session_exports_do_not_weaken_existing_flavors(self):
        original = {'nv_api': 'EXPORT_SYMBOL_GPL'}
        expected = {'hybrid580_open_nv_api': 'EXPORT_SYMBOL_GPL',
            'hybrid580_open_register_file_projection_v1': 'EXPORT_SYMBOL',
            'hybrid580_open_unregister_file_projection_v1': 'EXPORT_SYMBOL'}
        for operation in ('create', 'get', 'put', 'file', 'attach'):
            expected['hybrid580_open_control_session_' + operation + '_v1'] = 'EXPORT_SYMBOL'
        builder.validate_backend_exports(original, expected, True, control_session=True)
        for symbol in ('hybrid580_open_control_session_put_v1', 'hybrid580_open_nv_api'):
            missing = dict(expected)
            del missing[symbol]
            with self.assertRaises(ValueError):
                builder.validate_backend_exports(original, missing, True, control_session=True)

    def test_missing_core_retains_failure_report(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            report = directory / 'failure.json'
            work = directory / 'never-created'
            result = subprocess.run([sys.executable, '-B', str(TOOL),
                '--core', str(directory / 'missing.o'), '--core-sha256', 'a' * 64,
                '--work-dir', str(work), '--report', str(report)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertTrue(report.exists(), 'missing core must produce a durable failed report')
            payload = json.loads(report.read_text())
            self.assertEqual(payload['qualification'], 'failed')
            self.assertIn('FileNotFoundError', payload['error'])
            self.assertFalse(payload['inputs_unchanged'])
            self.assertFalse(work.exists())

    def test_alternative_core_requires_explicit_digest(self):
        for args in (['--core', '/tmp/untrusted-core.o'], ['--core-sha256', 'a' * 64]):
            result = subprocess.run([sys.executable, '-B', str(TOOL), *args],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('--core and --core-sha256 must be provided together', result.stderr)

    def test_alternative_core_digest_is_sha256(self):
        result = subprocess.run([sys.executable, '-B', str(TOOL), '--core', '/tmp/core.o',
                                 '--core-sha256', 'not-a-digest'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('64 lowercase hexadecimal', result.stderr)

    def test_projection_exports_are_exact_and_preserve_flavors(self):
        self.assertTrue(hasattr(builder, 'validate_backend_exports'), 'projection export contract missing')
        original = {'nv_rm_api': 'EXPORT_SYMBOL', 'nv_gpl_api': 'EXPORT_SYMBOL_GPL'}
        base = {'hybrid580_open_' + key: value for key, value in original.items()}
        extended = dict(base,
            hybrid580_open_register_file_projection_v1='EXPORT_SYMBOL',
            hybrid580_open_unregister_file_projection_v1='EXPORT_SYMBOL')
        builder.validate_backend_exports(original, base, False)
        builder.validate_backend_exports(original, extended, True)
        for bad in (base, dict(extended, nv_rm_api='EXPORT_SYMBOL'),
                    dict(extended, hybrid580_open_nv_gpl_api='EXPORT_SYMBOL'),
                    dict(extended, hybrid580_open_register_file_projection_v1='EXPORT_SYMBOL_GPL')):
            with self.subTest(exports=bad), self.assertRaises(ValueError):
                builder.validate_backend_exports(original, bad, True)


if __name__ == '__main__':
    unittest.main()
