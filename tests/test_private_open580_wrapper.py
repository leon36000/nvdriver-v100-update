# SPDX-License-Identifier: MIT
"""Native R580 patch contracts in disposable source copies; never GPU tests."""
import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

class PrivateOpen580Tests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('private_open580',ROOT/'tools/build_private_open580_wrapper.py')
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def test_exact_r580_19607_release_and_rm_build_are_pinned(self):
        release=self.m.source_release('580.196.07')
        self.assertEqual(release['archive_sha256'],
                         '21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084')
        self.assertEqual(release['source_top'],
                         'NVIDIA-kernel-module-source-580.196.07')
        command=self.m.rm_core_build_command(self.root/'source',jobs=3)
        self.assertIn('-j3',command)
        self.assertIn('EXTRA_CFLAGS=-mfunction-return=thunk-extern',command)
        self.assertEqual(self.m.source_release('580.178.04')['core_mode'],'pinned')
        self.assertEqual(self.m.source_release('580.196.07')['core_mode'],'build-from-source')
        with self.assertRaisesRegex(ValueError,'unsupported R580 source version'):
            self.m.source_release('580.999.99')
        with self.assertRaisesRegex(ValueError,'positive integer'):
            self.m.rm_core_build_command(self.root/'source',jobs=0)

    def test_legacy_provider_report_requires_matching_isolated_release(self):
        report={
            'schema':'r58019607-proprietary-port-build-v1',
            'status':'compiled-private-proprietary-backend',
            'loaded_or_installed':False,
            'runtime_or_hardware_validated':False,
            'module':{'metadata':{'name':'hybrid580_legacy','version':'580.196.07'}},
        }
        self.assertEqual(self.m.validate_legacy_provider_report(report,'580.196.07'),
                         '580.196.07')
        with self.assertRaisesRegex(ValueError,'same pinned R580 release'):
            self.m.validate_legacy_provider_report(report,'580.178.04')
        changed={**report,'loaded_or_installed':True}
        with self.assertRaisesRegex(ValueError,'isolated R580.196.07 compile'):
            self.m.validate_legacy_provider_report(changed,'580.196.07')

    def test_kernel_release_accepts_v100_guest_and_rejects_path_injection(self):
        self.assertEqual(self.m.validate_kernel_release('6.8.0-147-generic'),
                         '6.8.0-147-generic')
        self.assertEqual(self.m.validate_kernel_release('7.0.0-38-generic'),
                         '7.0.0-38-generic')
        for bad in ('', '../6.8.0', '6.8/0', 'x' * 129, '6.8.0\n'):
            with self.subTest(release=bad):
                with self.assertRaisesRegex(ValueError, 'kernel release'):
                    self.m.validate_kernel_release(bad)

    def test_readelf_modinfo_parser_preserves_kernel_metadata_and_repeated_aliases(self):
        output = '''String dump of section '.modinfo':
  [     0]  license=Dual MIT/GPL
  [    14]  name=hybrid580_open
  [    27]  alias=usb:v1234p0001
  [    44]  alias=pci:v000010DEd*
  [    60]  vermagic=6.8.0-147-generic SMP preempt mod_unload modversions 
header without an offset ignored
'''
        fields = self.m.parse_readelf_modinfo(output)
        self.assertEqual(fields["license"], ["Dual MIT/GPL"])
        self.assertEqual(fields["name"], ["hybrid580_open"])
        self.assertEqual(fields["alias"], ["usb:v1234p0001", "pci:v000010DEd*"])
        self.assertEqual(fields["vermagic"], ["6.8.0-147-generic SMP preempt mod_unload modversions"])

    def test_target_kbuild_common_header_symlinks_are_pinned_by_resolved_path(self):
        build = self.root / 'headers-generic'
        common = build / 'headers-common'
        for relative in self.m.KERNEL_BUILD_INPUTS:
            path = build / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(relative + '\\n')
        common_file = common / 'scripts/Makefile.build'
        common_file.parent.mkdir(parents=True)
        common_file.write_text('common Kbuild makefile\\n')
        (build / 'scripts/Makefile.build').unlink()
        (build / 'scripts/Makefile.build').symlink_to('../headers-common/scripts/Makefile.build')

        report = self.m.target_kernel_input_fingerprints('6.8.0-147-generic', build_root=build)
        entry = report['files']['scripts/Makefile.build']
        self.assertEqual(entry['resolved_path'], str(common_file.resolve()))
        self.assertEqual(entry['bytes'], common_file.stat().st_size)
        self.assertEqual(entry['sha256'], self.m.sha(common_file))

    def test_target_kbuild_rejects_symlink_escaping_pinned_header_trees(self):
        build = self.root / 'headers-generic'
        outside = self.root / 'unrelated'
        for relative in self.m.KERNEL_BUILD_INPUTS:
            path = build / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(relative + '\\n')
        external_file = outside / 'Makefile.build'
        external_file.parent.mkdir(parents=True)
        external_file.write_text('unrelated file\\n')
        (build / 'scripts/Makefile.build').unlink()
        (build / 'scripts/Makefile.build').symlink_to(external_file)

        with self.assertRaisesRegex(ValueError, 'outside the pinned header trees'):
            self.m.target_kernel_input_fingerprints('6.8.0-147-generic', build_root=build)

    def test_output_path_rejects_symlinked_allowed_ancestor(self):
        project = self.root / "project"
        outside = self.root / "outside"
        project.mkdir()
        (outside / "experiments").mkdir(parents=True)
        (project / "build").symlink_to(outside, target_is_directory=True)
        self.m.ROOT = project
        allowed = project / "build" / "experiments"
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.m.canonical_project_destination(allowed / "candidate", allowed)

    def test_timed_out_build_kills_the_entire_process_group(self):
        import sys
        import time

        marker = self.root / "child-survived-timeout"
        child_code = (
            "import pathlib,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "time.sleep(0.8); "
            f"pathlib.Path({str(marker)!r}).write_text('alive')"
        )
        parent_code = (
            "import signal,subprocess,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            f"subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
            "time.sleep(30)"
        )
        result = self.m.run_process_group(
            [sys.executable, "-c", parent_code], cwd=self.root, env=None,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.15,
            termination_grace=0.1)
        self.assertEqual(result, 124)
        time.sleep(1.0)
        self.assertFalse(marker.exists())

    def test_rm_core_log_requires_flag_on_every_actual_c_compile(self):
        log=('cc -O2 -mfunction-return=thunk-extern -c src/gpu.c -o gpu.o\n'
             'cc -O2 -mfunction-return=thunk-extern -c src/mem.c -o mem.o\n')
        audit=self.m.audit_rm_compile_commands(log)
        self.assertEqual(audit['c_compile_count'],2)
        self.assertTrue(audit['all_have_return_thunk_flag'])
        with self.assertRaisesRegex(ValueError,'missing return-thunk flag'):
            self.m.audit_rm_compile_commands(log.replace(' -mfunction-return=thunk-extern','',1))
        with self.assertRaisesRegex(ValueError,'no verbose RM C compilation'):
            self.m.audit_rm_compile_commands('make: nothing to do\n')

    def test_actual_native_isolation_series_and_provider_header_contract(self):
        paths=self.m.patch_paths()
        targets=set()
        for path in paths:
            for line in path.read_text().splitlines():
                if line.startswith('+++ b/'):targets.add(line[6:])
        targets.add('kernel-open/nvidia/libspdm_ecc.c')
        with tarfile.open(self.m.ARCHIVE,'r:xz') as archive:
            for path in targets:
                try: member=archive.getmember(self.m.SOURCE_TOP+'/'+path)
                except KeyError:continue
                target=self.root/path;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
        self.m.apply_patches(self.root,paths)
        result=self.m.source_contract(self.root)
        self.assertTrue(result['dynamic_major'])
        self.assertTrue(result['deny_by_default_pci'])
        self.assertTrue(result['public_hardware_aliases_removed'])
        self.assertTrue(result['resource_names_private'])
        self.assertTrue(result['kmod_softdep_space_delimiters'])
        self.assertEqual(len(result['private_baseline_export_macros']),94)
        export_header=(self.root/'kernel-open/nvidia/hybrid580-open-exports.h').read_text()
        self.assertIn('#define nvUvmInterfaceDupMemoryWithControlFd hybrid580_open_nvUvmInterfaceDupMemoryWithControlFd',export_header)
        self.assertTrue(result['control_fd_dispatch_private'])
        self.assertTrue(result['system_features_single_definition'])
        self.assertTrue(result['fabric_status_single_definition'])
        self.assertTrue(result['gpu_name_string_single_definition'])
        self.assertTrue(result['client_share_policy_single_definition'])
        self.assertTrue(result['sync_boost_groups_single_definition'])
        with self.assertRaisesRegex(RuntimeError,'already applied'):
            self.m.apply_patches(self.root,[ROOT/'patches/r580.178.04/0044-private-open-system-features.patch'])
        with self.assertRaisesRegex(RuntimeError,'already applied'):
            self.m.apply_patches(self.root,[ROOT/'patches/r580.178.04/0045-private-open-fabric-status.patch'])
        softdep=(self.root/'kernel-open/nvidia/libspdm_ecc.c').read_text()
        self.assertIn('MODULE_SOFTDEP("pre: ecdh_generic ecdsa_generic");',softdep)
        self.assertNotIn('MODULE_SOFTDEP("pre: ecdh_generic,ecdsa_generic");',softdep)

    def test_map_update_overlay_changes_context_only_and_requires_unique_anchor(self):
        patch=ROOT/'patches/r580.178.04/0041-private-open-update-device-mapping-info.patch'
        original=patch.read_text()
        overlay=self.m.rebase_map_update_context(original)
        def additions(text):
            return [line for line in text.splitlines() if line.startswith('+') and not line.startswith('+++')]
        self.assertEqual(additions(original),additions(overlay))
        self.assertIn(' EXPORT_SYMBOL(hybrid580_open_control_session_build_version_v1);',overlay)
        with self.assertRaises(ValueError):self.m.rebase_map_update_context(original.replace('EXPORT_SYMBOL(hybrid580_open_control_session_unmap_memory_v1);','unexpected'))

    def test_version_check_patch_is_kernel_buffer_only(self):
        patch=ROOT/'patches/r580.178.04/0043-private-open-version-check.patch'
        text=patch.read_text()
        self.assertEqual(re.findall(r'^\+\+\+ b/([^\n]+)$',text,re.M),
                         ['kernel-open/nvidia/nv.c'])
        for fragment in ('nv_ioctl_rm_api_version_t *params',
                         'size != sizeof(*params)',
                         'rm_perform_version_check(sp, params, size)',
                         'EXPORT_SYMBOL(hybrid580_open_control_session_check_version_v1);'):
            self.assertIn(fragment,text)
        self.assertNotIn('copy_from_user',text)

    def test_system_features_provider_is_fixed_kernel_buffer_only(self):
        patch=ROOT/'patches/r580.178.04/0044-private-open-system-features.patch'
        text=patch.read_text()
        self.assertEqual(re.findall(r'^\+\+\+ b/([^\n]+)$',text,re.M),
                         ['kernel-open/nvidia/nv.c'])
        for fragment in ('NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS *params',
                         'paramsSize = sizeof(result)',
                         'KERNEL_POINTER_TO_NvP64(&result)',
                         'rm_kernel_rmapi_op(sp, &ops)',
                         'EXPORT_SYMBOL(hybrid580_open_control_session_system_features_v1);'):
            self.assertIn(fragment,text)
        self.assertNotIn('copy_from_user',text)
        self.assertNotIn('copy_to_user',text)

    def test_fabric_status_provider_is_fixed_kernel_buffer_only(self):
        patch=ROOT/'patches/r580.178.04/0045-private-open-fabric-status.patch'
        text=patch.read_text()
        self.assertEqual(re.findall(r'^\+\+\+ b/([^\n]+)$',text,re.M),
                         ['kernel-open/nvidia/nv.c'])
        for fragment in ('NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS *params',
                         'paramsSize = sizeof(result)',
                         'KERNEL_POINTER_TO_NvP64(&result)',
                         'NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS',
                         'rm_kernel_rmapi_op(sp, &ops)',
                         'EXPORT_SYMBOL(hybrid580_open_control_session_fabric_status_v1);'):
            self.assertIn(fragment,text)
        self.assertNotIn('copy_from_user',text)
        self.assertNotIn('copy_to_user',text)

    def test_gpu_name_string_provider_uses_fixed_r580_subdevice_packet(self):
        patch=ROOT/'patches/r580.178.04/0046-private-open-gpu-name-string.patch'
        text=patch.read_text()
        self.assertEqual(re.findall(r'^\+\+\+ b/([^\n]+)$',text,re.M),
                         ['kernel-open/nvidia/nv.c'])
        for fragment in ('NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS *params',
                         'NV2080_CTRL_CMD_GPU_GET_NAME_STRING',
                         'NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_ASCII',
                         'NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_UNICODE',
                         'paramsSize = sizeof(result)',
                         'KERNEL_POINTER_TO_NvP64(&result)',
                         'rm_kernel_rmapi_op(sp, &ops)',
                         'EXPORT_SYMBOL(hybrid580_open_control_session_gpu_name_string_v1);'):
            self.assertIn(fragment,text)
        self.assertNotIn('copy_from_user',text)
        self.assertNotIn('copy_to_user',text)

    def test_client_share_policy_provider_uses_fixed_kernel_packet(self):
        patch=ROOT/'patches/r580.178.04/0047-private-open-client-share-policy.patch'
        text=patch.read_text()
        self.assertEqual(re.findall(r'^\+\+\+ b/([^\n]+)$',text,re.M),
                         ['kernel-open/nvidia/nv.c'])
        for fragment in ('RS_SHARE_POLICY *policy',
                         '.cmd = 0x00000d04U',
                         'paramsSize = sizeof(result)',
                         'KERNEL_POINTER_TO_NvP64(&result)',
                         'rm_kernel_rmapi_op(sp, &ops)',
                         'BUILD_BUG_ON(sizeof(result) != 12)',
                         'EXPORT_SYMBOL(hybrid580_open_control_session_client_share_policy_v1);'):
            self.assertIn(fragment,text)
        self.assertNotIn('copy_from_user',text)
        self.assertNotIn('copy_to_user',text)

    def test_sync_boost_groups_provider_uses_heap_packet_and_exports_count_only(self):
        patch=ROOT/'patches/r580.178.04/0048-private-open-sync-boost-groups.patch'
        text=patch.read_text()
        self.assertEqual(re.findall(r'^\+\+\+ b/([^\n]+)$',text,re.M),
                         ['kernel-open/nvidia/nv.c'])
        for fragment in ('NvU32 *group_count', 'NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO',
                         'NV0000_SYNC_GPU_BOOST_MAX_GROUPS', 'kzalloc(sizeof(*result), GFP_KERNEL)',
                         'result->groupCount = 0xffffffffU',
                         '.params = KERNEL_POINTER_TO_NvP64(result)',
                         'paramsSize = sizeof(*result)', 'rm_kernel_rmapi_op(sp, &ops)',
                         '*group_count = result->groupCount', 'kfree(result)',
                         'EXPORT_SYMBOL(hybrid580_open_control_session_sync_boost_groups_v1);'):
            self.assertIn(fragment,text)
        self.assertNotIn('copy_from_user',text)
        self.assertNotIn('copy_to_user',text)
        self.assertNotIn('*group_count = result->groupCount +',text)

    def test_rs_access_duplicate_types_share_exact_vendor_declarations(self):
        with tarfile.open(self.m.ARCHIVE,'r:xz') as archive:
            sdk=archive.extractfile(self.m.SOURCE_TOP+'/src/common/sdk/nvidia/inc/rs_access.h').read().decode()
            kernel=archive.extractfile(self.m.SOURCE_TOP+'/kernel-open/common/inc/rs_access.h').read().decode()
        changed=self.m.share_rs_access_sdk(sdk,kernel)
        self.assertTrue(changed.startswith(sdk.split('#pragma once',1)[0]))
        self.assertIn('#include "../../../../../kernel-open/common/inc/rs_access.h"',changed)
        self.assertNotIn('struct RS_ACCESS_MASK',changed)
        with self.assertRaises(ValueError):self.m.share_rs_access_sdk(sdk+'unexpected',kernel)

    def test_missing_source_anchor_fails_closed(self):
        (self.root/'a').write_text('unexpected\n')
        patch=self.root/'anchor.patch'
        patch.write_text('--- a/a\n+++ b/a\n@@ -1 +1 @@\n-expected\n+changed\n')
        with self.assertRaisesRegex(RuntimeError,'patch'):
            self.m.apply_patches(self.root,[patch])
        self.assertEqual((self.root/'a').read_text(),'unexpected\n')

    def test_patch_offset_requires_unique_literal_context(self):
        (self.root/'a').write_text('one\ntwo\n')
        patch=self.root/'offset.patch'
        patch.write_text('--- a/a\n+++ b/a\n@@ -1 +1 @@\n-two\n+changed\n')
        records=self.m.apply_patches(self.root,[patch])
        self.assertTrue(records[0]['offset_messages'])
        self.assertEqual((self.root/'a').read_text(),'one\nchanged\n')
        (self.root/'a').write_text('two\ntwo\n')
        with self.assertRaisesRegex(RuntimeError,'ambiguous'):
            self.m.apply_patches(self.root,[patch])

    def test_exact_export_flavors_and_prefix_are_required(self):
        original={'a':'EXPORT_SYMBOL','b':'EXPORT_SYMBOL_GPL'}
        self.m.validate_exports(original,{'hybrid580_open_a':'EXPORT_SYMBOL','hybrid580_open_b':'EXPORT_SYMBOL_GPL','hybrid580_open_provider':'EXPORT_SYMBOL'})
        for bad in ({'hybrid580_open_a':'EXPORT_SYMBOL'},
                    {'hybrid580_open_a':'EXPORT_SYMBOL','hybrid580_open_b':'EXPORT_SYMBOL'},
                    {'hybrid580_open_a':'EXPORT_SYMBOL','hybrid580_open_b':'EXPORT_SYMBOL_GPL','public':'EXPORT_SYMBOL'}):
            with self.assertRaises(ValueError):self.m.validate_exports(original,bad)

if __name__=='__main__':unittest.main()
