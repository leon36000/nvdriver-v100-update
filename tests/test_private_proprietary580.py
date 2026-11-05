# SPDX-License-Identifier: MIT
"""Private proprietary wrapper source/CPU contracts; never execute kernel/RM/GPU."""
from pathlib import Path
import importlib.util
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

import test_private_backend_control_session as session
import test_private_backend_file_projection as projection
import test_private_backend_pci as pci
from gpu_session_register_harness import run_register_control_contract

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / '.cache/vendor-proprietary/r580.178.04-ubuntu/usr/src/nvidia-580.178.04'
PATCH_DIR = ROOT / 'patches/r580.178.04/proprietary'
NOTICE_PATCH = PATCH_DIR / '0010-local-modification-notices.patch'
EXPERIMENTAL_DEBUGGER_MASK_GUARD = (
    PATCH_DIR / '0049-private-legacy-debugger-mask-fail-closed.patch')
DEVICE_OBJECT_PATCH = PATCH_DIR / '0018-private-legacy-device-object.patch'
PATCHES = [patch for patch in sorted(PATCH_DIR.glob('*.patch'))
           if patch not in (NOTICE_PATCH, EXPERIMENTAL_DEBUGGER_MASK_GUARD)] + [NOTICE_PATCH]
SDK = ROOT / 'build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04'
VENDOR_MODIFIED = (
    'common/inc/nv-linux.h', 'common/inc/nv.h', 'nvidia/export_nvswitch.h', 'nvidia/nv-caps-imex.c',
    'nvidia/nv-caps.c', 'nvidia/nv-mmap.c', 'nvidia/nv-pci-table.c', 'nvidia/nv-pci.c',
    'nvidia/nv-platform.c', 'nvidia/nv-procfs.c', 'nvidia/nv.c',
    'nvidia/nvidia.Kbuild', 'nvidia/nvlink_linux.c', 'nvidia/nvlink_linux.h',
    'nvidia/procfs_nvswitch.c')
NOTICE_ID = 'LOCAL MODIFICATION NOTICE - NVIDIA Hybrid Driver Lab, 2026-10-19.'


class PrivateProprietary580Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.tree = Path(cls.tmp.name)
        targets = set()
        for patch in PATCHES:
            targets.update(re.findall(r'^--- a/([^\n]+)$', patch.read_text(), re.M))
        for target in targets:
            dest = cls.tree / target
            if not (SOURCE / target).is_file():
                if target not in ('nvidia/hybrid580-gpu-session.h',
                                  'nvidia/hybrid580-control-session.h'):
                    raise AssertionError('unexpected authored-file target: ' + target)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(SOURCE / target, dest)
        for patch in PATCHES:
            result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                                    cwd=cls.tree, capture_output=True, text=True)
            if result.returncode or 'fuzz' in result.stdout:
                raise AssertionError(result.stdout + result.stderr)
        gpu_header = cls.tree / 'nvidia/hybrid580-gpu-session.h'
        cls.source = (cls.tree / 'nvidia/nv.c').read_text()
        cls.gpu_header = gpu_header.read_text()
        cls.control_header = (ROOT / 'src/hybrid580-control-session.h').read_text().replace(
            'hybrid580_open', 'hybrid580_legacy')
        shutil.copy2(SDK / 'src/common/sdk/nvidia/inc/nvos.h', cls.tree / 'common/inc/nvos.h')
        cls.vendor_macros = ''
        for header, names in [('common/inc/nv-linux.h', ('NV_STATE_PTR',)),
                              ('common/inc/nv.h', ('NV_FLAG_OPEN', 'NV_FLAG_CONTROL'))]:
            text = (SOURCE / header).read_text()
            for name in names:
                rows = re.findall(r'^#define ' + name + r'(?:\([^\n]*?\))?[^\n]+$', text, re.M)
                if len(rows) != 1:
                    raise AssertionError('ambiguous vendor macro ' + name)
                cls.vendor_macros += rows[0] + '\n'

    def test_private_module_license_exports_and_early_guard(self):
        self.assertEqual(re.findall(r'MODULE_LICENSE\("([^\"]+)"\)', self.source), ['NVIDIA'])
        kbuild = (self.tree / 'nvidia/nvidia.Kbuild').read_text()
        self.assertIn('obj-m += hybrid580_legacy.o', kbuild)
        self.assertNotIn('obj-m += nvidia.o', kbuild)

    def test_register_control_api_is_present_without_test_fixture_rewriting(self):
        expected = (ROOT / 'src/hybrid580-gpu-session.h').read_bytes().replace(
            b'hybrid580_open', b'hybrid580_legacy').decode()
        self.assertEqual(self.gpu_header, expected)
        namespace = (self.tree / 'nvidia/hybrid580-legacy-exports.h').read_text()
        self.assertEqual(len(re.findall(r'^#define \w+ hybrid580_legacy_', namespace, re.M)), 94)
        self.assertIn('#define nv_vma_start_write hybrid580_legacy_nv_vma_start_write', namespace)
        pci = (self.tree / 'nvidia/nv-pci.c').read_text()
        probe = pci[pci.index('nv_pci_probe\n'):]
        self.assertLess(probe.index('if (!hybrid_pci_bdf_selected'),
                        probe.index('regs_bar_index = nv_bar_index_to_os_bar_index'))
        self.assertNotIn('NV_MAJOR_DEVICE_NUMBER', self.source)
        self.assertIn('alloc_chrdev_region', self.source)
        self.assertIn('fput can defer', (self.tree / 'nvidia/hybrid580-control-session.h').read_text())
        # Proprietary IMEX source deliberately supplies a stub for channel0;
        # no absent GPL-only class/device creation is introduced by this port.
        imex = (self.tree / 'nvidia/nv-caps-imex.c').read_text()
        self.assertNotIn('class_create(', imex)
        self.assertNotIn('device_create(', imex)
        self.assertNotIn('"nvidia-caps-imex-channels"', imex)

    def test_openrm580_nv_gpu_ops_master_contract_is_four_bytes_and_single_live_object(self):
        source = (SDK / 'src/nvidia/src/kernel/rmapi/nv_gpu_ops.c').read_text()
        ecc_start = source.index('static NV_STATUS gpuDeviceRmSubDeviceInitEcc(')
        nvlink_start = source.index('static NV_STATUS gpuDeviceRmSubDeviceInitNvlink(')
        nvlink_end = source.index('static NV_STATUS getSwizzIdFromSmcPartHandle(', nvlink_start)
        ecc = source[ecc_start:nvlink_start]
        nvlink = source[nvlink_start:nvlink_end]
        self.assertIn('This can only be done once per RM subdevice as GF100_SUBDEVICE_MASTER can',
                      source)
        self.assertRegex(ecc, r'int tempPtr\s*=\s*0;')
        self.assertRegex(ecc, r'GF100_SUBDEVICE_MASTER,\s*&tempPtr,\s*sizeof\(tempPtr\)')
        self.assertRegex(nvlink, r'int tempPtr\s*=\s*0;')
        self.assertRegex(nvlink, r'GF100_SUBDEVICE_MASTER,\s*&tempPtr,\s*sizeof\(tempPtr\)')
        self.assertIn('Only one GF100_SUBDEVICE_MASTER can be allocated at once', nvlink)
        ctrl = (SDK / 'src/common/sdk/nvidia/inc/ctrl/ctrl90e6.h').read_text()
        self.assertIn('#define NV90E6_CTRL_CMD_MASTER_GET_ECC_INTR_OFFSET_MASK '
                      'NV90E6_CTRL_CMD_MASTER_GET_ERROR_INTR_OFFSET_MASK', ctrl)

    def test_map_memory_bridge_calls_native_escape_and_preserves_status(self):
        for name in ('map_memory', 'unmap_memory'):
            symbol=f'EXPORT_SYMBOL(hybrid580_legacy_control_session_{name}_v1);'
            self.assertEqual(self.source.count(symbol), 1)
        start=self.source.index('NV_STATUS hybrid580_legacy_control_session_map_memory_v1(')
        end=self.source.index('EXPORT_SYMBOL(hybrid580_legacy_control_session_unmap_memory_v1);',start)
        bridge=self.source[start:end]
        self.assertIn('NV_ESC_RM_MAP_MEMORY',bridge)
        self.assertIn('nv_ioctl_nvos33_parameters_with_fd',bridge)
        self.assertIn('api.fd = fd',bridge)
        self.assertIn('mutex_lock_interruptible(&session->lock)',bridge)
        self.assertIn('nv_down_read_interruptible(&nv_system_pm_lock)',bridge)
        self.assertIn('*params = api.params',bridge)
        self.assertIn('NV_ESC_RM_UNMAP_MEMORY',bridge)

    def test_mapping_update_bridge_is_synchronous_fixed_nvos56(self):
        symbol = ('EXPORT_SYMBOL('
                  'hybrid580_legacy_control_session_update_device_mapping_info_v1);')
        self.assertEqual(self.source.count(symbol), 1)
        start = self.source.index(
            'NV_STATUS hybrid580_legacy_control_session_update_device_mapping_info_v1(')
        end = self.source.index(symbol, start)
        bridge = self.source[start:end]
        for fragment in ('NVOS56_PARAMETERS api',
                         'NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO',
                         'sizeof(api)', 'mutex_lock_interruptible(&session->lock)',
                         'nv_down_read_interruptible(&nv_system_pm_lock)',
                         'if (status == NV_OK)\n            *params = api'):
            self.assertIn(fragment, bridge)
        self.assertNotIn('schedule_work', bridge)
        self.assertNotIn('queue_work', bridge)
        self.assertNotIn('kthread_', bridge)

    def test_version_check_bridge_uses_native_rm_on_fixed_kernel_packet(self):
        symbol = 'EXPORT_SYMBOL(hybrid580_legacy_control_session_check_version_v1);'
        self.assertEqual(self.source.count(symbol), 1)
        start = self.source.index(
            'NV_STATUS hybrid580_legacy_control_session_check_version_v1(')
        end = self.source.index(symbol, start)
        bridge = self.source[start:end]
        for fragment in ('nv_ioctl_rm_api_version_t *params',
                         'size != sizeof(*params)', 'nv_ctl_device',
                         'NV_FLAG_CONTROL',
                         'nv_down_read_interruptible(&nv_system_pm_lock)',
                         'nv_kmem_cache_alloc_stack(&sp)',
                         'rm_perform_version_check(sp, params, size)'):
            self.assertIn(fragment, bridge)
        self.assertNotIn('copy_from_user', bridge)
        self.assertNotIn('copy_to_user', bridge)

    def test_gpu_name_string_bridge_is_typed_fixed_and_subdevice_scoped(self):
        symbol = ('EXPORT_SYMBOL('
                  'hybrid580_legacy_control_session_gpu_name_string_v1);')
        self.assertEqual(self.source.count(symbol), 1)
        start = self.source.index(
            'NV_STATUS hybrid580_legacy_control_session_gpu_name_string_v1(')
        end = self.source.index(symbol, start)
        bridge = self.source[start:end]
        for fragment in ('NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS *params',
                         'NV2080_CTRL_CMD_GPU_GET_NAME_STRING',
                         '.hClient = h_root', '.hObject = h_subdevice',
                         'NVOS54_FLAGS_NONE', 'KERNEL_POINTER_TO_NvP64(&result)',
                         'NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_ASCII',
                         'NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_UNICODE',
                         'nv_down_read_interruptible(&nv_system_pm_lock)',
                         'rm_kernel_rmapi_op(sp, &ops)'):
            self.assertIn(fragment, bridge)
        self.assertNotIn('copy_from_user', bridge)
        self.assertNotIn('copy_to_user', bridge)

    def test_client_share_policy_bridge_is_fixed_and_input_only(self):
        symbol = ('EXPORT_SYMBOL('
                  'hybrid580_legacy_control_session_client_share_policy_v1);')
        self.assertEqual(self.source.count(symbol), 1)
        start = self.source.index(
            'NV_STATUS hybrid580_legacy_control_session_client_share_policy_v1(')
        end = self.source.index(symbol, start)
        bridge = self.source[start:end]
        for fragment in ('RS_SHARE_POLICY *policy',
                         'h_client != h_object',
                         '.cmd = 0x00000d04U',
                         '.params = KERNEL_POINTER_TO_NvP64(&result)',
                         'paramsSize = sizeof(result)',
                         'nv_ctl_device', 'NV_FLAG_CONTROL',
                         'nv_down_read_interruptible(&nv_system_pm_lock)',
                         'rm_kernel_rmapi_op(sp, &ops)'):
            self.assertIn(fragment, bridge)
        self.assertNotIn('copy_from_user', bridge)
        self.assertNotIn('copy_to_user', bridge)

    def test_client_share_policy_is_declared_in_the_shared_provider_api(self):
        header = (ROOT / 'src/hybrid580-control-session.h').read_text()
        self.assertIn('hybrid580_open_control_session_client_share_policy_v1(', header)
        self.assertIn('RS_SHARE_POLICY *policy', header)

    def test_sync_boost_groups_bridge_uses_heap_and_keeps_ids_local(self):
        symbol = ('EXPORT_SYMBOL('
                  'hybrid580_legacy_control_session_sync_boost_groups_v1);')
        self.assertEqual(self.source.count(symbol), 1)
        start = self.source.index(
            'NV_STATUS hybrid580_legacy_control_session_sync_boost_groups_v1(')
        end = self.source.index(symbol, start)
        bridge = self.source[start:end]
        for fragment in ('NvU32 *group_count', 'NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO',
                         'kzalloc(sizeof(*result), GFP_KERNEL)',
                         'result->groupCount = 0xffffffffU',
                         'NV0000_SYNC_GPU_BOOST_MAX_GROUPS',
                         '.params = KERNEL_POINTER_TO_NvP64(result)',
                         'paramsSize = sizeof(*result)',
                         'nv_down_read_interruptible(&nv_system_pm_lock)',
                         'rm_kernel_rmapi_op(sp, &ops)',
                         '*group_count = result->groupCount',
                         'kfree(result)'):
            self.assertIn(fragment, bridge)
        self.assertNotIn('copy_from_user', bridge)
        self.assertNotIn('copy_to_user', bridge)

    def test_v100_bar1_p2p_bridge_is_fixed_typed_and_legacy_owned(self):
        symbol = 'EXPORT_SYMBOL(hybrid580_legacy_control_session_p2p_alloc_v1);'
        self.assertEqual(self.source.count(symbol), 1)
        start = self.source.index(
            'NV_STATUS hybrid580_legacy_control_session_p2p_alloc_v1(')
        end = self.source.index(symbol, start)
        bridge = self.source[start:end]
        for fragment in ('NV503C_ALLOC_PARAMETERS',
                         'NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1',
                         'NV50_THIRD_PARTY_P2P', '.hRoot = h_root',
                         '.hObjectParent = h_subdevice', '.hObjectNew = h_p2p',
                         '.paramsSize = params_size',
                         'params_size != 0 && params_size != sizeof(alloc_params)',
                         'NV_ESC_RM_ALLOC', 'rm_ioctl(sp, nv, &nvlfp->nvfp',
                         '*rm_status = alloc.status',
                         '*returned_p2p = alloc.hObjectNew',
                         'mutex_lock_interruptible(&session->lock)',
                         'nv_down_read_interruptible(&nv_system_pm_lock)'):
            self.assertIn(fragment, bridge)
        self.assertNotIn('NV_COPY_FROM_USER', bridge)
        self.assertNotIn('NV_COPY_TO_USER', bridge)

    def test_observed_v100_p2p_controls_use_fixed_kernel_owned_rm_controls(self):
        names = ('register_va_space', 'unregister_va_space',
                 'register_vidmem', 'unregister_vidmem')
        for name in names:
            symbol = f'EXPORT_SYMBOL(hybrid580_legacy_control_session_p2p_{name}_v1);'
            self.assertEqual(self.source.count(symbol), 1)
        start = self.source.index(
            'static NV_STATUS hybrid580_legacy_control_session_p2p_control_v1(')
        end = self.source.index(
            'EXPORT_SYMBOL(hybrid580_legacy_control_session_p2p_unregister_vidmem_v1);', start)
        bridge = self.source[start:end]
        for command in ('NV503C_CTRL_CMD_REGISTER_VA_SPACE',
                        'NV503C_CTRL_CMD_UNREGISTER_VA_SPACE',
                        'NV503C_CTRL_CMD_REGISTER_VIDMEM',
                        'NV503C_CTRL_CMD_UNREGISTER_VIDMEM'):
            self.assertIn(command, bridge)
        for fragment in ('NV04_CONTROL', 'KERNEL_POINTER_TO_NvP64(params)',
                         '.hClient = h_root', '.hObject = h_p2p',
                         'params_size != sizeof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS)',
                         'mutex_lock_interruptible(&session->lock)',
                         'nv_down_read_interruptible(&nv_system_pm_lock)',
                         'rm_kernel_rmapi_op(sp, &ops)', '*control_status = control.status'):
            self.assertIn(fragment, bridge)
        self.assertNotIn('NV_COPY_FROM_USER', bridge)
        self.assertNotIn('NV_COPY_TO_USER', bridge)

    def test_gpu_session_api_is_namespaced_and_checks_the_opened_bdf(self):
        for operation in ('create', 'create_by_bdf', 'get', 'put', 'file', 'ioctl',
                          'register_control'):
            self.assertEqual(self.source.count(
                f'EXPORT_SYMBOL(hybrid580_legacy_gpu_session_{operation}_v1);'), 1)
        start = self.source.index(
            'int hybrid580_legacy_gpu_session_register_control_v1(')
        end = self.source.index(
            'EXPORT_SYMBOL(hybrid580_legacy_gpu_session_register_control_v1);', start)
        register = self.source[start:end]
        for fragment in ('get_file(control->file)',
                         'hybrid580_legacy_backend_file(control_file, 1)',
                         'rm_acquire_api_lock(sp)',
                         'gpu_nvlfp->nvfp.ctl_nvfp != NULL',
                         'control_nvlfp->nvfp.ctl_nvfp != NULL',
                         'cmpxchg(&gpu_nvlfp->nvfp.register_or_refcount',
                         'cmpxchg(&gpu_nvlfp->nvfp.ctl_nvfp',
                         'NVFP_TYPE_REGISTERED',
                         'gpu_nvlfp->nvfp.ctl_nvfp_priv = control_file',
                         'control_file = NULL;'):
            self.assertIn(fragment, register)
        self.assertNotIn('portAtomicCompareAndSwapU32', register)
        self.assertNotIn('portAtomicSetSize', register)
        self.assertNotIn('fget(', register)
        self.assertNotIn('copy_from_user', register)
        self.assertEqual(
            run_register_control_contract(self.source, 'legacy'),
            'provider REGISTER_FD bridge CPU/UBSan scenarios: 12')
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_legacy_gpu_inventory_v1);'), 1)
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_legacy_gpu_card_info_v1);'), 1)
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_legacy_control_session_gpu_id_info_v1);'), 1)
        start = self.source.index('NV_STATUS hybrid580_legacy_control_session_gpu_id_info_v1(')
        end = self.source.index('EXPORT_SYMBOL(hybrid580_legacy_control_session_gpu_id_info_v1);', start)
        gpu_id_info = self.source[start:end]
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', gpu_id_info)
        self.assertIn('.params.control = control', gpu_id_info)
        self.assertIn('.op = NV04_CONTROL', gpu_id_info)
        start = self.source.index('NV_STATUS hybrid580_legacy_control_session_attached_ids_v1(')
        end = self.source.index('EXPORT_SYMBOL(hybrid580_legacy_control_session_attached_ids_v1);', start)
        attached_ids = self.source[start:end]
        self.assertIn('NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS', attached_ids)
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', attached_ids)
        self.assertIn('.params.control = control', attached_ids)
        self.assertIn('.op = NV04_CONTROL', attached_ids)
        probed_start = self.source.index('NV_STATUS hybrid580_legacy_control_session_probed_ids_v1(')
        probed_end = self.source.index('EXPORT_SYMBOL(hybrid580_legacy_control_session_probed_ids_v1);', probed_start)
        probed_ids = self.source[probed_start:probed_end]
        self.assertIn('NV0000_CTRL_CMD_GPU_GET_PROBED_IDS', probed_ids)
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', probed_ids)
        self.assertIn('.op = NV04_CONTROL', probed_ids)
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_legacy_control_session_device_ids_v1);'), 1)
        device_ids_start = self.source.index(
            'NV_STATUS hybrid580_legacy_control_session_device_ids_v1(')
        device_ids_end = self.source.index(
            'EXPORT_SYMBOL(hybrid580_legacy_control_session_device_ids_v1);', device_ids_start)
        device_ids = self.source[device_ids_start:device_ids_end]
        self.assertIn('NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS', device_ids)
        self.assertIn('NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS', device_ids)
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', device_ids)
        self.assertIn('.op = NV04_CONTROL', device_ids)
        self.assertIn('h_client != h_object', gpu_id_info)
        self.assertNotIn('rm_ioctl(', gpu_id_info)
        self.assertIn('pci_name(nvl->pci_dev)', self.source)
        self.assertIn('nv_wait_open_complete_interruptible(nvlfp)', self.source)
        self.assertIn('for (minor = 0; minor <= NV_MINOR_DEVICE_NUMBER_REGULAR_MAX; ++minor)', self.source)
        self.assertIn('return -EXDEV;', self.source)
        header = (self.tree / 'nvidia/hybrid580-gpu-session.h').read_text()
        self.assertIn('hybrid580_legacy_gpu_session_ioctl_v1', header)
        self.assertIn('hybrid580_legacy_gpu_session_register_control_v1', header)
        self.assertIn('hybrid580_legacy_gpu_inventory_v1', header)
        self.assertIn('hybrid580_legacy_gpu_card_info_v1', header)
        start = self.source.index('int hybrid580_legacy_gpu_inventory_v1(')
        end = self.source.index('EXPORT_SYMBOL(hybrid580_legacy_gpu_inventory_v1);', start)
        inventory = self.source[start:end]
        self.assertIn('LOCK_NV_LINUX_DEVICES()', inventory)
        self.assertIn('NV_FLAG_EXCLUDE', inventory)
        self.assertIn('PCI_FUNC(nvl->pci_dev->devfn)', inventory)
        self.assertIn('rc = -ENOSPC;', inventory)

        start = self.source.index('int hybrid580_legacy_gpu_card_info_v1(')
        end = self.source.index('EXPORT_SYMBOL(hybrid580_legacy_gpu_card_info_v1);', start)
        card_info = self.source[start:end]
        self.assertIn('nv_down_read_interruptible(&nv_system_pm_lock)', card_info)
        self.assertIn('nv_check_gpu_state(nv)', card_info)
        self.assertIn('nvidia_read_card_info(typed_records, capacity)', card_info)

    def test_binapi_alloc_is_private_typed_and_uses_legacy_rm_ioctl(self):
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_legacy_control_session_binapi_alloc_v1);'), 1)
        start = self.source.index(
            'NV_STATUS hybrid580_legacy_control_session_binapi_alloc_v1(')
        end = self.source.index(
            'EXPORT_SYMBOL(hybrid580_legacy_control_session_binapi_alloc_v1);', start)
        body = self.source[start:end]
        self.assertIn('hObjectParent = h_subdevice', body)
        self.assertIn('.hClass = NV2081_BINAPI', body)
        self.assertIn('params->reserved != 0', body)
        self.assertIn('rm_ioctl(sp, nv, &nvlfp->nvfp, NV_ESC_RM_ALLOC', body)
        self.assertNotIn('NV_COPY_FROM_USER', body)
        self.assertNotIn('NV_COPY_TO_USER', body)

    def test_rusd_alloc_is_private_typed_and_uses_legacy_rm_ioctl(self):
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_legacy_control_session_rusd_alloc_v1);'), 1)
        start = self.source.index(
            'NV_STATUS hybrid580_legacy_control_session_rusd_alloc_v1(')
        end = self.source.index(
            'EXPORT_SYMBOL(hybrid580_legacy_control_session_rusd_alloc_v1);', start)
        body = self.source[start:end]
        self.assertIn('hObjectParent = h_subdevice', body)
        self.assertIn('.hClass = RM_USER_SHARED_DATA', body)
        self.assertIn('NV00DE_ALLOC_PARAMETERS alloc_params', body)
        self.assertIn('alloc_params = *params', body)
        self.assertIn('rm_ioctl(sp, nv, &nvlfp->nvfp, NV_ESC_RM_ALLOC', body)
        self.assertNotIn('NV_COPY_FROM_USER', body)
        self.assertNotIn('NV_COPY_TO_USER', body)

    def test_usermode_alloc_is_backend_owned_nonprivileged_and_typed(self):
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_legacy_control_session_usermode_alloc_v1);'), 1)
        start = self.source.index(
            'NV_STATUS hybrid580_legacy_control_session_usermode_alloc_v1(')
        end = self.source.index(
            'EXPORT_SYMBOL(hybrid580_legacy_control_session_usermode_alloc_v1);', start)
        body = self.source[start:end]
        self.assertIn('hObjectParent = h_subdevice', body)
        self.assertIn('.hClass = class_id', body)
        self.assertIn('class_id != VOLTA_USERMODE_A', body)
        self.assertIn('class_id != HOPPER_USERMODE_A', body)
        self.assertIn('params->bPriv != NV_FALSE', body)
        self.assertIn('rm_ioctl(sp, nv, &nvlfp->nvfp, NV_ESC_RM_ALLOC', body)
        self.assertNotIn('NV_COPY_FROM_USER', body)
        self.assertNotIn('NV_COPY_TO_USER', body)

    def test_engine_alloc_bridge_is_volta_only_and_uses_zero_size_rm_packet(self):
        symbol = 'EXPORT_SYMBOL(hybrid580_legacy_control_session_engine_alloc_v1);'
        self.assertEqual(self.source.count(symbol), 1)
        start = self.source.index(
            'NV_STATUS hybrid580_legacy_control_session_engine_alloc_v1(')
        end = self.source.index(symbol, start)
        body = self.source[start:end]
        for fragment in ('class_id != VOLTA_DMA_COPY_A',
                         'class_id != VOLTA_COMPUTE_A',
                         '.hObjectParent = h_channel',
                         '.hObjectNew = h_engine',
                         '.pAllocParms = NvP64_NULL',
                         '.pRightsRequested = NvP64_NULL',
                         '.paramsSize = 0',
                         '.flags = NVOS64_FLAGS_NONE',
                         'rm_ioctl(sp, nv, &nvlfp->nvfp, NV_ESC_RM_ALLOC',
                         '*rm_status = alloc.status',
                         '*returned_engine = alloc.hObjectNew',
                         'mutex_lock_interruptible(&session->lock)',
                         'nv_down_read_interruptible(&nv_system_pm_lock)',
                         'nv_check_gpu_state(nv)'):
            self.assertIn(fragment, body)
        self.assertNotIn('BLACKWELL_', body)
        self.assertNotIn('copy_from_user', body)
        self.assertNotIn('NV_COPY_FROM_USER', body)
        self.assertNotIn('NV_COPY_TO_USER', body)
        self.assertIn(
            'NV_STATUS hybrid580_legacy_control_session_engine_alloc_v1(',
            self.control_header)

    def test_vendor_modified_files_have_prominent_notice_and_original_notices(self):
        # Compare against a separately built pre-notice candidate: the notice
        # patch must change comments only and must cover exactly vendor files.
        previous = ROOT / 'build/experiments/private-proprietary-session-v2/nvidia-580.178.04'
        missing = []
        for name in VENDOR_MODIFIED:
            text = (self.tree / name).read_text()
            if NOTICE_ID not in text[:180]:
                missing.append(name)
                continue
            if name.endswith('.Kbuild'):
                prefix, separator, remainder = text.partition('\n\n')
                self.assertTrue(all(line.startswith('#') for line in prefix.splitlines()))
                self.assertTrue(separator)
            else:
                self.assertTrue(text.startswith('/*\n * ' + NOTICE_ID))
                prefix, separator, remainder = text.partition(' */\n')
                self.assertTrue(separator)
            expected = (previous / name).read_text()
            if name == 'nvidia/nv.c':
                with tempfile.TemporaryDirectory() as temp:
                    tree = Path(temp)
                    target = tree / name
                    target.parent.mkdir(parents=True)
                    target.write_text(expected)
                    control_header = previous / 'nvidia/hybrid580-control-session.h'
                    control_target = tree / 'nvidia/hybrid580-control-session.h'
                    control_target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(control_header, control_target)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(ROOT / 'patches/r580.178.04/proprietary/0009-private-legacy-gpu-session.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(ROOT / 'patches/r580.178.04/proprietary/0009z-private-legacy-gpu-bdf-lookup.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(ROOT / 'patches/r580.178.04/proprietary/0011-private-legacy-gpu-inventory.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(ROOT / 'patches/r580.178.04/proprietary/0012-private-legacy-control-attach.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(ROOT / 'patches/r580.178.04/proprietary/0013-private-legacy-card-info.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(ROOT / 'patches/r580.178.04/proprietary/0014-private-legacy-gpu-id-info.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(ROOT / 'patches/r580.178.04/proprietary/0015-private-legacy-attached-ids.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(ROOT / 'patches/r580.178.04/proprietary/0016-private-legacy-probed-ids.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(ROOT / 'patches/r580.178.04/proprietary/0017-private-legacy-device-ids.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(DEVICE_OBJECT_PATCH)], cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0019-private-legacy-memory-object.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0020-private-legacy-vaspace-object.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0021-private-legacy-channel-group-object.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0022-private-legacy-context-share-object.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0023-private-legacy-channel-object.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0024-private-legacy-subdevice-and-tpc-mask.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0025-private-legacy-binapi-object.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0026-private-legacy-usermode-object.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0027-private-legacy-map-memory.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0028-private-legacy-p2p-object.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0029-private-legacy-p2p-controls.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0030-private-legacy-rusd-object.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0031-private-legacy-pm-channel-depth.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0035-private-legacy-pm-recovery-provider.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0036-private-legacy-pm-channel-dpm-modeset.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0037-private-legacy-sys-params.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotRegex(result.stdout + result.stderr,
                                        r'Hunk #\d+ succeeded[^\n]*(?:offset|fuzz)')
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0038-private-legacy-gpu-register-control.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn('fuzz', result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0039-private-legacy-engine-object.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn('fuzz', result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0040-private-legacy-update-device-mapping-info.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0043-private-legacy-version-check.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn('fuzz', result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0044-private-legacy-gpu-name-string.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn('fuzz', result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0045-private-legacy-client-share-policy.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn('fuzz', result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0046-private-legacy-sync-boost-groups.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn('fuzz', result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0047-private-legacy-gf100-master-object.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn('fuzz', result.stdout + result.stderr)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0048-private-legacy-debugger-bridge.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn('fuzz', result.stdout + result.stderr)
                    expected = target.read_text()
            elif name == 'nvidia/nv-procfs.c':
                with tempfile.TemporaryDirectory() as temp:
                    tree = Path(temp)
                    for relative in ('nvidia/nv-procfs.c', 'nvidia/nv.c'):
                        target = tree / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(previous / relative, target)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0032-private-legacy-pm-procfs-channel-depth.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    expected = (tree / name).read_text()
            elif name == 'nvidia/nv-mmap.c':
                with tempfile.TemporaryDirectory() as temp:
                    tree = Path(temp)
                    target = tree / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(SOURCE / name, target)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0033-private-legacy-pm-vma-access-guard.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    expected = target.read_text()
            elif name == 'common/inc/nv-linux.h':
                with tempfile.TemporaryDirectory() as temp:
                    tree = Path(temp)
                    target = tree / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(previous / name, target)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0034-private-legacy-vma-free-list-lock.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    expected = target.read_text()
            elif name == 'common/inc/nv.h':
                with tempfile.TemporaryDirectory() as temp:
                    tree = Path(temp)
                    target = tree / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(SOURCE / name, target)
                    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                        str(PATCH_DIR / '0001-private-legacy-pm-channel-depth-enum.patch')],
                        cwd=tree, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    expected = target.read_text()
            self.assertEqual(remainder, expected, name)
            original = (SOURCE / name).read_text()
            if original.startswith('/*'):
                original_notice = original[:original.index('*/') + 2]
                self.assertTrue(remainder.startswith(original_notice), name)
        self.assertEqual(missing, [], 'missing prominent local notices: ' + ', '.join(missing))
        notice_patch = ROOT / 'patches/r580.178.04/proprietary/0010-local-modification-notices.patch'
        targets = re.findall(r'^\+\+\+ b/([^\n]+)$', notice_patch.read_text(), re.M)
        self.assertEqual(sorted(targets), list(VENDOR_MODIFIED))
        for header in ('hybrid580-legacy-exports.h', 'hybrid580-file-projection.h',
                       'hybrid580-control-session.h', 'hybrid580-gpu-session.h'):
            self.assertNotIn(NOTICE_ID, (self.tree / 'nvidia' / header).read_text())

    def test_build_notice_replay_includes_register_control_patch(self):
        spec = importlib.util.spec_from_file_location(
            'private_proprietary580_build', ROOT / 'tools/build_private_proprietary580.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        patches = builder.PM_CHANNEL_DEPTH_PREDECESSOR_PATCHES + [
            builder.PM_CHANNEL_DEPTH_PATCH,
            builder.PM_RECOVERY_PROVIDER_PATCH,
            builder.PM_CHANNEL_DPM_MODESET_PATCH,
            builder.SYS_PARAMS_PATCH,
        ]
        replayed = builder.apply_patches_to_text(
            (builder.PREVIOUS_SOURCE / 'nvidia/nv.c').read_text(), patches,
            'nvidia/nv.c',
            extra_files=(('nvidia/hybrid580-control-session.h',
                          builder.PREVIOUS_CONTROL_HEADER),
                         ('nvidia/nv-procfs.c',
                          builder.PREVIOUS_SOURCE / 'nvidia/nv-procfs.c')))
        replayed = builder.apply_patches_to_text(
            replayed, [builder.GPU_REGISTER_CONTROL_PATCH], 'nvidia/nv.c',
            target_filter={'nvidia/nv.c'})
        replayed = builder.apply_patches_to_text(
            replayed, [PATCH_DIR / '0039-private-legacy-engine-object.patch'],
            'nvidia/nv.c', target_filter={'nvidia/nv.c'})
        replayed = builder.apply_patches_to_text(
            replayed, [PATCH_DIR / '0040-private-legacy-update-device-mapping-info.patch'],
            'nvidia/nv.c', target_filter={'nvidia/nv.c'})
        replayed = builder.apply_patches_to_text(
            replayed, [builder.VERSION_CHECK_PATCH], 'nvidia/nv.c',
            target_filter={'nvidia/nv.c'})
        replayed = builder.apply_patches_to_text(
            replayed, [builder.GPU_NAME_STRING_PATCH], 'nvidia/nv.c',
            target_filter={'nvidia/nv.c'})
        replayed = builder.apply_patches_to_text(
            replayed, [builder.CLIENT_SHARE_POLICY_PATCH], 'nvidia/nv.c',
            target_filter={'nvidia/nv.c'})
        replayed = builder.apply_patches_to_text(
            replayed, [PATCH_DIR / '0046-private-legacy-sync-boost-groups.patch'],
            'nvidia/nv.c', target_filter={'nvidia/nv.c'})
        replayed = builder.apply_patches_to_text(
            replayed, [PATCH_DIR / '0047-private-legacy-gf100-master-object.patch'],
            'nvidia/nv.c', target_filter={'nvidia/nv.c'})
        replayed = builder.apply_patches_to_text(
            replayed, [PATCH_DIR / '0048-private-legacy-debugger-bridge.patch'],
            'nvidia/nv.c', target_filter={'nvidia/nv.c'})
        _, actual = builder.split_local_notice(self.source, 'nvidia/nv.c')
        self.assertEqual(replayed, actual)

    def test_exact_proprietary_session_helpers_cpu(self):
        opening = projection.function(self.source, 'nvidia_open')
        original = opening
        pm_lock = '    rc = nv_down_read_interruptible(&nv_system_pm_lock);'
        control_call = opening.index('nvidia_ctl_open(inode, file)')
        first_pm = opening.index(pm_lock)
        pm_gated_control_open = first_pm < control_call
        if pm_gated_control_open:
            device_pm = opening.index(pm_lock, first_pm + len(pm_lock))
        else:
            device_pm = first_pm
        opening = opening[:device_pm]
        if pm_gated_control_open:
            opening += '    (void)nv; (void)nvl; return 0;\n}\n'
        else:
            opening += '    (void)nv; (void)nvl;\n' + original[original.index('failed:\n'):]
        closing = projection.function(self.source, 'nvidia_close')
        if 'nvidia_ctl_close_callback(nvlfp);' in closing:
            close_control = closing.index('if (nv_is_control_device(inode))')
            close_deferred = closing.index('\n        else\n', close_control)
            closing = closing[:close_deferred] + '        return 0;\n    }\n    (void)rc; return -EINVAL;\n}\n'
        else:
            closing = closing[:closing.index('    NV_SET_FILE_PRIVATE(file, NULL);')]
            closing += '    (void)rc; return -EINVAL;\n}\n'
        actual = 'static DEFINE_MUTEX(hybrid580_sys_params_lock);\n' + \
            projection.function(self.source, 'hybrid580_set_sys_params')
        actual += projection.function(self.source[self.source.index('static int\nnvidia_ctl_open('):],
                                     'nvidia_ctl_open') + opening + closing
        actual += projection.function(self.source, 'hybrid580_legacy_backend_file')
        attach_start = self.source.index('static int hybrid580_attach_gpus_to_file(\n    nv_linux_file_private_t *nvlfp')
        actual += projection.function(self.source[attach_start:], 'hybrid580_attach_gpus_to_file')
        begin = self.source.index('struct hybrid580_control_session {')
        end = self.source.index('struct hybrid580_gpu_session {', begin)
        actual += self.source[begin:end]
        stubs = session.STUBS.replace(
            '#include <class/clc96f.h>\n',
            '#include <class/clc96f.h>\n#include <class/clc3b5.h>\n'
            '#include <class/clc3c0.h>\n')
        stubs = stubs.replace(
            '#include <class/cl9067.h>\n',
            '#include <class/cl9067.h>\n#include <class/cl90e6.h>\n'
            '#include <ctrl/ctrl90e6.h>\n')
        stubs = stubs.replace(
            'static int rm_memory_alloc_calls, rm_memory_free_calls, rm_capture_memory_free;',
            'static int rm_memory_alloc_calls, rm_memory_free_calls, rm_capture_memory_free;\n'
            'static int rm_p2p_alloc_calls;\n'
            'static NvHandle rm_p2p_root, rm_p2p_parent, rm_p2p_handle;\n'
            'static NvU32 rm_p2p_params_size, rm_p2p_payload_flags;\n'
            'static int rm_engine_alloc_calls;\n'
            'static NvHandle rm_engine_alloc_root, rm_engine_alloc_parent, rm_engine_alloc_handle;\n'
            'static NvU32 rm_engine_alloc_class, rm_engine_alloc_size;\n'
            'static NvHandle rm_engine_return_override;')
        stubs = stubs.replace(
            'static NvHandle rm_engine_return_override;',
            'static NvHandle rm_engine_return_override;\n'
            'static int rm_master_alloc_calls;\n'
            'static NvHandle rm_master_alloc_root, rm_master_alloc_parent, rm_master_alloc_handle;\n'
            'static NvU32 rm_master_alloc_class, rm_master_alloc_size;\n'
            'static NvP64 rm_master_alloc_payload, rm_master_alloc_rights;\n'
            'static NvS32 rm_master_alloc_payload_value;\n'
            'static NvU32 rm_master_alloc_flags;\n'
            'static NvU32 rm_master_alloc_status=NV_OK;\n'
            'static int rm_master_control_calls;\n'
            'static NvHandle rm_master_control_client, rm_master_control_object;\n'
            'static NvU32 rm_master_control_cmd, rm_master_control_flags, rm_master_control_size;\n'
            'static NvU32 rm_master_control_status=NV_OK;')
        stubs = stubs.replace(
            'typedef struct { nv_state_t nv_state; int usage_count, ldata_lock; } nv_linux_state_t;',
            'typedef struct { nv_state_t nv_state; int usage_count, ldata_lock; '
            'NvU64 numa_memblock_size; } nv_linux_state_t;')
        stubs = stubs.replace(
            'struct mutex { pthread_mutex_t value; };',
            'struct mutex { pthread_mutex_t value; };\n'
            '#define DEFINE_MUTEX(name) struct mutex name = { .value = PTHREAD_MUTEX_INITIALIZER }\n'
            '#define mutex_lock(m) do { assert(pthread_mutex_lock(&(m)->value)==0); ++mutex_depth; } while (0)')
        stubs = stubs.replace(
            'if (alloc->hClass==NV01_MEMORY_SYSTEM || alloc->hClass==NV01_MEMORY_LOCAL_USER) {',
            'if (alloc->hClass==0x503c) {\n'
            '            assert(alloc->hRoot && alloc->hObjectParent && alloc->hObjectNew &&\n'
            '                   alloc->pAllocParms!=NvP64_NULL &&\n'
            '                   (alloc->paramsSize==0 || alloc->paramsSize==sizeof(NvU32)));\n'
            '            NvU32 *p2p=(void *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);\n'
            '            assert(p2p); ++rm_p2p_alloc_calls; rm_p2p_root=alloc->hRoot;\n'
            '            rm_p2p_parent=alloc->hObjectParent; rm_p2p_handle=alloc->hObjectNew;\n'
            '            rm_p2p_params_size=alloc->paramsSize; rm_p2p_payload_flags=*p2p;\n'
            '        } else if (alloc->hClass==NV01_MEMORY_SYSTEM || alloc->hClass==NV01_MEMORY_LOCAL_USER) {')
        rm_ioctl_start = stubs.index('static NV_STATUS rm_ioctl(')
        before_rm_ioctl, legacy_stubs = stubs[:rm_ioctl_start], stubs[rm_ioctl_start:]
        before_rm_ioctl = before_rm_ioctl.replace(
            '        if (alloc->hClass==NV01_MEMORY_SYSTEM || alloc->hClass==NV01_MEMORY_LOCAL_USER ||',
            '        if (alloc->hClass==GF100_SUBDEVICE_MASTER) {\n'
            '            assert(alloc->hRoot && alloc->hObjectParent && alloc->hObjectNew &&\n'
            '                   alloc->paramsSize==sizeof(NvS32) && alloc->pAllocParms!=NvP64_NULL &&\n'
            '                   alloc->pRightsRequested==NvP64_NULL && alloc->flags==NVOS64_FLAGS_NONE);\n'
            '        } else if (alloc->hClass==NV01_MEMORY_SYSTEM || alloc->hClass==NV01_MEMORY_LOCAL_USER ||',
            1)
        before_rm_ioctl = before_rm_ioctl.replace(
            '        } else {\n'
            '            assert(!"unapproved typed RM allocation class");\n'
            '        }\n'
            '        alloc->status=rm_payload;',
            '        } else if (alloc->hClass==GF100_SUBDEVICE_MASTER) {\n'
            '            ++rm_master_alloc_calls; rm_master_alloc_root=alloc->hRoot;\n'
            '            rm_master_alloc_parent=alloc->hObjectParent; rm_master_alloc_handle=alloc->hObjectNew;\n'
            '            rm_master_alloc_class=alloc->hClass; rm_master_alloc_size=alloc->paramsSize;\n'
            '            rm_master_alloc_payload=alloc->pAllocParms;\n'
            '            rm_master_alloc_rights=alloc->pRightsRequested; rm_master_alloc_flags=alloc->flags;\n'
            '            rm_master_alloc_payload_value=*(NvS32 *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);\n'
            '            alloc->status=rm_master_alloc_status; return;\n'
            '        } else {\n'
            '            assert(!"unapproved typed RM allocation class");\n'
            '        }\n'
            '        alloc->status=rm_payload;',
            1)
        before_rm_ioctl = before_rm_ioctl.replace(
            '    assert(control->cmd==NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2);',
            '    if (control->cmd==NV90E6_CTRL_CMD_MASTER_GET_ERROR_INTR_OFFSET_MASK) {\n'
            '        assert(control->paramsSize==sizeof(NV90E6_CTRL_MASTER_GET_ERROR_INTR_OFFSET_MASK_PARAMS));\n'
            '        ++rm_master_control_calls; rm_master_control_client=control->hClient;\n'
            '        rm_master_control_object=control->hObject; rm_master_control_cmd=control->cmd;\n'
            '        rm_master_control_flags=control->flags; rm_master_control_size=control->paramsSize;\n'
            '        NV90E6_CTRL_MASTER_GET_ERROR_INTR_OFFSET_MASK_PARAMS *p=(void *)(uintptr_t)control->params;\n'
            '        p->offset=0x1234; p->mask=0x10; p->eccMask=0x20; p->nvlinkMask=0x40;\n'
            '        control->status=rm_master_control_status; return;\n'
            '    }\n'
            '    assert(control->cmd==NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2);',
            1)
        stubs = before_rm_ioctl + legacy_stubs
        legacy_stubs = legacy_stubs.replace(
            '        } else if (alloc->hClass==NV01_MEMORY_SYSTEM || alloc->hClass==NV01_MEMORY_LOCAL_USER) {',
            '        } else if (alloc->hClass==VOLTA_DMA_COPY_A || alloc->hClass==VOLTA_COMPUTE_A) {\n'
            '            assert(alloc->paramsSize==0 && alloc->pAllocParms==NvP64_NULL &&\n'
            '                   alloc->pRightsRequested==NvP64_NULL && alloc->flags==NVOS64_FLAGS_NONE &&\n'
            '                   alloc->hRoot && alloc->hObjectParent && alloc->hObjectNew);\n'
            '            ++rm_engine_alloc_calls; rm_engine_alloc_root=alloc->hRoot;\n'
            '            rm_engine_alloc_parent=alloc->hObjectParent; rm_engine_alloc_handle=alloc->hObjectNew;\n'
            '            rm_engine_alloc_class=alloc->hClass; rm_engine_alloc_size=alloc->paramsSize;\n'
            '            if (rm_engine_return_override) alloc->hObjectNew=rm_engine_return_override;\n'
            '        } else if (alloc->hClass==NV01_MEMORY_SYSTEM || alloc->hClass==NV01_MEMORY_LOCAL_USER) {',
            1)
        legacy_stubs = legacy_stubs.replace(
            '        } else if (alloc->hClass==NV01_MEMORY_SYSTEM || alloc->hClass==NV01_MEMORY_LOCAL_USER) {',
            '        } else if (alloc->hClass==RM_USER_SHARED_DATA) {\n'
            '            assert(alloc->paramsSize==sizeof(NV00DE_ALLOC_PARAMETERS) &&\n'
            '                   alloc->hRoot && alloc->hObjectParent && alloc->hObjectNew &&\n'
            '                   alloc->pAllocParms!=NvP64_NULL);\n'
            '            NV00DE_ALLOC_PARAMETERS *rusd=(void *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);\n'
            '            assert(rusd); ++rm_rusd_alloc_calls; rm_rusd_alloc_root=alloc->hRoot;\n'
            '            rm_rusd_alloc_parent=alloc->hObjectParent; rm_rusd_alloc_handle=alloc->hObjectNew;\n'
            '            rm_rusd_alloc_class=alloc->hClass; rm_rusd_alloc_size=alloc->paramsSize;\n'
            '            rm_rusd_alloc_input=*rusd;\n'
            '            if (rm_rusd_return_override) alloc->hObjectNew=rm_rusd_return_override;\n'
            '        } else if (alloc->hClass==NV01_MEMORY_SYSTEM || alloc->hClass==NV01_MEMORY_LOCAL_USER) {',
            1)
        stubs = before_rm_ioctl + legacy_stubs
        self.assertIn('rm_p2p_params_size=alloc->paramsSize', stubs)
        code = ('#define BUILD_BUG_ON(condition) _Static_assert(!(condition), "BUILD_BUG_ON")\n' +
                stubs + '#include <nv-unix-nvos-params-wrappers.h>\n'
                '#include <class/cl0080.h>\n#include <class/cl003e.h>\n'
                '#include <class/cl0040.h>\n#include <class/cl2080.h>\n'
                '#include <class/cl2081.h>\n'
                '#include <class/cl503c.h>\n#include <class/clc3b5.h>\n'
                '#include <class/clc3c0.h>\n'
                '#include <class/clc361.h>\n#include <class/clc661.h>\n'
                '#include <class/cl83de.h>\n#include <ctrl/ctrl83de.h>\n'
                '#include <ctrl/ctrl2080/ctrl2080gpu.h>\n'
                '#include <ctrl/ctrl2080/ctrl2080gr.h>\n'
                '#include <ctrl/ctrl0000/ctrl0000syncgpuboost.h>\n'
                '#include <ctrl/ctrl503c.h>\n#include <nv-ioctl.h>\n' + self.vendor_macros +
                session.DECLARATIONS +
                'NV_STATUS NV_API_CALL rm_perform_version_check(nvidia_stack_t *, void *, NvU32);\n' +
                actual +
                '\nstatic int rm_version_check_calls;\n'
                'static NvU32 rm_version_check_size;\n'
                'static NV_STATUS rm_version_check_status=NV_OK;\n'
                'NV_STATUS NV_API_CALL rm_perform_version_check(nvidia_stack_t *sp, void *opaque, NvU32 size) {\n'
                '    assert(sp && opaque && mutex_depth==1 && pm_depth==1 && stack_count==2);\n'
                '    assert(size==sizeof(nv_ioctl_rm_api_version_t));\n'
                '    ++rm_version_check_calls; rm_version_check_size=size;\n'
                '    ((nv_ioctl_rm_api_version_t *)opaque)->reply=0x55;\n'
                '    return rm_version_check_status;\n'
                '}\n')
        cases = session.CASES.replace(
            'unsigned cases=0; hybrid_chrdev_base=MKDEV(240,0);',
            'unsigned cases=0; hybrid_chrdev_base=MKDEV(240,0);\n'
            '    nv_linux_state_t sys_params_state={0};\n'
            '    assert(hybrid580_set_sys_params(&sys_params_state,0)==0);\n'
            '    assert(hybrid580_set_sys_params(&sys_params_state,0x200000ULL)==0);\n'
            '    assert(hybrid580_set_sys_params(&sys_params_state,0x200000ULL)==0);\n'
            '    assert(hybrid580_set_sys_params(&sys_params_state,0x400000ULL)==-EBUSY);\n'
            '    assert(sys_params_state.numa_memblock_size==0x200000ULL); cases+=4;')
        cases = cases.replace(
            'assert(atomic_load(&anchor.refs)==1 && hybrid580_open_backend_file(s->file,1)); ++cases;',
            'assert(atomic_load(&anchor.refs)==1 && hybrid580_open_backend_file(s->file,1)); ++cases;\n'
            '#ifdef HYBRID_LEGACY\n'
            '    { NvHandle master_returned=0; NvU32 master_status=0; NvS32 master_params=0;\n'
            '      int master_before=rm_master_alloc_calls;\n'
            '      assert(hybrid580_legacy_control_session_master_alloc_v1(NULL,0x1234,0x2345,0x3456,\n'
            '          &master_params,&master_returned,&master_status)==NV_ERR_INVALID_ARGUMENT);\n'
            '      assert(master_returned==0 && master_status==NV_ERR_INVALID_ARGUMENT &&\n'
            '          rm_master_alloc_calls==master_before); ++cases;\n'
            '      assert(hybrid580_legacy_control_session_master_alloc_v1(s,0x1234,0x2345,0x3456,\n'
            '          NULL,&master_returned,&master_status)==NV_ERR_INVALID_ARGUMENT); ++cases;\n'
            '      assert(hybrid580_legacy_control_session_master_alloc_v1(s,0,0x2345,0x3456,\n'
            '          &master_params,&master_returned,&master_status)==NV_ERR_INVALID_ARGUMENT); ++cases;\n'
            '      fail_at=7; assert(hybrid580_legacy_control_session_master_alloc_v1(s,0x1234,0x2345,0x3456,\n'
            '          &master_params,&master_returned,&master_status)==NV_ERR_OPERATING_SYSTEM);\n'
            '      assert(rm_master_alloc_calls==master_before && !mutex_depth && !pm_depth); ++cases;\n'
            '      fail_at=8; assert(hybrid580_legacy_control_session_master_alloc_v1(s,0x1234,0x2345,0x3456,\n'
            '          &master_params,&master_returned,&master_status)==NV_ERR_OPERATING_SYSTEM);\n'
            '      assert(rm_master_alloc_calls==master_before && !mutex_depth && !pm_depth); ++cases;\n'
            '      fail_at=9; assert(hybrid580_legacy_control_session_master_alloc_v1(s,0x1234,0x2345,0x3456,\n'
            '          &master_params,&master_returned,&master_status)==NV_ERR_NO_MEMORY);\n'
            '      assert(rm_master_alloc_calls==master_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;\n'
            '      fail_at=0; assert(hybrid580_legacy_control_session_master_alloc_v1(s,0x1234,0x2345,0x3456,\n'
            '          &master_params,&master_returned,&master_status)==NV_OK);\n'
            '      assert(master_returned==0x3456 && master_status==NV_OK &&\n'
            '          rm_master_alloc_calls==master_before+1 && rm_master_alloc_root==0x1234 &&\n'
            '          rm_master_alloc_parent==0x2345 && rm_master_alloc_handle==0x3456 &&\n'
            '          rm_master_alloc_class==GF100_SUBDEVICE_MASTER &&\n'
            '          rm_master_alloc_size==sizeof(NvS32) && rm_master_alloc_payload!=NvP64_NULL &&\n'
            '          rm_master_alloc_payload_value==0 && rm_master_alloc_rights==NvP64_NULL &&\n'
            '          rm_master_alloc_flags==NVOS64_FLAGS_NONE); ++cases;\n'
            '      rm_master_alloc_status=NV_ERR_NOT_SUPPORTED;\n'
            '      assert(hybrid580_legacy_control_session_master_alloc_v1(s,0x1234,0x2345,0x3457,\n'
            '          &master_params,&master_returned,&master_status)==NV_OK);\n'
            '      assert(master_returned==0x3457 && master_status==NV_ERR_NOT_SUPPORTED); ++cases;\n'
            '      rm_master_alloc_status=NV_OK; master_before=rm_master_alloc_calls;\n'
            '      gpu_status=NV_ERR_GPU_IS_LOST;\n'
            '      assert(hybrid580_legacy_control_session_master_alloc_v1(s,0x1234,0x2345,0x3458,\n'
            '          &master_params,&master_returned,&master_status)==NV_ERR_GPU_IS_LOST);\n'
            '      assert(rm_master_alloc_calls==master_before && stack_count==1 &&\n'
            '          !mutex_depth && !pm_depth); ++cases; gpu_status=NV_OK; }\n'
            '    { NV90E6_CTRL_MASTER_GET_ERROR_INTR_OFFSET_MASK_PARAMS master_params={0};\n'
            '      NvU32 master_control_status=0xffffffffU; int master_control_before=rm_master_control_calls;\n'
            '      assert(hybrid580_legacy_control_session_master_error_intr_offset_mask_v1(s,0x1234,0x3456,\n'
            '          NVOS54_FLAGS_NONE,&master_params,&master_control_status)==NV_OK);\n'
            '      assert(master_control_status==NV_OK && master_params.offset==0x1234 &&\n'
            '          master_params.mask==0x10 && master_params.eccMask==0x20 &&\n'
            '          master_params.nvlinkMask==0x40 && rm_master_control_calls==master_control_before+1 &&\n'
            '          rm_master_control_client==0x1234 && rm_master_control_object==0x3456 &&\n'
            '          rm_master_control_cmd==NV90E6_CTRL_CMD_MASTER_GET_ERROR_INTR_OFFSET_MASK &&\n'
            '          rm_master_control_flags==NVOS54_FLAGS_NONE &&\n'
            '          rm_master_control_size==sizeof(master_params)); ++cases;\n'
            '      rm_master_control_status=NV_ERR_NOT_SUPPORTED; master_params.offset=0;\n'
            '      assert(hybrid580_legacy_control_session_master_error_intr_offset_mask_v1(s,0x1234,0x3456,\n'
            '          NVOS54_FLAGS_NONE,&master_params,&master_control_status)==NV_OK);\n'
            '      assert(master_control_status==NV_ERR_NOT_SUPPORTED && master_params.offset==0x1234); ++cases;\n'
            '      master_control_before=rm_master_control_calls;\n'
            '      assert(hybrid580_legacy_control_session_master_error_intr_offset_mask_v1(s,0x1234,0x3456,\n'
            '          1,&master_params,&master_control_status)==NV_ERR_INVALID_ARGUMENT);\n'
            '      assert(rm_master_control_calls==master_control_before &&\n'
            '          master_control_status==NV_ERR_INVALID_ARGUMENT); ++cases;\n'
            '      fail_at=7; assert(hybrid580_legacy_control_session_master_error_intr_offset_mask_v1(s,0x1234,0x3456,\n'
            '          NVOS54_FLAGS_NONE,&master_params,&master_control_status)==NV_ERR_OPERATING_SYSTEM);\n'
            '      assert(rm_master_control_calls==master_control_before && !mutex_depth && !pm_depth); ++cases;\n'
            '      fail_at=8; assert(hybrid580_legacy_control_session_master_error_intr_offset_mask_v1(s,0x1234,0x3456,\n'
            '          NVOS54_FLAGS_NONE,&master_params,&master_control_status)==NV_ERR_OPERATING_SYSTEM);\n'
            '      assert(rm_master_control_calls==master_control_before && !mutex_depth && !pm_depth); ++cases;\n'
            '      fail_at=9; assert(hybrid580_legacy_control_session_master_error_intr_offset_mask_v1(s,0x1234,0x3456,\n'
            '          NVOS54_FLAGS_NONE,&master_params,&master_control_status)==NV_ERR_NO_MEMORY);\n'
            '      assert(rm_master_control_calls==master_control_before && stack_count==1 &&\n'
            '          !mutex_depth && !pm_depth); ++cases;\n'
            '      fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST;\n'
            '      assert(hybrid580_legacy_control_session_master_error_intr_offset_mask_v1(s,0x1234,0x3456,\n'
            '          NVOS54_FLAGS_NONE,&master_params,&master_control_status)==NV_ERR_GPU_IS_LOST);\n'
            '      assert(rm_master_control_calls==master_control_before && stack_count==1 &&\n'
            '          !mutex_depth && !pm_depth); ++cases; gpu_status=NV_OK; rm_master_control_status=NV_OK; }\n'
            '    { nv_ioctl_rm_api_version_t version={.cmd=NV_RM_API_VERSION_CMD_QUERY};\n'
            '      int version_before=rm_version_check_calls;\n'
            '      assert(hybrid580_legacy_control_session_check_version_v1(NULL,&version,sizeof(version))==NV_ERR_INVALID_ARGUMENT); ++cases;\n'
            '      assert(hybrid580_legacy_control_session_check_version_v1(s,NULL,sizeof(version))==NV_ERR_INVALID_ARGUMENT); ++cases;\n'
            '      assert(hybrid580_legacy_control_session_check_version_v1(s,&version,sizeof(version)-1)==NV_ERR_INVALID_ARGUMENT); ++cases;\n'
            '      fail_at=7; assert(hybrid580_legacy_control_session_check_version_v1(s,&version,sizeof(version))==NV_ERR_OPERATING_SYSTEM);\n'
            '      assert(rm_version_check_calls==version_before && !mutex_depth && !pm_depth); ++cases;\n'
            '      fail_at=8; assert(hybrid580_legacy_control_session_check_version_v1(s,&version,sizeof(version))==NV_ERR_OPERATING_SYSTEM);\n'
            '      assert(rm_version_check_calls==version_before && !mutex_depth && !pm_depth); ++cases;\n'
            '      fail_at=9; assert(hybrid580_legacy_control_session_check_version_v1(s,&version,sizeof(version))==NV_ERR_NO_MEMORY);\n'
            '      assert(rm_version_check_calls==version_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;\n'
            '      fail_at=0; version.reply=0xffffffffU;\n'
            '      assert(hybrid580_legacy_control_session_check_version_v1(s,&version,sizeof(version))==NV_OK);\n'
            '      assert(version.reply==0x55 && rm_version_check_calls==version_before+1 &&\n'
            '          rm_version_check_size==sizeof(version) && stack_count==1 && !mutex_depth && !pm_depth); ++cases;\n'
            '      rm_version_check_status=NV_ERR_INVALID_STATE;\n'
            '      assert(hybrid580_legacy_control_session_check_version_v1(s,&version,sizeof(version))==NV_ERR_INVALID_STATE); ++cases;\n'
            '      rm_version_check_status=NV_OK; }\n'
            '    { NV503C_ALLOC_PARAMETERS p2p={.flags=NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1};\n'
            '      NvHandle returned=0; NvU32 status=0xffffffffU; int before=atomic_load(&rm_calls);\n'
            '      assert(hybrid580_legacy_control_session_p2p_alloc_v1(s,0x1234,0x2345,0x3456,0,&p2p,&returned,&status)==NV_OK);\n'
            '      assert(status==NV_OK && returned==0x3456 && atomic_load(&rm_calls)==before+1);\n'
            '      assert(rm_p2p_alloc_calls==1 && rm_p2p_root==0x1234 && rm_p2p_parent==0x2345 &&\n'
            '             rm_p2p_handle==0x3456 && rm_p2p_params_size==0 &&\n'
            '             rm_p2p_payload_flags==NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1);\n'
            '      assert(hybrid580_legacy_control_session_p2p_alloc_v1(s,0x1234,0x2345,0x3457,\n'
            '             sizeof(p2p),&p2p,&returned,&status)==NV_OK && returned==0x3457);\n'
            '      assert(rm_p2p_alloc_calls==2 && rm_p2p_params_size==sizeof(p2p));\n'
            '      before=atomic_load(&rm_calls);\n'
            '      assert(hybrid580_legacy_control_session_p2p_alloc_v1(s,0x1234,0x2345,0x3458,\n'
            '             sizeof(p2p)+1,&p2p,&returned,&status)==NV_ERR_INVALID_ARGUMENT);\n'
            '      p2p.flags=0;\n'
            '      assert(hybrid580_legacy_control_session_p2p_alloc_v1(s,0x1234,0x2345,0x3458,\n'
            '             0,&p2p,&returned,&status)==NV_ERR_INVALID_ARGUMENT);\n'
            '      assert(atomic_load(&rm_calls)==before && rm_p2p_alloc_calls==2); cases+=4; }\n'
            '    { NV503C_CTRL_REGISTER_VA_SPACE_PARAMS va={.hVASpace=0x4567};\n'
            '      NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS unva={.hVASpace=0x4567};\n'
            '      NV503C_CTRL_REGISTER_VIDMEM_PARAMS mem={.hMemory=0x5678,.address=0x10000,\n'
            '          .size=0x20000,.offset=0x30000};\n'
            '      NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS unmem={.hMemory=0x5678};\n'
            '      NvU32 control_status=0xffffffffU; int before_calls=rm_p2p_control_calls, before=0;\n'
            '      assert(hybrid580_legacy_control_session_p2p_register_va_space_v1(s,0x1234,0x3456,&va,&control_status)==NV_OK);\n'
            '      assert(control_status==NV_OK && va.vaSpaceToken==0x76543210ULL);\n'
            '      assert(rm_p2p_control_client==0x1234 && rm_p2p_control_object==0x3456 &&\n'
            '          rm_p2p_control_cmd==NV503C_CTRL_CMD_REGISTER_VA_SPACE &&\n'
            '          rm_p2p_control_vaspace==0x4567 &&\n'
            '          rm_p2p_control_size==sizeof(va));\n'
            '      assert(hybrid580_legacy_control_session_p2p_unregister_va_space_v1(s,0x1234,0x3456,&unva,&control_status)==NV_OK);\n'
            '      assert(control_status==NV_OK && rm_p2p_control_cmd==NV503C_CTRL_CMD_UNREGISTER_VA_SPACE);\n'
            '      assert(hybrid580_legacy_control_session_p2p_register_vidmem_v1(s,0x1234,0x3456,&mem,&control_status)==NV_OK);\n'
            '      assert(control_status==NV_OK && rm_p2p_control_cmd==NV503C_CTRL_CMD_REGISTER_VIDMEM &&\n'
            '          rm_p2p_control_memory==0x5678 && rm_p2p_control_address==0x10000 &&\n'
            '          rm_p2p_control_bytes==0x20000 && rm_p2p_control_offset==0x30000);\n'
            '      assert(hybrid580_legacy_control_session_p2p_unregister_vidmem_v1(s,0x1234,0x3456,&unmem,&control_status)==NV_OK);\n'
            '      assert(control_status==NV_OK && rm_p2p_control_cmd==NV503C_CTRL_CMD_UNREGISTER_VIDMEM &&\n'
            '          rm_p2p_control_memory==0x5678 && rm_p2p_control_calls==before_calls+4);\n'
            '      rm_payload=NV_ERR_NOT_SUPPORTED;\n'
            '      assert(hybrid580_legacy_control_session_p2p_unregister_vidmem_v1(s,0x1234,0x3456,&unmem,&control_status)==NV_OK);\n'
            '      assert(control_status==NV_ERR_NOT_SUPPORTED); rm_payload=NV_OK;\n'
            '      before=atomic_load(&rm_calls);\n'
            '      assert(hybrid580_legacy_control_session_p2p_register_va_space_v1(s,0x1234,0x3456,NULL,&control_status)==NV_ERR_INVALID_ARGUMENT);\n'
            '      assert(atomic_load(&rm_calls)==before && rm_p2p_control_calls==before_calls+5);\n'
            '      cases+=6; }\n'
            '    { NvHandle engine_returned=0; NvU32 engine_status=0;\n'
            '      int engine_before=rm_engine_alloc_calls, before=atomic_load(&rm_calls);\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(NULL,0x1234,0x2345,0x3456,\n'
            '          VOLTA_DMA_COPY_A,&engine_returned,&engine_status)==NV_ERR_INVALID_ARGUMENT);\n'
            '      assert(engine_status==NV_ERR_INVALID_ARGUMENT && engine_returned==0); ++cases;\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0,0x2345,0x3456,\n'
            '          VOLTA_DMA_COPY_A,&engine_returned,&engine_status)==NV_ERR_INVALID_ARGUMENT); ++cases;\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0,0x3456,\n'
            '          VOLTA_DMA_COPY_A,&engine_returned,&engine_status)==NV_ERR_INVALID_ARGUMENT); ++cases;\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x1234,\n'
            '          VOLTA_DMA_COPY_A,&engine_returned,&engine_status)==NV_ERR_INVALID_ARGUMENT); ++cases;\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x2345,\n'
            '          VOLTA_COMPUTE_A,&engine_returned,&engine_status)==NV_ERR_INVALID_ARGUMENT); ++cases;\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x3456,\n'
            '          VOLTA_DMA_COPY_A,NULL,&engine_status)==NV_ERR_INVALID_ARGUMENT); ++cases;\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x3456,\n'
            '          VOLTA_DMA_COPY_A,&engine_returned,NULL)==NV_ERR_INVALID_ARGUMENT); ++cases;\n'
            '      assert(atomic_load(&rm_calls)==before && rm_engine_alloc_calls==engine_before); ++cases;\n'
            '      engine_returned=0; engine_status=0;\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x3456,\n'
            '          VOLTA_DMA_COPY_A,&engine_returned,&engine_status)==NV_OK);\n'
            '      assert(engine_status==NV_OK && engine_returned==0x3456 &&\n'
            '          rm_engine_alloc_calls==engine_before+1 && rm_engine_alloc_root==0x1234 &&\n'
            '          rm_engine_alloc_parent==0x2345 && rm_engine_alloc_handle==0x3456 &&\n'
            '          rm_engine_alloc_class==VOLTA_DMA_COPY_A && rm_engine_alloc_size==0); ++cases;\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x3457,\n'
            '          VOLTA_COMPUTE_A,&engine_returned,&engine_status)==NV_OK);\n'
            '      assert(engine_status==NV_OK && engine_returned==0x3457 &&\n'
            '          rm_engine_alloc_calls==engine_before+2 && rm_engine_alloc_class==VOLTA_COMPUTE_A); ++cases;\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x3458,\n'
            '          0xdead,&engine_returned,&engine_status)==NV_ERR_INVALID_CLASS);\n'
            '      assert(engine_status==NV_ERR_INVALID_CLASS && engine_returned==0 &&\n'
            '          rm_engine_alloc_calls==engine_before+2); ++cases;\n'
            '      rm_engine_return_override=0xbeef;\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x3459,\n'
            '          VOLTA_DMA_COPY_A,&engine_returned,&engine_status)==NV_OK && engine_returned==0xbeef); ++cases;\n'
            '      rm_engine_return_override=0; rm_transport=NV_ERR_INVALID_STATE; rm_payload=NV_OK;\n'
            '      engine_returned=0x9999; engine_status=0x8888; before=atomic_load(&rm_calls);\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x3460,\n'
            '          VOLTA_DMA_COPY_A,&engine_returned,&engine_status)==NV_ERR_INVALID_STATE);\n'
            '      assert(engine_returned==0 && engine_status==0xffffffffU &&\n'
            '          atomic_load(&rm_calls)==before+1); ++cases;\n'
            '      rm_transport=NV_OK; rm_payload=NV_ERR_INVALID_ARGUMENT;\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x3461,\n'
            '          VOLTA_COMPUTE_A,&engine_returned,&engine_status)==NV_OK);\n'
            '      assert(engine_returned==0x3461 && engine_status==NV_ERR_INVALID_ARGUMENT); ++cases;\n'
            '      rm_payload=NV_OK; engine_before=rm_engine_alloc_calls; before=atomic_load(&rm_calls);\n'
            '      fail_at=7; assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x3462,\n'
            '          VOLTA_DMA_COPY_A,&engine_returned,&engine_status)==NV_ERR_OPERATING_SYSTEM);\n'
            '      assert(atomic_load(&rm_calls)==before && rm_engine_alloc_calls==engine_before &&\n'
            '          engine_returned==0 && engine_status==0xffffffffU && !mutex_depth && !pm_depth); ++cases;\n'
            '      fail_at=8; assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x3463,\n'
            '          VOLTA_DMA_COPY_A,&engine_returned,&engine_status)==NV_ERR_OPERATING_SYSTEM);\n'
            '      assert(atomic_load(&rm_calls)==before && rm_engine_alloc_calls==engine_before &&\n'
            '          !mutex_depth && !pm_depth); ++cases;\n'
            '      fail_at=9; assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x3464,\n'
            '          VOLTA_DMA_COPY_A,&engine_returned,&engine_status)==NV_ERR_NO_MEMORY);\n'
            '      assert(atomic_load(&rm_calls)==before && rm_engine_alloc_calls==engine_before &&\n'
            '          stack_count==1 && !mutex_depth && !pm_depth); ++cases;\n'
            '      fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST;\n'
            '      assert(hybrid580_legacy_control_session_engine_alloc_v1(s,0x1234,0x2345,0x3465,\n'
            '          VOLTA_DMA_COPY_A,&engine_returned,&engine_status)==NV_ERR_GPU_IS_LOST);\n'
            '      assert(atomic_load(&rm_calls)==before && rm_engine_alloc_calls==engine_before &&\n'
            '          stack_count==1 && !mutex_depth && !pm_depth); ++cases; gpu_status=NV_OK; }\n'
            '#endif')
        self.assertNotEqual(cases, session.CASES)
        code += '#define HYBRID_LEGACY\n' + cases.replace(
            'hybrid580_open', 'hybrid580_legacy')
        code = code.replace('hybrid580_open', 'hybrid580_legacy')
        source, binary = self.tree / 'legacy-session.c', self.tree / 'legacy-session'
        source.write_text(code)
        includes = ['-I' + str(ROOT / 'src'), '-I' + str(self.tree / 'common/inc'),
                    '-I' + str(SOURCE / 'common/inc')] + ['-I' + str(SDK / part) for part in (
            'src/common/sdk/nvidia/inc', 'src/common/inc',
            'src/common/inc/swref', 'src/nvidia/arch/nvalloc/unix/include')]
        # These SDK/wrapper types are public same-branch source; the code under
        # test is the actual proprietary wrapper path, with only OS/RM doubles.
        result = subprocess.run(['cc', '-std=gnu11', '-DNVRM', '-Wall', '-Wextra', '-Werror',
                                 '-Wno-unused-parameter', '-pthread', '-fsanitize=undefined',
                                 '-fno-sanitize-recover=all', *includes, str(source), '-o', str(binary)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('control-session CPU scenarios: 302', result.stdout)
        print(result.stdout.strip())

    def test_exact_proprietary_projection_cpu(self):
        header = (self.tree / 'nvidia/hybrid580-file-projection.h').read_text()
        header = re.sub(r'^#include[^\n]*\n', '', header, flags=re.M)
        begin = self.source.index('struct hybrid580_file_projection_provider {')
        end = self.source.index('\nint NV_API_CALL nv_get_event(', begin)
        section = self.source[begin:end]
        attach_start = section.index('static int hybrid580_attach_gpus_to_file(\n    nv_linux_file_private_t *nvlfp')
        attach = projection.function(section[attach_start:], 'hybrid580_attach_gpus_to_file')
        section = section.replace(attach, '')
        session_begin = section.index('struct hybrid580_control_session {')
        session_end = section.index('nv_file_private_t* NV_API_CALL nv_get_file_private(', session_begin)
        actual = section[:session_begin] + section[session_end:]
        actual += projection.function(self.source, 'nv_match_dev_state')
        code = projection.STUBS + self.vendor_macros + header + actual
        code += projection.CASES.replace('hybrid580_open', 'hybrid580_legacy')
        source, binary = self.tree / 'legacy-projection.c', self.tree / 'legacy-projection'
        source.write_text(code)
        result = subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-parameter', '-pthread', '-fsanitize=undefined',
            '-fno-sanitize-recover=all', str(source), '-o', str(binary)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('projection CPU scenarios: 38; writer waited for reader', result.stdout)
        print(result.stdout.strip())

    def test_pinned_r580_register_fd_case_uses_proprietary_backend_projection(self):
        # The R580 proprietary RM implementation is binary-only here. Execute
        # the public R580 REGISTER_FD source case against the actual patched
        # proprietary nv_get_file_private/projection wrapper; kernel, RM and
        # real VFS execution remain outside this CPU contract.
        with tarfile.open(projection.ARCHIVE) as archive:
            escape = archive.extractfile(
                'NVIDIA-kernel-module-source-580.178.04/src/nvidia/arch/nvalloc/unix/src/escape.c'
            ).read().decode()
            osapi = archive.extractfile(
                'NVIDIA-kernel-module-source-580.178.04/src/nvidia/arch/nvalloc/unix/src/osapi.c'
            ).read().decode()
        case_start = escape.index('case NV_ESC_REGISTER_FD:')
        register_case = 'case NV_ESC_REGISTER_FD: ' + projection.braced_block(escape, case_start)
        done_start = osapi.index('if (nvfp->ctl_nvfp != NULL)', osapi.index('done:'))
        close_cleanup = projection.braced_block(osapi, done_start)

        header = (self.tree / 'nvidia/hybrid580-file-projection.h').read_text()
        header = re.sub(r'^#include[^\n]*\n', '', header, flags=re.M)
        begin = self.source.index('struct hybrid580_file_projection_provider {')
        end = self.source.index('\nint NV_API_CALL nv_get_event(', begin)
        section = self.source[begin:end]
        attach_start = section.index('static int hybrid580_attach_gpus_to_file(\n    nv_linux_file_private_t *nvlfp')
        section = section.replace(projection.function(section[attach_start:],
                                                       'hybrid580_attach_gpus_to_file'), '')
        session_begin = section.index('struct hybrid580_control_session {')
        session_end = section.index('nv_file_private_t* NV_API_CALL nv_get_file_private(', session_begin)
        actual = section[:session_begin] + section[session_end:]
        registration_stubs = projection.STUBS.replace(
            'typedef struct { int marker; } nv_file_private_t;',
            'typedef struct nv_file_private_t { int marker; struct nv_file_private_t *ctl_nvfp; '
            'void *ctl_nvfp_priv; uint32_t register_or_refcount; } nv_file_private_t;').replace(
            'static nv_linux_state_t nv_ctl_device, gpu_state, other_gpu_state;',
            'static nv_linux_state_t nv_ctl_device, gpu_state;')
        code = registration_stubs + self.vendor_macros + header + actual
        code += projection.REGISTER_FD_HARNESS_PREFIX.replace(
            'hybrid580_open', 'hybrid580_legacy') + register_case
        code += projection.REGISTER_FD_HARNESS_SUFFIX.replace(
            'hybrid580_open', 'hybrid580_legacy').replace(
                '/* INSERT_CLOSE_CLEANUP */', close_cleanup)
        source, binary = self.tree / 'legacy-register-fd.c', self.tree / 'legacy-register-fd'
        source.write_text(code)
        result = subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                 '-Wno-unused-parameter', '-pthread', '-fsanitize=undefined',
                                 '-fno-sanitize-recover=all', str(source), '-o', str(binary)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('R580 REGISTER_FD CPU scenarios: 11; held control reference released on GPU close',
                      result.stdout)
        print(result.stdout.strip())

    def test_objtool_classifies_only_pinned_core_warnings_and_repeat_link_skips(self):
        spec = importlib.util.spec_from_file_location(
            'private_proprietary580_objtool_build', ROOT / 'tools/build_private_proprietary580.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        prefix = 'hybrid580_legacy.o: warning: objtool: '
        output = '\n'.join((
            prefix + "_nvVendor+0x4: 'naked' return found in MITIGATION_RETHUNK build",
            prefix + '_nvVendor+0x1a: call without frame pointer save/setup',
            prefix + 'file already has .retpoline_sites, skipping',
            prefix + 'file already has .return_sites, skipping',
        ))
        result = builder.classify_objtool_output(output, {'_nvVendor'}, 0)
        self.assertEqual(result['warning_count'], 2)
        self.assertEqual(result['warning_symbol_count'], 1)
        self.assertEqual(result['warning_instances_from_unchanged_core'], 2)
        self.assertEqual(result['existing_link_metadata_skip_count'], 2)
        self.assertEqual(result['unclassified_diagnostics'], 0)

        with self.assertRaisesRegex(ValueError, 'outside the unchanged proprietary core'):
            builder.classify_objtool_output(
                prefix + '_hybridWrapper+0x1a: call without frame pointer save/setup',
                {'_nvVendor'}, 0)
        with self.assertRaisesRegex(ValueError, 'unclassified diagnostic'):
            builder.classify_objtool_output(prefix + 'new warning family', {'_nvVendor'}, 0)

    def test_exact_proprietary_pci_guard_cpu(self):
        self.text = (self.tree / 'nvidia/nv-pci.c').read_text()
        self.root = self.tree
        pci.PrivatePciTests.test_actual_source_guard_and_probe_prefix_before_effect(self)


if __name__ == '__main__':
    unittest.main()
