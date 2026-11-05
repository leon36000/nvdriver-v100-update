# SPDX-License-Identifier: MIT
"""Source contracts for unpublished real GPU-file sessions.

CPU/source checks do not establish Linux VFS, PCI hotplug, RM, or GPU behavior.
"""
from pathlib import Path
import re
import subprocess
import unittest

import test_private_backend_control_session as control
from gpu_session_register_harness import run_register_control_contract

ROOT = Path(__file__).resolve().parents[1]
PATCHES = (ROOT / 'patches/r580.178.04/0010-private-open-gpu-session.patch',
           ROOT / 'patches/r580.178.04/0011-private-open-gpu-session-bdf-lookup.patch',
           ROOT / 'patches/r580.178.04/0012-private-open-gpu-inventory.patch')
REGISTER_CONTROL_PATCH = ROOT / 'patches/r580.178.04/0039-private-open-gpu-register-control.patch'
ENGINE_OBJECT_PATCH = ROOT / 'patches/r580.178.04/0040-private-open-engine-object.patch'
ATTACH_AFTER_GPU = ROOT / 'patches/r580.178.04/0014-private-control-attach-after-gpu.patch'
CARD_INFO_PATCH = ROOT / 'patches/r580.178.04/0015-private-open-card-info.patch'
GPU_ID_INFO_PATCH = ROOT / 'patches/r580.178.04/0016-private-open-gpu-id-info.patch'
ATTACHED_IDS_PATCH = ROOT / 'patches/r580.178.04/0017-private-open-attached-ids.patch'


class PrivateGpuSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the complete typed-control-session source chain. The engine
        # allocation patch is intentionally downstream of the channel/RUSD
        # helpers, just as in the production builder.
        control.PrivateControlSessionTests.setUpClass.__func__(cls)
        for patch in (REGISTER_CONTROL_PATCH, ENGINE_OBJECT_PATCH):
            result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                                    cwd=cls.tree, capture_output=True, text=True)
            if result.returncode or re.search(r'\b(?:fuzz|offset)\b', result.stdout + result.stderr):
                raise AssertionError(result.stdout + result.stderr)
        header_path = cls.tree / 'kernel-open/nvidia/hybrid580-gpu-session.h'
        cls.source = (cls.tree / 'kernel-open/nvidia/nv.c').read_text()
        cls.header = (cls.tree / 'kernel-open/nvidia/hybrid580-gpu-session.h').read_text()
        # The production Open builder overlays this project-owned shared API
        # after replaying vendor-source patches. Mirror that exact build input
        # instead of testing the stale header carried by the upstream archive.
        control_header_path = cls.tree / 'kernel-open/nvidia/hybrid580-control-session.h'
        expected_control_header = ROOT / 'src/hybrid580-control-session.h'
        control_header_path.write_bytes(expected_control_header.read_bytes())
        if control_header_path.read_bytes() != expected_control_header.read_bytes():
            raise AssertionError('control session API header differs from project source')
        cls.control_header = control_header_path.read_text()

    def test_gpu_session_api_is_versioned_and_validates_selected_device(self):
        for operation in ('create', 'create_by_bdf', 'get', 'put', 'file', 'ioctl',
                          'register_control'):
            self.assertEqual(self.source.count(
                f'EXPORT_SYMBOL(hybrid580_open_gpu_session_{operation}_v1);'), 1)
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_open_gpu_inventory_v1);'), 1)
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_open_gpu_card_info_v1);'), 1)
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_open_control_session_gpu_id_info_v1);'), 1)
        start = self.source.index('NV_STATUS hybrid580_open_control_session_gpu_id_info_v1(')
        end = self.source.index('EXPORT_SYMBOL(hybrid580_open_control_session_gpu_id_info_v1);', start)
        gpu_id_info = self.source[start:end]
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', gpu_id_info)
        self.assertIn('.params.control = control', gpu_id_info)
        self.assertIn('.op = NV04_CONTROL', gpu_id_info)
        self.assertIn('h_client != h_object', gpu_id_info)
        self.assertNotIn('rm_ioctl(', gpu_id_info)
        self.assertIn('pci_name(nvl->pci_dev)', self.source)
        self.assertIn('nv_wait_open_complete_interruptible(nvlfp)', self.source)
        self.assertIn('for (minor = 0; minor <= NV_MINOR_DEVICE_NUMBER_REGULAR_MAX; ++minor)', self.source)
        self.assertIn('return -EXDEV;', self.source)
        self.assertIn('nvidia_unlocked_ioctl(session->file, command, argument)', self.source)
        self.assertIn('expected_bdf', self.header)
        self.assertIn('hybrid580_open_gpu_session_create_by_bdf_v1', self.header)
        self.assertEqual(self.header.encode(), (ROOT / 'src/hybrid580-gpu-session.h').read_bytes())

    def test_register_control_is_declared_by_the_incremental_provider_patch(self):
        self.assertIn('hybrid580_open_gpu_session_register_control_v1', self.header)

    def test_engine_alloc_bridge_is_blackwell_only_and_zero_size(self):
        symbol = 'EXPORT_SYMBOL(hybrid580_open_control_session_engine_alloc_v1);'
        self.assertEqual(self.source.count(symbol), 1)
        start = self.source.index(
            'NV_STATUS hybrid580_open_control_session_engine_alloc_v1(')
        end = self.source.index(symbol, start)
        body = self.source[start:end]
        for fragment in ('class_id != BLACKWELL_DMA_COPY_B',
                         'class_id != BLACKWELL_COMPUTE_B',
                         '.hObjectParent = h_channel',
                         '.hObjectNew = h_engine',
                         '.pAllocParms = NvP64_NULL',
                         '.pRightsRequested = NvP64_NULL',
                         '.paramsSize = 0',
                         '.flags = NVOS64_FLAGS_NONE',
                         '.op = NV04_ALLOC',
                         'rm_kernel_rmapi_op(sp, &ops)',
                         '*rm_status = alloc.status',
                         '*returned_engine = alloc.hObjectNew',
                         'mutex_lock_interruptible(&session->lock)',
                         'nv_down_read_interruptible(&nv_system_pm_lock)',
                         'nv_check_gpu_state(nv)'):
            self.assertIn(fragment, body)
        self.assertNotIn('VOLTA_', body)
        self.assertNotIn('copy_from_user', body)
        self.assertNotIn('NV_COPY_FROM_USER', body)
        self.assertIn(
            'NV_STATUS hybrid580_open_control_session_engine_alloc_v1(',
            self.control_header)
        self.assertIn('#include <class/clcab5.h>', self.control_header)
        self.assertIn('#include <class/clcec0.h>', self.control_header)

    def test_register_control_uses_the_pinned_provider_file_and_native_rm_contract(self):
        start = self.source.index('int hybrid580_open_gpu_session_register_control_v1(')
        end = self.source.index(
            'EXPORT_SYMBOL(hybrid580_open_gpu_session_register_control_v1);', start)
        bridge = self.source[start:end]
        self.assertIn('get_file(control->file)', bridge)
        self.assertIn('hybrid580_open_backend_file(control_file, 1)', bridge)
        self.assertIn('rm_acquire_api_lock(sp)', bridge)
        self.assertIn('gpu_nvlfp->nvfp.ctl_nvfp != NULL', bridge)
        self.assertIn('control_nvlfp->nvfp.ctl_nvfp != NULL', bridge)
        self.assertIn('cmpxchg(&gpu_nvlfp->nvfp.register_or_refcount', bridge)
        self.assertIn('NVFP_TYPE_REGISTERED', bridge)
        self.assertIn('cmpxchg(&gpu_nvlfp->nvfp.ctl_nvfp', bridge)
        self.assertNotIn('portAtomicCompareAndSwapU32', bridge)
        self.assertNotIn('portAtomicSetSize', bridge)
        self.assertIn('gpu_nvlfp->nvfp.ctl_nvfp_priv = control_file', bridge)
        self.assertIn('control_file = NULL;', bridge)
        self.assertNotIn('fget(', bridge)
        self.assertNotIn('copy_from_user', bridge)

    def test_register_control_provider_executes_ownership_and_unwind_contract(self):
        output = run_register_control_contract(self.source, 'open')
        self.assertEqual(output, 'provider REGISTER_FD bridge CPU/UBSan scenarios: 12')

    def test_card_info_snapshot_uses_pm_and_gpu_state_guards(self):
        start = self.source.index('int hybrid580_open_gpu_card_info_v1(')
        end = self.source.index('EXPORT_SYMBOL(hybrid580_open_gpu_card_info_v1);', start)
        card_info = self.source[start:end]
        self.assertIn('nv_down_read_interruptible(&nv_system_pm_lock)', card_info)
        self.assertIn('nv_check_gpu_state(nv)', card_info)
        self.assertIn('nvidia_read_card_info(typed_records, capacity)', card_info)
        self.assertIn('nv_kmem_cache_free_stack(sp)', card_info)
        self.assertIn('up_read(&nv_system_pm_lock)', card_info)
        self.assertIn('if (typed_records[i].valid)', card_info)

    def test_inventory_snapshot_holds_device_lock_and_rejects_partial_capacity(self):
        start = self.source.index('int hybrid580_open_gpu_inventory_v1(')
        end = self.source.index('EXPORT_SYMBOL(hybrid580_open_gpu_inventory_v1);', start)
        inventory = self.source[start:end]
        self.assertIn('LOCK_NV_LINUX_DEVICES()', inventory)
        self.assertIn('UNLOCK_NV_LINUX_DEVICES()', inventory)
        self.assertIn('NV_FLAG_EXCLUDE', inventory)
        self.assertIn('PCI_FUNC(nvl->pci_dev->devfn)', inventory)
        self.assertIn('pci_name(nvl->pci_dev)', inventory)
        self.assertIn('if (capacity < required)', inventory)
        self.assertIn('rc = -ENOSPC;', inventory)
        self.assertIn('memset(records, 0, capacity * sizeof(*records))', inventory)

    def test_gpu_session_never_projects_a_control_file_or_keeps_a_frontend_fd(self):
        begin = self.source.index('struct hybrid580_gpu_session {')
        end = self.source.index('nv_file_private_t* NV_API_CALL nv_get_file_private(', begin)
        session = self.source[begin:end]
        self.assertNotIn('fd_install(', session)
        self.assertNotIn('fget(', session)
        self.assertIn('get_file(session->file)', session)
        self.assertIn('fput(session->file)', session)
        self.assertIn('NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE', session)


if __name__ == '__main__':
    unittest.main()
