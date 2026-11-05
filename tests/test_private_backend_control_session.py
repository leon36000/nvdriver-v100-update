# SPDX-License-Identifier: MIT
"""CPU contracts for actual patched session source, not real Linux/VFS/RM.

Models enforce reference/lock/failure ordering; they do not establish kernel
inode, security/LSM, delayed fput, module unloading or hardware correctness.
"""
import re
from pathlib import Path
import subprocess
import tarfile
import unittest

import test_private_backend_file_projection as projection

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'patches/r580.178.04/0009-private-open-control-session.patch'
ATTACH_PATCH = ROOT / 'patches/r580.178.04/0013-private-control-attach.patch'
GPU_SESSION_PATCHES = (
    ROOT / 'patches/r580.178.04/0010-private-open-gpu-session.patch',
    ROOT / 'patches/r580.178.04/0011-private-open-gpu-session-bdf-lookup.patch',
    ROOT / 'patches/r580.178.04/0012-private-open-gpu-inventory.patch')
ATTACH_GPU_PATCH = ROOT / 'patches/r580.178.04/0014-private-control-attach-after-gpu.patch'
CARD_INFO_PATCH = ROOT / 'patches/r580.178.04/0015-private-open-card-info.patch'
GPU_ID_INFO_PATCH = ROOT / 'patches/r580.178.04/0016-private-open-gpu-id-info.patch'
ATTACHED_IDS_PATCH = ROOT / 'patches/r580.178.04/0017-private-open-attached-ids.patch'
PROBED_IDS_PATCH = ROOT / 'patches/r580.178.04/0018-private-open-probed-ids.patch'
DEVICE_IDS_PATCH = ROOT / 'patches/r580.178.04/0019-private-open-device-ids.patch'
DEVICE_OBJECT_PATCH = ROOT / 'patches/r580.178.04/0020-private-open-device-object.patch'
MEMORY_OBJECT_PATCH = ROOT / 'patches/r580.178.04/0021-private-open-memory-object.patch'
VASPACE_OBJECT_PATCH = ROOT / 'patches/r580.178.04/0022-private-open-vaspace-object.patch'
CHANNEL_GROUP_OBJECT_PATCH = ROOT / 'patches/r580.178.04/0023-private-open-channel-group-object.patch'
CONTEXT_SHARE_OBJECT_PATCH = ROOT / 'patches/r580.178.04/0024-private-open-context-share-object.patch'
CHANNEL_OBJECT_PATCH = ROOT / 'patches/r580.178.04/0025-private-open-channel-object.patch'
SUBDEVICE_TPC_MASK_PATCH = ROOT / 'patches/r580.178.04/0026-private-open-subdevice-and-tpc-mask.patch'
BINAPI_OBJECT_PATCH = ROOT / 'patches/r580.178.04/0027-private-open-binapi-object.patch'
USERMODE_OBJECT_PATCH = ROOT / 'patches/r580.178.04/0028-private-open-usermode-object.patch'
MAP_MEMORY_PATCH = ROOT / 'patches/r580.178.04/0029-private-open-map-memory.patch'
RUSD_OBJECT_PATCH = ROOT / 'patches/r580.178.04/0030-private-open-rusd-object.patch'
VERSION_CHECK_PATCH = ROOT / 'patches/r580.178.04/0043-private-open-version-check.patch'
BASE = ROOT / 'build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04'


class PrivateControlSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        projection.PrivateFileProjectionTests.setUpClass.__func__(cls)
        for patch in (PATCH, *GPU_SESSION_PATCHES, ATTACH_GPU_PATCH,
                      CARD_INFO_PATCH, GPU_ID_INFO_PATCH, ATTACHED_IDS_PATCH,
                      PROBED_IDS_PATCH, DEVICE_IDS_PATCH, DEVICE_OBJECT_PATCH,
                      MEMORY_OBJECT_PATCH, VASPACE_OBJECT_PATCH, CHANNEL_GROUP_OBJECT_PATCH,
                      CONTEXT_SHARE_OBJECT_PATCH, CHANNEL_OBJECT_PATCH):
            result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                                    cwd=cls.tree, capture_output=True, text=True)
            if result.returncode or re.search(r'\b(?:fuzz|offset)\b', result.stdout + result.stderr):
                raise AssertionError(result.stdout + result.stderr)
        cls.source = (cls.tree / 'kernel-open/nvidia/nv.c').read_text()
        cls.header = (cls.tree / 'kernel-open/nvidia/hybrid580-control-session.h').read_text()
        for patch in (SUBDEVICE_TPC_MASK_PATCH, BINAPI_OBJECT_PATCH, USERMODE_OBJECT_PATCH,
                      MAP_MEMORY_PATCH, RUSD_OBJECT_PATCH):
            result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                                    cwd=cls.tree, capture_output=True, text=True)
            if result.returncode or re.search(r'\b(?:fuzz|offset)\b', result.stdout + result.stderr):
                raise AssertionError(result.stdout + result.stderr)
        cls.rusd_source = (cls.tree / 'kernel-open/nvidia/nv.c').read_text()
        with tarfile.open(projection.ARCHIVE) as archive:
            for name in ('src/common/sdk/nvidia/inc/nvos.h',
                         'src/nvidia/arch/nvalloc/unix/include/nv_escape.h'):
                actual = archive.extractfile('NVIDIA-kernel-module-source-580.178.04/' + name).read()
                if (BASE / name).read_bytes() != actual:
                    raise AssertionError('SDK header drift: ' + name)

    def test_patch_scope_and_real_vendor_failure_prefix(self):
        targets = re.findall(r'^\+\+\+ b/([^\n]+)$', PATCH.read_text(), re.M)
        self.assertEqual(targets, ['kernel-open/nvidia/nv.c', 'kernel-open/nvidia/nvidia.Kbuild',
                                  'kernel-open/nvidia/hybrid580-control-session.h'])
        for suffix in ('create', 'get', 'put', 'file'):
            self.assertEqual(self.source.count('EXPORT_SYMBOL(hybrid580_open_control_session_' + suffix + '_v1);'), 1)
        for forbidden in ('anon_inode_getfile(', 'kern_mount(', 'fd_install(', 'get_unused_fd',
                          'NV_COPY_FROM_USER(', 'NV_COPY_TO_USER('):
            session = self.source[self.source.index('struct hybrid580_control_session {'):
                                  self.source.index('nv_file_private_t* NV_API_CALL nv_get_file_private(')]
            self.assertNotIn(forbidden, session)
        close = projection.function(self.source, 'nvidia_close')
        self.assertLess(close.index('if (nvlfp == NULL)'), close.index('nv_printf('))
        self.assertIn('rm_session_endpoint.h', self.header)
        self.assertIn('fput can defer', self.header)
        attach_targets = re.findall(r'^\+\+\+ b/([^\n]+)$', ATTACH_PATCH.read_text(), re.M)
        self.assertEqual(attach_targets, ['kernel-open/nvidia/nv.c',
                                          'kernel-open/nvidia/hybrid580-control-session.h'])
        self.assertEqual(self.source.count('EXPORT_SYMBOL(hybrid580_open_control_session_attach_v1);'), 1)
        ioctl_attach = self.source[self.source.index('case NV_ESC_ATTACH_GPUS_TO_FD:'):
                                   self.source.index('case NV_ESC_CHECK_VERSION_STR:')]
        self.assertIn('hybrid580_attach_gpus_to_file(nvlfp, sp, arg_copy, arg_size)', ioctl_attach)
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_open_control_session_gpu_id_info_v1);'), 1)
        gpu_targets = re.findall(r'^\+\+\+ b/([^\n]+)$', GPU_ID_INFO_PATCH.read_text(), re.M)
        self.assertEqual(gpu_targets, ['kernel-open/nvidia/nv.c',
                                      'kernel-open/nvidia/hybrid580-control-session.h'])
        declaration = self.header[self.header.index('NV_STATUS hybrid580_open_control_session_gpu_id_info_v1'):]
        self.assertIn('NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS *params', declaration)
        helper_start = self.source.index('NV_STATUS hybrid580_open_control_session_gpu_id_info_v1(')
        helper_end = self.source.index('EXPORT_SYMBOL(hybrid580_open_control_session_gpu_id_info_v1);',
                                        helper_start)
        helper = self.source[helper_start:helper_end]
        self.assertIn('#include <nv-kernel-rmapi-ops.h>', self.source)
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', helper)
        self.assertIn('.params.control = control', helper)
        self.assertIn('.op = NV04_CONTROL', helper)
        self.assertIn('NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2', helper)
        self.assertIn('.params = KERNEL_POINTER_TO_NvP64(&result)', helper)
        self.assertNotIn('rm_ioctl(', helper)
        self.assertNotIn('NV_COPY_FROM_USER', helper)
        self.assertNotIn('NV_COPY_TO_USER', helper)
        attached_start = self.source.index('NV_STATUS hybrid580_open_control_session_attached_ids_v1(')
        attached_end = self.source.index('EXPORT_SYMBOL(hybrid580_open_control_session_attached_ids_v1);', attached_start)
        attached = self.source[attached_start:attached_end]
        self.assertIn('NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS', attached)
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', attached)
        self.assertIn('.params.control = control', attached)
        self.assertIn('.op = NV04_CONTROL', attached)
        self.assertNotIn('NV_COPY_FROM_USER', attached)
        self.assertNotIn('NV_COPY_TO_USER', attached)
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_open_control_session_probed_ids_v1);'), 1)
        declaration = self.header[self.header.index(
            'NV_STATUS hybrid580_open_control_session_probed_ids_v1'):]
        self.assertIn('NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS *params', declaration)
        probed_start = self.source.index('NV_STATUS hybrid580_open_control_session_probed_ids_v1(')
        probed_end = self.source.index('EXPORT_SYMBOL(hybrid580_open_control_session_probed_ids_v1);', probed_start)
        probed = self.source[probed_start:probed_end]
        self.assertIn('NV0000_CTRL_CMD_GPU_GET_PROBED_IDS', probed)
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', probed)
        self.assertIn('.params = KERNEL_POINTER_TO_NvP64(&result)', probed)
        self.assertIn('memset(&result, 0xff, sizeof(result))', probed)
        self.assertNotIn('NV_COPY_FROM_USER', probed)
        self.assertNotIn('NV_COPY_TO_USER', probed)

    def test_version_check_bridge_patch_adds_fixed_kernel_payload(self):
        self.assertTrue(VERSION_CHECK_PATCH.is_file(),
                        'R580 version-check backend bridge patch is missing')
        patch = VERSION_CHECK_PATCH.read_text()
        targets = re.findall(r'^\+\+\+ b/([^\n]+)$', patch, re.M)
        self.assertEqual(targets, ['kernel-open/nvidia/nv.c'])
        for fragment in ('hybrid580_open_control_session_check_version_v1',
                         'nv_ioctl_rm_api_version_t *params',
                         'size != sizeof(*params)',
                         'rm_perform_version_check(sp, params, size)',
                         'mutex_lock_interruptible(&session->lock)',
                         'nv_down_read_interruptible(&nv_system_pm_lock)',
                         'EXPORT_SYMBOL(hybrid580_open_control_session_check_version_v1);'):
            self.assertIn(fragment, patch)
        self.assertNotIn('copy_from_user', patch)
        self.assertNotIn('NV_COPY_FROM_USER', patch)
        public_header = (ROOT / 'src/hybrid580-control-session.h').read_text()
        self.assertIn('<nv-ioctl.h>', public_header)
        self.assertIn('nv_ioctl_rm_api_version_t *params', public_header)

    def test_rusd_bridge_is_a_typed_subdevice_child(self):
        start = self.rusd_source.index(
            'NV_STATUS hybrid580_open_control_session_rusd_alloc_v1(')
        end = self.rusd_source.index(
            'EXPORT_SYMBOL(hybrid580_open_control_session_rusd_alloc_v1);', start)
        bridge = self.rusd_source[start:end]
        for fragment in ('RM_USER_SHARED_DATA', 'NV00DE_ALLOC_PARAMETERS alloc_params',
                         'alloc_params = *params', '.hObjectParent = h_subdevice',
                         '.paramsSize = sizeof(alloc_params)', '.params.alloc = alloc',
                         '*rm_status = alloc.status', '*returned_rusd = alloc.hObjectNew'):
            self.assertIn(fragment, bridge)
        self.assertNotIn('NV_COPY_FROM_USER', bridge)
        self.assertNotIn('NV_COPY_TO_USER', bridge)

        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_open_control_session_device_ids_v1);'), 1)
        declaration = self.header[self.header.index(
            'NV_STATUS hybrid580_open_control_session_device_ids_v1'):]
        self.assertIn('NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS *params', declaration)
        device_ids_start = self.source.index(
            'NV_STATUS hybrid580_open_control_session_device_ids_v1(')
        device_ids_end = self.source.index(
            'EXPORT_SYMBOL(hybrid580_open_control_session_device_ids_v1);', device_ids_start)
        device_ids = self.source[device_ids_start:device_ids_end]
        self.assertIn('NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS', device_ids)
        self.assertIn('NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS', device_ids)
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', device_ids)
        self.assertIn('.params = KERNEL_POINTER_TO_NvP64(&result)', device_ids)
        self.assertIn('result = { 0 }', device_ids)
        self.assertNotIn('NV_COPY_FROM_USER', device_ids)
        self.assertNotIn('NV_COPY_TO_USER', device_ids)
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_open_control_session_vaspace_alloc_v1);'), 1)
        vaspace_decl = self.header[self.header.index(
            'NV_STATUS hybrid580_open_control_session_vaspace_alloc_v1'):]
        self.assertIn('NV_VASPACE_ALLOCATION_PARAMETERS *params', vaspace_decl)
        vaspace_start = self.source.index(
            'NV_STATUS hybrid580_open_control_session_vaspace_alloc_v1(')
        vaspace_end = self.source.index(
            'EXPORT_SYMBOL(hybrid580_open_control_session_vaspace_alloc_v1);', vaspace_start)
        vaspace = self.source[vaspace_start:vaspace_end]
        self.assertIn('FERMI_VASPACE_A', vaspace)
        self.assertIn('.hObjectParent = h_device', vaspace)
        self.assertIn('NV_VASPACE_ALLOCATION_FLAGS_SHARED_MANAGEMENT', vaspace)
        self.assertIn('NV_VASPACE_ALLOCATION_FLAGS_ENABLE_NVLINK_ATS_TEST', vaspace)
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', vaspace)
        self.assertNotIn('NV_COPY_FROM_USER', vaspace)
        self.assertNotIn('NV_COPY_TO_USER', vaspace)
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_open_control_session_channel_group_alloc_v1);'), 1)
        group_start = self.source.index(
            'NV_STATUS hybrid580_open_control_session_channel_group_alloc_v1(')
        group_end = self.source.index(
            'EXPORT_SYMBOL(hybrid580_open_control_session_channel_group_alloc_v1);', group_start)
        group = self.source[group_start:group_end]
        self.assertIn('KEPLER_CHANNEL_GROUP_A', group)
        self.assertIn('NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS', group)
        self.assertIn('.hObjectParent = h_device', group)
        self.assertIn('params->hVASpace == 0', group)
        self.assertIn('params->bIsCallingContextVgpuPlugin != NV_FALSE', group)
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', group)
        self.assertNotIn('NV_COPY_FROM_USER', group)
        self.assertNotIn('NV_COPY_TO_USER', group)
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_open_control_session_context_share_alloc_v1);'), 1)
        context_start = self.source.index(
            'NV_STATUS hybrid580_open_control_session_context_share_alloc_v1(')
        context_end = self.source.index(
            'EXPORT_SYMBOL(hybrid580_open_control_session_context_share_alloc_v1);', context_start)
        context_share = self.source[context_start:context_end]
        self.assertIn('FERMI_CONTEXT_SHARE_A', context_share)
        self.assertIn('.hObjectParent = h_group', context_share)
        self.assertIn('NV_CTXSHARE_ALLOCATION_PARAMETERS', context_share)
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', context_share)
        self.assertNotIn('NV_COPY_FROM_USER', context_share)
        self.assertNotIn('NV_COPY_TO_USER', context_share)
        self.assertEqual(self.source.count(
            'EXPORT_SYMBOL(hybrid580_open_control_session_channel_alloc_v1);'), 1)
        channel_start = self.source.index(
            'NV_STATUS hybrid580_open_control_session_channel_alloc_v1(')
        channel_end = self.source.index(
            'EXPORT_SYMBOL(hybrid580_open_control_session_channel_alloc_v1);', channel_start)
        channel = self.source[channel_start:channel_end]
        self.assertIn('class_id != BLACKWELL_CHANNEL_GPFIFO_A', channel)
        self.assertIn('params->hVASpace != 0', channel)
        self.assertIn('NVOS04_FLAGS_CHANNEL_TYPE_PHYSICAL', channel)
        self.assertIn('.hObjectParent = h_group', channel)
        self.assertIn('paramsSize = sizeof(alloc_params)', channel)
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', channel)
        self.assertNotIn('NV_COPY_FROM_USER', channel)
        self.assertNotIn('NV_COPY_TO_USER', channel)

    def test_actual_session_source_failure_references_and_serialization(self):
        opening = projection.function(self.source, 'nvidia_open')
        # Execute the exact vendor control-open path. Device-open remainder is
        # deliberately outside this control-only test and API.
        original = projection.function(self.source, 'nvidia_open')
        pm_lock = '    rc = nv_down_read_interruptible(&nv_system_pm_lock);'
        control_call = opening.index('nvidia_ctl_open(inode, file)')
        first_pm = opening.index(pm_lock)
        pm_gated_control_open = first_pm < control_call
        if pm_gated_control_open:
            # The PM-enabled source gates the control open and has a second
            # lock for the ordinary GPU-device path.
            device_pm = opening.index(pm_lock, first_pm + len(pm_lock))
        else:
            # Earlier source slices have no control-device PM gate.
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
        actual = projection.function(self.source[self.source.index('static int\nnvidia_ctl_open('):], 'nvidia_ctl_open')
        actual += opening + closing
        actual += projection.function(self.source, 'hybrid580_open_backend_file')
        helper_start = self.source.index('/* Kernel-owned equivalent of the NV_ESC_ATTACH_GPUS_TO_FD wrapper path.')
        actual += projection.function(self.source[helper_start:], 'hybrid580_attach_gpus_to_file')
        begin = self.source.index('struct hybrid580_control_session {')
        end_marker = ('struct hybrid580_gpu_session {' if 'struct hybrid580_gpu_session {' in self.source
                      else 'nv_file_private_t* NV_API_CALL nv_get_file_private(')
        end = self.source.index(end_marker, begin)
        actual += self.source[begin:end]
        actual += projection.function(self.rusd_source,
                                      'hybrid580_open_control_session_rusd_alloc_v1')
        code = STUBS + self.vendor_macros + DECLARATIONS + actual + CASES
        source, binary = self.tree / 'session-contract.c', self.tree / 'session-contract'
        source.write_text(code)
        includes = ['-I' + str(ROOT / 'src')] + ['-I' + str(BASE / part) for part in (
            'kernel-open/common/inc', 'src/common/sdk/nvidia/inc', 'src/common/inc',
            'src/common/inc/swref', 'src/nvidia/arch/nvalloc/unix/include')]
        result = subprocess.run(['cc', '-std=gnu11', '-DNVRM', '-Wall', '-Wextra',
                                 '-Werror', '-Wno-unused-parameter', '-pthread',
                                 '-fsanitize=undefined', '-fno-sanitize-recover=all', *includes,
                                 str(source), '-o', str(binary)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('control-session CPU scenarios:', result.stdout)
        self.assertIn('mutex serialized two invocations', result.stdout)
        print(result.stdout.strip())


STUBS = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <fcntl.h>
#include <nv-kernel-interface-api.h>
#include "rm_session_endpoint.h"
#include <nvos.h>
#include <nv_escape.h>
#include <class/cl0080.h>
#include <class/cl003e.h>
#include <class/cl0040.h>
#include <ctrl/ctrl0000/ctrl0000gpu.h>
#include <ctrl/ctrl503c.h>
#include <nv-kernel-rmapi-ops.h>
#include <class/cl90f1.h>
#include <class/cla06c.h>
#include <class/cl9067.h>
#include <class/cl00de.h>
#include <class/clc36f.h>
#include <class/clc96f.h>
#include <alloc/alloc_channel.h>
#define GFP_KERNEL 0
#define EXPORT_SYMBOL(name)
#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255
#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247
#define NV_ABSOLUTE_MAX_IOCTL_SIZE 16384
#define MAJOR(v) major(v)
#define MINOR(v) minor(v)
#define MKDEV(a,b) makedev(a,b)
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define ERR_PTR(v) ((void *)(intptr_t)(v))
#define PTR_ERR(p) ((intptr_t)(p))
#define READ_ONCE(x) __atomic_load_n(&(x), __ATOMIC_ACQUIRE)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define nv_printf(...) ((void)0)
#define NV_DBG_INFO 0
#define NV_DBG_ERRORS 0
struct super_block { int marker; };
struct vfsmount { struct super_block *mnt_sb; };
struct inode { struct super_block *i_sb; mode_t i_mode; dev_t i_rdev; };
struct dentry { struct inode *inode; };
struct path { struct vfsmount *mnt; struct dentry *dentry; };
struct file;
struct file_operations { int (*release)(struct inode *, struct file *); };
struct file { struct path f_path; struct inode *f_inode; const struct file_operations *f_op;
              void *private_data; atomic_int refs; bool allocated; };
typedef struct { int flags; } nv_state_t;
typedef struct { nv_state_t nv_state; int usage_count, ldata_lock; } nv_linux_state_t;
typedef struct { int marker; } nv_file_private_t;
typedef struct { int marker; } nvidia_stack_t;
typedef struct { nv_file_private_t nvfp; nvidia_stack_t *sp; nv_linux_state_t *nvptr;
                 NvU32 num_attached_gpus; NvU32 *attached_gpus; } nv_linux_file_private_t;
#define NV_GET_LINUX_FILE_PRIVATE(f) ((nv_linux_file_private_t *)(f)->private_data)
#define NV_SET_FILE_PRIVATE(f,p) ((f)->private_data=(p))
#define NV_FILE_INODE(f) ((f)->f_inode)
#define NV_DEVICE_MINOR_NUMBER(i) MINOR((i)->i_rdev)
#define atomic64_read(p) (*(p))
#define atomic64_inc(p) (++*(p))
static int fail_attach_alloc;
#define NV_KMALLOC(p,n) do { (p)=fail_attach_alloc?NULL:malloc(n); } while (0)
#define NV_KFREE(p,n) do { (void)(n); free(p); (p)=NULL; } while (0)
static void nvidia_dev_put(NvU32,nvidia_stack_t *);
static void down(int *p) { assert(!*p); *p=1; }
static void up(int *p) { assert(*p); *p=0; }
static struct inode *d_inode(struct dentry *d) { return d->inode; }
static nv_linux_state_t nv_ctl_device;
static nv_linux_state_t *nv_linux_minor_num_table[248];
static dev_t hybrid_chrdev_base;
static int fail_at, allocations, inodes, fops_refs, files, stack_count, private_count, cleanup_calls;
static _Thread_local int mutex_depth, pm_depth;
static int nv_system_pm_lock;
static atomic_int rm_calls, rm_active, rm_max_active, rm_block, rm_entered, rm_release, mutex_attempts;
static int rm_write_status=1;
static NV_STATUS rm_transport=NV_OK, rm_payload=NV_OK, gpu_status=NV_OK;
static int rm_control_calls, rm_control_write_outputs=1;
static int rm_attached_calls, rm_attached_write_outputs=1;
static NV_STATUS rm_attached_status=NV_OK;
static NvU32 rm_attached_ids[NV0000_CTRL_GPU_MAX_ATTACHED_GPUS];
static int rm_probed_calls, rm_probed_write_outputs=1;
static NV_STATUS rm_probed_status=NV_OK;
static NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS rm_probed_ids;
static NvHandle rm_probed_client, rm_probed_object;
static NvU32 rm_probed_cmd, rm_probed_flags, rm_probed_size;
static int rm_device_ids_calls, rm_device_ids_write_outputs=1;
static NV_STATUS rm_device_ids_status=NV_OK;
static NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS rm_device_ids;
static NvHandle rm_device_ids_client, rm_device_ids_object;
static NvU32 rm_device_ids_cmd, rm_device_ids_flags, rm_device_ids_size;
static NV_STATUS rm_control_status=NV_OK;
static NvHandle rm_control_client, rm_control_object;
static NvU32 rm_control_cmd, rm_control_flags, rm_control_size, rm_control_gpu_id;
static int rm_p2p_control_calls;
static NvHandle rm_p2p_control_client, rm_p2p_control_object, rm_p2p_control_vaspace;
static NvHandle rm_p2p_control_memory;
static NvU32 rm_p2p_control_cmd, rm_p2p_control_size;
static NvU64 rm_p2p_control_address, rm_p2p_control_bytes, rm_p2p_control_offset;
static int rm_memory_alloc_calls, rm_memory_free_calls, rm_capture_memory_free;
static NvHandle rm_memory_alloc_root, rm_memory_alloc_parent, rm_memory_alloc_handle;
static NvHandle rm_memory_free_root, rm_memory_free_parent, rm_memory_free_handle;
static NvU32 rm_memory_alloc_class, rm_memory_alloc_size;
static NV_MEMORY_ALLOCATION_PARAMS rm_memory_alloc_input;
static int rm_memory_write_outputs=1;
static NvHandle rm_memory_return_override;
static int rm_rusd_alloc_calls;
static NvHandle rm_rusd_alloc_root, rm_rusd_alloc_parent, rm_rusd_alloc_handle;
static NvU32 rm_rusd_alloc_class, rm_rusd_alloc_size;
static NV00DE_ALLOC_PARAMETERS rm_rusd_alloc_input;
static NvHandle rm_rusd_return_override;
static int rm_vaspace_alloc_calls;
static NvHandle rm_vaspace_alloc_root, rm_vaspace_alloc_parent, rm_vaspace_alloc_handle;
static NvU32 rm_vaspace_alloc_class, rm_vaspace_alloc_size;
static NV_VASPACE_ALLOCATION_PARAMETERS rm_vaspace_alloc_input;
static int rm_vaspace_write_outputs=1;
static NvHandle rm_vaspace_return_override;
static int rm_channel_group_alloc_calls;
static NvHandle rm_channel_group_alloc_root, rm_channel_group_alloc_parent, rm_channel_group_alloc_handle;
static NvU32 rm_channel_group_alloc_class, rm_channel_group_alloc_size;
static NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS rm_channel_group_alloc_input;
static NvHandle rm_channel_group_return_override;
static int rm_context_share_alloc_calls;
static NvHandle rm_context_share_alloc_root, rm_context_share_alloc_parent, rm_context_share_alloc_handle;
static NvU32 rm_context_share_alloc_class, rm_context_share_alloc_size;
static NV_CTXSHARE_ALLOCATION_PARAMETERS rm_context_share_alloc_input;
static NvHandle rm_context_share_return_override;
static int rm_channel_alloc_calls;
static NvHandle rm_channel_alloc_root, rm_channel_alloc_parent, rm_channel_alloc_handle;
static NvU32 rm_channel_alloc_class, rm_channel_alloc_size;
static NV_CHANNEL_ALLOC_PARAMS rm_channel_alloc_input;
static NvHandle rm_channel_return_override;
static int fail_gpu_id=-1, gpu_get_calls, gpu_put_calls;
static unsigned int gpu_refs[256];
static void *kzalloc(size_t n, int flags) { if (fail_at==1) return NULL; ++allocations; return calloc(1,n); }
static void kfree(void *p) { assert(p && allocations>0); --allocations; free(p); }
static struct inode *alloc_anon_inode(struct super_block *sb) {
    if (fail_at==2) return ERR_PTR(-ENOMEM);
    struct inode *i=calloc(1,sizeof(*i)); assert(i); i->i_sb=sb; ++inodes; return i;
}
static void iput(struct inode *i) { assert(inodes>0); --inodes; free(i); }
static const struct file_operations *cpu_fops_get(const struct file_operations *f) {
    if (fail_at==3) return NULL;
    ++fops_refs; return f;
}
#define fops_get(f) cpu_fops_get(f)
static void fops_put(const struct file_operations *f) { assert(f && fops_refs>0); --fops_refs; }
static struct file *get_file(struct file *f) { assert(atomic_fetch_add(&f->refs,1)>0); return f; }
static void fput(struct file *f) {
    assert(atomic_fetch_sub(&f->refs,1)>0);
    if (atomic_load(&f->refs)==0) {
        assert(f->allocated && !mutex_depth && !pm_depth);
        if (f->f_op->release) assert(f->f_op->release(f->f_inode,f)==0);
        iput(f->f_inode); fops_put(f->f_op); free(f->f_path.dentry); free(f); --files;
    }
}
static struct file *alloc_file_pseudo(struct inode *i, struct vfsmount *m,
        const char *n, int flags, const struct file_operations *fops) {
    /* CPU model of the pinned v7.0 success ownership contract and OPENED
     * release behavior; no claim about real VFS/superblock/LSM semantics. */
    if (fail_at==4) return ERR_PTR(-ENFILE);
    struct file *f=calloc(1,sizeof(*f)); assert(f);
    f->f_path=(struct path){m,calloc(1,sizeof(struct dentry))}; assert(f->f_path.dentry);
    f->f_path.dentry->inode=i; f->f_inode=i; f->f_op=fops;
    atomic_init(&f->refs,1); f->allocated=true; ++files; return f;
}
static nv_linux_file_private_t *nv_alloc_file_private(void) {
    if (fail_at==5) return NULL;
    ++private_count; return calloc(1,sizeof(nv_linux_file_private_t));
}
static void nv_free_file_private(nv_linux_file_private_t *p) { assert(private_count>0); --private_count; free(p); }
static int nv_kmem_cache_alloc_stack(nvidia_stack_t **p) {
    if (fail_at==6 || fail_at==9) return -ENOMEM;
    ++stack_count; *p=calloc(1,sizeof(**p)); assert(*p); return 0;
}
static void nv_kmem_cache_free_stack(nvidia_stack_t *p) { assert(stack_count>0); --stack_count; free(p); }
void rm_kernel_rmapi_op(nvidia_stack_t *sp, void *opaque) {
    nvidia_kernel_rmapi_ops_t *ops=opaque;
    assert(sp && ops && mutex_depth==1 && pm_depth==1 && stack_count==2);
    if (ops->op==NV04_ALLOC) {
        NVOS64_PARAMETERS *alloc=&ops->params.alloc;
        assert(alloc->flags==NVOS64_FLAGS_NONE);
        if (alloc->hClass==NV01_MEMORY_SYSTEM || alloc->hClass==NV01_MEMORY_LOCAL_USER ||
            alloc->hClass==FERMI_VASPACE_A || alloc->hClass==KEPLER_CHANNEL_GROUP_A ||
            alloc->hClass==FERMI_CONTEXT_SHARE_A ||
            alloc->hClass==VOLTA_CHANNEL_GPFIFO_A ||
            alloc->hClass==BLACKWELL_CHANNEL_GPFIFO_A ||
            alloc->hClass==RM_USER_SHARED_DATA) {
            assert(alloc->hRoot && alloc->hObjectParent && alloc->hObjectNew &&
                   alloc->pAllocParms!=NvP64_NULL);
        } else {
            assert((alloc->hClass==NV01_ROOT || alloc->hClass==NV01_ROOT_CLIENT) &&
                   alloc->hRoot && alloc->hObjectParent==0 && alloc->pAllocParms==NvP64_NULL);
        }
        if (alloc->hClass==NV01_MEMORY_SYSTEM || alloc->hClass==NV01_MEMORY_LOCAL_USER) {
            assert(alloc->paramsSize==sizeof(NV_MEMORY_ALLOCATION_PARAMS));
            NV_MEMORY_ALLOCATION_PARAMS *p=(void *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);
            assert(p);
            ++rm_memory_alloc_calls;
            rm_memory_alloc_root=alloc->hRoot; rm_memory_alloc_parent=alloc->hObjectParent;
            rm_memory_alloc_handle=alloc->hObjectNew; rm_memory_alloc_class=alloc->hClass;
            rm_memory_alloc_size=alloc->paramsSize; rm_memory_alloc_input=*p;
            if (rm_memory_write_outputs) {
                p->size=0x4000; p->address=(NvP64)(uintptr_t)0xabc000;
                p->pitch=64; p->zcullCovg=0x55;
            }
            if (rm_memory_return_override) alloc->hObjectNew=rm_memory_return_override;
        } else if (alloc->hClass==RM_USER_SHARED_DATA) {
            assert(alloc->paramsSize==sizeof(NV00DE_ALLOC_PARAMETERS));
            NV00DE_ALLOC_PARAMETERS *p=(void *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);
            assert(p);
            ++rm_rusd_alloc_calls;
            rm_rusd_alloc_root=alloc->hRoot; rm_rusd_alloc_parent=alloc->hObjectParent;
            rm_rusd_alloc_handle=alloc->hObjectNew; rm_rusd_alloc_class=alloc->hClass;
            rm_rusd_alloc_size=alloc->paramsSize; rm_rusd_alloc_input=*p;
            if (rm_rusd_return_override) alloc->hObjectNew=rm_rusd_return_override;
        } else if (alloc->hClass==KEPLER_CHANNEL_GROUP_A) {
            assert(alloc->paramsSize==sizeof(NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS));
            NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS *p=(void *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);
            assert(p);
            ++rm_channel_group_alloc_calls;
            rm_channel_group_alloc_root=alloc->hRoot; rm_channel_group_alloc_parent=alloc->hObjectParent;
            rm_channel_group_alloc_handle=alloc->hObjectNew; rm_channel_group_alloc_class=alloc->hClass;
            rm_channel_group_alloc_size=alloc->paramsSize; rm_channel_group_alloc_input=*p;
            if (rm_channel_group_return_override) alloc->hObjectNew=rm_channel_group_return_override;
        } else if (alloc->hClass==FERMI_VASPACE_A) {
            assert(alloc->paramsSize==sizeof(NV_VASPACE_ALLOCATION_PARAMETERS));
            NV_VASPACE_ALLOCATION_PARAMETERS *p=(void *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);
            assert(p);
            ++rm_vaspace_alloc_calls;
            rm_vaspace_alloc_root=alloc->hRoot; rm_vaspace_alloc_parent=alloc->hObjectParent;
            rm_vaspace_alloc_handle=alloc->hObjectNew; rm_vaspace_alloc_class=alloc->hClass;
            rm_vaspace_alloc_size=alloc->paramsSize; rm_vaspace_alloc_input=*p;
            if (rm_vaspace_write_outputs) { p->vaBase=0x20000; p->vaSize=0x200000000ULL; }
            if (rm_vaspace_return_override) alloc->hObjectNew=rm_vaspace_return_override;
        } else if (alloc->hClass==FERMI_CONTEXT_SHARE_A) {
            assert(alloc->paramsSize==sizeof(NV_CTXSHARE_ALLOCATION_PARAMETERS));
            NV_CTXSHARE_ALLOCATION_PARAMETERS *p=(void *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);
            assert(p);
            ++rm_context_share_alloc_calls;
            rm_context_share_alloc_root=alloc->hRoot; rm_context_share_alloc_parent=alloc->hObjectParent;
            rm_context_share_alloc_handle=alloc->hObjectNew; rm_context_share_alloc_class=alloc->hClass;
            rm_context_share_alloc_size=alloc->paramsSize; rm_context_share_alloc_input=*p;
            p->subctxId=0x1b;
            if (rm_context_share_return_override) alloc->hObjectNew=rm_context_share_return_override;
        } else if (alloc->hClass==VOLTA_CHANNEL_GPFIFO_A ||
                   alloc->hClass==BLACKWELL_CHANNEL_GPFIFO_A) {
            assert(alloc->paramsSize==sizeof(NV_CHANNEL_ALLOC_PARAMS));
            NV_CHANNEL_ALLOC_PARAMS *p=(void *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);
            assert(p);
            ++rm_channel_alloc_calls;
            rm_channel_alloc_root=alloc->hRoot; rm_channel_alloc_parent=alloc->hObjectParent;
            rm_channel_alloc_handle=alloc->hObjectNew; rm_channel_alloc_class=alloc->hClass;
            rm_channel_alloc_size=alloc->paramsSize; rm_channel_alloc_input=*p;
            if (rm_channel_return_override) alloc->hObjectNew=rm_channel_return_override;
        } else {
            assert(!"unapproved typed RM allocation class");
        }
        alloc->status=rm_payload;
        return;
    }
    if (ops->op==NV01_FREE) {
        NVOS00_PARAMETERS *packet=&ops->params.free;
        assert(packet->hRoot && packet->hObjectParent && packet->hObjectOld);
        if (rm_capture_memory_free) {
            ++rm_memory_free_calls;
            rm_memory_free_root=packet->hRoot; rm_memory_free_parent=packet->hObjectParent;
            rm_memory_free_handle=packet->hObjectOld;
        }
        packet->status=rm_payload;
        return;
    }
    assert(ops->op==NV04_CONTROL);
    NVOS54_PARAMETERS *control=&ops->params.control;
    assert(control->flags==NVOS54_FLAGS_NONE && control->params!=0);
    if (control->cmd==NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS) {
        assert(control->paramsSize==sizeof(NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS));
        ++rm_device_ids_calls;
        rm_device_ids_client=control->hClient; rm_device_ids_object=control->hObject;
        rm_device_ids_cmd=control->cmd; rm_device_ids_flags=control->flags;
        rm_device_ids_size=control->paramsSize;
        NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS *p=(void *)(uintptr_t)control->params;
        if (rm_device_ids_write_outputs) *p=rm_device_ids;
        control->status=rm_device_ids_status;
        return;
    }
    if (control->cmd==NV0000_CTRL_CMD_GPU_GET_PROBED_IDS) {
        assert(control->paramsSize==sizeof(NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS));
        ++rm_probed_calls;
        rm_probed_client=control->hClient; rm_probed_object=control->hObject;
        rm_probed_cmd=control->cmd; rm_probed_flags=control->flags;
        rm_probed_size=control->paramsSize;
        NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS *p=(void *)(uintptr_t)control->params;
        if (rm_probed_write_outputs) *p=rm_probed_ids;
        control->status=rm_probed_status;
        return;
    }
    if (control->cmd==NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS) {
        assert(control->paramsSize==sizeof(NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS));
        ++rm_attached_calls;
        NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS *p=(void *)(uintptr_t)control->params;
        if (rm_attached_write_outputs)
            memcpy(p->gpuIds,rm_attached_ids,sizeof(rm_attached_ids));
        control->status=rm_attached_status;
        return;
    }
    if (control->cmd>=NV503C_CTRL_CMD_REGISTER_VA_SPACE &&
        control->cmd<=NV503C_CTRL_CMD_UNREGISTER_VIDMEM) {
        ++rm_p2p_control_calls;
        rm_p2p_control_client=control->hClient;
        rm_p2p_control_object=control->hObject;
        rm_p2p_control_cmd=control->cmd;
        rm_p2p_control_size=control->paramsSize;
        if (control->cmd==NV503C_CTRL_CMD_REGISTER_VA_SPACE) {
            assert(control->paramsSize==sizeof(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS));
            NV503C_CTRL_REGISTER_VA_SPACE_PARAMS *p=(void *)(uintptr_t)control->params;
            rm_p2p_control_vaspace=p->hVASpace; p->vaSpaceToken=0x76543210ULL;
        } else if (control->cmd==NV503C_CTRL_CMD_UNREGISTER_VA_SPACE) {
            assert(control->paramsSize==sizeof(NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS));
            NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS *p=(void *)(uintptr_t)control->params;
            rm_p2p_control_vaspace=p->hVASpace;
        } else if (control->cmd==NV503C_CTRL_CMD_REGISTER_VIDMEM) {
            assert(control->paramsSize==sizeof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS));
            NV503C_CTRL_REGISTER_VIDMEM_PARAMS *p=(void *)(uintptr_t)control->params;
            rm_p2p_control_memory=p->hMemory; rm_p2p_control_address=p->address;
            rm_p2p_control_bytes=p->size; rm_p2p_control_offset=p->offset;
        } else {
            assert(control->cmd==NV503C_CTRL_CMD_UNREGISTER_VIDMEM);
            assert(control->paramsSize==sizeof(NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS));
            NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS *p=(void *)(uintptr_t)control->params;
            rm_p2p_control_memory=p->hMemory;
        }
        control->status=rm_payload;
        return;
    }
    assert(control->cmd==NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2);
    assert(control->paramsSize==sizeof(NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS));
    ++rm_control_calls;
    rm_control_client=control->hClient; rm_control_object=control->hObject;
    rm_control_cmd=control->cmd; rm_control_flags=control->flags;
    rm_control_size=control->paramsSize;
    NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS *p=(void *)(uintptr_t)control->params;
    rm_control_gpu_id=p->gpuId;
    if (rm_control_write_outputs) {
        p->gpuFlags=0x11; p->deviceInstance=0x22; p->subDeviceInstance=0x33;
        p->sliStatus=0x44; p->boardId=0x55; p->gpuInstance=0x66; p->numaId=-1;
    }
    control->status=rm_control_status;
}
static int nv_is_control_device(struct inode *i) { return MINOR(i->i_rdev)==255; }
void nvidia_ctl_close_callback(nv_linux_file_private_t *p) {
    assert(p && p->nvptr==&nv_ctl_device);
    assert(nv_ctl_device.usage_count>0); --nv_ctl_device.usage_count;
    if (!nv_ctl_device.usage_count) nv_ctl_device.nv_state.flags &= ~0x1;
    for (NvU32 j=0;j<p->num_attached_gpus;j++)
        if (p->attached_gpus[j]) nvidia_dev_put(p->attached_gpus[j],p->sp);
    free(p->attached_gpus); p->attached_gpus=NULL; p->num_attached_gpus=0;
    ++cleanup_calls; nv_kmem_cache_free_stack(p->sp); nv_free_file_private(p);
}
int nvidia_ctl_close(struct inode *i,struct file *f) {
    nv_linux_file_private_t *p=NV_GET_LINUX_FILE_PRIVATE(f);
    nvidia_ctl_close_callback(p); f->private_data=NULL; return 0;
}
struct kref { atomic_int refs; };
static void kref_init(struct kref *k) { atomic_init(&k->refs,1); }
static void kref_get(struct kref *k) { assert(atomic_fetch_add(&k->refs,1)>0); }
static void kref_put(struct kref *k,void (*release)(struct kref *)) { if (atomic_fetch_sub(&k->refs,1)==1) release(k); }
struct mutex { pthread_mutex_t value; };
static void mutex_init(struct mutex *m) { assert(pthread_mutex_init(&m->value,NULL)==0); }
static int mutex_lock_interruptible(struct mutex *m) {
    if (fail_at==7) return -EINTR;
    atomic_fetch_add(&mutex_attempts,1);
    assert(pthread_mutex_lock(&m->value)==0); ++mutex_depth; return 0;
}
static void mutex_unlock(struct mutex *m) { assert(mutex_depth==1); --mutex_depth; assert(pthread_mutex_unlock(&m->value)==0); }
static int nv_down_read_interruptible(int *l) { assert(mutex_depth==0 || mutex_depth==1); if (fail_at==8) return -EINTR; ++pm_depth; return 0; }
static void up_read(int *l) { assert(pm_depth==1); --pm_depth; }
static NV_STATUS nv_check_gpu_state(nv_state_t *nv) { assert(pm_depth && mutex_depth); return gpu_status; }
static int nvidia_dev_get(NvU32 gpu_id,nvidia_stack_t *sp) {
    assert(sp && pm_depth==1 && mutex_depth==1 && gpu_id<256); ++gpu_get_calls;
    if ((int)gpu_id==fail_gpu_id) return -ENODEV;
    ++gpu_refs[gpu_id]; return 0;
}
static void nvidia_dev_put(NvU32 gpu_id,nvidia_stack_t *sp) {
    assert(sp && ((pm_depth==1 && (mutex_depth==0 || mutex_depth==1)) ||
                  (pm_depth==0 && mutex_depth==0)) &&
           gpu_id<256 && gpu_refs[gpu_id]);
    --gpu_refs[gpu_id]; ++gpu_put_calls;
}
static NV_STATUS rm_ioctl(nvidia_stack_t *sp,nv_state_t *nv,nv_file_private_t *fp,NvU32 cmd,void *data,NvU32 size) {
    nv_linux_file_private_t *p=container_of(fp,nv_linux_file_private_t,nvfp);
    assert(sp && sp!=p->sp && nv==&nv_ctl_device.nv_state && pm_depth==1 && mutex_depth==1);
    int active=atomic_fetch_add(&rm_active,1)+1; atomic_store(&rm_max_active,active);
    atomic_fetch_add(&rm_calls,1);
    if (atomic_load(&rm_block)) {
        atomic_store(&rm_entered,1);
        while (!atomic_load(&rm_release)) sched_yield();
    }
    if (cmd==NV_ESC_RM_FREE) {
        NVOS00_PARAMETERS *packet=data;
        if (rm_capture_memory_free) {
            ++rm_memory_free_calls;
            rm_memory_free_root=packet->hRoot; rm_memory_free_parent=packet->hObjectParent;
            rm_memory_free_handle=packet->hObjectOld;
        }
        if (rm_write_status) packet->status=rm_payload;
    } else if (size==sizeof(NVOS21_PARAMETERS)) {
        if (rm_write_status) ((NVOS21_PARAMETERS *)data)->status=rm_payload;
    } else {
        NVOS64_PARAMETERS *alloc=data;
        if (alloc->hClass==NV01_MEMORY_SYSTEM || alloc->hClass==NV01_MEMORY_LOCAL_USER) {
            assert(alloc->paramsSize==sizeof(NV_MEMORY_ALLOCATION_PARAMS) &&
                   alloc->hRoot && alloc->hObjectParent && alloc->hObjectNew &&
                   alloc->pAllocParms!=NvP64_NULL);
            NV_MEMORY_ALLOCATION_PARAMS *p=(void *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);
            assert(p);
            ++rm_memory_alloc_calls;
            rm_memory_alloc_root=alloc->hRoot; rm_memory_alloc_parent=alloc->hObjectParent;
            rm_memory_alloc_handle=alloc->hObjectNew; rm_memory_alloc_class=alloc->hClass;
            rm_memory_alloc_size=alloc->paramsSize; rm_memory_alloc_input=*p;
            if (rm_memory_write_outputs) {
                p->size=0x4000; p->address=(NvP64)(uintptr_t)0xabc000;
                p->pitch=64; p->zcullCovg=0x55;
            }
            if (rm_memory_return_override) alloc->hObjectNew=rm_memory_return_override;
        } else if (alloc->hClass==KEPLER_CHANNEL_GROUP_A) {
            assert(alloc->paramsSize==sizeof(NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) &&
                   alloc->hRoot && alloc->hObjectParent && alloc->hObjectNew &&
                   alloc->pAllocParms!=NvP64_NULL);
            NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS *p=(void *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);
            assert(p);
            ++rm_channel_group_alloc_calls;
            rm_channel_group_alloc_root=alloc->hRoot; rm_channel_group_alloc_parent=alloc->hObjectParent;
            rm_channel_group_alloc_handle=alloc->hObjectNew; rm_channel_group_alloc_class=alloc->hClass;
            rm_channel_group_alloc_size=alloc->paramsSize; rm_channel_group_alloc_input=*p;
            if (rm_channel_group_return_override) alloc->hObjectNew=rm_channel_group_return_override;
        } else if (alloc->hClass==FERMI_VASPACE_A) {
            assert(alloc->paramsSize==sizeof(NV_VASPACE_ALLOCATION_PARAMETERS) &&
                   alloc->hRoot && alloc->hObjectParent && alloc->hObjectNew &&
                   alloc->pAllocParms!=NvP64_NULL);
            NV_VASPACE_ALLOCATION_PARAMETERS *p=(void *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);
            assert(p);
            ++rm_vaspace_alloc_calls;
            rm_vaspace_alloc_root=alloc->hRoot; rm_vaspace_alloc_parent=alloc->hObjectParent;
            rm_vaspace_alloc_handle=alloc->hObjectNew; rm_vaspace_alloc_class=alloc->hClass;
            rm_vaspace_alloc_size=alloc->paramsSize; rm_vaspace_alloc_input=*p;
            if (rm_vaspace_write_outputs) { p->vaBase=0x20000; p->vaSize=0x200000000ULL; }
            if (rm_vaspace_return_override) alloc->hObjectNew=rm_vaspace_return_override;
        } else if (alloc->hClass==FERMI_CONTEXT_SHARE_A) {
            assert(alloc->paramsSize==sizeof(NV_CTXSHARE_ALLOCATION_PARAMETERS) &&
                   alloc->hRoot && alloc->hObjectParent && alloc->hObjectNew &&
                   alloc->pAllocParms!=NvP64_NULL);
            NV_CTXSHARE_ALLOCATION_PARAMETERS *p=(void *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);
            assert(p);
            ++rm_context_share_alloc_calls;
            rm_context_share_alloc_root=alloc->hRoot; rm_context_share_alloc_parent=alloc->hObjectParent;
            rm_context_share_alloc_handle=alloc->hObjectNew; rm_context_share_alloc_class=alloc->hClass;
            rm_context_share_alloc_size=alloc->paramsSize; rm_context_share_alloc_input=*p;
            p->subctxId=0x1b;
            if (rm_context_share_return_override) alloc->hObjectNew=rm_context_share_return_override;
        } else if (alloc->hClass==VOLTA_CHANNEL_GPFIFO_A ||
                   alloc->hClass==BLACKWELL_CHANNEL_GPFIFO_A) {
            assert(alloc->paramsSize==sizeof(NV_CHANNEL_ALLOC_PARAMS) &&
                   alloc->hRoot && alloc->hObjectParent && alloc->hObjectNew &&
                   alloc->pAllocParms!=NvP64_NULL);
            NV_CHANNEL_ALLOC_PARAMS *p=(void *)(uintptr_t)NvP64_VALUE(alloc->pAllocParms);
            assert(p);
            ++rm_channel_alloc_calls;
            rm_channel_alloc_root=alloc->hRoot; rm_channel_alloc_parent=alloc->hObjectParent;
            rm_channel_alloc_handle=alloc->hObjectNew; rm_channel_alloc_class=alloc->hClass;
            rm_channel_alloc_size=alloc->paramsSize; rm_channel_alloc_input=*p;
            if (rm_channel_return_override) alloc->hObjectNew=rm_channel_return_override;
        } else if (alloc->hClass!=NV01_ROOT && alloc->hClass!=NV01_ROOT_CLIENT) {
            assert(!"unapproved typed RM allocation class");
        }
        if (rm_write_status) alloc->status=rm_payload;
    }
    atomic_fetch_sub(&rm_active,1); return rm_transport;
}
'''

DECLARATIONS = r'''
static int nvidia_open(struct inode *,struct file *);
static int nvidia_close(struct inode *,struct file *);
static struct file_operations nvidia_fops={.release=nvidia_close};
'''

CASES = r'''
#ifdef HYBRID_LEGACY
#define TEST_CHANNEL_CLASS VOLTA_CHANNEL_GPFIFO_A
#else
#define TEST_CHANNEL_CLASS BLACKWELL_CHANNEL_GPFIFO_A
#endif
static struct super_block sb={1},other_sb={2};
static struct vfsmount mnt={&sb};
static struct inode anchor_inode={&sb,S_IFCHR,0};
static struct dentry anchor_dentry={&anchor_inode};
static struct file anchor={.f_path={&mnt,&anchor_dentry},.f_inode=&anchor_inode,.refs=1};
static void balanced(void) {
    assert(allocations==0 && inodes==0 && fops_refs==0 && files==0 && private_count==0 && stack_count==0);
    assert(atomic_load(&anchor.refs)==1 && nv_ctl_device.usage_count==0 && !mutex_depth && !pm_depth);
    for (unsigned int i=0;i<256;i++) assert(gpu_refs[i]==0);
}
static void creation_failure(int error) {
    struct hybrid580_control_session *s=(void *)1;
    struct hybrid_rm_session_endpoint_v1 ep; memset(&ep,0xff,sizeof(ep));
    int before=cleanup_calls;
    assert(hybrid580_open_control_session_create_v1(&anchor,&s,&ep)==error);
    struct hybrid_rm_session_endpoint_v1 zero={0};
    assert(s==NULL && memcmp(&ep,&zero,sizeof(ep))==0 && cleanup_calls==before);
    balanced();
}
static NVOS21_PARAMETERS packet(void) {
    NVOS21_PARAMETERS p={0}; p.hClass=NV01_ROOT_CLIENT; p.status=0xffffffffU; return p;
}
static struct hybrid_rm_session_endpoint_v1 thread_ep;
static void *invoke_thread(void *unused) {
    NVOS21_PARAMETERS p=packet();
    assert(thread_ep.invoke(thread_ep.context,NV_ESC_RM_ALLOC,&p,sizeof(p))==NV_OK);
    return NULL;
}
int main(void) {
    unsigned cases=0; hybrid_chrdev_base=MKDEV(240,0);
    for (fail_at=1;fail_at<=6;++fail_at) { creation_failure(fail_at==3?-ENODEV:fail_at==4?-ENFILE:-ENOMEM); ++cases; }
    fail_at=0;
    anchor.f_inode=NULL; creation_failure(-EINVAL); anchor.f_inode=&anchor_inode; ++cases;
    anchor.f_path.mnt=NULL; creation_failure(-EINVAL); anchor.f_path.mnt=&mnt; ++cases;
    anchor.f_path.dentry=NULL; creation_failure(-EINVAL); anchor.f_path.dentry=&anchor_dentry; ++cases;
    mnt.mnt_sb=&other_sb; creation_failure(-EINVAL); mnt.mnt_sb=&sb; ++cases;
    anchor_dentry.inode=NULL; creation_failure(-EINVAL); anchor_dentry.inode=&anchor_inode; ++cases;
    hybrid_chrdev_base=0; creation_failure(-ENODEV); hybrid_chrdev_base=MKDEV(240,0); ++cases;
    struct hybrid580_control_session *s=NULL;
    struct hybrid_rm_session_endpoint_v1 ep;
    assert(hybrid580_open_control_session_create_v1(NULL,&s,&ep)==-EINVAL && s==NULL); ++cases;
    assert(hybrid580_open_control_session_create_v1(&anchor,NULL,&ep)==-EINVAL); ++cases;
    assert(hybrid580_open_control_session_create_v1(&anchor,&s,NULL)==-EINVAL); ++cases;
    assert(hybrid580_open_control_session_create_v1(&anchor,&s,&ep)==0 && s);
    assert(ep.abi_version==HYBRID_RM_SESSION_ABI_V1 && ep.struct_size==sizeof(ep));
    assert(ep.context==s && ep.backend_identity==&nv_ctl_device && ep.file_identity==s->file);
    assert(s->file->f_op==&nvidia_fops && nv_ctl_device.usage_count==1 && stack_count==1);
    assert(atomic_load(&anchor.refs)==1 && hybrid580_open_backend_file(s->file,1)); ++cases;
    NVOS21_PARAMETERS p=packet();
    assert(ep.invoke(NULL,NV_ESC_RM_ALLOC,&p,sizeof(p))==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(ep.invoke(s,NV_ESC_RM_ALLOC,NULL,sizeof(p))==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(ep.invoke(s,0xff,&p,sizeof(p))==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(ep.invoke(s,NV_ESC_RM_ALLOC,&p,sizeof(p)-1)==NV_ERR_INVALID_ARGUMENT); ++cases;
    for (int bad=0;bad<5;++bad) {
        p=packet();
        if (bad==0) p.hObjectParent=1;
        if (bad==1) p.hObjectNew=1;
        if (bad==2) p.hClass=0xdead;
        if (bad==3) p.pAllocParms=(NvP64)(uintptr_t)1;
        if (bad==4) p.paramsSize=1;
        assert(ep.invoke(s,NV_ESC_RM_ALLOC,&p,sizeof(p))==NV_ERR_INVALID_ARGUMENT); ++cases;
    }
    NVOS64_PARAMETERS q={0}; q.hClass=NV01_ROOT; q.flags=NVOS64_FLAGS_NONE;
    q.hRoot=0x1234; assert(ep.invoke(s,NV_ESC_RM_ALLOC,&q,sizeof(q))==NV_OK); ++cases;
    for (int bad=0;bad<7;++bad) {
        q=(NVOS64_PARAMETERS){0}; q.hClass=NV01_ROOT_CLIENT;
        if (bad==0) q.hObjectParent=1;
        if (bad==1) q.hObjectNew=1;
        if (bad==2) q.hClass=0xdead;
        if (bad==3) q.pAllocParms=(NvP64)(uintptr_t)1;
        if (bad==4) q.paramsSize=1;
        if (bad==5) q.pRightsRequested=(NvP64)(uintptr_t)1;
        if (bad==6) q.flags=0x80000000U;
        assert(ep.invoke(s,NV_ESC_RM_ALLOC,&q,sizeof(q))==NV_ERR_INVALID_ARGUMENT); ++cases;
    }
    NVOS00_PARAMETERS f={0};
    assert(ep.invoke(s,NV_ESC_RM_FREE,&f,sizeof(f))==NV_ERR_INVALID_ARGUMENT); ++cases;
    f.hRoot=1; f.hObjectOld=2;
    assert(ep.invoke(s,NV_ESC_RM_FREE,&f,sizeof(f))==NV_ERR_INVALID_ARGUMENT); ++cases;
    f.hObjectOld=1; f.hObjectParent=2;
    assert(ep.invoke(s,NV_ESC_RM_FREE,&f,sizeof(f))==NV_ERR_INVALID_ARGUMENT); ++cases;
    f.hObjectParent=0;
    assert(ep.invoke(s,NV_ESC_RM_FREE,&f,sizeof(f))==NV_OK); ++cases;
    for (fail_at=7;fail_at<=9;++fail_at) {
        p=packet(); int before=atomic_load(&rm_calls);
        assert(ep.invoke(s,NV_ESC_RM_ALLOC,&p,sizeof(p))==(fail_at==9?NV_ERR_NO_MEMORY:NV_ERR_OPERATING_SYSTEM));
        assert(atomic_load(&rm_calls)==before && p.status==0xffffffffU && stack_count==1 && !pm_depth && !mutex_depth); ++cases;
    }
    fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST; p=packet();
    int before=atomic_load(&rm_calls);
    assert(ep.invoke(s,NV_ESC_RM_ALLOC,&p,sizeof(p))==NV_ERR_GPU_IS_LOST);
    assert(atomic_load(&rm_calls)==before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    gpu_status=NV_OK; rm_transport=NV_ERR_INVALID_STATE; rm_payload=NV_OK; p=packet();
    assert(ep.invoke(s,NV_ESC_RM_ALLOC,&p,sizeof(p))==NV_ERR_INVALID_STATE && p.status==NV_OK); ++cases;
    rm_transport=NV_OK; rm_payload=NV_ERR_INVALID_ARGUMENT; p=packet();
    assert(ep.invoke(s,NV_ESC_RM_ALLOC,&p,sizeof(p))==NV_OK && p.status==NV_ERR_INVALID_ARGUMENT); ++cases;
    rm_payload=NV_OK; rm_write_status=0; p=packet(); p.status=NV_OK;
    assert(ep.invoke(s,NV_ESC_RM_ALLOC,&p,sizeof(p))==NV_OK && p.status==0xffffffffU); ++cases;
    q=(NVOS64_PARAMETERS){0}; q.hClass=NV01_ROOT_CLIENT; q.status=NV_OK;
    assert(ep.invoke(s,NV_ESC_RM_ALLOC,&q,sizeof(q))==NV_OK && q.status==0xffffffffU); ++cases;
    f.status=NV_OK;
    assert(ep.invoke(s,NV_ESC_RM_FREE,&f,sizeof(f))==NV_OK && f.status==0xffffffffU); ++cases;
    rm_write_status=1; p=packet(); p.hRoot=0x1234;
    assert(ep.invoke(s,NV_ESC_RM_ALLOC,&p,sizeof(p))==NV_OK && p.status==NV_OK); ++cases;
    NvU32 attach_ids[]={7,0,7};
    assert(hybrid580_open_control_session_attach_v1(s,NULL,1)==-EINVAL); ++cases;
    assert(hybrid580_open_control_session_attach_v1(s,attach_ids,0)==-EINVAL); ++cases;
    assert(hybrid580_open_control_session_attach_v1(s,attach_ids,
        NV_ABSOLUTE_MAX_IOCTL_SIZE/sizeof(NvU32)+1)==-EINVAL); ++cases;
    fail_at=7; assert(hybrid580_open_control_session_attach_v1(s,attach_ids,3)==-EINTR); fail_at=0; ++cases;
    fail_at=8; assert(hybrid580_open_control_session_attach_v1(s,attach_ids,3)==-EINTR); fail_at=0; ++cases;
    fail_at=9; assert(hybrid580_open_control_session_attach_v1(s,attach_ids,3)==-ENOMEM); fail_at=0; ++cases;
    gpu_status=NV_ERR_GPU_IS_LOST;
    assert(hybrid580_open_control_session_attach_v1(s,attach_ids,3)==-EINVAL);
    gpu_status=NV_OK; ++cases;
    assert(hybrid580_open_control_session_attach_v1(s,attach_ids,3)==0);
    nv_linux_file_private_t *attached=NV_GET_LINUX_FILE_PRIVATE(s->file);
    assert(attached->num_attached_gpus==3 && attached->attached_gpus[0]==7 &&
           attached->attached_gpus[1]==0 && attached->attached_gpus[2]==7);
    assert(gpu_get_calls==2 && gpu_refs[7]==2); ++cases;
    assert(hybrid580_open_control_session_attach_v1(s,attach_ids,3)==-EINVAL);
    assert(gpu_get_calls==2 && gpu_refs[7]==2); ++cases;

    NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS id_info={.gpuId=55};
    NvU32 control_status=0;
    int control_calls_before=rm_control_calls;
    assert(hybrid580_open_control_session_gpu_id_info_v1(NULL,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&id_info,&control_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_gpu_id_info_v1(s,0,0,NVOS54_FLAGS_NONE,
        &id_info,&control_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_gpu_id_info_v1(s,0x1234,0x4321,NVOS54_FLAGS_NONE,
        &id_info,&control_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_gpu_id_info_v1(s,0x1234,0x1234,1,
        &id_info,&control_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_gpu_id_info_v1(s,0x1234,0x1234,NVOS54_FLAGS_NONE,
        NULL,&control_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_gpu_id_info_v1(s,0x1234,0x1234,NVOS54_FLAGS_NONE,
        &id_info,NULL)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(rm_control_calls==control_calls_before); ++cases;
    assert(hybrid580_open_control_session_gpu_id_info_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&id_info,&control_status)==NV_OK);
    assert(control_status==NV_OK && rm_control_calls==control_calls_before+1);
    assert(rm_control_client==0x1234 && rm_control_object==0x1234 &&
           rm_control_cmd==NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 &&
           rm_control_flags==NVOS54_FLAGS_NONE && rm_control_size==sizeof(id_info) &&
           rm_control_gpu_id==55);
    assert(id_info.gpuId==55 && id_info.gpuFlags==0x11 && id_info.deviceInstance==0x22 &&
           id_info.subDeviceInstance==0x33 && id_info.sliStatus==0x44 &&
           id_info.boardId==0x55 && id_info.gpuInstance==0x66 && id_info.numaId==-1); ++cases;
    rm_control_status=NV_ERR_INVALID_ARGUMENT;
    assert(hybrid580_open_control_session_gpu_id_info_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&id_info,&control_status)==NV_OK);
    assert(control_status==NV_ERR_INVALID_ARGUMENT); ++cases;
    rm_control_status=NV_OK; rm_control_write_outputs=0;
    id_info=(NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS){.gpuId=55};
    assert(hybrid580_open_control_session_gpu_id_info_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&id_info,&control_status)==NV_OK);
    assert(control_status==NV_OK && id_info.gpuId==55 && id_info.gpuFlags==0xffffffffU &&
           id_info.deviceInstance==0xffffffffU && id_info.subDeviceInstance==0xffffffffU &&
           id_info.sliStatus==0xffffffffU && id_info.boardId==0xffffffffU &&
           id_info.gpuInstance==0xffffffffU && id_info.numaId==-1); ++cases;
    rm_control_write_outputs=1;
    fail_at=7; control_calls_before=rm_control_calls;
    assert(hybrid580_open_control_session_gpu_id_info_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&id_info,&control_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_control_calls==control_calls_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=8;
    assert(hybrid580_open_control_session_gpu_id_info_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&id_info,&control_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_control_calls==control_calls_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=9;
    assert(hybrid580_open_control_session_gpu_id_info_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&id_info,&control_status)==NV_ERR_NO_MEMORY);
    assert(rm_control_calls==control_calls_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST;
    assert(hybrid580_open_control_session_gpu_id_info_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&id_info,&control_status)==NV_ERR_GPU_IS_LOST);
    assert(rm_control_calls==control_calls_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    gpu_status=NV_OK;

    NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS device_ids={.deviceIds=0xdeadbeefU};
    NvU32 device_ids_status=0;
    int device_ids_calls_before=rm_device_ids_calls;
    assert(hybrid580_open_control_session_device_ids_v1(NULL,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&device_ids,&device_ids_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_device_ids_v1(s,0,0,NVOS54_FLAGS_NONE,
        &device_ids,&device_ids_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_device_ids_v1(s,0x1234,0x4321,NVOS54_FLAGS_NONE,
        &device_ids,&device_ids_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_device_ids_v1(s,0x1234,0x1234,1,
        &device_ids,&device_ids_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_device_ids_v1(s,0x1234,0x1234,NVOS54_FLAGS_NONE,
        NULL,&device_ids_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_device_ids_v1(s,0x1234,0x1234,NVOS54_FLAGS_NONE,
        &device_ids,NULL)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(rm_device_ids_calls==device_ids_calls_before); ++cases;
    rm_device_ids.deviceIds=0x80000005U;
    assert(hybrid580_open_control_session_device_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&device_ids,&device_ids_status)==NV_OK);
    assert(device_ids_status==NV_OK && device_ids.deviceIds==0x80000005U);
    assert(rm_device_ids_client==0x1234 && rm_device_ids_object==0x1234 &&
        rm_device_ids_cmd==NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS &&
        rm_device_ids_flags==NVOS54_FLAGS_NONE &&
        rm_device_ids_size==sizeof(NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS)); ++cases;
    rm_device_ids_status=NV_ERR_INVALID_ARGUMENT;
    assert(hybrid580_open_control_session_device_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&device_ids,&device_ids_status)==NV_OK);
    assert(device_ids_status==NV_ERR_INVALID_ARGUMENT && device_ids.deviceIds==0x80000005U); ++cases;
    rm_device_ids_status=NV_OK; rm_device_ids_write_outputs=0;
    device_ids.deviceIds=0xdeadbeefU;
    assert(hybrid580_open_control_session_device_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&device_ids,&device_ids_status)==NV_OK);
    assert(device_ids_status==NV_OK && device_ids.deviceIds==0); ++cases;
    rm_device_ids_write_outputs=1; fail_at=7; device_ids_calls_before=rm_device_ids_calls;
    assert(hybrid580_open_control_session_device_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&device_ids,&device_ids_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_device_ids_calls==device_ids_calls_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=8;
    assert(hybrid580_open_control_session_device_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&device_ids,&device_ids_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_device_ids_calls==device_ids_calls_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=9;
    assert(hybrid580_open_control_session_device_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&device_ids,&device_ids_status)==NV_ERR_NO_MEMORY);
    assert(rm_device_ids_calls==device_ids_calls_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST;
    assert(hybrid580_open_control_session_device_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&device_ids,&device_ids_status)==NV_ERR_GPU_IS_LOST);
    assert(rm_device_ids_calls==device_ids_calls_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    gpu_status=NV_OK;

    NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS probed_ids={0};
    NvU32 probed_status=0;
    int probed_calls_before=rm_probed_calls;
    assert(hybrid580_open_control_session_probed_ids_v1(NULL,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&probed_ids,&probed_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_probed_ids_v1(s,0,0,NVOS54_FLAGS_NONE,
        &probed_ids,&probed_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_probed_ids_v1(s,0x1234,0x4321,NVOS54_FLAGS_NONE,
        &probed_ids,&probed_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_probed_ids_v1(s,0x1234,0x1234,1,
        &probed_ids,&probed_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_probed_ids_v1(s,0x1234,0x1234,NVOS54_FLAGS_NONE,
        NULL,&probed_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_probed_ids_v1(s,0x1234,0x1234,NVOS54_FLAGS_NONE,
        &probed_ids,NULL)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(rm_probed_calls==probed_calls_before); ++cases;
    memset(&rm_probed_ids,0xff,sizeof(rm_probed_ids));
    rm_probed_ids.gpuIds[0]=5; rm_probed_ids.excludedGpuIds[0]=7;
    rm_probed_ids.gpuFlags[0]=NV0000_CTRL_GPU_PROBED_ID_FLAGS_SOC_DISPLAY_TRUE;
    assert(hybrid580_open_control_session_probed_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&probed_ids,&probed_status)==NV_OK);
    assert(probed_status==NV_OK && probed_ids.gpuIds[0]==5 &&
        probed_ids.excludedGpuIds[0]==7 && probed_ids.gpuFlags[0]==1);
    assert(rm_probed_client==0x1234 && rm_probed_object==0x1234 &&
        rm_probed_cmd==NV0000_CTRL_CMD_GPU_GET_PROBED_IDS &&
        rm_probed_flags==NVOS54_FLAGS_NONE &&
        rm_probed_size==sizeof(NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS)); ++cases;
    rm_probed_status=NV_ERR_INVALID_ARGUMENT;
    assert(hybrid580_open_control_session_probed_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&probed_ids,&probed_status)==NV_OK);
    assert(probed_status==NV_ERR_INVALID_ARGUMENT && probed_ids.gpuIds[0]==5); ++cases;
    rm_probed_status=NV_OK; rm_probed_write_outputs=0;
    memset(&probed_ids,0,sizeof(probed_ids));
    assert(hybrid580_open_control_session_probed_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&probed_ids,&probed_status)==NV_OK);
    for (unsigned int i=0;i<NV0000_CTRL_GPU_MAX_PROBED_GPUS;i++) {
        assert(probed_ids.gpuIds[i]==NV0000_CTRL_GPU_INVALID_ID);
        assert(probed_ids.excludedGpuIds[i]==NV0000_CTRL_GPU_INVALID_ID);
        assert(probed_ids.gpuFlags[i]==0xffffffffU);
    }
    ++cases;
    rm_probed_write_outputs=1; fail_at=7; probed_calls_before=rm_probed_calls;
    assert(hybrid580_open_control_session_probed_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&probed_ids,&probed_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_probed_calls==probed_calls_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=8;
    assert(hybrid580_open_control_session_probed_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&probed_ids,&probed_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_probed_calls==probed_calls_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=9;
    assert(hybrid580_open_control_session_probed_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&probed_ids,&probed_status)==NV_ERR_NO_MEMORY);
    assert(rm_probed_calls==probed_calls_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST;
    assert(hybrid580_open_control_session_probed_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&probed_ids,&probed_status)==NV_ERR_GPU_IS_LOST);
    assert(rm_probed_calls==probed_calls_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    gpu_status=NV_OK;

    NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS attached_ids={0};
    NvU32 attached_status=0;
    int attached_calls_before=rm_attached_calls;
    assert(hybrid580_open_control_session_attached_ids_v1(NULL,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&attached_ids,&attached_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_attached_ids_v1(s,0,0,NVOS54_FLAGS_NONE,
        &attached_ids,&attached_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_attached_ids_v1(s,0x1234,0x4321,NVOS54_FLAGS_NONE,
        &attached_ids,&attached_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_attached_ids_v1(s,0x1234,0x1234,1,
        &attached_ids,&attached_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_attached_ids_v1(s,0x1234,0x1234,NVOS54_FLAGS_NONE,
        NULL,&attached_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_attached_ids_v1(s,0x1234,0x1234,NVOS54_FLAGS_NONE,
        &attached_ids,NULL)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(rm_attached_calls==attached_calls_before); ++cases;
    for (unsigned int i=0;i<NV0000_CTRL_GPU_MAX_ATTACHED_GPUS;i++)
        rm_attached_ids[i]=NV0000_CTRL_GPU_INVALID_ID;
    rm_attached_ids[0]=7; rm_attached_ids[1]=11;
    assert(hybrid580_open_control_session_attached_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&attached_ids,&attached_status)==NV_OK);
    assert(attached_status==NV_OK && attached_ids.gpuIds[0]==7 &&
           attached_ids.gpuIds[1]==11 && attached_ids.gpuIds[2]==NV0000_CTRL_GPU_INVALID_ID); ++cases;
    rm_attached_status=NV_ERR_INVALID_ARGUMENT;
    assert(hybrid580_open_control_session_attached_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&attached_ids,&attached_status)==NV_OK);
    assert(attached_status==NV_ERR_INVALID_ARGUMENT && attached_ids.gpuIds[0]==7); ++cases;
    rm_attached_status=NV_OK; rm_attached_write_outputs=0;
    memset(&attached_ids,0,sizeof(attached_ids));
    assert(hybrid580_open_control_session_attached_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&attached_ids,&attached_status)==NV_OK);
    for (unsigned int i=0;i<NV0000_CTRL_GPU_MAX_ATTACHED_GPUS;i++) {
        assert(attached_ids.gpuIds[i]==NV0000_CTRL_GPU_INVALID_ID);
    }
    ++cases;
    rm_attached_write_outputs=1; fail_at=7; attached_calls_before=rm_attached_calls;
    assert(hybrid580_open_control_session_attached_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&attached_ids,&attached_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_attached_calls==attached_calls_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=8;
    assert(hybrid580_open_control_session_attached_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&attached_ids,&attached_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_attached_calls==attached_calls_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=9;
    assert(hybrid580_open_control_session_attached_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&attached_ids,&attached_status)==NV_ERR_NO_MEMORY);
    assert(rm_attached_calls==attached_calls_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST;
    assert(hybrid580_open_control_session_attached_ids_v1(s,0x1234,0x1234,
        NVOS54_FLAGS_NONE,&attached_ids,&attached_status)==NV_ERR_GPU_IS_LOST);
    assert(rm_attached_calls==attached_calls_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    gpu_status=NV_OK;

    NV00DE_ALLOC_PARAMETERS rusd={.polledDataMask=0xfedcba9876543210ULL};
    NvHandle rusd_returned=0; NvU32 rusd_status=0;
    int rusd_before=rm_rusd_alloc_calls;
    assert(hybrid580_open_control_session_rusd_alloc_v1(NULL,0x1234,0x5678,
        0x2390,&rusd,&rusd_returned,&rusd_status)==NV_ERR_INVALID_ARGUMENT);
    assert(rusd_status==NV_ERR_INVALID_ARGUMENT && rusd_returned==0); ++cases;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0,0x5678,
        0x2390,&rusd,&rusd_returned,&rusd_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0x1234,0,
        0x2390,&rusd,&rusd_returned,&rusd_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0x1234,0x5678,
        0x1234,&rusd,&rusd_returned,&rusd_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0x1234,0x5678,
        0x5678,&rusd,&rusd_returned,&rusd_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0x1234,0x5678,
        0x2390,NULL,&rusd_returned,&rusd_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0x1234,0x5678,
        0x2390,&rusd,NULL,&rusd_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0x1234,0x5678,
        0x2390,&rusd,&rusd_returned,NULL)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(rm_rusd_alloc_calls==rusd_before); ++cases;
    rusd_returned=0; rusd_status=0; rm_payload=NV_OK;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0x1234,0x5678,
        0x2390,&rusd,&rusd_returned,&rusd_status)==NV_OK);
    assert(rusd_status==NV_OK && rusd_returned==0x2390 &&
        rm_rusd_alloc_calls==rusd_before+1 && rm_rusd_alloc_root==0x1234 &&
        rm_rusd_alloc_parent==0x5678 && rm_rusd_alloc_handle==0x2390 &&
        rm_rusd_alloc_class==RM_USER_SHARED_DATA &&
        rm_rusd_alloc_size==sizeof(rusd) &&
        rm_rusd_alloc_input.polledDataMask==0xfedcba9876543210ULL); ++cases;
    rm_payload=NV_ERR_INVALID_ARGUMENT; rusd_returned=0; rusd_status=0;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0x1234,0x5678,
        0x2391,&rusd,&rusd_returned,&rusd_status)==NV_OK);
    assert(rusd_status==NV_ERR_INVALID_ARGUMENT && rusd_returned==0x2391); ++cases;
    rm_payload=NV_OK; rm_rusd_return_override=0xbeef;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0x1234,0x5678,
        0x2392,&rusd,&rusd_returned,&rusd_status)==NV_OK && rusd_returned==0xbeef); ++cases;
    rm_rusd_return_override=0; fail_at=7; rusd_before=rm_rusd_alloc_calls;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0x1234,0x5678,
        0x2393,&rusd,&rusd_returned,&rusd_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_rusd_alloc_calls==rusd_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=8;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0x1234,0x5678,
        0x2393,&rusd,&rusd_returned,&rusd_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_rusd_alloc_calls==rusd_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=9;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0x1234,0x5678,
        0x2393,&rusd,&rusd_returned,&rusd_status)==NV_ERR_NO_MEMORY);
    assert(rm_rusd_alloc_calls==rusd_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST;
    assert(hybrid580_open_control_session_rusd_alloc_v1(s,0x1234,0x5678,
        0x2393,&rusd,&rusd_returned,&rusd_status)==NV_ERR_GPU_IS_LOST);
    assert(rm_rusd_alloc_calls==rusd_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    gpu_status=NV_OK;

    NV_MEMORY_ALLOCATION_PARAMS memory={.owner=3,.type=4,.pitch=8,.size=0x800,
        .address=(NvP64)(uintptr_t)0x111000,.hVASpace=0};
    NvHandle memory_returned=0; NvU32 memory_status=0;
    int memory_alloc_before=rm_memory_alloc_calls;
    assert(hybrid580_open_control_session_memory_alloc_v1(NULL,0x1234,0x5678,0x2345,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,&memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0,0x5678,0x2345,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,&memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0,0x2345,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,&memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,&memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x1234,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,&memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x5678,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,&memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x2345,
        0xdead,&memory,&memory_returned,&memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x2345,
        NV01_MEMORY_SYSTEM,NULL,&memory_returned,&memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x2345,
        NV01_MEMORY_SYSTEM,&memory,NULL,&memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x2345,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,NULL)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(rm_memory_alloc_calls==memory_alloc_before &&
        memory_status==NV_ERR_INVALID_ARGUMENT); ++cases;
    memory_returned=0; memory_status=0;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x2345,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,&memory_status)==NV_OK);
    assert(memory_status==NV_OK && memory_returned==0x2345 && memory.size==0x4000 &&
        NvP64_VALUE(memory.address)==(void *)(uintptr_t)0xabc000 && memory.pitch==64 &&
        memory.zcullCovg==0x55);
    assert(rm_memory_alloc_calls==memory_alloc_before+1 && rm_memory_alloc_root==0x1234 &&
        rm_memory_alloc_parent==0x5678 && rm_memory_alloc_handle==0x2345 &&
        rm_memory_alloc_class==NV01_MEMORY_SYSTEM &&
        rm_memory_alloc_size==sizeof(NV_MEMORY_ALLOCATION_PARAMS) &&
        rm_memory_alloc_input.owner==3 && rm_memory_alloc_input.type==4 &&
        rm_memory_alloc_input.size==0x800 && rm_memory_alloc_input.pitch==8 &&
        NvP64_VALUE(rm_memory_alloc_input.address)==(void *)(uintptr_t)0x111000); ++cases;
    rm_payload=NV_ERR_INVALID_ARGUMENT; memory_returned=0; memory_status=0;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x2346,
        NV01_MEMORY_LOCAL_USER,&memory,&memory_returned,&memory_status)==NV_OK);
    assert(memory_status==NV_ERR_INVALID_ARGUMENT && memory_returned==0x2346 &&
        rm_memory_alloc_class==NV01_MEMORY_LOCAL_USER); ++cases;
    rm_payload=NV_OK; rm_memory_write_outputs=0;
    memory=(NV_MEMORY_ALLOCATION_PARAMS){.owner=9,.pitch=12,.size=0x900,
        .address=(NvP64)(uintptr_t)0x222000};
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x2347,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,&memory_status)==NV_OK);
    assert(memory.size==0x900 && memory.pitch==12 &&
        NvP64_VALUE(memory.address)==(void *)(uintptr_t)0x222000); ++cases;
    rm_memory_write_outputs=1; rm_memory_return_override=0xbeef;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x2348,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,&memory_status)==NV_OK);
    assert(memory_returned==0xbeef); ++cases;
    rm_memory_return_override=0; fail_at=7; memory_alloc_before=rm_memory_alloc_calls;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x2349,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,&memory_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_memory_alloc_calls==memory_alloc_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=8;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x2349,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,&memory_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_memory_alloc_calls==memory_alloc_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=9;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x2349,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,&memory_status)==NV_ERR_NO_MEMORY);
    assert(rm_memory_alloc_calls==memory_alloc_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST;
    assert(hybrid580_open_control_session_memory_alloc_v1(s,0x1234,0x5678,0x2349,
        NV01_MEMORY_SYSTEM,&memory,&memory_returned,&memory_status)==NV_ERR_GPU_IS_LOST);
    assert(rm_memory_alloc_calls==memory_alloc_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    gpu_status=NV_OK;

    NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS group={
        .hVASpace=0x3333, .engineType=1,
        .bIsCallingContextVgpuPlugin=NV_FALSE};
    NvHandle group_returned=0; NvU32 group_status=0;
    int group_before=rm_channel_group_alloc_calls;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(NULL,0x1234,0x5678,
        0x2340,&group,&group_returned,&group_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0,0x5678,
        0x2340,&group,&group_returned,&group_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0,
        0x2340,&group,&group_returned,&group_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0,&group,&group_returned,&group_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x1234,&group,&group_returned,&group_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x5678,&group,&group_returned,&group_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x2340,NULL,&group_returned,&group_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x2340,&group,NULL,&group_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x2340,&group,&group_returned,NULL)==NV_ERR_INVALID_ARGUMENT); ++cases;
    NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS invalid_group=group; invalid_group.hVASpace=0;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x2340,&invalid_group,&group_returned,&group_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    invalid_group=group; invalid_group.bIsCallingContextVgpuPlugin=NV_TRUE;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x2340,&invalid_group,&group_returned,&group_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(rm_channel_group_alloc_calls==group_before); ++cases;
    group_returned=0; group_status=0;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x2340,&group,&group_returned,&group_status)==NV_OK);
    assert(group_returned==0x2340 && group_status==NV_OK &&
        rm_channel_group_alloc_calls==group_before+1 && rm_channel_group_alloc_root==0x1234 &&
        rm_channel_group_alloc_parent==0x5678 && rm_channel_group_alloc_handle==0x2340 &&
        rm_channel_group_alloc_class==KEPLER_CHANNEL_GROUP_A &&
        rm_channel_group_alloc_size==sizeof(group) && rm_channel_group_alloc_input.hVASpace==0x3333 &&
        rm_channel_group_alloc_input.engineType==1); ++cases;
    rm_payload=NV_ERR_INVALID_STATE;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x2341,&group,&group_returned,&group_status)==NV_OK &&
        group_status==NV_ERR_INVALID_STATE && group_returned==0x2341); ++cases;
    rm_payload=NV_OK; rm_channel_group_return_override=0xbeef;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x2342,&group,&group_returned,&group_status)==NV_OK && group_returned==0xbeef); ++cases;
    rm_channel_group_return_override=0; fail_at=7; group_before=rm_channel_group_alloc_calls;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x2343,&group,&group_returned,&group_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_channel_group_alloc_calls==group_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=8;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x2343,&group,&group_returned,&group_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_channel_group_alloc_calls==group_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=9;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x2343,&group,&group_returned,&group_status)==NV_ERR_NO_MEMORY);
    assert(rm_channel_group_alloc_calls==group_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST;
    assert(hybrid580_open_control_session_channel_group_alloc_v1(s,0x1234,0x5678,
        0x2343,&group,&group_returned,&group_status)==NV_ERR_GPU_IS_LOST);
    assert(rm_channel_group_alloc_calls==group_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    gpu_status=NV_OK;

    NV_CTXSHARE_ALLOCATION_PARAMETERS context_share={.hVASpace=0x3333,
        .flags=NV_CTXSHARE_ALLOCATION_FLAGS_SUBCONTEXT_SPECIFIED,.subctxId=0x17};
    NvHandle context_share_returned=0; NvU32 context_share_status=0;
    int context_share_before=rm_context_share_alloc_calls;
    assert(hybrid580_open_control_session_context_share_alloc_v1(NULL,0x1234,0x2340,
        0x2344,&context_share,&context_share_returned,&context_share_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0,0x2340,
        0x2344,&context_share,&context_share_returned,&context_share_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0,
        0x2344,&context_share,&context_share_returned,&context_share_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0,&context_share,&context_share_returned,&context_share_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x1234,&context_share,&context_share_returned,&context_share_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2340,&context_share,&context_share_returned,&context_share_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2344,NULL,&context_share_returned,&context_share_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2344,&context_share,NULL,&context_share_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2344,&context_share,&context_share_returned,NULL)==NV_ERR_INVALID_ARGUMENT); ++cases;
    NV_CTXSHARE_ALLOCATION_PARAMETERS invalid_context_share=context_share;
    invalid_context_share.hVASpace=0;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2344,&invalid_context_share,&context_share_returned,&context_share_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    invalid_context_share=context_share; invalid_context_share.flags=4;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2344,&invalid_context_share,&context_share_returned,&context_share_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    invalid_context_share=context_share; invalid_context_share.subctxId=0x80000001U;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2344,&invalid_context_share,&context_share_returned,&context_share_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    invalid_context_share=context_share; invalid_context_share.flags=NV_CTXSHARE_ALLOCATION_FLAGS_SUBCONTEXT_ASYNC;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2344,&invalid_context_share,&context_share_returned,&context_share_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(rm_context_share_alloc_calls==context_share_before); ++cases;
    context_share_returned=0; context_share_status=0;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2344,&context_share,&context_share_returned,&context_share_status)==NV_OK);
    assert(context_share_returned==0x2344 && context_share_status==NV_OK && context_share.subctxId==0x1b &&
        rm_context_share_alloc_calls==context_share_before+1 && rm_context_share_alloc_root==0x1234 &&
        rm_context_share_alloc_parent==0x2340 && rm_context_share_alloc_handle==0x2344 &&
        rm_context_share_alloc_class==FERMI_CONTEXT_SHARE_A &&
        rm_context_share_alloc_size==sizeof(context_share) &&
        rm_context_share_alloc_input.hVASpace==0x3333 &&
        rm_context_share_alloc_input.flags==NV_CTXSHARE_ALLOCATION_FLAGS_SUBCONTEXT_SPECIFIED &&
        rm_context_share_alloc_input.subctxId==0x17); ++cases;
    rm_payload=NV_ERR_INVALID_STATE;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2345,&context_share,&context_share_returned,&context_share_status)==NV_OK &&
        context_share_status==NV_ERR_INVALID_STATE && context_share_returned==0x2345); ++cases;
    rm_payload=NV_OK; rm_context_share_return_override=0xbeef;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2346,&context_share,&context_share_returned,&context_share_status)==NV_OK &&
        context_share_returned==0xbeef); ++cases;
    rm_context_share_return_override=0; fail_at=7; context_share_before=rm_context_share_alloc_calls;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2347,&context_share,&context_share_returned,&context_share_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_context_share_alloc_calls==context_share_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=8;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2347,&context_share,&context_share_returned,&context_share_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_context_share_alloc_calls==context_share_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=9;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2347,&context_share,&context_share_returned,&context_share_status)==NV_ERR_NO_MEMORY);
    assert(rm_context_share_alloc_calls==context_share_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST;
    assert(hybrid580_open_control_session_context_share_alloc_v1(s,0x1234,0x2340,
        0x2347,&context_share,&context_share_returned,&context_share_status)==NV_ERR_GPU_IS_LOST);
    assert(rm_context_share_alloc_calls==context_share_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    gpu_status=NV_OK;

    NV_CHANNEL_ALLOC_PARAMS channel={.flags=NVOS04_FLAGS_CHANNEL_TYPE_PHYSICAL,
        .gpFifoOffset=0x4000};
    NvHandle channel_returned=0; NvU32 channel_status=0;
    int channel_before=rm_channel_alloc_calls;
#ifdef HYBRID_LEGACY
    const NvU32 wrong_channel_class=BLACKWELL_CHANNEL_GPFIFO_A;
#else
    const NvU32 wrong_channel_class=VOLTA_CHANNEL_GPFIFO_A;
#endif
    assert(hybrid580_open_control_session_channel_alloc_v1(s,0x1234,0x2340,
        0x2380,wrong_channel_class,&channel,&channel_returned,&channel_status)==
        NV_ERR_INVALID_CLASS && channel_status==NV_ERR_INVALID_CLASS); ++cases;
    channel.hVASpace=0x3333;
    assert(hybrid580_open_control_session_channel_alloc_v1(s,0x1234,0x2340,
        0x2380,TEST_CHANNEL_CLASS,&channel,&channel_returned,&channel_status)==
        NV_ERR_INVALID_ARGUMENT); ++cases;
    channel.hVASpace=0;
    assert(rm_channel_alloc_calls==channel_before); ++cases;
    channel_returned=0; channel_status=0;
    assert(hybrid580_open_control_session_channel_alloc_v1(s,0x1234,0x2340,
        0x2380,TEST_CHANNEL_CLASS,&channel,&channel_returned,&channel_status)==NV_OK);
    assert(channel_status==NV_OK && channel_returned==0x2380 &&
        rm_channel_alloc_calls==channel_before+1 && rm_channel_alloc_root==0x1234 &&
        rm_channel_alloc_parent==0x2340 && rm_channel_alloc_handle==0x2380 &&
        rm_channel_alloc_class==TEST_CHANNEL_CLASS &&
        rm_channel_alloc_size==sizeof(channel) &&
        rm_channel_alloc_input.gpFifoOffset==0x4000); ++cases;
    rm_payload=NV_ERR_INVALID_STATE;
    assert(hybrid580_open_control_session_channel_alloc_v1(s,0x1234,0x2340,
        0x2381,TEST_CHANNEL_CLASS,&channel,&channel_returned,&channel_status)==NV_OK &&
        channel_status==NV_ERR_INVALID_STATE && channel_returned==0x2381); ++cases;
    rm_payload=NV_OK; fail_at=7; channel_before=rm_channel_alloc_calls;
    assert(hybrid580_open_control_session_channel_alloc_v1(s,0x1234,0x2340,
        0x2382,TEST_CHANNEL_CLASS,&channel,&channel_returned,&channel_status)==
        NV_ERR_OPERATING_SYSTEM);
    assert(rm_channel_alloc_calls==channel_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=8;
    assert(hybrid580_open_control_session_channel_alloc_v1(s,0x1234,0x2340,
        0x2382,TEST_CHANNEL_CLASS,&channel,&channel_returned,&channel_status)==
        NV_ERR_OPERATING_SYSTEM);
    assert(rm_channel_alloc_calls==channel_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=9;
    assert(hybrid580_open_control_session_channel_alloc_v1(s,0x1234,0x2340,
        0x2382,TEST_CHANNEL_CLASS,&channel,&channel_returned,&channel_status)==
        NV_ERR_NO_MEMORY);
    assert(rm_channel_alloc_calls==channel_before && stack_count==1 &&
        !mutex_depth && !pm_depth); ++cases;
    fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST;
    assert(hybrid580_open_control_session_channel_alloc_v1(s,0x1234,0x2340,
        0x2382,TEST_CHANNEL_CLASS,&channel,&channel_returned,&channel_status)==
        NV_ERR_GPU_IS_LOST);
    assert(rm_channel_alloc_calls==channel_before && stack_count==1 &&
        !mutex_depth && !pm_depth); ++cases;
    gpu_status=NV_OK;

    NV_VASPACE_ALLOCATION_PARAMETERS vaspace={
        .index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW,
        .flags=NV_VASPACE_ALLOCATION_FLAGS_ENABLE_PAGE_FAULTING,
        .bigPageSize=NV_VASPACE_BIG_PAGE_SIZE_64K,
        .vaSize=0x400000000ULL};
    NvHandle vaspace_returned=0; NvU32 vaspace_status=0;
    int vaspace_before=rm_vaspace_alloc_calls;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(NULL,0x1234,0x5678,
        0x2350,&vaspace,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0,0x5678,
        0x2350,&vaspace,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0,
        0x2350,&vaspace,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0,&vaspace,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x1234,&vaspace,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x5678,&vaspace,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2350,NULL,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2350,&vaspace,NULL,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2350,&vaspace,&vaspace_returned,NULL)==NV_ERR_INVALID_ARGUMENT); ++cases;
    NV_VASPACE_ALLOCATION_PARAMETERS invalid_va=vaspace;
    invalid_va.index=NV_VASPACE_ALLOCATION_INDEX_GPU_MAX;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2350,&invalid_va,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    invalid_va=vaspace; invalid_va.flags=NV_VASPACE_ALLOCATION_FLAGS_SHARED_MANAGEMENT;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2350,&invalid_va,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    invalid_va=vaspace; invalid_va.flags=NV_VASPACE_ALLOCATION_FLAGS_IS_EXTERNALLY_OWNED;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2350,&invalid_va,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    invalid_va=vaspace; invalid_va.flags=NV_VASPACE_ALLOCATION_FLAGS_VA_INTERNAL_LIMIT;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2350,&invalid_va,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    invalid_va=vaspace; invalid_va.flags=NV_VASPACE_ALLOCATION_FLAGS_ENABLE_NVLINK_ATS_TEST;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2350,&invalid_va,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    invalid_va=vaspace; invalid_va.vaStartInternal=0x1000;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2350,&invalid_va,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    invalid_va=vaspace; invalid_va.vaLimitInternal=0x1000;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2350,&invalid_va,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    invalid_va=vaspace; invalid_va.pasid=1;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2350,&invalid_va,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    invalid_va=vaspace; invalid_va.bigPageSize=12345;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2350,&invalid_va,&vaspace_returned,&vaspace_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(rm_vaspace_alloc_calls==vaspace_before); ++cases;
    vaspace_returned=0; vaspace_status=0;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2350,&vaspace,&vaspace_returned,&vaspace_status)==NV_OK);
    assert(vaspace_status==NV_OK && vaspace_returned==0x2350 &&
        vaspace.vaBase==0x20000 && vaspace.vaSize==0x200000000ULL);
    assert(rm_vaspace_alloc_calls==vaspace_before+1 &&
        rm_vaspace_alloc_root==0x1234 && rm_vaspace_alloc_parent==0x5678 &&
        rm_vaspace_alloc_handle==0x2350 && rm_vaspace_alloc_class==FERMI_VASPACE_A &&
        rm_vaspace_alloc_size==sizeof(vaspace) &&
        rm_vaspace_alloc_input.index==NV_VASPACE_ALLOCATION_INDEX_GPU_NEW &&
        rm_vaspace_alloc_input.flags==NV_VASPACE_ALLOCATION_FLAGS_ENABLE_PAGE_FAULTING &&
        rm_vaspace_alloc_input.vaSize==0x400000000ULL); ++cases;
    rm_payload=NV_ERR_INVALID_STATE; vaspace_returned=0; vaspace_status=0;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2351,&vaspace,&vaspace_returned,&vaspace_status)==NV_OK);
    assert(vaspace_status==NV_ERR_INVALID_STATE && vaspace_returned==0x2351); ++cases;
    rm_payload=NV_OK; rm_vaspace_return_override=0xbeef;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2352,&vaspace,&vaspace_returned,&vaspace_status)==NV_OK && vaspace_returned==0xbeef); ++cases;
    rm_vaspace_return_override=0; fail_at=7; vaspace_before=rm_vaspace_alloc_calls;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2353,&vaspace,&vaspace_returned,&vaspace_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_vaspace_alloc_calls==vaspace_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=8;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2353,&vaspace,&vaspace_returned,&vaspace_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_vaspace_alloc_calls==vaspace_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=9;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2353,&vaspace,&vaspace_returned,&vaspace_status)==NV_ERR_NO_MEMORY);
    assert(rm_vaspace_alloc_calls==vaspace_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST;
    assert(hybrid580_open_control_session_vaspace_alloc_v1(s,0x1234,0x5678,
        0x2353,&vaspace,&vaspace_returned,&vaspace_status)==NV_ERR_GPU_IS_LOST);
    assert(rm_vaspace_alloc_calls==vaspace_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    gpu_status=NV_OK;

    int memory_free_before=rm_memory_free_calls; rm_capture_memory_free=1;
    assert(hybrid580_open_control_session_object_free_v1(NULL,0x1234,0x5678,0x2345,
        &memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_object_free_v1(s,0,0x5678,0x2345,
        &memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_object_free_v1(s,0x1234,0,0x2345,
        &memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_object_free_v1(s,0x1234,0x5678,0,
        &memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_object_free_v1(s,0x1234,0x5678,0x1234,
        &memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_object_free_v1(s,0x1234,0x5678,0x5678,
        &memory_status)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(hybrid580_open_control_session_object_free_v1(s,0x1234,0x5678,0x2345,
        NULL)==NV_ERR_INVALID_ARGUMENT); ++cases;
    assert(rm_memory_free_calls==memory_free_before); ++cases;
    rm_payload=NV_ERR_INVALID_STATE; memory_status=0;
    assert(hybrid580_open_control_session_object_free_v1(s,0x1234,0x5678,0x2345,
        &memory_status)==NV_OK);
    assert(memory_status==NV_ERR_INVALID_STATE && rm_memory_free_calls==memory_free_before+1 &&
        rm_memory_free_root==0x1234 && rm_memory_free_parent==0x5678 &&
        rm_memory_free_handle==0x2345); ++cases;
    rm_payload=NV_OK; fail_at=7; memory_free_before=rm_memory_free_calls;
    assert(hybrid580_open_control_session_object_free_v1(s,0x1234,0x5678,0x2345,
        &memory_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_memory_free_calls==memory_free_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=8;
    assert(hybrid580_open_control_session_object_free_v1(s,0x1234,0x5678,0x2345,
        &memory_status)==NV_ERR_OPERATING_SYSTEM);
    assert(rm_memory_free_calls==memory_free_before && !mutex_depth && !pm_depth); ++cases;
    fail_at=9;
    assert(hybrid580_open_control_session_object_free_v1(s,0x1234,0x5678,0x2345,
        &memory_status)==NV_ERR_NO_MEMORY);
    assert(rm_memory_free_calls==memory_free_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    fail_at=0; gpu_status=NV_ERR_GPU_IS_LOST;
    assert(hybrid580_open_control_session_object_free_v1(s,0x1234,0x5678,0x2345,
        &memory_status)==NV_ERR_GPU_IS_LOST);
    assert(rm_memory_free_calls==memory_free_before && stack_count==1 && !mutex_depth && !pm_depth); ++cases;
    gpu_status=NV_OK; rm_capture_memory_free=0;

    struct hybrid580_control_session *s2=NULL;
    struct hybrid_rm_session_endpoint_v1 ep2;
    assert(hybrid580_open_control_session_create_v1(&anchor,&s2,&ep2)==0 && s2); ++cases;
    NvU32 failing_ids[]={7,0,99}; fail_gpu_id=99;
    assert(hybrid580_open_control_session_attach_v1(s2,failing_ids,3)==-EINVAL);
    nv_linux_file_private_t *failed=NV_GET_LINUX_FILE_PRIVATE(s2->file);
    assert(failed->num_attached_gpus==0 && failed->attached_gpus==NULL);
    assert(gpu_refs[7]==2 && gpu_put_calls==1); ++cases;
    fail_gpu_id=-1; fail_attach_alloc=1;
    NvU32 retry_ids[]={9};
    assert(hybrid580_open_control_session_attach_v1(s2,retry_ids,1)==-ENOMEM);
    assert(failed->num_attached_gpus==0 && failed->attached_gpus==NULL);
    fail_attach_alloc=0; assert(hybrid580_open_control_session_attach_v1(s2,retry_ids,1)==0);
    assert(gpu_refs[9]==1); ++cases;
    hybrid580_open_control_session_put_v1(s2);
    assert(gpu_refs[9]==0 && gpu_put_calls==2); ++cases;
    nv_linux_file_private_t *saved=s->file->private_data; s->file->private_data=NULL;
    assert(ep.invoke(s,NV_ESC_RM_ALLOC,&p,sizeof(p))==NV_ERR_INVALID_STATE);
    s->file->private_data=saved; ++cases;
    hybrid580_open_control_session_get_v1(s);
    struct file *back=hybrid580_open_control_session_file_v1(s);
    assert(back==s->file && atomic_load(&back->refs)==2); ++cases;
    hybrid580_open_control_session_put_v1(s); assert(stack_count==1); ++cases;
    thread_ep=ep; atomic_store(&rm_block,1);
    int attempts=atomic_load(&mutex_attempts);
    pthread_t first,second; pthread_create(&first,NULL,invoke_thread,NULL);
    while (!atomic_load(&rm_entered)) sched_yield();
    pthread_create(&second,NULL,invoke_thread,NULL);
    while (atomic_load(&mutex_attempts)<attempts+2) sched_yield();
    /* file callback must remain nonblocking while invoke holds mutex/PM. */
    struct file *atomic_back=hybrid580_open_control_session_file_v1(s);
    assert(atomic_back==back); fput(atomic_back);
    atomic_store(&rm_release,1); pthread_join(first,NULL); pthread_join(second,NULL);
    assert(atomic_load(&rm_max_active)==1 && atomic_load(&rm_active)==0); ++cases;
    int clean=cleanup_calls;
    hybrid580_open_control_session_put_v1(s);
    assert(cleanup_calls==clean && allocations==0 && stack_count==1); ++cases;
    fput(back); assert(cleanup_calls==clean+1); balanced(); ++cases;
    hybrid580_open_control_session_get_v1(NULL); hybrid580_open_control_session_put_v1(NULL);
    assert(hybrid580_open_control_session_file_v1(NULL)==NULL); ++cases;
    printf("control-session CPU scenarios: %u; mutex serialized two invocations\n",cases);
    return 0;
}
'''
