# SPDX-License-Identifier: MIT
"""Contract for the typed, kernel-owned GPU_GET_DEVICE_IDS bridge."""
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
OPEN_PATCH = ROOT / 'patches/r580.178.04/0019-private-open-device-ids.patch'
LEGACY_PATCH = ROOT / 'patches/r580.178.04/proprietary/0017-private-legacy-device-ids.patch'
API = ROOT / 'src/hybrid580-control-session.h'
OPEN_BUILDER = ROOT / 'tools/probe_private_backend_chardev.py'
LEGACY_BUILDER = ROOT / 'tools/build_private_proprietary580.py'
FRONTEND_BUILDER = ROOT / 'tools/build_hybrid_frontend.py'


class BackendDeviceIdsApiTests(unittest.TestCase):
    def test_project_api_has_exact_typed_entrypoints(self):
        header = API.read_text()
        self.assertIn('hybrid580_open_control_session_device_ids_v1', header)
        self.assertIn('NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS *params', header)
        legacy_builder = LEGACY_BUILDER.read_text()
        self.assertIn("CONTROL_SESSION_HEADER.read_bytes().replace(", legacy_builder)
        self.assertIn("b'hybrid580_open', b'hybrid580_legacy'", legacy_builder)
        self.assertIn('control_session_device_ids_v1', FRONTEND_BUILDER.read_text())

    def test_device_object_api_is_typed_kernel_owned_and_paired_alloc_free(self):
        header = API.read_text()
        self.assertIn('hybrid580_open_control_session_device_alloc_v1', header)
        self.assertIn('hybrid580_open_control_session_device_free_v1', header)
        self.assertIn('NV0080_ALLOC_PARAMETERS *params', header)
        self.assertIn('#include <class/cl0080.h>', header)
        open_patch = (ROOT / 'patches/r580.178.04/0020-private-open-device-object.patch').read_text()
        legacy_patch = (ROOT / 'patches/r580.178.04/proprietary/0018-private-legacy-device-object.patch').read_text()
        for patch, prefix, operation in (
                (open_patch, 'hybrid580_open', 'rm_kernel_rmapi_op(sp, &ops)'),
                (legacy_patch, 'hybrid580_legacy', 'rm_ioctl(sp, nv, &nvlfp->nvfp')):
            self.assertIn(prefix + '_control_session_device_alloc_v1', patch)
            self.assertIn(prefix + '_control_session_device_free_v1', patch)
            self.assertIn('NV01_DEVICE_0', patch)
            self.assertIn('NV0080_ALLOC_PARAMETERS', patch)
            self.assertIn(operation, patch)
            self.assertIn('paramsSize = sizeof(*params)', patch)
            self.assertNotIn('NV_COPY_FROM_USER', patch)
            self.assertNotIn('NV_COPY_TO_USER', patch)
        self.assertIn('0020-private-open-device-object.patch', OPEN_BUILDER.read_text())
        self.assertIn('0018-private-legacy-device-object.patch', LEGACY_BUILDER.read_text())

    def test_memory_object_api_is_allowlisted_typed_and_parent_bound(self):
        header = API.read_text()
        self.assertIn('hybrid580_open_control_session_memory_alloc_v1', header)
        self.assertIn('hybrid580_open_control_session_object_free_v1', header)
        self.assertIn('NV_MEMORY_ALLOCATION_PARAMS *params', header)
        self.assertIn('#include <class/cl003e.h>', header)
        self.assertIn('#include <class/cl0040.h>', header)
        open_patch = (ROOT / 'patches/r580.178.04/0021-private-open-memory-object.patch').read_text()
        legacy_patch = (ROOT / 'patches/r580.178.04/proprietary/0019-private-legacy-memory-object.patch').read_text()
        for patch, prefix, operation in (
                (open_patch, 'hybrid580_open', 'rm_kernel_rmapi_op(sp, &ops)'),
                (legacy_patch, 'hybrid580_legacy', 'rm_ioctl(sp, nv, &nvlfp->nvfp')):
            self.assertIn(prefix + '_control_session_memory_alloc_v1', patch)
            self.assertIn(prefix + '_control_session_object_free_v1', patch)
            self.assertIn('NV01_MEMORY_SYSTEM', patch)
            self.assertIn('NV01_MEMORY_LOCAL_USER', patch)
            self.assertIn('NV_MEMORY_ALLOCATION_PARAMS', patch)
            self.assertIn('hObjectParent = h_parent', patch)
            self.assertIn(operation, patch)
            self.assertIn('paramsSize = sizeof(alloc_params)', patch)
            self.assertNotIn('NV_COPY_FROM_USER', patch)
            self.assertNotIn('NV_COPY_TO_USER', patch)
        self.assertIn('0021-private-open-memory-object.patch', OPEN_BUILDER.read_text())
        self.assertIn('0019-private-legacy-memory-object.patch', LEGACY_BUILDER.read_text())

    def test_vaspace_bridge_is_typed_tracked_and_used_to_translate_memory_parent(self):
        header = API.read_text()
        self.assertIn('hybrid580_open_control_session_vaspace_alloc_v1', header)
        self.assertIn('NV_VASPACE_ALLOCATION_PARAMETERS *params', header)
        self.assertIn('#include <class/cl90f1.h>', header)
        open_patch = (ROOT / 'patches/r580.178.04/0022-private-open-vaspace-object.patch').read_text()
        legacy_patch = (ROOT / 'patches/r580.178.04/proprietary/0020-private-legacy-vaspace-object.patch').read_text()
        for patch, prefix, operation in (
                (open_patch, 'hybrid580_open', 'rm_kernel_rmapi_op(sp, &ops)'),
                (legacy_patch, 'hybrid580_legacy', 'rm_ioctl(sp, nv, &nvlfp->nvfp')):
            self.assertIn(prefix + '_control_session_vaspace_alloc_v1', patch)
            self.assertIn('NV_VASPACE_ALLOCATION_PARAMETERS', patch)
            self.assertIn('FERMI_VASPACE_A', patch)
            self.assertIn(operation, patch)
            self.assertNotIn('NV_COPY_FROM_USER', patch)
            self.assertNotIn('NV_COPY_TO_USER', patch)
        source = (ROOT / 'src/hybrid_frontend.c').read_text()
        self.assertIn('hybrid_front_vaspace_alloc64', source)
        self.assertIn('backend_params.hVASpace = vaspace->backend_handle', source)
        self.assertIn('vaspace->class_id != FERMI_VASPACE_A', source)
        self.assertIn('0022-private-open-vaspace-object.patch', OPEN_BUILDER.read_text())
        self.assertIn('hybrid580_legacy_control_session_vaspace_alloc_v1', LEGACY_BUILDER.read_text())
        self.assertIn('control_session_vaspace_alloc_v1', FRONTEND_BUILDER.read_text())

    def test_channel_group_bridge_is_typed_and_tracks_vaspace_and_notifiers(self):
        header = API.read_text()
        self.assertIn('hybrid580_open_control_session_channel_group_alloc_v1', header)
        self.assertIn('NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS *params', header)
        self.assertIn('#include <class/cla06c.h>', header)
        open_patch = (ROOT / 'patches/r580.178.04/0023-private-open-channel-group-object.patch').read_text()
        legacy_patch = (ROOT / 'patches/r580.178.04/proprietary/0021-private-legacy-channel-group-object.patch').read_text()
        for patch, prefix, operation in (
                (open_patch, 'hybrid580_open', 'rm_kernel_rmapi_op(sp, &ops)'),
                (legacy_patch, 'hybrid580_legacy', 'rm_ioctl(sp, nv, &nvlfp->nvfp')):
            self.assertIn(prefix + '_control_session_channel_group_alloc_v1', patch)
            self.assertIn('KEPLER_CHANNEL_GROUP_A', patch)
            self.assertIn('NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS', patch)
            self.assertIn('hObjectParent = h_device', patch)
            self.assertIn(operation, patch)
            self.assertNotIn('NV_COPY_FROM_USER', patch)
            self.assertNotIn('NV_COPY_TO_USER', patch)
        source = (ROOT / 'src/hybrid_frontend.c').read_text()
        self.assertIn('hybrid_front_channel_group_alloc64', source)
        self.assertIn('backend_params.hVASpace = vaspace->backend_handle', source)
        self.assertIn('error_object_handle', source)
        self.assertIn('ecc_error_object_handle', source)
        self.assertIn('0023-private-open-channel-group-object.patch', OPEN_BUILDER.read_text())
        self.assertIn('hybrid580_legacy_control_session_channel_group_alloc_v1', LEGACY_BUILDER.read_text())
        self.assertIn('control_session_channel_group_alloc_v1', FRONTEND_BUILDER.read_text())

    def test_open_patch_uses_kernel_owned_fixed_payload(self):
        patch = OPEN_PATCH.read_text()
        targets = re.findall(r'^\+\+\+ b/([^\n]+)$', patch, re.M)
        self.assertEqual(targets, ['kernel-open/nvidia/nv.c',
                                   'kernel-open/nvidia/hybrid580-control-session.h'])
        for required in ('NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS',
                         'NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS',
                         'KERNEL_POINTER_TO_NvP64(&result)',
                         '.paramsSize = sizeof(result)',
                         'rm_kernel_rmapi_op(sp, &ops)',
                         'EXPORT_SYMBOL(hybrid580_open_control_session_device_ids_v1)'):
            self.assertIn(required, patch)
        self.assertNotIn('NV_COPY_FROM_USER', patch)
        self.assertNotIn('NV_COPY_TO_USER', patch)

    def test_legacy_patch_and_builders_pin_the_api(self):
        patch = LEGACY_PATCH.read_text()
        targets = re.findall(r'^\+\+\+ b/([^\n]+)$', patch, re.M)
        self.assertEqual(targets, ['nvidia/nv.c',
                                   'nvidia/hybrid580-control-session.h'])
        self.assertIn('EXPORT_SYMBOL(hybrid580_legacy_control_session_device_ids_v1)', patch)
        open_builder = OPEN_BUILDER.read_text()
        legacy_builder = LEGACY_BUILDER.read_text()
        self.assertIn('0019-private-open-device-ids.patch', open_builder)
        self.assertIn('hybrid580_open_control_session_device_ids_v1', open_builder)
        self.assertIn('hybrid580_legacy_control_session_device_ids_v1', legacy_builder)

    def test_channel_alloc_bridges_are_architecture_typed_and_build_pinned(self):
        header = API.read_text()
        self.assertIn('hybrid580_open_control_session_channel_alloc_v1', header)
        self.assertIn('NV_CHANNEL_ALLOC_PARAMS *params', header)
        self.assertIn('#include <class/clc36f.h>', header)
        self.assertIn('#include <class/clc96f.h>', header)
        open_patch = (ROOT / 'patches/r580.178.04/0025-private-open-channel-object.patch').read_text()
        legacy_patch = (ROOT / 'patches/r580.178.04/proprietary/0023-private-legacy-channel-object.patch').read_text()
        for patch, prefix, class_id, operation in (
                (open_patch, 'hybrid580_open', 'BLACKWELL_CHANNEL_GPFIFO_A',
                 'rm_kernel_rmapi_op(sp, &ops)'),
                (legacy_patch, 'hybrid580_legacy', 'VOLTA_CHANNEL_GPFIFO_A',
                 'rm_ioctl(sp, nv, &nvlfp->nvfp')):
            self.assertIn(prefix + '_control_session_channel_alloc_v1', patch)
            self.assertIn('class_id != ' + class_id, patch)
            self.assertIn('NV_CHANNEL_ALLOC_PARAMS', patch)
            self.assertIn('hObjectParent = h_group', patch)
            self.assertIn('paramsSize = sizeof(alloc_params)', patch)
            self.assertIn(operation, patch)
            self.assertNotIn('NV_COPY_FROM_USER', patch)
            self.assertNotIn('NV_COPY_TO_USER', patch)
        self.assertIn('0025-private-open-channel-object.patch', OPEN_BUILDER.read_text())
        self.assertIn('0023-private-legacy-channel-object.patch', LEGACY_BUILDER.read_text())
        self.assertIn('control_session_channel_alloc_v1', FRONTEND_BUILDER.read_text())

    def test_subdevice_tpc_mask_bridge_is_typed_and_build_pinned(self):
        header = API.read_text()
        self.assertIn('hybrid580_open_control_session_subdevice_alloc_v1', header)
        self.assertIn('hybrid580_open_control_session_gr_tpc_mask_v1', header)
        self.assertIn('NV2080_ALLOC_PARAMETERS *params', header)
        self.assertIn('NV2080_CTRL_GR_GET_TPC_MASK_PARAMS *params', header)
        self.assertIn('#include <class/cl2080.h>', header)
        self.assertIn('#include <ctrl/ctrl2080/ctrl2080gr.h>', header)
        open_patch = (ROOT / 'patches/r580.178.04/0026-private-open-subdevice-and-tpc-mask.patch').read_text()
        legacy_patch = (ROOT / 'patches/r580.178.04/proprietary/0024-private-legacy-subdevice-and-tpc-mask.patch').read_text()
        for patch, prefix, operation in (
                (open_patch, 'hybrid580_open', 'rm_kernel_rmapi_op(sp, &ops)'),
                (legacy_patch, 'hybrid580_legacy', 'rm_kernel_rmapi_op(sp, &ops)')):
            self.assertIn(prefix + '_control_session_subdevice_alloc_v1', patch)
            self.assertIn(prefix + '_control_session_gr_tpc_mask_v1', patch)
            self.assertIn('NV20_SUBDEVICE_0', patch)
            self.assertIn('NV2080_CTRL_CMD_GR_GET_TPC_MASK', patch)
            self.assertIn('paramsSize = sizeof(alloc_params)', patch)
            self.assertIn(operation, patch)
            self.assertNotIn('NV_COPY_FROM_USER', patch)
            self.assertNotIn('NV_COPY_TO_USER', patch)
        self.assertIn('0026-private-open-subdevice-and-tpc-mask.patch', OPEN_BUILDER.read_text())
        self.assertIn('0024-private-legacy-subdevice-and-tpc-mask.patch', LEGACY_BUILDER.read_text())
        self.assertIn('control_session_subdevice_alloc_v1', FRONTEND_BUILDER.read_text())
        self.assertIn('control_session_gr_tpc_mask_v1', FRONTEND_BUILDER.read_text())

    def test_observed_volta_p2p_controls_have_typed_legacy_only_bridges(self):
        header = API.read_text()
        for suffix, params in (
                ('p2p_register_va_space_v1', 'NV503C_CTRL_REGISTER_VA_SPACE_PARAMS'),
                ('p2p_unregister_va_space_v1', 'NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS'),
                ('p2p_register_vidmem_v1', 'NV503C_CTRL_REGISTER_VIDMEM_PARAMS'),
                ('p2p_unregister_vidmem_v1', 'NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS')):
            self.assertIn('hybrid580_open_control_session_' + suffix, header)
            self.assertIn(params + ' *params', header)
        self.assertIn('#include <ctrl/ctrl503c.h>', header)
        patch = (ROOT / 'patches/r580.178.04/proprietary/0029-private-legacy-p2p-controls.patch').read_text()
        for command in ('NV503C_CTRL_CMD_REGISTER_VA_SPACE',
                        'NV503C_CTRL_CMD_UNREGISTER_VA_SPACE',
                        'NV503C_CTRL_CMD_REGISTER_VIDMEM',
                        'NV503C_CTRL_CMD_UNREGISTER_VIDMEM'):
            self.assertIn(command, patch)
        self.assertIn('rm_kernel_rmapi_op(sp, &ops)', patch)
        self.assertNotIn('NV_COPY_FROM_USER', patch)
        self.assertNotIn('NV_COPY_TO_USER', patch)
        builder = (ROOT / 'tools/build_private_proprietary580.py').read_text()
        self.assertIn("PATCH_DIR / '0029-private-legacy-p2p-controls.patch'", builder)
        for operation in ('register_va_space', 'unregister_va_space',
                          'register_vidmem', 'unregister_vidmem'):
            self.assertIn("'" + operation + "'", builder)
        self.assertIn("'hybrid580_legacy_control_session_p2p_' + operation + '_v1'",
                      FRONTEND_BUILDER.read_text())

    def test_binapi_bridge_is_parent_typed_and_build_pinned(self):
        header = API.read_text()
        self.assertIn('#include <class/cl2081.h>', header)
        self.assertIn('hybrid580_open_control_session_binapi_alloc_v1', header)
        self.assertIn('const NV2081_ALLOC_PARAMETERS *params', header)
        open_patch = (ROOT / 'patches/r580.178.04/0027-private-open-binapi-object.patch').read_text()
        legacy_patch = (ROOT / 'patches/r580.178.04/proprietary/0025-private-legacy-binapi-object.patch').read_text()
        for patch, prefix, operation in (
                (open_patch, 'hybrid580_open', 'rm_kernel_rmapi_op(sp, &ops)'),
                (legacy_patch, 'hybrid580_legacy', 'rm_ioctl(sp, nv, &nvlfp->nvfp')):
            self.assertIn(prefix + '_control_session_binapi_alloc_v1', patch)
            self.assertIn('NV2081_BINAPI', patch)
            self.assertIn('hObjectParent = h_subdevice', patch)
            self.assertIn('paramsSize = sizeof(alloc_params)', patch)
            self.assertIn(operation, patch)
            self.assertNotIn('NV_COPY_FROM_USER', patch)
            self.assertNotIn('NV_COPY_TO_USER', patch)
        self.assertIn('0027-private-open-binapi-object.patch', OPEN_BUILDER.read_text())
        self.assertIn('0025-private-legacy-binapi-object.patch', LEGACY_BUILDER.read_text())
        self.assertIn('control_session_binapi_alloc_v1', FRONTEND_BUILDER.read_text())

    def test_rusd_allocation_is_fixed_typed_backend_affine_and_build_pinned(self):
        header = API.read_text()
        self.assertIn('#include <class/cl00de.h>', header)
        self.assertIn('hybrid580_open_control_session_rusd_alloc_v1', header)
        self.assertIn('const NV00DE_ALLOC_PARAMETERS *params', header)
        open_patch = (ROOT / 'patches/r580.178.04/0030-private-open-rusd-object.patch').read_text()
        legacy_patch = (ROOT / 'patches/r580.178.04/proprietary/0030-private-legacy-rusd-object.patch').read_text()
        for patch, prefix, operation in (
                (open_patch, 'hybrid580_open', 'rm_kernel_rmapi_op(sp, &ops)'),
                (legacy_patch, 'hybrid580_legacy', 'rm_ioctl(sp, nv, &nvlfp->nvfp')):
            self.assertIn(prefix + '_control_session_rusd_alloc_v1', patch)
            self.assertIn('RM_USER_SHARED_DATA', patch)
            self.assertIn('NV00DE_ALLOC_PARAMETERS', patch)
            self.assertIn('hObjectParent = h_subdevice', patch)
            self.assertIn('paramsSize = sizeof(alloc_params)', patch)
            self.assertIn(operation, patch)
            self.assertNotIn('NV_COPY_FROM_USER', patch)
            self.assertNotIn('NV_COPY_TO_USER', patch)
        self.assertIn("RUSD_OBJECT_PATCH=ROOT/'patches/r580.178.04/0030-private-open-rusd-object.patch'",
                      OPEN_BUILDER.read_text())
        self.assertIn("PATCH_DIR / '0030-private-legacy-rusd-object.patch'", LEGACY_BUILDER.read_text())
        self.assertIn('control_session_rusd_alloc_v1', FRONTEND_BUILDER.read_text())
        frontend = (ROOT / 'src/hybrid_frontend.c').read_text()
        self.assertIn('packet.alloc64.hClass == RM_USER_SHARED_DATA', frontend)
        self.assertIn('object->class_id == RM_USER_SHARED_DATA', frontend)


if __name__ == '__main__':
    unittest.main()
