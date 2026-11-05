# SPDX-License-Identifier: MIT
"""R580 usermode doorbell object source/ABI contract."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class UsermodeObjectTests(unittest.TestCase):
    def test_r580_maps_volta_or_hopper_doorbell_with_typed_lifetime(self):
        source = (ROOT / 'build/experiments/openrm580-baseline-v1/'
                  'NVIDIA-kernel-module-source-580.178.04/src/nvidia/src/kernel/'
                  'rmapi/nv_gpu_ops.c').read_text()
        body = source.split('static NV_STATUS gpuDeviceMapUsermodeRegion(struct gpuDevice *device)\n{', 1)[1]
        body = body.split('\nstatic NV_STATUS', 1)[0]
        self.assertIn('NvU32 usermodeClass = VOLTA_USERMODE_A;', body)
        self.assertIn('if (isDeviceHopperPlus(device))', body)
        self.assertIn('usermodeClass = HOPPER_USERMODE_A;', body)
        self.assertIn('.bBar1Mapping = NV_TRUE', body)
        self.assertIn('.bPriv = NV_FALSE', body)
        self.assertIn('pRmApi->MapToCpu', body)
        self.assertIn('NVC361_NV_USERMODE__SIZE', body)
        self.assertIn('DRF_DEF(OS33, _FLAGS, _ACCESS, _WRITE_ONLY)', body)

    def test_frontend_declares_backend_affine_typed_usermode_route(self):
        header = (ROOT / 'src/hybrid580-control-session.h').read_text()
        frontend = (ROOT / 'src/hybrid_frontend.c').read_text()
        for name in ('<class/clc361.h>', '<class/clc661.h>',
                     'NV_HOPPER_USERMODE_A_PARAMS'):
            self.assertIn(name, header)
        self.assertIn('hybrid580_open_control_session_usermode_alloc_v1', header)
        self.assertIn('hybrid580_legacy_control_session_usermode_alloc_v1', frontend)
        self.assertIn('hybrid580_open_control_session_usermode_alloc_v1', frontend)
        self.assertIn('hybrid_front_usermode_alloc64', frontend)
        self.assertIn('packet->hClass != VOLTA_USERMODE_A', frontend)
        self.assertIn('HOPPER_USERMODE_A)', frontend)

    def test_both_backend_build_chains_pin_typed_usermode_patch(self):
        open_builder = (ROOT / 'tools/probe_private_backend_chardev.py').read_text()
        legacy_builder = (ROOT / 'tools/build_private_proprietary580.py').read_text()
        self.assertIn('0028-private-open-usermode-object.patch', open_builder)
        self.assertIn('0026-private-legacy-usermode-object.patch', legacy_builder)
        self.assertTrue((ROOT / 'patches/r580.178.04/0028-private-open-usermode-object.patch').is_file())
        self.assertTrue((ROOT / 'patches/r580.178.04/proprietary/0026-private-legacy-usermode-object.patch').is_file())


if __name__ == '__main__':
    unittest.main()
