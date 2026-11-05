# SPDX-License-Identifier: MIT
"""The R580 VA-space ioctl binds and retains its exact control file."""
from pathlib import Path
import importlib
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
probe = importlib.import_module("tools.probe_r580_uvm_isolated_execution")
audit = importlib.import_module("tools.audit_uvm_owner_isolation_architecture")


class R580UvmControlFileLifetimeTests(unittest.TestCase):
    def test_va_space_registration_resolves_file_before_api_and_retains_owner(self):
        names = [patch.name for patch in probe.PATCHES]
        self.assertEqual(names[-9:], [
            "0006-pin-control-file-before-va-space-registration.patch",
            "0007-reject-cross-gpu-tracker-dependencies.patch",
            "0008-pmm-allocation-outside-va-block-lock.patch",
            "0009-reject-hmm-gpu-migration-in-isolated-mode.patch",
            "0010-reject-unsupported-isolated-staged-migrations.patch",
            "0011-preflight-unsupported-staging-before-unmap.patch",
            "0012-exact-isolated-staged-page-mask.patch",
            "0013-reject-foreign-pmm-trackers-in-isolated-mode.patch",
            "0014-reject-foreign-pmm-trackers-before-eviction.patch",
        ])
        sources = (
            "common/inc/nv_uvm_interface.h",
            "nvidia/nv_uvm_interface.c",
            "nvidia-uvm/uvm_map_external.c",
            "nvidia-uvm/nvidia-uvm.Kbuild",
            "nvidia/nvidia.Kbuild",
            "nvidia-uvm/uvm_api.h",
            "nvidia-uvm/uvm.c",
            "nvidia-uvm/uvm_common.h",
            "nvidia-uvm/uvm_gpu.c",
            "nvidia-uvm/uvm_va_space.c",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in sources:
                source = audit.SOURCE_ROOT / relative
                target = root / "kernel-open" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            # This test exercises the control-file patch series. The tracker,
            # PMM retry, and HMM-isolation overlays are covered separately.
            for patch in probe.PATCHES[1:-8]:
                result = subprocess.run(
                    ["patch", "--batch", "--fuzz=0", "--forward", "-p1",
                     "-i", str(patch)],
                    cwd=root, capture_output=True, text=True, timeout=30,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            ioctl = (root / "kernel-open/nvidia-uvm/uvm.c").read_text()
            route = ioctl.split("static long uvm_ioctl_register_gpu_va_space(", 1)[1]
            route = route.split("static long uvm_ioctl(", 1)[0]
            resolve = route.index("fget((unsigned int)params.rmCtrlFd)")
            dispatch_match = re.search(
                r"uvm_api_register_gpu_va_space\(\s*&params,\s*filp,\s*rm_control_file\)",
                route,
            )
            self.assertIsNotNone(dispatch_match)
            dispatch = dispatch_match.start()
            release = route.index("fput(rm_control_file)")
            self.assertLess(resolve, dispatch)
            self.assertLess(dispatch, release)
            self.assertEqual(route.count("fget((unsigned int)params.rmCtrlFd)"), 1)
            self.assertEqual(route.count("fput(rm_control_file)"), 1)

            api = (root / "kernel-open/nvidia-uvm/uvm_gpu.c").read_text()
            self.assertIn(".rm_control_file = rm_control_file", api)
            va_space = (root / "kernel-open/nvidia-uvm/uvm_va_space.c").read_text()
            self.assertIn("user_rm_va_space->rm_control_file", va_space)
            dispatch_header = (root / "kernel-open/common/inc/"
                              "hybrid580_uvm_control_fd_dispatch.h").read_text()
            self.assertIn("struct file *rmControlFile", dispatch_header)


if __name__ == "__main__":
    unittest.main()
