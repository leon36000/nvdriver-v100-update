# SPDX-License-Identifier: MIT
"""Compile ABI probes against hash-pinned R580 and R595 UVM headers."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
R580_SOURCE = (ROOT / "build/experiments/private-open580-native-v3-20261023"
               / "private/NVIDIA-kernel-module-source-580.178.04")
R595_SOURCE = (ROOT / "build/experiments/r595-r580-open-fullbuild-v3-20261023"
               / "source")
KERNEL_BUILD = Path("/usr/src/linux-headers-7.0.0-38-generic")
KERNEL_CC = shutil.which("x86_64-linux-gnu-gcc") or shutil.which("gcc")
PROBE = ROOT / "tests/fixtures/uvm_event_header_probe.c"

PINNED_HEADERS = {
    "R580": {
        "kernel-open/common/inc/nv_uvm_interface.h":
            "68b6cae62ad0bdf6940d48a34084d789cd1f87a06b84310195cd2adc4b9e50f8",
        "kernel-open/common/inc/nv_uvm_types.h":
            "5216a6a83924511f38c8a881ee0ffc601e2851e92e6a9b49810f9cc9e90dd614",
    },
    "R595": {
        "kernel-open/common/inc/nv_uvm_interface.h":
            "4d8e4f46bc2afc99cb074f425f459b98ca072d50b91e25b7085db0df0081c89d",
        "kernel-open/common/inc/nv_uvm_types.h":
            "5515b06a13072584d4668251c2e31bbb724118c914691eb4abf1cd76c1b63e65",
    },
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def include_dirs(source):
    return (
        source / "kernel-open/common/inc",
        source / "kernel-open",
        source / "kernel-open/nvidia",
        source / "src/common/sdk/nvidia/inc",
        source / "src/common/inc",
        source / "src/common/inc/swref",
        source / "src/nvidia/arch/nvalloc/unix/include",
    )


class Hybrid580UvmRealHeaderAbiTests(unittest.TestCase):
    def test_header_sources_match_pinned_release_inputs(self):
        for release, source in (("R580", R580_SOURCE), ("R595", R595_SOURCE)):
            with self.subTest(release=release):
                for relative, expected in PINNED_HEADERS[release].items():
                    header = source / relative
                    self.assertTrue(header.is_file(), header)
                    self.assertEqual(sha256(header), expected, str(header))

    def test_event_and_access_bits_abi_probes_compile_against_both_real_releases(self):
        self.assertTrue(KERNEL_BUILD.is_dir(), KERNEL_BUILD)
        self.assertIsNotNone(KERNEL_CC, "x86_64 kernel C compiler is unavailable")
        self.assertTrue(PROBE.is_file(), PROBE)

        for release, source, r580 in (
                ("R580", R580_SOURCE, True), ("R595", R595_SOURCE, False)):
            with self.subTest(release=release), tempfile.TemporaryDirectory() as tmp:
                build_dir = Path(tmp)
                shutil.copyfile(PROBE, build_dir / "eventprobe.c")
                flags = [
                    "-DNVRM", "-DNV_KERNEL_INTERFACE_LAYER", "-DNV_UVM_ENABLE",
                    "-Werror", "-Wno-unused-function", "-Wno-missing-prototypes",
                ]
                if r580:
                    flags.append("-DHYBRID_PROBE_R580")
                for include in include_dirs(source):
                    self.assertTrue(include.is_dir(), include)
                    flags.append(f"-I{include}")
                (build_dir / "Kbuild").write_text(
                    "obj-m += eventprobe.o\n"
                    + "ccflags-y += " + " ".join(flags) + "\n"
                )
                result = subprocess.run(
                    ["make", "-s", "-C", str(KERNEL_BUILD), f"M={build_dir}",
                     f"CC={KERNEL_CC}", "eventprobe.o"],
                    capture_output=True, text=True, timeout=120, check=False)
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertTrue((build_dir / "eventprobe.o").is_file())

    def test_access_bits_contract_is_r595_only_and_not_an_access_counter_alias(self):
        interface_header = "kernel-open/common/inc/nv_uvm_interface.h"
        types_header = "kernel-open/common/inc/nv_uvm_types.h"
        r580_interface = (R580_SOURCE / interface_header).read_text()
        r580_types = (R580_SOURCE / types_header).read_text()
        r595_interface = (R595_SOURCE / interface_header).read_text()
        r595_types = (R595_SOURCE / types_header).read_text()

        self.assertNotIn("nvUvmInterfaceAccessBits", r580_interface)
        self.assertNotIn("UvmGpuAccessBitsBufferAlloc", r580_types)
        self.assertIn("nvUvmInterfaceAccessBitsBufAlloc", r595_interface)
        self.assertIn("nvUvmInterfaceAccessBitsBufFree", r595_interface)
        self.assertIn("nvUvmInterfaceAccessBitsDump", r595_interface)
        self.assertIn("UvmGpuAccessBitsBufferAlloc", r595_types)
        self.assertIn("UvmGpuAccessCntrInfo", r580_types)


if __name__ == "__main__":
    unittest.main()
