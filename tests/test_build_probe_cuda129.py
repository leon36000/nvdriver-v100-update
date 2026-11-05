# SPDX-License-Identifier: MIT
import unittest

from tools.build_probe_cuda129 import (
    parse_image_inventory,
    reject_direct_libcuda_link,
    validate_stage_receipt,
)


class Cuda129ProbeBuilderTests(unittest.TestCase):
    def test_requires_volta_ptx_and_blackwell_cubin(self):
        elf = "ELF file 1: hybrid.sm_120a.cubin\n"
        ptx = "PTX file 1: hybrid.sm_70.ptx\n"
        images = parse_image_inventory(elf, ptx)
        self.assertEqual(images["cubins"], ["120a"])
        self.assertEqual(images["ptx"], ["70"])
        self.assertEqual(images["sm120a_cubin_count"], 1)
        self.assertEqual(images["sm70_ptx_count"], 1)

    def test_rejects_wrong_architecture_pair(self):
        with self.assertRaisesRegex(ValueError, "SM120a cubin and SM70 PTX"):
            parse_image_inventory("ELF file 1: hybrid.sm_120.cubin", "PTX file 1: hybrid.sm_80.ptx")

    def test_rejects_direct_driver_library_link(self):
        reject_direct_libcuda_link("0x1 NEEDED Shared library: [libcudart.so.12]\n")
        with self.assertRaisesRegex(ValueError, "dynamically"):
            reject_direct_libcuda_link("0x1 NEEDED Shared library: [libcuda.so.1]\n")

    def test_accepts_only_no_driver_stage_receipt(self):
        receipt = {
            "schema": "nvdriver-cuda-toolchain-stage-v1",
            "toolkit": "12.9.2",
            "qualification": "local-user-space-toolchain-stage-only",
            "state": {
                "driver_package_included": False,
                "system_files_modified": False,
                "gpu_accessed": False,
                "binary_executed": False,
            },
        }
        validate_stage_receipt(receipt)
        receipt["state"]["driver_package_included"] = True
        with self.assertRaisesRegex(ValueError, "no-driver local stage"):
            validate_stage_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
