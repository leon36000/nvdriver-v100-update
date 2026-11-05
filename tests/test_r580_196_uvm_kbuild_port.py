# SPDX-License-Identifier: MIT
"""Regression contract for the R580.196.07 isolated-UVM Kbuild port."""
import hashlib
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / (
    "build/experiments/private-open580-native-19607-v1-20261024/inputs/"
    "open580-580.196.07.tar.xz"
)
ARCHIVE_SHA256 = "21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084"
PATCH = ROOT / (
    "patches/r580.196.07/uvm/"
    "0001-share-linux-conftests-with-uvm-consumer.patch"
)
ARCHIVE_ROOT = "NVIDIA-kernel-module-source-580.196.07/kernel-open/"
KBUILD_FILES = (
    "nvidia/nvidia.Kbuild",
    "nvidia-uvm/nvidia-uvm.Kbuild",
)


def _conftest_entries(text):
    return re.findall(r"^NV_CONFTEST_[A-Z_]+ \+= [^\n]+$", text, re.MULTILINE)


class R580196UvmKbuildPortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if hashlib.sha256(ARCHIVE.read_bytes()).hexdigest() != ARCHIVE_SHA256:
            raise AssertionError("pinned R580.196.07 archive mismatch")
        cls.temp = tempfile.TemporaryDirectory(prefix="r580-196-uvm-kbuild-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.original = {}
        with tarfile.open(ARCHIVE, "r:xz") as archive:
            for relative in KBUILD_FILES:
                member = archive.extractfile(ARCHIVE_ROOT + relative)
                if member is None:
                    raise AssertionError(f"missing pinned Kbuild input: {relative}")
                content = member.read()
                cls.original[relative] = content.decode("utf-8")
                target = cls.root / "kernel-open" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
        cls.patch_result = subprocess.run(
            ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
            cwd=cls.root,
            capture_output=True,
            text=True,
        )

    def test_patch_applies_to_exact_official_source_without_fuzz_or_offset(self):
        self.assertEqual(self.patch_result.returncode, 0,
                         self.patch_result.stdout + self.patch_result.stderr)
        self.assertNotRegex(self.patch_result.stdout, r"\b(offset|fuzz)\b")

    def test_every_r580_196_rm_conftest_is_preserved_in_shared_fragment(self):
        self.assertEqual(self.patch_result.returncode, 0,
                         self.patch_result.stdout + self.patch_result.stderr)
        original_rm = _conftest_entries(self.original["nvidia/nvidia.Kbuild"])
        shared = (self.root / "kernel-open/common/nvidia-kernel-interface-conftests.Kbuild")
        self.assertTrue(shared.is_file())
        shared_entries = _conftest_entries(shared.read_text())
        self.assertEqual(shared_entries, original_rm)
        nvidia = (self.root / "kernel-open/nvidia/nvidia.Kbuild").read_text()
        self.assertIn("include $(src)/common/nvidia-kernel-interface-conftests.Kbuild", nvidia)
        self.assertEqual(_conftest_entries(nvidia), [])

    def test_uvm_only_provider_consumes_shared_list_without_duplicate_entries(self):
        self.assertEqual(self.patch_result.returncode, 0,
                         self.patch_result.stdout + self.patch_result.stderr)
        uvm = (self.root / "kernel-open/nvidia-uvm/nvidia-uvm.Kbuild").read_text()
        self.assertIn("ifeq ($(filter nvidia,$(NV_KERNEL_MODULES)),)", uvm)
        self.assertIn("include $(src)/common/nvidia-kernel-interface-conftests.Kbuild", uvm)
        for entry in (
            "NV_CONFTEST_FUNCTION_COMPILE_TESTS += list_is_first",
            "NV_CONFTEST_FUNCTION_COMPILE_TESTS += ioasid_get",
            "NV_CONFTEST_FUNCTION_COMPILE_TESTS += mm_pasid_drop",
            "NV_CONFTEST_FUNCTION_COMPILE_TESTS += iommu_sva_bind_device_has_drvdata_arg",
        ):
            self.assertNotIn(entry, uvm)
        for entry in self.original["nvidia-uvm/nvidia-uvm.Kbuild"].splitlines():
            if entry.startswith("NV_CONFTEST_") and not any(
                entry.endswith(" += " + name)
                for name in ("list_is_first", "ioasid_get", "mm_pasid_drop",
                             "iommu_sva_bind_device_has_drvdata_arg")
            ):
                self.assertIn(entry, uvm)

    def test_full_isolated_uvm_patch_series_applies_sequentially(self):
        patch_names = (
            "0002-hybrid-isolated-gpu-execution.patch",
            "0003-pass-control-fd-to-dup-memory.patch",
            "0001-share-linux-conftests-with-uvm-consumer.patch",
            "0005-pass-control-fd-to-dup-address-space.patch",
            "0006-pin-control-file-before-va-space-registration.patch",
            "0007-reject-cross-gpu-tracker-dependencies.patch",
            "0008-pmm-allocation-outside-va-block-lock.patch",
            "0009-reject-hmm-gpu-migration-in-isolated-mode.patch",
            "0010-reject-unsupported-isolated-staged-migrations.patch",
            "0011-preflight-unsupported-staging-before-unmap.patch",
            "0012-exact-isolated-staged-page-mask.patch",
            "0013-reject-foreign-pmm-trackers-in-isolated-mode.patch",
            "0014-reject-foreign-pmm-trackers-before-eviction.patch",
        )
        patch_dirs = {
            name: ROOT / "patches/r580.196.07/uvm" / name
            if name.startswith("0001-share-")
            else ROOT / "patches/r580.178.04/uvm" / name
            for name in patch_names
        }
        with tempfile.TemporaryDirectory(prefix="r580-196-uvm-series-") as directory:
            destination = Path(directory)
            with tarfile.open(ARCHIVE, "r:xz") as archive:
                archive.extractall(destination)
            source = destination / "NVIDIA-kernel-module-source-580.196.07"
            outputs = []
            for name in patch_names:
                result = subprocess.run(
                    ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i",
                     str(patch_dirs[name])],
                    cwd=source,
                    capture_output=True,
                    text=True,
                )
                outputs.append(result.stdout + result.stderr)
                self.assertEqual(result.returncode, 0, outputs[-1])
                self.assertNotRegex(outputs[-1], r"\bFAILED\b|with fuzz")
                if name == "0014-reject-foreign-pmm-trackers-before-eviction.patch":
                    self.assertNotRegex(outputs[-1], r"\boffset\b")
            self.assertEqual(len(outputs), len(patch_names))


if __name__ == "__main__":
    unittest.main()
