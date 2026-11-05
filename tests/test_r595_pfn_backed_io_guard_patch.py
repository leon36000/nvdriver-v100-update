# SPDX-License-Identifier: MIT
"""Pin the minimal R595.112 page-backed PFN guard port to R595.99."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches/r595.99.02/0013-open-pfn-backed-io-guard.patch"
R595_99 = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
           "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia/os-mlock.c")
R595_112 = (ROOT / "build/research/open-gpu-kernel-modules-595.112.07/source/"
            "open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2/"
            "kernel-open/nvidia/os-mlock.c")
R595_99_SHA256 = "dcee9c5d88286ab8b07b6a9e991b64da7f125c0c8a387f11ab1aecbf5a0cd15e"
R595_112_SHA256 = "760a5ee564cd0f151aea337eca146578bed157c80c8152f9aa9b414db6576609"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class R595PfnBackedIoGuardPatchTests(unittest.TestCase):
    def test_zero_fuzz_patch_reproduces_the_pinned_r595112_file(self):
        self.assertEqual(sha256(R595_99), R595_99_SHA256)
        self.assertEqual(sha256(R595_112), R595_112_SHA256)
        patch_text = PATCH.read_text()
        with tempfile.TemporaryDirectory(prefix="r595-pfn-guard-test-") as tmp:
            temp_root = Path(tmp)
            target = temp_root / "kernel-open/nvidia/os-mlock.c"
            target.parent.mkdir(parents=True)
            shutil.copyfile(R595_99, target)
            dry_run = subprocess.run(
                ["patch", "--fuzz=0", "-p1", "--dry-run"],
                cwd=temp_root, input=patch_text, text=True,
                capture_output=True, check=False)
            self.assertEqual(dry_run.returncode, 0, dry_run.stdout + dry_run.stderr)
            self.assertNotIn("fuzz", (dry_run.stdout + dry_run.stderr).lower())
            applied = subprocess.run(
                ["patch", "--fuzz=0", "-p1"], cwd=temp_root,
                input=patch_text, text=True, capture_output=True, check=False)
            self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
            self.assertEqual(target.read_bytes(), R595_112.read_bytes())
            self.assertEqual(sha256(target), R595_112_SHA256)

    def test_guard_rejects_page_backed_pfns_before_exposing_the_address(self):
        self.assertEqual(sha256(R595_99), R595_99_SHA256)
        patched_source = R595_112.read_text()
        self.assertIn("return pfn_is_map_memory(pfn);", patched_source)
        self.assertIn("return pfn_valid(pfn);", patched_source)
        self.assertIn("if (nv_pfn_has_page_backing(pfn))", patched_source)
        self.assertIn("return NV_ERR_INVALID_ADDRESS;", patched_source)
        self.assertLess(patched_source.index("if (nv_pfn_has_page_backing(pfn))"),
                        patched_source.index("pte_array[i] = (NvU64 *)(pfn << PAGE_SHIFT);"))


if __name__ == "__main__":
    unittest.main()
