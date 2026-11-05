# SPDX-License-Identifier: MIT
"""Pin the kmod whitespace softdep overlay for the exact R595.99 source."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches/r595.99.02/0014-open-kmod-softdep-space-separators.patch"
SOURCE = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
          "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia/libspdm_ecc.c")
SOURCE_SHA256 = "9dc820124a9f568d38d35c324bac8e845ddbc7158959ac94ed0000248749fb61"
PATCH_SHA256 = "6384b2ec99b5768a751cc71edda3bdda4c326fe9f60f80a7b76dd8afc4bfaeaf"
PATCHED_SHA256 = "ffb79501c6725ade872304e5b826973011097002f122fed11f7f201c47f965ac"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class R595KmodSoftdepSeparatorPatchTests(unittest.TestCase):
    def test_zero_fuzz_overlay_changes_only_the_pinned_softdep_source(self):
        self.assertEqual(sha256(SOURCE), SOURCE_SHA256)
        self.assertEqual(sha256(PATCH), PATCH_SHA256)
        patch_text = PATCH.read_text()
        with tempfile.TemporaryDirectory(prefix="r595-kmod-softdep-") as tmp:
            temp_root = Path(tmp)
            target = temp_root / "kernel-open/nvidia/libspdm_ecc.c"
            target.parent.mkdir(parents=True)
            shutil.copyfile(SOURCE, target)

            dry_run = subprocess.run(
                ["patch", "--batch", "--fuzz=0", "-p1", "--dry-run"],
                cwd=temp_root, input=patch_text, text=True,
                capture_output=True, check=False)
            self.assertEqual(dry_run.returncode, 0, dry_run.stdout + dry_run.stderr)
            self.assertNotIn("fuzz", (dry_run.stdout + dry_run.stderr).lower())
            self.assertNotIn("offset", (dry_run.stdout + dry_run.stderr).lower())

            applied = subprocess.run(
                ["patch", "--batch", "--fuzz=0", "-p1"],
                cwd=temp_root, input=patch_text, text=True,
                capture_output=True, check=False)
            self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
            self.assertEqual(sha256(target), PATCHED_SHA256)
            text = target.read_text()
            self.assertEqual(
                text.count('MODULE_SOFTDEP("pre: ecdh_generic ecdsa_generic");'), 1)
            self.assertNotIn(
                'MODULE_SOFTDEP("pre: ecdh_generic,ecdsa_generic");', text)

    def test_overlay_is_the_single_delimiter_change(self):
        source = SOURCE.read_bytes()
        old = b'MODULE_SOFTDEP("pre: ecdh_generic,ecdsa_generic");'
        new = b'MODULE_SOFTDEP("pre: ecdh_generic ecdsa_generic");'
        self.assertEqual(source.count(old), 1)
        patched = source.replace(old, new, 1)
        self.assertEqual(patched.count(new), 1)
        self.assertEqual(hashlib.sha256(patched).hexdigest(), PATCHED_SHA256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
