# SPDX-License-Identifier: MIT
"""Exact replay tests for the R595.112.07 modeset return-thunk overlay."""
import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/upstream/nvidia-r595-rethunk/595.112.07/src/nvidia-modeset/Makefile"
PATCH = ROOT / "patches/r595.112.07/0002-open-modeset-rethunk-return-thunk.patch"
UPSTREAM_SHA256 = "138c4f2777e03c68f5b2ffc1a7b31902af513315fda2b0522b93fb879db1f0a6"
PATCHED_SHA256 = "c0a924e120846ea6e83c984a791f71afb0eda27f091bd25c7268cf31c28914e9"
PATCH_SHA256 = "26d886f71d91c1b40cebe57f19407b75c63d953670e2e2176fb2db86395f1d00"

sys.path.insert(0, str(ROOT))
from tools.prepare_r595_hybrid_source import PatchSeriesError, apply_exact_patch_series  # noqa: E402


class R595ModesetRethunkPatchTests(unittest.TestCase):
    def _make_tree(self, destination: Path) -> Path:
        source = destination / "source"
        target = source / "src/nvidia-modeset/Makefile"
        target.parent.mkdir(parents=True)
        shutil.copyfile(FIXTURE, target)
        return source

    def test_pinned_upstream_makefile_replays_once_without_offset_or_fuzz(self):
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), UPSTREAM_SHA256)
        self.assertEqual(hashlib.sha256(PATCH.read_bytes()).hexdigest(), PATCH_SHA256)
        with tempfile.TemporaryDirectory(prefix="r595-modeset-rethunk-exact-") as temporary:
            source = self._make_tree(Path(temporary))
            result = apply_exact_patch_series(source, [PATCH])
            target = source / "src/nvidia-modeset/Makefile"
            text = target.read_text()
            self.assertTrue(result[0]["zero_offset_zero_fuzz"])
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), PATCHED_SHA256)
            self.assertEqual(text.count("-mfunction-return=thunk-extern"), 1)
            self.assertEqual(text.count("-mindirect-branch=thunk-extern"), 1)

    def test_rejects_modified_upstream_hunk_without_editing_input(self):
        with tempfile.TemporaryDirectory(prefix="r595-modeset-rethunk-drift-") as temporary:
            source = self._make_tree(Path(temporary))
            target = source / "src/nvidia-modeset/Makefile"
            target.write_text(target.read_text().replace(
                "-mindirect-branch=thunk-extern",
                "-mindirect-branch=unexpected",
                1,
            ))
            mutated = target.read_bytes()
            with self.assertRaises(PatchSeriesError):
                apply_exact_patch_series(source, [PATCH])
            self.assertEqual(target.read_bytes(), mutated)


if __name__ == "__main__":
    unittest.main()
