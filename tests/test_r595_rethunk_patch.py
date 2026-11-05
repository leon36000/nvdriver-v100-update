# SPDX-License-Identifier: MIT
"""Fail-closed replay tests for the R595.112.07 RETHUNK build patch."""
import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
FIXTURE = ROOT / "tests/fixtures/upstream/nvidia-r595-rethunk/595.112.07/src/nvidia/Makefile"
PATCH = ROOT / "patches/r595.112.07/0001-open-core-rethunk-return-thunk.patch"
UPSTREAM_SHA256 = "a5b0653bd0142ca0d1ffeaac895750a3c76bd66f4d24b8ae9496bd04025112ee"
PATCHED_SHA256 = "5d8734c91b9721054e222fddd65e14b5b4567d893e943c798fbc7665503e980d"

from tools.prepare_r595_hybrid_source import (  # noqa: E402
    PatchSeriesError,
    apply_exact_patch_series,
)


class R595RethunkPatchTests(unittest.TestCase):
    def _make_tree(self, destination: Path) -> Path:
        source = destination / "source"
        target = source / "src/nvidia/Makefile"
        target.parent.mkdir(parents=True)
        shutil.copyfile(FIXTURE, target)
        return source

    def test_pinned_upstream_makefile_replays_patch_exactly(self):
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), UPSTREAM_SHA256)
        with tempfile.TemporaryDirectory(prefix="r595-rethunk-exact-") as temporary:
            source = self._make_tree(Path(temporary))
            result = apply_exact_patch_series(source, [PATCH])
            patched = source / "src/nvidia/Makefile"
            self.assertTrue(result[0]["zero_offset_zero_fuzz"])
            self.assertEqual(hashlib.sha256(patched.read_bytes()).hexdigest(), PATCHED_SHA256)
            self.assertEqual(
                patched.read_text().count(
                    "CONDITIONAL_CFLAGS += $(call TEST_CC_ARG, -mfunction-return=thunk-extern)"
                ),
                1,
            )

    def test_rejects_modified_upstream_hunk_without_editing_input(self):
        with tempfile.TemporaryDirectory(prefix="r595-rethunk-drift-") as temporary:
            source = self._make_tree(Path(temporary))
            target = source / "src/nvidia/Makefile"
            original = target.read_text()
            target.write_text(original.replace(
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
