# SPDX-License-Identifier: MIT
"""Guard isolated PMM eviction before detaching VA-block trackers."""
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from tools import probe_r580_uvm_isolated_execution as probe
from tools.audit_hybrid_uvm_abi import c_function_definition


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / (
    "patches/r580.178.04/uvm/"
    "0014-reject-foreign-pmm-trackers-before-eviction.patch"
)
SOURCES = (
    (
        ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz",
        "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8",
        "NVIDIA-kernel-module-source-580.178.04/",
        "580.178.04",
    ),
    (
        ROOT / (
            "build/experiments/private-open580-native-19607-v1-20261024/inputs/"
            "open580-580.196.07.tar.xz"
        ),
        "21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084",
        "NVIDIA-kernel-module-source-580.196.07/",
        "580.196.07",
    ),
)
SOURCE_RELATIVE = "kernel-open/nvidia-uvm/uvm_va_block.c"


def _extract_and_patch(archive_path, expected_sha256, archive_root):
    if not PATCH.is_file():
        raise AssertionError(f"missing targeted eviction-lifetime patch: {PATCH}")
    if hashlib.sha256(archive_path.read_bytes()).hexdigest() != expected_sha256:
        raise AssertionError(f"pinned source archive digest mismatch: {archive_path}")

    with tempfile.TemporaryDirectory(prefix="r580-pmm-eviction-lifetime-") as directory:
        root = Path(directory)
        with tarfile.open(archive_path, "r:xz") as archive:
            stream = archive.extractfile(archive_root + SOURCE_RELATIVE)
            if stream is None:
                raise AssertionError(f"pinned source member missing: {SOURCE_RELATIVE}")
            source_path = root / SOURCE_RELATIVE
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_bytes(stream.read())

        # These earlier overlays insert code above the eviction function.
        # Apply them first so the final patch is verified at its intended
        # position in the composed build tree, rather than against a pristine
        # file where the same exact hunk would report a line-number offset.
        prior_patches = (
            probe.PATCHES[6],
            probe.PATCHES[8],
            probe.PATCHES[9],
            probe.PATCHES[10],
        )
        for prior_patch in prior_patches:
            result = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(prior_patch)],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                raise AssertionError(result.stdout + result.stderr)

        result = subprocess.run(
            ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stdout + result.stderr)
        if "offset" in result.stdout or "fuzz" in result.stdout:
            raise AssertionError(result.stdout)
        return c_function_definition(source_path, "uvm_va_block_evict_chunks")


def _validate_eviction_guard(function):
    block_lock = function.index("uvm_assert_mutex_locked(&va_block->lock);")
    guard = function.index("uvm_tracker_has_other_gpus(&va_block->tracker, gpu)")
    va_space_retain = function.index("uvm_va_space_mm_retain(va_space)")
    service_alloc = function.index("uvm_service_block_context_alloc(mm)")
    resident_migration = function.index("uvm_va_block_make_resident(")
    detached_copy = function.index("uvm_tracker_add_tracker_safe(tracker, &va_block->tracker)")

    guard_start = function.rfind("if (uvm_push_isolated_gpu_execution_enabled()", block_lock, guard)
    guard_end = function.index("}", guard)
    rejection = function[guard_start:guard_end]
    assert block_lock < guard_start < guard < va_space_retain
    assert guard_start < service_alloc
    assert guard_start < resident_migration
    assert guard_start < detached_copy
    assert "return NV_ERR_NOT_SUPPORTED;" in rejection
    return True


class R580UvmPmmEvictionTrackerLifetimeTests(unittest.TestCase):
    def test_guard_applies_before_eviction_side_effects_to_both_pinned_sources(self):
        for archive, digest, archive_root, tag in SOURCES:
            with self.subTest(source=tag):
                function = _extract_and_patch(archive, digest, archive_root)
                self.assertTrue(_validate_eviction_guard(function))

    def test_contract_rejects_missing_or_late_eviction_guard(self):
        archive, digest, archive_root, _ = SOURCES[0]
        function = _extract_and_patch(archive, digest, archive_root)
        condition = (
            "if (uvm_push_isolated_gpu_execution_enabled() && "
            "uvm_tracker_has_other_gpus(&va_block->tracker, gpu))"
        )
        self.assertIn(condition, function)
        without_guard = function.replace(
            condition + " return NV_ERR_NOT_SUPPORTED;",
            "if (false) return NV_ERR_NOT_SUPPORTED;",
            1,
        )
        with self.assertRaises((AssertionError, ValueError)):
            _validate_eviction_guard(without_guard)
        late = function.replace(condition, "", 1).replace(
            "mm = uvm_va_space_mm_retain(va_space);",
            "mm = uvm_va_space_mm_retain(va_space); "
            + condition
            + " return NV_ERR_NOT_SUPPORTED;",
            1,
        )
        with self.assertRaises((AssertionError, ValueError)):
            _validate_eviction_guard(late)

    def test_eviction_overlay_follows_the_pmm_allocation_guard(self):
        names = [patch.name for patch in probe.PATCHES]
        self.assertEqual(
            names[-2:],
            [
                "0013-reject-foreign-pmm-trackers-in-isolated-mode.patch",
                "0014-reject-foreign-pmm-trackers-before-eviction.patch",
            ],
        )


if __name__ == "__main__":
    unittest.main()
