# SPDX-License-Identifier: MIT
"""Guard the isolated PMM path against copying foreign raw channel pointers."""
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_178 = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
ARCHIVE_178_SHA256 = "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
ARCHIVE_196 = ROOT / (
    "build/experiments/private-open580-native-19607-v1-20261024/inputs/"
    "open580-580.196.07.tar.xz"
)
ARCHIVE_196_SHA256 = "21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084"
PATCH = ROOT / "patches/r580.178.04/uvm/0013-reject-foreign-pmm-trackers-in-isolated-mode.patch"
SOURCE_RELATIVE = "kernel-open/nvidia-uvm/uvm_pmm_gpu.c"


def _validate_isolated_pmm_guard(source):
    start = source.index("static NV_STATUS pmm_gpu_alloc(")
    end = source.index("NV_STATUS uvm_pmm_gpu_alloc_kernel(", start)
    body = source[start:end]
    lock = body.index("root_chunk_lock(pmm, root_chunk);")
    prune = body.index("uvm_tracker_remove_completed(&root_chunk->tracker);", lock)
    guard = body.index("uvm_tracker_has_other_gpus(&root_chunk->tracker, gpu)", prune)
    copy = body.index("uvm_tracker_add_tracker_safe(&local_tracker, &root_chunk->tracker)", guard)
    assert lock < prune < guard < copy

    guard_start = body.rfind("if (uvm_push_isolated_gpu_execution_enabled()", prune, guard)
    assert guard_start >= prune
    failure = body[guard_start:copy]
    assert "status = NV_ERR_NOT_SUPPORTED;" in failure
    assert "root_chunk_unlock(pmm, root_chunk);" in failure
    assert "i++;" in failure
    assert "goto error;" in failure
    return True


class R580UvmPmmTrackerLifetimeTests(unittest.TestCase):
    def _patched_source(self, archive_path, expected_sha256, archive_root):
        self.assertTrue(PATCH.is_file(), f"missing targeted PMM safety patch: {PATCH}")
        self.assertEqual(hashlib.sha256(archive_path.read_bytes()).hexdigest(), expected_sha256)
        with tempfile.TemporaryDirectory(prefix="r580-pmm-tracker-lifetime-") as directory:
            root = Path(directory)
            with tarfile.open(archive_path, "r:xz") as archive:
                stream = archive.extractfile(archive_root + SOURCE_RELATIVE)
                self.assertIsNotNone(stream)
                source = root / SOURCE_RELATIVE
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(stream.read())
            result = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
                cwd=root,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotRegex(result.stdout, r"\b(offset|fuzz)\b")
            return source.read_text()

    def test_guard_applies_exactly_to_both_pinned_r580_sources(self):
        for archive, digest, tag in (
            (ARCHIVE_178, ARCHIVE_178_SHA256, "580.178.04"),
            (ARCHIVE_196, ARCHIVE_196_SHA256, "580.196.07"),
        ):
            with self.subTest(source=tag):
                source = self._patched_source(
                    archive,
                    digest,
                    f"NVIDIA-kernel-module-source-{tag}/",
                )
                self.assertTrue(_validate_isolated_pmm_guard(source))

    def test_contract_rejects_unlocked_or_late_foreign_tracker_check(self):
        source = self._patched_source(
            ARCHIVE_178,
            ARCHIVE_178_SHA256,
            "NVIDIA-kernel-module-source-580.178.04/",
        )
        guard = "if (uvm_push_isolated_gpu_execution_enabled() &&\n            uvm_tracker_has_other_gpus(&root_chunk->tracker, gpu))"
        self.assertIn(guard, source)
        with self.assertRaises((AssertionError, ValueError)):
            _validate_isolated_pmm_guard(source.replace(guard, "if (false)", 1))


if __name__ == "__main__":
    unittest.main()
