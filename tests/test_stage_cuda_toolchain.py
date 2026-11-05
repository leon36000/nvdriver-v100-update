# SPDX-License-Identifier: MIT
"""Contract tests for the pinned non-installing CUDA toolchain stage."""
from pathlib import Path, PurePosixPath
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.stage_cuda_toolchain import (  # noqa: E402
    LOCK,
    _safe_unpack,
    _overlay_component,
    _ensure_target_layout,
    validate_lock,
)


class StageCudaToolchainTests(unittest.TestCase):
    def setUp(self):
        self.lock = validate_lock(__import__("json").loads(LOCK.read_text(encoding="utf-8")))

    def test_lock_has_required_components_and_excludes_driver_packages(self):
        names = {row["name"] for row in self.lock["components"]}
        self.assertIn("cuda_nvcc", names)
        self.assertIn("cuda_cudart", names)
        self.assertIn("libcublas", names)
        self.assertNotIn("nvidia_driver", names)
        self.assertFalse(any(name in {"nvidia_driver", "cuda_compat", "fabricmanager"}
                             for name in names))

    def test_lock_rejects_driver_package(self):
        bad = {**self.lock, "components": [*self.lock["components"],
               {"name": "nvidia_driver", "version": "1", "path":
                "nvidia_driver/linux-x86_64/driver-archive.tar.xz", "sha256": "0" * 64,
                "bytes": 1}]}
        with self.assertRaisesRegex(ValueError, "unknown, duplicated, or a driver"):
            validate_lock(bad)

    def test_lock_rejects_path_traversal(self):
        bad = {**self.lock, "components": [dict(row) for row in self.lock["components"]]}
        bad["components"][0]["path"] = "../cuda_nvcc/linux-x86_64/compiler-archive.tar.xz"
        with self.assertRaisesRegex(ValueError, "unsafe or malformed"):
            validate_lock(bad)

    def test_archive_extraction_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "bad.tar.xz"
            with tarfile.open(archive, "w:xz") as tar:
                info = tarfile.TarInfo("cuda-test-archive/../../escape")
                payload = b"escape"
                info.size = len(payload)
                import io
                tar.addfile(info, io.BytesIO(payload))
            with self.assertRaisesRegex(ValueError, "unsafe member path"):
                _safe_unpack(archive, root / "out")
            self.assertFalse((root / "escape").exists())

    def test_overlay_rejects_conflicting_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second, merged = root / "first", root / "second", root / "merged"
            for component, content in ((first, b"first"), (second, b"second")):
                path = component / "include/common.h"
                path.parent.mkdir(parents=True)
                path.write_bytes(content)
            _overlay_component(first, merged)
            with self.assertRaisesRegex(ValueError, "file collision"):
                _overlay_component(second, merged)

    def test_overlay_keeps_identical_shared_headers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second, merged = root / "first", root / "second", root / "merged"
            for component in (first, second):
                path = component / "include/common.h"
                path.parent.mkdir(parents=True)
                path.write_bytes(b"same")
            _overlay_component(first, merged)
            _overlay_component(second, merged)
            self.assertEqual((merged / "include/common.h").read_bytes(), b"same")

    def test_overlay_retains_package_licenses_without_merging_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second, merged = root / "first", root / "second", root / "merged"
            first.mkdir()
            second.mkdir()
            (first / "LICENSE").write_text("license one", encoding="utf-8")
            (second / "LICENSE").write_text("license two", encoding="utf-8")
            _overlay_component(first, merged)
            _overlay_component(second, merged)
            self.assertFalse((merged / "LICENSE").exists())
            self.assertEqual((first / "LICENSE").read_text(encoding="utf-8"), "license one")
            self.assertEqual((second / "LICENSE").read_text(encoding="utf-8"), "license two")

    def test_nvcc_target_alias_resolves_to_the_staged_toolkit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "toolkit"
            root.mkdir()
            _ensure_target_layout(root)
            target = root / "targets/x86_64-linux"
            self.assertTrue(target.is_symlink())
            self.assertEqual(target.resolve(strict=True), root.resolve(strict=True))


if __name__ == "__main__":
    unittest.main()
