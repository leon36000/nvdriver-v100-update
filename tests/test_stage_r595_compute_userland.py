# SPDX-License-Identifier: MIT
"""Tests for the non-installing R595.99.02 compute-userland stage."""

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.stage_r595_compute_userland import (  # noqa: E402
    LIBDIR,
    LOADER_LINKS,
    REQUIRED_LIBRARIES,
    inventory_tree,
    validate_provenance,
    validate_compute_userland,
)


def fake_compute_userland(root: Path) -> Path:
    libdir = root / Path(*LIBDIR.parts)
    libdir.mkdir(parents=True)
    for index, name in enumerate(REQUIRED_LIBRARIES.values()):
        (libdir / name).write_bytes(f"r595-component-{index}".encode())
    for name, target in LOADER_LINKS.items():
        (libdir / name).symlink_to(target)
    return root


class StageR595ComputeUserlandTests(unittest.TestCase):
    def test_provenance_matches_pinned_signed_archive_audit(self):
        provenance = validate_provenance()
        self.assertEqual(provenance["package_signed_source"], "resolute-updates/restricted")
        self.assertEqual(provenance["signing_fingerprint"],
                         "F6ECB3762474EDA9D21B7022871920D1991BC93C")

    def test_provenance_rejects_changed_archive_audit_hash(self):
        with mock.patch("tools.stage_r595_compute_userland.ARCHIVE_AUDIT_SHA256", "0" * 64):
            with self.assertRaisesRegex(ValueError, "archive audit hash differs"):
                validate_provenance()

    def test_inventory_hashes_components_and_records_loader_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = fake_compute_userland(Path(temporary))
            entries = inventory_tree(root)
            components = validate_compute_userland(root, entries)
            by_path = {entry["path"]: entry for entry in entries}
            cuda_path = (LIBDIR / REQUIRED_LIBRARIES["libcuda"]).as_posix()
            self.assertEqual(components["libcuda"]["sha256"],
                             hashlib.sha256(b"r595-component-0").hexdigest())
            self.assertEqual(by_path[(LIBDIR / "libcuda.so.1").as_posix()]["target"],
                             REQUIRED_LIBRARIES["libcuda"])
            self.assertEqual(components["libcuda"]["path"], cuda_path)

    def test_inventory_rejects_escaping_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "stage"
            libdir = root / Path(*LIBDIR.parts)
            libdir.mkdir(parents=True)
            (libdir / "libcuda.so.1").symlink_to("../../../../../../etc/passwd")
            with self.assertRaisesRegex(ValueError, "escapes stage root"):
                inventory_tree(root)

    def test_validation_rejects_missing_required_runtime_library(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = fake_compute_userland(Path(temporary))
            libdir = root / Path(*LIBDIR.parts)
            (libdir / REQUIRED_LIBRARIES["ptx_jit_compiler"]).unlink()
            (libdir / "libnvidia-ptxjitcompiler.so.1").unlink()
            (libdir / "libnvidia-ptxjitcompiler.so").unlink()
            with self.assertRaisesRegex(ValueError, "libnvidia-ptxjitcompiler"):
                validate_compute_userland(root, inventory_tree(root))

    def test_validation_rejects_changed_loader_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = fake_compute_userland(Path(temporary))
            link = root / Path(*LIBDIR.parts) / "libcuda.so.1"
            link.unlink()
            link.symlink_to("libnvidia-ml.so.595.99.02")
            with self.assertRaisesRegex(ValueError, "loader symlink"):
                validate_compute_userland(root, inventory_tree(root))

    def test_validation_rejects_missing_cuda_debugger(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = fake_compute_userland(Path(temporary))
            libdir = root / Path(*LIBDIR.parts)
            (libdir / REQUIRED_LIBRARIES["cuda_debugger"]).unlink()
            (libdir / "libcudadebugger.so.1").unlink()
            with self.assertRaisesRegex(ValueError, "libcudadebugger"):
                validate_compute_userland(root, inventory_tree(root))


if __name__ == "__main__":
    unittest.main()
