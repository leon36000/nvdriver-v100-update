# SPDX-License-Identifier: MIT
"""Tests for the non-installing R580.178.04 compute-userland stage."""

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.stage_r58017804_compute_userland import (  # noqa: E402
    EXPECTED_GUEST_LIBRARY_SHA256,
    inventory_tree,
    validate_compute_userland,
)


def fake_compute_userland(root: Path, *, libcuda_bytes: bytes = b"pinned",
                          include_ptx: bool = True) -> Path:
    libdir = root / "usr/lib/x86_64-linux-gnu"
    libdir.mkdir(parents=True)
    libcuda = libdir / "libcuda.so.580.178.04"
    libcuda.write_bytes(libcuda_bytes)
    (libdir / "libcuda.so.1").symlink_to(libcuda.name)
    (libdir / "libcuda.so").symlink_to("libcuda.so.1")
    components = [
        "libcudadebugger.so.580.178.04",
        "libnvidia-ml.so.580.178.04",
        "libnvidia-nvvm.so.580.178.04",
        "libnvidia-nvvm70.so.4",
    ]
    if include_ptx:
        components.append("libnvidia-ptxjitcompiler.so.580.178.04")
    for index, name in enumerate(components):
        (libdir / name).write_bytes(f"component-{index}".encode())
    return root


class StageR58017804ComputeUserlandTests(unittest.TestCase):
    def test_inventory_hashes_regular_files_and_records_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            libdir = root / "usr/lib/x86_64-linux-gnu"
            libdir.mkdir(parents=True)
            binary = libdir / "libcuda.so.580.178.04"
            binary.write_bytes(b"cuda")
            (libdir / "libcuda.so.1").symlink_to(binary.name)
            entries = inventory_tree(root)
            by_path = {entry["path"]: entry for entry in entries}
            self.assertEqual(by_path["usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04"]["sha256"],
                             hashlib.sha256(b"cuda").hexdigest())
            self.assertEqual(by_path["usr/lib/x86_64-linux-gnu/libcuda.so.1"]["target"],
                             "libcuda.so.580.178.04")

    def test_inventory_rejects_escaping_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "stage"
            libdir = root / "usr/lib/x86_64-linux-gnu"
            libdir.mkdir(parents=True)
            (libdir / "libcuda.so.1").symlink_to("../../../../../../etc/passwd")
            with self.assertRaisesRegex(ValueError, "escapes stage root"):
                inventory_tree(root)

    def test_validation_requires_exact_guest_libcuda_and_compute_components(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = fake_compute_userland(Path(temporary))
            components = validate_compute_userland(
                root,
                inventory_tree(root),
                expected_libcuda_sha256=hashlib.sha256(b"pinned").hexdigest(),
            )
            self.assertEqual(components["libcuda"]["path"],
                             "usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04")

    def test_validation_rejects_guest_libcuda_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = fake_compute_userland(Path(temporary), libcuda_bytes=b"not-pinned")
            with self.assertRaisesRegex(ValueError, "guest libcuda hash"):
                validate_compute_userland(root, inventory_tree(root))

    def test_validation_rejects_missing_ptx_jit_component(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = fake_compute_userland(Path(temporary), include_ptx=False)
            with self.assertRaisesRegex(ValueError, "PTX JIT compiler"):
                validate_compute_userland(
                    root,
                    inventory_tree(root),
                    expected_libcuda_sha256=EXPECTED_GUEST_LIBRARY_SHA256,
                )


if __name__ == "__main__":
    unittest.main()
