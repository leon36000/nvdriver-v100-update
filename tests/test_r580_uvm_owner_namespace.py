# SPDX-License-Identifier: MIT
"""Contracts for building R580 UVM under a private module/device identity."""
from pathlib import Path
import tempfile
import unittest

from tools.probe_r580_uvm_isolated_execution import apply_owner_namespace


class R580UvmOwnerNamespaceTests(unittest.TestCase):
    def _tree(self, root: Path) -> None:
        files = {
            "nvidia-uvm/nvidia-uvm.Kbuild": (
                "obj-m += nvidia-uvm.o\n"
                "nvidia-uvm-y := $(NVIDIA_UVM_OBJECTS)\n"
                "NVIDIA_UVM_KO = nvidia-uvm/nvidia-uvm.ko\n"
            ),
            "nvidia-uvm/uvm.c": (
                '#define NVIDIA_UVM_DEVICE_NAME          "nvidia-uvm"\n'
            ),
            "nvidia-uvm/uvm_procfs.c": (
                '#define UVM_PROC_DIR_NAME "driver/nvidia-uvm"\n'
            ),
            "nvidia-uvm/uvm_linux.h": (
                '#define NVIDIA_UVM_PRETTY_PRINTING_PREFIX "nvidia-uvm: "\n'
            ),
        }
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def test_private_owner_renames_module_device_procfs_and_log_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._tree(root)

            result = apply_owner_namespace(root, "hybrid580")

            self.assertEqual(result["module_filename"], "hybrid580-uvm.ko")
            self.assertEqual(result["module_name"], "hybrid580_uvm")
            self.assertEqual(result["device_name"], "hybrid580-uvm")
            self.assertEqual(result["procfs_path"], "driver/hybrid580-uvm")
            self.assertIn("obj-m += hybrid580-uvm.o", (root / "nvidia-uvm/nvidia-uvm.Kbuild").read_text())
            self.assertIn("hybrid580-uvm-y :=", (root / "nvidia-uvm/nvidia-uvm.Kbuild").read_text())
            self.assertIn('"hybrid580-uvm"', (root / "nvidia-uvm/uvm.c").read_text())
            self.assertIn('"driver/hybrid580-uvm"', (root / "nvidia-uvm/uvm_procfs.c").read_text())
            self.assertIn('"hybrid580-uvm: "', (root / "nvidia-uvm/uvm_linux.h").read_text())

    def test_private_module_can_keep_stock_chardev_registration_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._tree(root)

            result = apply_owner_namespace(
                root, "hybrid580", chardev_name="nvidia-uvm")

            self.assertEqual(result["module_name"], "hybrid580_uvm")
            self.assertEqual(result["device_name"], "nvidia-uvm")
            self.assertEqual(result["procfs_path"], "driver/hybrid580-uvm")
            self.assertIn(
                '#define NVIDIA_UVM_DEVICE_NAME          "nvidia-uvm"',
                (root / "nvidia-uvm/uvm.c").read_text())
            self.assertIn(
                '#define NVIDIA_UVM_PRETTY_PRINTING_PREFIX "hybrid580-uvm: "',
                (root / "nvidia-uvm/uvm_linux.h").read_text())

    def test_invalid_chardev_name_fails_before_changing_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._tree(root)
            before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}

            for invalid in ("../nvidia", "nvidia-uvm\nbroken", 'nvidia"uvm'):
                with self.subTest(invalid=invalid):
                    with self.assertRaisesRegex(ValueError, "character-device name"):
                        apply_owner_namespace(root, "hybrid580", chardev_name=invalid)

            self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_invalid_owner_name_fails_before_changing_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._tree(root)
            before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}

            for invalid in ("../nvidia", "nvidia"):
                with self.subTest(invalid=invalid):
                    with self.assertRaisesRegex(ValueError, "owner namespace"):
                        apply_owner_namespace(root, invalid)

            self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_missing_or_ambiguous_upstream_identity_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._tree(root)
            path = root / "nvidia-uvm/uvm.c"
            path.write_text(
                path.read_text() +
                '#define NVIDIA_UVM_DEVICE_NAME          "nvidia-uvm"\n'
            )
            before = {item: item.read_bytes() for item in root.rglob("*") if item.is_file()}

            with self.assertRaisesRegex(ValueError, "exactly once"):
                apply_owner_namespace(root, "hybrid580")
            self.assertEqual(before, {item: item.read_bytes() for item in before})


if __name__ == "__main__":
    unittest.main()
