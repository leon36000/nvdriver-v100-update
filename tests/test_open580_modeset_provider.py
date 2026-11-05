# SPDX-License-Identifier: MIT
"""Tests for the isolated R580 Open NVKMS provider-link prototype."""
from pathlib import Path
import importlib.util
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_open580_modeset_provider",
    ROOT / "tools/build_open580_modeset_provider.py")
BUILDER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(BUILDER)


def fixture_tree(root: Path) -> Path:
    source = root / "source"
    (source / "nvidia-modeset").mkdir(parents=True)
    (source / "nvidia-modeset/nvidia-modeset.Kbuild").write_text(
        "NVIDIA_MODESET_CFLAGS += -I$(src)/nvidia-modeset "
        "-I$(src)/common/inc\n")
    (source / "Module.symvers").write_text(
        "0x1234abcd\thybrid580_open_nvidia_get_rm_ops\t"
        "hybrid580_open\tEXPORT_SYMBOL_GPL\t\n")
    return source


class Open580ModesetProviderTests(unittest.TestCase):
    def test_namespaces_only_the_modeset_rm_ops_import(self):
        with tempfile.TemporaryDirectory() as directory:
            source = fixture_tree(Path(directory))
            kbuild = source / "nvidia-modeset/nvidia-modeset.Kbuild"
            before, after = BUILDER.add_provider_namespace(kbuild)
            self.assertEqual(before, "NVIDIA_MODESET_CFLAGS += -I$(src)/nvidia-modeset -I$(src)/common/inc\n")
            self.assertIn(BUILDER.NAMESPACE_DEFINE, after)
            self.assertEqual(after.count(BUILDER.NAMESPACE_DEFINE), 1)
            BUILDER.add_provider_namespace(kbuild)
            self.assertEqual(after, kbuild.read_text())

    def test_namespace_define_requires_one_known_kbuild_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            kbuild = Path(directory) / "nvidia-modeset.Kbuild"
            kbuild.write_text("unknown Kbuild layout\n")
            with self.assertRaisesRegex(ValueError, "expected one NVKMS CFLAGS anchor"):
                BUILDER.add_provider_namespace(kbuild)

    def test_import_contract_requires_namespaced_symbol_and_matching_crc(self):
        symvers = BUILDER.parse_symvers(
            "0x1234abcd\thybrid580_open_nvidia_get_rm_ops\t"
            "hybrid580_open\tEXPORT_SYMBOL_GPL\t\n")
        actual = BUILDER.verify_provider_import(
            ["hybrid580_open_nvidia_get_rm_ops"],
            {"hybrid580_open_nvidia_get_rm_ops": "0x1234abcd"}, symvers)
        self.assertEqual(actual["crc"], "0x1234abcd")
        self.assertEqual(actual["provider_module"], "hybrid580_open")

    def test_import_contract_rejects_stock_name_crc_drift_and_missing_import(self):
        symvers = BUILDER.parse_symvers(
            "0x1234abcd\thybrid580_open_nvidia_get_rm_ops\t"
            "hybrid580_open\tEXPORT_SYMBOL_GPL\t\n")
        cases = [
            (["nvidia_get_rm_ops"], {"nvidia_get_rm_ops": "0x1234abcd"},
             "stock symbol remains"),
            (["hybrid580_open_nvidia_get_rm_ops"],
             {"hybrid580_open_nvidia_get_rm_ops": "0x00000000"}, "CRC mismatch"),
            ([], {}, "namespaced provider import is absent"),
        ]
        for undefined, versions, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    BUILDER.verify_provider_import(undefined, versions, symvers)

    def test_scratch_preparation_refuses_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = fixture_tree(root)
            scratch = root / "scratch"
            BUILDER.prepare_scratch(source, scratch)
            self.assertEqual(
                (scratch / "nvidia-modeset/nvidia-modeset.Kbuild").read_text(),
                (source / "nvidia-modeset/nvidia-modeset.Kbuild").read_text())
            sentinel = scratch / "sentinel"
            sentinel.write_text("keep")
            with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
                BUILDER.prepare_scratch(source, scratch)
            self.assertEqual(sentinel.read_text(), "keep")

    def test_stages_only_the_hash_pinned_release_modeset_core_object(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "reference.o_binary"
            source.write_bytes(b"release-pinned NVKMS core")
            destination = root / "scratch/nvidia-modeset/nv-modeset-kernel.o_binary"
            digest = BUILDER.sha256_file(source)
            report = BUILDER.stage_modeset_binary(source, destination, digest)
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertEqual(report["sha256"], digest)
            self.assertEqual(report["bytes"], len(source.read_bytes()))

    def test_modeset_core_staging_rejects_hash_drift_and_existing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "reference.o_binary"
            source.write_bytes(b"unexpected input")
            destination = root / "scratch/nv-modeset-kernel.o_binary"
            with self.assertRaisesRegex(ValueError, "modeset core hash changed"):
                BUILDER.stage_modeset_binary(source, destination, "0" * 64)
            self.assertFalse(destination.exists())
            digest = BUILDER.sha256_file(source)
            BUILDER.stage_modeset_binary(source, destination, digest)
            with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
                BUILDER.stage_modeset_binary(source, destination, digest)

    def test_modpost_receives_provider_symvers_as_a_separate_input(self):
        command = BUILDER.make_build_command(
            Path("/scratch/kernel-open"), "7.0.0-38-generic", 4,
            Path("/scratch/provider-Module.symvers"))
        self.assertIn("KBUILD_EXTRA_SYMBOLS=/scratch/provider-Module.symvers", command)
        self.assertIn("NV_KERNEL_MODULES=nvidia-modeset", command)
        self.assertIn("modules", command)
        self.assertNotIn("modules_install", command)
        self.assertNotIn("install", command)

    def test_provider_symvers_staging_is_hash_pinned_and_non_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.symvers"
            source.write_text("0x1234abcd\tprovider_symbol\tprovider\tEXPORT_SYMBOL\n")
            destination = root / "provider-copy.symvers"
            digest = BUILDER.sha256_file(source)
            report = BUILDER.stage_provider_symvers(source, destination, digest)
            self.assertEqual(report["sha256"], digest)
            self.assertEqual(destination.read_bytes(), source.read_bytes())

    def test_fixed_char_device_audit_accepts_vendor_wrapping_and_whitespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "common/inc").mkdir(parents=True)
            (root / "nvidia-modeset").mkdir()
            (root / "common/inc/nv-chardev-numbers.h").write_text(
                "#define NV_MAJOR_DEVICE_NUMBER  195\n"
                "#define NV_MINOR_DEVICE_NUMBER_MODESET_DEVICE      254\n")
            (root / "nvidia-modeset/nvidia-modeset-linux.c").write_text(
                "#define NVKMS_RDEV  (MKDEV(NV_MAJOR_DEVICE_NUMBER, \\\n"
                " NV_MINOR_DEVICE_NUMBER_MODESET_DEVICE))\n"
                "static int nvkms_register_chrdev(void) { return \\\n"
                "register_chrdev_region(NVKMS_RDEV, 1, \"nvidia-modeset\"); }\n")
            self.assertEqual(BUILDER.verify_fixed_char_device(root),
                             {"major": 195, "minor": 254,
                              "source_reservation_verified": True})

    def test_fixed_char_device_audit_rejects_a_changed_minor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "common/inc").mkdir(parents=True)
            (root / "nvidia-modeset").mkdir()
            (root / "common/inc/nv-chardev-numbers.h").write_text(
                "#define NV_MAJOR_DEVICE_NUMBER 195\n"
                "#define NV_MINOR_DEVICE_NUMBER_MODESET_DEVICE 255\n")
            (root / "nvidia-modeset/nvidia-modeset-linux.c").write_text(
                "#define NVKMS_RDEV MKDEV(NV_MAJOR_DEVICE_NUMBER, "
                "NV_MINOR_DEVICE_NUMBER_MODESET_DEVICE)\n"
                "static int nvkms_register_chrdev(void) { "
                "return register_chrdev_region(NVKMS_RDEV, 1, \"nvidia-modeset\"); }\n")
            with self.assertRaisesRegex(ValueError, "fixed NVKMS char-device"):
                BUILDER.verify_fixed_char_device(root)


if __name__ == "__main__":
    unittest.main()
