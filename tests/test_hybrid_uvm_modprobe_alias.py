# SPDX-License-Identifier: MIT
"""Verify standard UVM modprobe requests resolve to the private R580 module."""
from pathlib import Path
import hashlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "packaging/modprobe.d/hybrid580-uvm.conf"
KERNEL_RELEASE = "7.0.0-38-generic"
MODULE_FIXTURES = {
    "nvidia-uvm.ko": (
        ROOT / "build/experiments/r580-uvm-frontend-currentpatch-v1-20261023T2254Z/"
        "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm.ko",
        "6774640660bfb7376e0bb572ef470df10cb4d938ce3686996393ff54a8e8c8dd",
    ),
    "hybrid580-uvm.ko": (
        ROOT / "build/experiments/r580-uvm-private-owner-stock-chardev-v2-20261027T214000Z/"
        "NVIDIA-kernel-module-source-580.178.04/kernel-open/hybrid580-uvm.ko",
        "9b5b1285b6178c84f5fa56317b6178a587f81e7882199d658bec28813576fbec",
    ),
    "hybrid580_frontend.ko": (
        ROOT / "build/experiments/hybrid-frontend-r580-version-check-copyout-v2-20261024/"
        "hybrid580_frontend.ko",
        "4e4ca112483049bfd428c3b39696c4098d18f69ca56a82d53fb79aeef3e2d77c",
    ),
    "hybrid580_open.ko": (
        ROOT / "build/experiments/private-open580-version-check-v4-20261024/private/"
        "NVIDIA-kernel-module-source-580.178.04/kernel-open/hybrid580_open.ko",
        "2eb5a2bb97452a6aeaba497b0f820da1be925f062d9209f614a73304527e993b",
    ),
    "hybrid580_legacy.ko": (
        ROOT / "build/experiments/private-proprietary-version-check-v8-20261023/"
        "nvidia-580.178.04/hybrid580_legacy.ko",
        "03e4dcd0c2f96e6d435b77c5253101ba62a80da43f911ab865b1352dc40bb7b8",
    ),
}


class HybridUvmModprobeAliasTests(unittest.TestCase):
    def test_standard_uvm_alias_resolves_to_the_private_module(self):
        config_text = CONFIG.read_text(encoding="utf-8")
        aliases = [
            line.split()
            for line in config_text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(aliases, [["alias", "nvidia-uvm", "hybrid580_uvm"]])

        modprobe = shutil.which("modprobe")
        if modprobe is None:
            return

        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "modprobe.conf"
            config.write_text(config_text, encoding="utf-8")
            result = subprocess.run(
                [modprobe, "--config", str(config), "--resolve-alias", "nvidia-uvm"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["hybrid580_uvm"])
        self.assertEqual(result.stderr, "")

    def test_alias_routes_to_private_owner_with_standard_module_in_isolated_db(self):
        modprobe = shutil.which("modprobe")
        depmod = shutil.which("depmod")
        if modprobe is None or depmod is None:
            self.fail("modprobe and depmod are required for the isolated resolver test")

        with tempfile.TemporaryDirectory(prefix="hybrid-uvm-modprobe-db-") as temporary:
            root = Path(temporary)
            module_dir = root / "lib/modules" / KERNEL_RELEASE / "updates"
            module_dir.mkdir(parents=True)
            for name, (source, expected_sha256) in MODULE_FIXTURES.items():
                self.assertTrue(source.is_file(), f"required pinned module is missing: {source}")
                digest = hashlib.sha256(source.read_bytes()).hexdigest()
                self.assertEqual(digest, expected_sha256, f"pinned module changed: {source}")
                shutil.copyfile(source, module_dir / name)

            modules_dir = module_dir.parent
            for metadata in ("modules.order", "modules.builtin", "modules.builtin.modinfo"):
                (modules_dir / metadata).write_text("", encoding="ascii")
            generated = subprocess.run(
                [depmod, "-a", "-b", str(root), KERNEL_RELEASE],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            dependency_index = (modules_dir / "modules.dep").read_text(encoding="utf-8")
            self.assertIn("updates/nvidia-uvm.ko:", dependency_index)
            self.assertIn("updates/hybrid580-uvm.ko:", dependency_index)

            config = root / "modprobe.conf"
            config.write_text(CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
            result = subprocess.run(
                [modprobe, "--config", str(config), "--dirname", str(root),
                 "--set-version", KERNEL_RELEASE, "--show-depends", "nvidia-uvm"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        selected = [line for line in result.stdout.splitlines()
                    if line.rstrip().endswith("hybrid580-uvm.ko")]
        self.assertEqual(len(selected), 1, result.stdout)
        self.assertNotIn("nvidia-uvm.ko", result.stdout)
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
