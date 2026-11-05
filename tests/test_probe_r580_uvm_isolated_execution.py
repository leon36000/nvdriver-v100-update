# SPDX-License-Identifier: MIT
"""Fail-closed contracts for the reproducible R580 UVM build probe."""
from pathlib import Path
import importlib
import hashlib
import io
import shutil
import subprocess
import tarfile
import tempfile
import unittest


probe = importlib.import_module("tools.probe_r580_uvm_isolated_execution")
audit = importlib.import_module("tools.audit_uvm_owner_isolation_architecture")


def make_archive(path: Path, members: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w") as archive:
        for name, payload in members:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))


class ProbeR580UvmIsolatedExecutionTests(unittest.TestCase):
    def test_kernel_config_selects_the_matching_modversion_format(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / '.config'
            config.write_text('CONFIG_MODVERSIONS=y\nCONFIG_EXTENDED_MODVERSIONS=y\n')
            self.assertTrue(probe.kernel_extended_modversions_enabled(config))
            config.write_text('CONFIG_MODVERSIONS=y\n# CONFIG_EXTENDED_MODVERSIONS is not set\n')
            self.assertFalse(probe.kernel_extended_modversions_enabled(config))
            config.write_text('CONFIG_MODVERSIONS=y\n')
            self.assertFalse(probe.kernel_extended_modversions_enabled(config))

    def test_archive_paths_are_confined_to_the_pinned_source_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "bad.tar"
            make_archive(
                archive_path,
                [
                    (f"NVIDIA-kernel-module-source-{probe.SOURCE_TAG}/safe.c", b"ok"),
                    (f"NVIDIA-kernel-module-source-{probe.SOURCE_TAG}/../../escape", b"bad"),
                ],
            )
            with tarfile.open(archive_path, "r:") as archive:
                with self.assertRaisesRegex(ValueError, "unsafe archive path"):
                    probe._validated_archive_members(archive)

    def test_archive_links_and_duplicate_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "bad.tar"
            with tarfile.open(archive_path, "w") as archive:
                link = tarfile.TarInfo(
                    f"NVIDIA-kernel-module-source-{probe.SOURCE_TAG}/linked.c"
                )
                link.type = tarfile.SYMTYPE
                link.linkname = "target.c"
                archive.addfile(link)
            with tarfile.open(archive_path, "r:") as archive:
                with self.assertRaisesRegex(ValueError, "non-regular archive member"):
                    probe._validated_archive_members(archive)

            make_archive(
                archive_path,
                [
                    (f"NVIDIA-kernel-module-source-{probe.SOURCE_TAG}/same.c", b"one"),
                    (f"NVIDIA-kernel-module-source-{probe.SOURCE_TAG}/same.c", b"two"),
                ],
            )
            with tarfile.open(archive_path, "r:") as archive:
                with self.assertRaisesRegex(ValueError, "duplicate archive path"):
                    probe._validated_archive_members(archive)

    def test_extraction_creates_only_files_under_the_package_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "safe.tar"
            package_name = f"NVIDIA-kernel-module-source-{probe.SOURCE_TAG}"
            make_archive(archive_path, [(f"{package_name}/kernel-open/test.c", b"ok")])
            destination = root / "fresh"
            extracted = probe.extract_source_archive(archive_path, destination)
            self.assertEqual(extracted, destination / package_name)
            self.assertEqual((extracted / "kernel-open/test.c").read_bytes(), b"ok")
            self.assertFalse((root / "escape").exists())

    def test_archive_digest_mismatch_is_rejected_before_creating_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "safe.tar"
            package_name = f"NVIDIA-kernel-module-source-{probe.SOURCE_TAG}"
            make_archive(archive_path, [(f"{package_name}/test.c", b"ok")])
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            destination = root / "fresh"
            self.assertNotEqual(digest, "0" * 64)
            with self.assertRaisesRegex(ValueError, "archive SHA-256 mismatch"):
                probe.extract_source_archive(archive_path, destination, "0" * 64)
            self.assertFalse(destination.exists())

    def test_source_hashes_are_derived_from_the_build_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary)
            for relative in probe.SOURCE_LABELS:
                source = audit.SOURCE_ROOT / relative
                if relative == "nvidia/nvidia.Kbuild":
                    member_name = (
                        f"NVIDIA-kernel-module-source-{probe.SOURCE_TAG}/"
                        "kernel-open/nvidia/nvidia.Kbuild"
                    )
                    with tarfile.open(probe.SOURCE_ARCHIVE, "r:xz") as archive:
                        source_bytes = archive.extractfile(member_name).read()
                    target = source_root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source_bytes)
                    continue
                if relative == "nvidia/nv_uvm_interface.c":
                    source = (probe.ROOT /
                              "build/experiments/r580-uvm-isolated-gpu-execution-v5-20261023T2130Z"
                              "/NVIDIA-kernel-module-source-580.178.04/kernel-open" / relative)
                target = source_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            hashes = probe._verified_source_hashes(source_root)
            self.assertEqual(set(hashes), set(probe.SOURCE_LABELS))

            changed = source_root / next(iter(probe.SOURCE_LABELS))
            changed.write_bytes(changed.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "pinned UVM source changed"):
                probe._verified_source_hashes(source_root)

    def test_build_selects_driver_and_uvm_kbuild_fragments_together(self):
        command = probe._build_command(Path("/scratch/source"), "7.0.0-38-generic", 8)
        self.assertIn("NV_KERNEL_MODULES=nvidia nvidia-uvm", command)
        self.assertNotIn("NV_KERNEL_MODULES=nvidia-uvm", command)

    def test_chardev_name_requires_private_owner_before_creating_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scratch = root / "scratch"
            with self.assertRaisesRegex(ValueError, "requires --owner-namespace"):
                probe.build_probe(
                    scratch,
                    root / "report.json",
                    root / "build.log",
                    "7.0.0-38-generic",
                    1,
                    chardev_name="nvidia-uvm",
                )
            self.assertFalse(scratch.exists())

    def test_frontend_consumer_build_selects_only_uvm_and_pins_frontend_symvers(self):
        frontend_symvers = Path("/scratch/frontend/Module.symvers")
        command = probe._build_command(
            Path("/scratch/source"), "7.0.0-38-generic", 8, frontend_symvers
        )
        self.assertIn("NV_KERNEL_MODULES=nvidia-uvm", command)
        self.assertIn(
            f"KBUILD_EXTRA_SYMBOLS={frontend_symvers}", command
        )
        self.assertNotIn("NV_KERNEL_MODULES=nvidia nvidia-uvm", command)

    def test_full_pair_excludes_frontend_only_dispatch_overlays(self):
        patches = probe._patches_for_build(None)
        names = [path.name for path in patches]

        self.assertEqual(
            names,
            [
                "0002-hybrid-isolated-gpu-execution.patch",
                "0003-pass-control-fd-to-dup-memory.patch",
                "0004-share-linux-conftests-with-uvm-consumer.patch",
                "0007-reject-cross-gpu-tracker-dependencies.patch",
                "0008-pmm-allocation-outside-va-block-lock.patch",
                "0009-reject-hmm-gpu-migration-in-isolated-mode.patch",
                "0010-reject-unsupported-isolated-staged-migrations.patch",
                "0011-preflight-unsupported-staging-before-unmap.patch",
                "0012-exact-isolated-staged-page-mask.patch",
                "0013-reject-foreign-pmm-trackers-in-isolated-mode.patch",
                "0014-reject-foreign-pmm-trackers-before-eviction.patch",
            ],
        )

    def test_r580_196_profile_pins_its_archive_hashes_and_kbuild_overlay(self):
        profile = probe.SOURCE_PROFILES["580.196.07"]
        self.assertEqual(
            hashlib.sha256(Path(profile["archive"]).read_bytes()).hexdigest(),
            profile["archive_sha256"],
        )
        full_pair = probe._patches_for_build(None, "580.196.07")
        frontend_consumer = probe._patches_for_build(
            Path("/scratch/frontend/Module.symvers"), "580.196.07"
        )
        self.assertEqual(full_pair[2], probe.R580_196_KBUILD_PATCH)
        self.assertEqual(frontend_consumer[2], probe.R580_196_KBUILD_PATCH)
        self.assertNotIn(
            probe.PATCHES[2],
            full_pair,
            "the 178.04 conftest rewrite must not be applied to 196.07",
        )
        self.assertEqual(len(frontend_consumer), len(probe.PATCHES))

    def test_r580_196_source_profile_extracts_and_verifies_pinned_inputs(self):
        profile = probe.SOURCE_PROFILES["580.196.07"]
        with tempfile.TemporaryDirectory(prefix="probe-r580-196-") as temporary:
            destination = Path(temporary) / "source"
            package = probe.extract_source_archive(
                profile["archive"],
                destination,
                expected_sha256=profile["archive_sha256"],
                source_tag="580.196.07",
            )
            self.assertEqual(package.name, "NVIDIA-kernel-module-source-580.196.07")
            hashes = probe._verified_source_hashes(
                package / "kernel-open", expected_hashes=profile["source_hashes"]
            )
            self.assertEqual(set(hashes), set(probe.SOURCE_LABELS))

    def test_frontend_consumer_build_includes_all_control_fd_overlays(self):
        patches = probe._patches_for_build(Path("/scratch/frontend/Module.symvers"))

        self.assertEqual(tuple(patches), probe.PATCHES)

    def test_frontend_consumer_binding_requires_matching_crcs_and_dependency(self):
        module_versions = {
            "nvUvmInterfaceDupMemoryWithControlFd": "0x1234abcd",
            "nvUvmInterfaceMemoryFree": "0xabcdef01",
        }
        symvers = (
            "0x1234abcd nvUvmInterfaceDupMemoryWithControlFd "
            "hybrid580_frontend EXPORT_SYMBOL\n"
            "0xabcdef01 nvUvmInterfaceMemoryFree hybrid580_frontend EXPORT_SYMBOL\n"
        )
        good = probe._verify_frontend_consumer_binding(
            module_versions, symvers, "hybrid580_frontend\n"
        )
        self.assertTrue(good["passed"])
        self.assertEqual(good["uvm_interface_import_count"], 2)
        self.assertEqual(good["matching_frontend_crc_count"], 2)

        wrong_dependency = probe._verify_frontend_consumer_binding(
            module_versions, symvers, "nvidia\n"
        )
        self.assertFalse(wrong_dependency["passed"])
        extra_provider = probe._verify_frontend_consumer_binding(
            module_versions, symvers, "hybrid580_frontend,unrelated_provider\n"
        )
        self.assertFalse(extra_provider["passed"])
        self.assertFalse(extra_provider["frontend_is_only_provider_dependency"])
        wrong_crc = probe._verify_frontend_consumer_binding(
            module_versions, symvers.replace("0x1234abcd", "0x1234abce", 1),
            "hybrid580_frontend\n",
        )
        self.assertFalse(wrong_crc["passed"])
        self.assertEqual(len(wrong_crc["mismatched_symbols"]), 1)

    def test_frontend_consumer_binding_supports_standard_nvidia_owner(self):
        module_versions = {
            "nvUvmInterfaceDupMemoryWithControlFd": "0x1234abcd",
            "nvUvmInterfaceMemoryFree": "0xabcdef01",
        }
        symvers = (
            "0x1234abcd nvUvmInterfaceDupMemoryWithControlFd nvidia EXPORT_SYMBOL\n"
            "0xabcdef01 nvUvmInterfaceMemoryFree nvidia EXPORT_SYMBOL\n"
        )
        good = probe._verify_frontend_consumer_binding(
            module_versions, symvers, "nvidia\n", frontend_module_name="nvidia"
        )
        self.assertTrue(good["passed"])
        self.assertEqual(good["frontend_module_name"], "nvidia")
        self.assertEqual(good["matching_frontend_crc_count"], 2)

        wrong_owner = probe._verify_frontend_consumer_binding(
            module_versions, symvers, "hybrid580_frontend\n",
            frontend_module_name="hybrid580_frontend",
        )
        self.assertFalse(wrong_owner["passed"])
        self.assertEqual(wrong_owner["matching_frontend_crc_count"], 0)

        wrong_dependency = probe._verify_frontend_consumer_binding(
            module_versions, symvers, "hybrid580_frontend\n",
            frontend_module_name="nvidia",
        )
        self.assertFalse(wrong_dependency["passed"])
        self.assertFalse(wrong_dependency["frontend_is_only_provider_dependency"])

    def test_frontend_consumer_binding_accepts_guest_kbuild_owner_object_path(self):
        module_versions = {"nvUvmInterfaceMemoryFree": "0xabcdef01"}
        symvers = (
            "0xabcdef01 nvUvmInterfaceMemoryFree "
            "/tmp/kbuild/nvidia EXPORT_SYMBOL\n"
        )
        result = probe._verify_frontend_consumer_binding(
            module_versions, symvers, "nvidia\n", frontend_module_name="nvidia"
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["matching_frontend_crc_count"], 1)
        bad_owner = symvers.replace("/tmp/kbuild/nvidia ", "/tmp/kbuild/not-nvidia ")
        result = probe._verify_frontend_consumer_binding(
            module_versions, bad_owner, "nvidia\n", frontend_module_name="nvidia"
        )
        self.assertFalse(result["passed"])

    def test_frontend_consumer_binding_rejects_non_export_and_empty_import_set(self):
        module_versions = {"nvUvmInterfaceMemoryFree": "0xabcdef01"}
        symvers = "0xabcdef01 nvUvmInterfaceMemoryFree nvidia EXPORT_SYMBOL_GPL\n"
        result = probe._verify_frontend_consumer_binding(
            module_versions, symvers, "nvidia\n", frontend_module_name="nvidia"
        )
        self.assertFalse(result["passed"])
        empty = probe._verify_frontend_consumer_binding(
            {"module_layout": "0x12345678"}, symvers, "nvidia\n",
            frontend_module_name="nvidia",
        )
        self.assertFalse(empty["passed"])

    def test_control_fd_patch_is_ordered_and_applies_to_pinned_r580_inputs(self):
        self.assertEqual(
            [path.name for path in probe.PATCHES],
            ["0002-hybrid-isolated-gpu-execution.patch",
             "0003-pass-control-fd-to-dup-memory.patch",
             "0004-share-linux-conftests-with-uvm-consumer.patch",
             "0005-pass-control-fd-to-dup-address-space.patch",
             "0006-pin-control-file-before-va-space-registration.patch",
             "0007-reject-cross-gpu-tracker-dependencies.patch",
             "0008-pmm-allocation-outside-va-block-lock.patch",
             "0009-reject-hmm-gpu-migration-in-isolated-mode.patch",
             "0010-reject-unsupported-isolated-staged-migrations.patch",
             "0011-preflight-unsupported-staging-before-unmap.patch",
             "0012-exact-isolated-staged-page-mask.patch",
             "0013-reject-foreign-pmm-trackers-in-isolated-mode.patch",
             "0014-reject-foreign-pmm-trackers-before-eviction.patch"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (
                "common/inc/nv_uvm_interface.h",
                "nvidia/nv_uvm_interface.c",
                "nvidia-uvm/uvm_map_external.c",
                "nvidia-uvm/uvm_va_space.c",
            ):
                source = audit.SOURCE_ROOT / relative
                target = root / "kernel-open" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            result = subprocess.run(
                ["patch", "--batch", "--fuzz=0", "--forward", "-p1",
                 "-i", str(probe.PATCHES[1])],
                cwd=root, capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            interface = (root / "kernel-open/common/inc/"
                         "hybrid580_uvm_control_fd_dispatch.h").read_text()
            external = (root / "kernel-open/nvidia-uvm/uvm_map_external.c").read_text()
            self.assertIn("nvUvmInterfaceDupMemoryWithControlFd", interface)
            self.assertIn(
                "nvUvmInterfaceDupMemoryWithControlFd(\n"
                "                                                        user_rm_mem->rm_control_fd,",
                external,
            )
            result = subprocess.run(
                ["patch", "--batch", "--fuzz=0", "--forward", "-p1",
                 "-i", str(probe.PATCHES[3])],
                cwd=root, capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            address_space = (root / "kernel-open/nvidia-uvm/uvm_va_space.c").read_text()
            self.assertIn("nvUvmInterfaceDupAddressSpaceWithControlFd(", address_space)
            self.assertIn("user_rm_va_space->rm_control_fd", address_space)
            self.assertNotIn("(void)user_rm_va_space->rm_control_fd", address_space)
            registration = address_space.split(
                "NV_STATUS uvm_va_space_register_gpu_va_space(", 1
            )[1].split("\nNV_STATUS uvm_va_space_unregister_gpu_va_space(", 1)[0]
            create = registration.index("status = create_gpu_va_space(")
            error_check = registration.index("if (status != NV_OK)", create)
            error_exit = registration.index("goto error_gpu_release;", error_check)
            first_lock = registration.index("uvm_gpu_va_space_acquire_mmap_lock(mm);")
            self.assertLess(create, error_check)
            self.assertLess(error_check, error_exit)
            self.assertLess(error_exit, first_lock)
            self.assertEqual(
                registration.count("status = create_gpu_va_space("), 1,
                "R580 GPU-VA-space registration has no in-function retry",
            )

    def test_shared_linux_conftest_patch_is_exact_and_deduplicated(self):
        archive_path = probe.SOURCE_ARCHIVE
        members = (
            "kernel-open/nvidia/nvidia.Kbuild",
            "kernel-open/nvidia-uvm/nvidia-uvm.Kbuild",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package_prefix = f"NVIDIA-kernel-module-source-{probe.SOURCE_TAG}/"
            with tarfile.open(archive_path, "r:xz") as archive:
                for relative in members:
                    archive_name = package_prefix + relative
                    source = archive.extractfile(archive_name).read()
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source)
            result = subprocess.run(
                ["patch", "--batch", "--fuzz=0", "--forward", "-p1",
                 "-i", str(probe.PATCHES[2])],
                cwd=root, capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            shared = (root / "kernel-open/common/nvidia-kernel-interface-conftests.Kbuild").read_text()
            nvidia = (root / "kernel-open/nvidia/nvidia.Kbuild").read_text()
            uvm = (root / "kernel-open/nvidia-uvm/nvidia-uvm.Kbuild").read_text()
            self.assertEqual(
                sum(line.startswith("NV_CONFTEST_") for line in shared.splitlines()),
                128,
            )
            include = "include $(src)/common/nvidia-kernel-interface-conftests.Kbuild"
            self.assertIn(include, nvidia)
            self.assertIn(include, uvm)
            self.assertRegex(
                uvm,
                r"ifeq \(\$\(filter nvidia,\$\(NV_KERNEL_MODULES\)\),\)\s*"
                r"include \$\(src\)/common/nvidia-kernel-interface-conftests\.Kbuild\s*"
                r"endif",
            )
            self.assertFalse(any(line.startswith("NV_CONFTEST_") for line in nvidia.splitlines()))

            def assignments(text):
                found = []
                for line in text.splitlines():
                    fields = line.split()
                    if len(fields) == 3 and fields[0].startswith("NV_CONFTEST_"):
                        found.append((fields[0], fields[2]))
                return found

            shared_assignments = assignments(shared)
            uvm_assignments = assignments(uvm)
            self.assertEqual(len(shared_assignments), 128)
            self.assertEqual(len(shared_assignments), len(set(shared_assignments)))
            self.assertEqual(len(uvm_assignments), len(set(uvm_assignments)))
            self.assertFalse(set(shared_assignments) & set(uvm_assignments))

    def test_additional_patch_overlay_applies_without_fuzz_and_is_hashed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            target = source_root / "kernel-open/sample.c"
            target.parent.mkdir(parents=True)
            target.write_text("old\n")
            overlay = root / "overlay.patch"
            overlay.write_text(
                "--- a/kernel-open/sample.c\n"
                "+++ b/kernel-open/sample.c\n"
                "@@ -1 +1 @@\n"
                "-old\n"
                "+new\n"
            )

            artifacts = probe._apply_patch_overlays(source_root, (overlay,))

            self.assertEqual(target.read_text(), "new\n")
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0]["sha256"], hashlib.sha256(overlay.read_bytes()).hexdigest())
            self.assertIn("--fuzz=0", artifacts[0]["apply_command"])
            self.assertEqual(artifacts[0]["apply_output"], "patching file kernel-open/sample.c\n")

    def test_additional_patch_overlay_rejects_symlinks_and_missing_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source_root.mkdir()
            patch_path = root / "overlay.patch"
            patch_path.write_text("not a patch\n")
            link_path = root / "overlay-link.patch"
            link_path.symlink_to(patch_path)

            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                probe._apply_patch_overlays(source_root, (link_path,))
            with self.assertRaisesRegex(ValueError, "must be a regular file"):
                probe._apply_patch_overlays(source_root, (root / "missing.patch",))

    def test_same_control_fd_patch_applies_to_pinned_r595_consumer_sources(self):
        source_root = (probe.ROOT /
                       "build/experiments/r595-r580-patch-replay-v39-20261023/source")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (
                "nvidia/nv_uvm_interface.c",
                "nvidia-uvm/uvm_map_external.c",
            ):
                source = source_root / "kernel-open" / relative
                target = root / "kernel-open" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            result = subprocess.run(
                ["patch", "--batch", "--fuzz=0", "--forward", "-p1",
                 "-i", str(probe.ROOT /
                     "patches/r595.99.02/uvm/0001-pass-control-fd-to-dup-memory.patch")],
                cwd=root, capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((root / "kernel-open/common/inc/"
                             "hybrid580_uvm_control_fd_dispatch.h").is_file())
            external = (root / "kernel-open/nvidia-uvm/uvm_map_external.c").read_text()
            self.assertIn("user_rm_mem->rm_control_fd", external)


if __name__ == "__main__":
    unittest.main()
