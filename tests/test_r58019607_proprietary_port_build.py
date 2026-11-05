import unittest

from tools.build_r58019607_proprietary_port import (
    classify_build_warnings,
    build_command,
    create_private_log_at,
    open_evidence_output_directories,
    read_open_file_bytes,
    resolve_compiler,
    resolve_kernel_build_tree,
    PATCHED_SOURCE,
    sdk_member_relative_path,
    PATCH_REPORT,
    PATCH_REPORT_SHA256,
    PATCHED_SOURCE_SHA256,
    sha256,
    tree_fingerprint,
    validate_direct_report_path,
    validate_module_metadata,
    validate_patch_port_report,
)


def valid_patch_report():
    return {
        "schema": "r580-proprietary-source-port-probe-v1",
        "version_under_test": "580.196.07",
        "patch_version": "580.178.04",
        "source_patch_probe_only": True,
        "patch_probe": {
            "patch_count": 48,
            "patches_applied_count": 48,
            "all_patches_applied": True,
            "fuzz_notices": [],
            "source_tree_unchanged": True,
            "proprietary_core_unchanged": True,
            "build_performed": False,
            "install_or_load_performed": False,
            "hardware_accessed": False,
            "vendor_binary_reverse_engineered": False,
            "vendor_binary_modified": False,
            "source_tree_sha256_after": "8abd0e8289b0bcf2403212d0a32d66931977d66f07777d47b5099a2c67b04972",
            "scratch_root": "/tmp/source",
        },
        "license_boundary": {
            "proprietary_binary_reverse_engineered": False,
            "proprietary_binary_modified": False,
            "redistribution_authorized": False,
        },
    }


class R58019607ProprietaryPortBuildTests(unittest.TestCase):
    def test_build_command_uses_explicit_kernel_tree_and_compiler(self):
        from pathlib import Path

        command = build_command(
            Path("/scratch/source"), "6.8.0-147-generic", Path("/kernel/headers"),
            3, Path("/toolchain/gcc-13"),
        )
        self.assertEqual(command[:3], ["make", "-C", "/scratch/source"])
        self.assertIn("KERNEL_UNAME=6.8.0-147-generic", command)
        self.assertIn("SYSSRC=/kernel/headers", command)
        self.assertIn("CC=/toolchain/gcc-13", command)
        self.assertIn("NV_KERNEL_MODULES=nvidia", command)
        self.assertIn("-j3", command)
        self.assertEqual(command[-1], "modules")

    def test_build_command_rejects_nonpositive_job_count(self):
        from pathlib import Path

        for jobs in (0, -1, True):
            with self.subTest(jobs=jobs):
                with self.assertRaises(ValueError):
                    build_command(Path("/source"), "6.8", Path("/headers"), jobs)

    def test_kernel_build_tree_requires_regular_kbuild_inputs(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temporary:
            kernel = Path(temporary)
            for name in ("Makefile", ".config", "Module.symvers"):
                (kernel / name).write_text("fixture\n")
            self.assertEqual(kernel.resolve(), resolve_kernel_build_tree("fixture", kernel))
            (kernel / "Module.symvers").unlink()
            (kernel / "Module.symvers").symlink_to(kernel / "Makefile")
            with self.assertRaisesRegex(ValueError, "regular Module.symvers"):
                resolve_kernel_build_tree("fixture", kernel)

    def test_compiler_must_resolve_to_an_executable_regular_file(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temporary:
            compiler = Path(temporary) / "gcc"
            compiler.write_text("#!/bin/sh\nexit 0\n")
            compiler.chmod(0o700)
            self.assertEqual(compiler.resolve(), resolve_compiler(compiler))
            compiler.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "executable regular file"):
                resolve_compiler(compiler)

    def test_provider_build_is_pinned_to_payload_corrected_source_port(self):
        import json
        from pathlib import Path

        self.assertEqual("r58019607-debugger-bridge-source-port-v2-20261101.json", PATCH_REPORT.name)
        self.assertEqual(PATCH_REPORT_SHA256, sha256(PATCH_REPORT))
        report = json.loads(PATCH_REPORT.read_text())
        self.assertEqual("source-patches-applied-no-build", report["qualification"])
        self.assertEqual(48, report["patch_probe"]["patches_applied_count"])
        self.assertEqual([], report["patch_probe"]["fuzz_notices"])
        self.assertEqual(
            PATCHED_SOURCE_SHA256,
            tree_fingerprint(PATCHED_SOURCE),
        )

    def test_created_log_descriptor_is_read_write_and_private(self):
        import os
        import stat
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "evidence"
            logs = evidence / "logs"
            logs.mkdir(parents=True)
            evidence_fd, logs_fd = open_evidence_output_directories(evidence)
            try:
                descriptor = create_private_log_at(logs_fd, "build.log")
                try:
                    os.write(descriptor, b"build output")
                    self.assertEqual(b"build output", read_open_file_bytes(descriptor))
                    self.assertEqual(0o600, stat.S_IMODE(os.fstat(descriptor).st_mode))
                finally:
                    os.close(descriptor)
            finally:
                os.close(logs_fd)
                os.close(evidence_fd)

    def test_open_log_descriptor_is_stable_if_its_directory_entry_is_replaced(self):
        import os
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temporary:
            logs = Path(temporary)
            original = logs / "build.log"
            descriptor = os.open(original, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            try:
                os.write(descriptor, b"original build output")
                original.unlink()
                original.write_bytes(b"replacement output")
                self.assertEqual(b"original build output", read_open_file_bytes(descriptor))
            finally:
                os.close(descriptor)

    def test_report_path_must_be_a_direct_child_of_evidence_root(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "evidence"
            nested = evidence / "subdir"
            nested.mkdir(parents=True)
            direct_report = (evidence / "report.json").resolve()
            nested_report = (nested / "report.json").resolve()
            self.assertEqual(direct_report, validate_direct_report_path(direct_report, evidence))
            with self.assertRaises(ValueError):
                validate_direct_report_path(nested_report, evidence)

    def test_output_directory_open_rejects_symlinked_logs_parent(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (evidence / "logs").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(OSError):
                open_evidence_output_directories(evidence)
            self.assertEqual([], list(outside.iterdir()))

    def test_output_directory_open_returns_real_directory_descriptors(self):
        import os
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "evidence"
            logs = evidence / "logs"
            logs.mkdir(parents=True)
            evidence_fd, logs_fd = open_evidence_output_directories(evidence)
            try:
                self.assertTrue(os.path.isdir(f"/proc/self/fd/{evidence_fd}"))
                self.assertTrue(os.path.isdir(f"/proc/self/fd/{logs_fd}"))
            finally:
                os.close(logs_fd)
                os.close(evidence_fd)

    def test_accepts_complete_source_patch_port_evidence(self):
        self.assertTrue(validate_patch_port_report(valid_patch_report()))

    def test_rejects_incomplete_or_fuzzed_patch_application(self):
        for field, value in (
            ("patches_applied_count", 44),
            ("all_patches_applied", False),
            ("fuzz_notices", ["Hunk applied with fuzz"]),
            ("source_tree_unchanged", False),
        ):
            with self.subTest(field=field):
                report = valid_patch_report()
                report["patch_probe"][field] = value
                with self.assertRaises(ValueError):
                    validate_patch_port_report(report)

    def test_rejects_wrong_release_and_reverse_engineering_claim(self):
        report = valid_patch_report()
        report["version_under_test"] = "580.178.04"
        with self.assertRaises(ValueError):
            validate_patch_port_report(report)

        report = valid_patch_report()
        report["patch_probe"]["hardware_accessed"] = True
        with self.assertRaises(ValueError):
            validate_patch_port_report(report)

        report = valid_patch_report()
        report["license_boundary"]["proprietary_binary_reverse_engineered"] = True
        with self.assertRaises(ValueError):
            validate_patch_port_report(report)

    def test_selects_only_regular_files_in_pinned_sdk_include_trees(self):
        self.assertEqual(
            "common/sdk/nvidia/inc/nvos.h",
            sdk_member_relative_path(
                "NVIDIA-kernel-module-source-580.196.07/src/common/sdk/nvidia/inc/nvos.h",
                "file",
            ),
        )
        self.assertIsNone(
            sdk_member_relative_path(
                "NVIDIA-kernel-module-source-580.196.07/src/common/other/private.h",
                "file",
            )
        )

    def test_rejects_unsafe_or_nonregular_selected_sdk_members(self):
        cases = (
            ("NVIDIA-kernel-module-source-580.196.07/src/common/sdk/nvidia/inc/../escape.h", "file"),
            ("NVIDIA-kernel-module-source-580.196.07/src/common/sdk/nvidia/inc/link.h", "symlink"),
            ("/tmp/NVIDIA-kernel-module-source-580.196.07/src/common/sdk/nvidia/inc/evil.h", "file"),
        )
        for member, kind in cases:
            with self.subTest(member=member, kind=kind):
                with self.assertRaises(ValueError):
                    sdk_member_relative_path(member, kind)

    def test_classifies_build_warnings_without_suppressing_them(self):
        result = classify_build_warnings([
            "hybrid580_legacy.o: warning: objtool: f+0x1: 'naked' return found in MITIGATION_RETHUNK build",
            "hybrid580_legacy.o: warning: objtool: g+0x2: call without frame pointer save/setup",
            "nvidia/nv-imp.c:77: warning: use of defined may not be portable",
        ])
        self.assertEqual(1, result["objtool_naked_return"])
        self.assertEqual(1, result["objtool_frame_pointer"])
        self.assertEqual(1, result["other_warning"])
        self.assertEqual(3, result["total_warning_lines"])

    def test_rejects_module_with_mismatched_identity_or_kernel(self):
        metadata = {
            "name": "hybrid580_legacy",
            "version": "580.196.07",
            "license": "NVIDIA",
            "vermagic": "7.0.0-38-generic SMP preempt modversions",
            "alias": "",
            "depends": "",
        }
        self.assertTrue(validate_module_metadata(metadata, "7.0.0-38-generic"))
        for key, value in (("name", "nvidia"), ("version", "580.178.04"),
                           ("license", "GPL"), ("vermagic", "6.8.0 SMP"),
                           ("alias", "pci:v000010DE*")):
            with self.subTest(key=key):
                bad = dict(metadata)
                bad[key] = value
                with self.assertRaises(ValueError):
                    validate_module_metadata(bad, "7.0.0-38-generic")


if __name__ == "__main__":
    unittest.main()
