import hashlib
import importlib.util
import io
import json
import base64
from pathlib import Path
import tarfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pc3_v100_private_legacy580_runner",
    ROOT / "tools/run_pc3_v100_private_proprietary580_build.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def successful_guest_result(feature_value, symbols_feature_value=None):
    run_id = "2" * 32
    bundle_sha = "b" * 64
    module = b"compiled-module"
    symvers = b"0x1234 symbol vmlinux EXPORT_SYMBOL\n"
    if symbols_feature_value is None:
        symbols_feature_value = feature_value
    symbols = ("#define NV_IS_EXPORT_SYMBOL_GPL___vma_start_write " +
               str(symbols_feature_value) + "\n").encode()
    symbols_sha = hashlib.sha256(symbols).hexdigest()
    target_config = b"CONFIG_STACK_VALIDATION=y\nCONFIG_UNWINDER_ORC=y\nCONFIG_RETHUNK=y\n"
    config_sha = hashlib.sha256(target_config).hexdigest()
    objtool_command = b"savedcmd_hybrid580_legacy.o := ld ... ; objtool --module hybrid580_legacy.o\n"
    objtool_command_sha = hashlib.sha256(objtool_command).hexdigest()
    objtool_sha = "c" * 64
    exports = {f"hybrid580_legacy_export_{index}": "EXPORT_SYMBOL"
               for index in range(144 + feature_value)}
    conditional_symbol = "hybrid580_legacy_nv_vma_start_write"
    if feature_value:
        exports[conditional_symbol] = "EXPORT_SYMBOL"
        exports.pop("hybrid580_legacy_export_0")
    builder_report = {
        "schema": "private-proprietary580-v1",
        "status": "compiled-private-proprietary-backend",
        "qualification": "compiled-module-and-CPU-model-only",
        "inputs_unchanged": True,
        "source_tree_unchanged": True,
        "gpl_only_imports": {},
        "module": {"sha256": hashlib.sha256(module).hexdigest(), "bytes": len(module)},
        "module_metadata": {"name": ["hybrid580_legacy"], "license": ["NVIDIA"],
                            "alias": [], "vermagic": ["6.8.0-147-generic SMP modversions"],
                            "version": ["580.178.04"]},
        "conditional_exports": {
            "feature_macro": "NV_IS_EXPORT_SYMBOL_GPL___vma_start_write",
            "feature_value": feature_value,
            "symbol": conditional_symbol,
            "expected_present": bool(feature_value),
            "actual_present": bool(feature_value),
            "conftest_symbols_sha256": symbols_sha,
        },
        "target_kernel_validation": {
            "kernel_release": "6.8.0-147-generic",
            "config_path": "/usr/src/linux-headers-6.8.0-147-generic/.config",
            "config_sha256": config_sha,
            "config_features": {"CONFIG_STACK_VALIDATION": "y",
                                "CONFIG_UNWINDER_ORC": "y", "CONFIG_RETHUNK": None,
                                "CONFIG_MITIGATION_RETHUNK": "y"},
            "objtool_path": "/usr/src/linux-headers-6.8.0-147-generic/tools/objtool/objtool",
            "objtool_present": True,
            "objtool_sha256": objtool_sha,
        },
        "objtool_command": {
            "path": "/tmp/guest/build/result/nvidia-580.178.04/.hybrid580_legacy.o.cmd",
            "sha256": objtool_command_sha,
            "required_flags_present": ["--retpoline", "--rethunk", "--sls", "--stackval", "--prefix=16"],
            "mode": "explicit-target-kernel-tool",
            "target_kernel_objtool_path": "/usr/src/linux-headers-6.8.0-147-generic/tools/objtool/objtool",
            "target_kernel_objtool_sha256": objtool_sha,
            "warning_count": 0,
            "warning_symbol_count": 0,
            "warning_symbol_set_sha256": hashlib.sha256(b"\n").hexdigest(),
            "warning_instances_from_unchanged_core": 0,
            "warning_counts_by_kind": {"naked_return": 0, "frame_pointer_call": 0},
            "existing_link_metadata_skip_count": 0,
            "existing_link_metadata_skip_sections": [],
            "unclassified_diagnostics": 0,
            "exit_code": 0,
            "diagnostic_classification":
                "exact-core-symbol-warnings-and-idempotent-link-metadata-skips",
        },
        "exports": exports,
    }
    builder_report_raw = (json.dumps(builder_report, indent=2, sort_keys=True) + "\n").encode()
    builder_report_path = "evidence/private-proprietary580-guestkernel-test.json"
    payloads = (
        ("build/result/hybrid580_legacy.ko", module),
        ("build/result/Module.symvers", symvers),
        ("build/result/conftest/symbols.h", symbols),
        ("build/result/target-kernel.config", target_config),
        ("build/result/nvidia-580.178.04/.hybrid580_legacy.o.cmd", objtool_command),
        (builder_report_path, builder_report_raw),
    )
    archive_io = io.BytesIO()
    with tarfile.open(fileobj=archive_io, mode="w:gz") as archive:
        for name, payload in payloads:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    packed = archive_io.getvalue()
    artifacts = [{"path": name, "bytes": len(payload),
                  "sha256": hashlib.sha256(payload).hexdigest()}
                 for name, payload in payloads]
    report = {
        "schema": RUNNER.GUEST_RESULT_SCHEMA, "run_id": run_id,
        "bundle_sha256": bundle_sha, "hostname": "pc3-v100",
        "kernel_release": "6.8.0-147-generic", "status": "completed",
        "builder_exit_code": 0, "builder_stdout_sha256": "d" * 64,
        "builder_stderr_sha256": "e" * 64, "builder_output_bytes": 0,
        "builder_report": builder_report,
        "builder_report_sha256": hashlib.sha256(builder_report_raw).hexdigest(),
        "artifacts": artifacts,
        "artifact_archive_bytes": len(packed),
        "artifact_archive_sha256": hashlib.sha256(packed).hexdigest(),
        "artifact_archive_base64": base64.b64encode(packed).decode(),
        "module_installed": False, "module_loaded": False, "gpu_accessed": False,
        "cuda_execution_tested": False, "scratch_removed": True,
        "staged_bundle_removed": True,
    }
    return (json.dumps(report) + "\n").encode(), run_id, bundle_sha


class PrivateLegacy580GuestRunnerTests(unittest.TestCase):
    def test_remote_scripts_are_syntax_valid_and_compile_only(self):
        for script in (RUNNER.GUEST_BUILD_SCRIPT, RUNNER.PC3_UPLOAD_SCRIPT,
                       RUNNER.PC3_CLEANUP_SCRIPT, RUNNER.PC3_ROOT_RUN_SCRIPT):
            compile(script, "<embedded-pc3-private-legacy580-script>", "exec")
        guest = RUNNER.GUEST_BUILD_SCRIPT
        self.assertIn("EXPECTED_KERNEL=\"6.8.0-147-generic\"", guest)
        self.assertIn("build_private_proprietary580.py", guest)
        self.assertIn(".hybrid580_legacy.o.cmd", guest)
        self.assertIn("target-kernel.config", guest)
        self.assertIn('"module_installed":False', guest)
        self.assertIn('"module_loaded":False', guest)
        self.assertIn('"gpu_accessed":False', guest)
        for forbidden in ("modprobe", "insmod", "rmmod", "nvidia-smi", "cudaDevice"):
            self.assertNotIn(forbidden, guest)

    def test_bound_transport_scripts_use_private_legacy_namespace(self):
        self.assertIn("codex-legacy580-", RUNNER.PC3_UPLOAD_SCRIPT)
        self.assertIn("codex-legacy580-", RUNNER.PC3_CLEANUP_SCRIPT)
        self.assertIn("codex-legacy580-", RUNNER.PC3_ROOT_RUN_SCRIPT)
        self.assertNotIn("codex-open580-", RUNNER.PC3_ROOT_RUN_SCRIPT)
        self.assertGreaterEqual(RUNNER.MAX_BUNDLE_BYTES, 300 * 1024 * 1024)
        self.assertGreater(RUNNER.MAX_RESULT_BYTES, 192 * 1024 * 1024)
        self.assertGreater(RUNNER.MAX_ARTIFACT_ARCHIVE_BYTES, 128 * 1024 * 1024)

    def test_input_manifest_contains_hash_pinned_proprietary_build_inputs(self):
        paths = set(RUNNER.input_bundle_paths())
        builder = RUNNER.load_module(RUNNER.ROOT / "tools/build_private_proprietary580.py",
                                     "private_legacy580_builder_for_test")
        baseline = builder.baseline
        required = {
            baseline.PACKAGE_DEB, builder.ARCHIVE,
            baseline.SOURCE_ROOT / "nvidia/nv-kernel.o_binary",
            builder.BASE / "nvidia.ko", builder.BASE / "Module.symvers",
            builder.PREVIOUS_REPORT, builder.PREVIOUS_SOURCE / "Module.symvers",
            builder.PREVIOUS_CONTROL_HEADER, builder.PM_CHANNEL_DEPTH_TEST,
            builder.PM_RECOVERY_TEST, builder.PM_RECOVERY_PROVIDER_TEST,
            builder.CONTROL_SESSION_HEADER, builder.GPU_SESSION_HEADER,
            RUNNER.ROOT / "src/hybrid580_pm_provider_recovery.h",
            RUNNER.ROOT / "src/hybrid580_pm_provider_kernel.h",
            RUNNER.ROOT / "tests/fixtures/hybrid580_pm_provider_recovery_test.c",
            RUNNER.ROOT / "tests/gpu_session_register_harness.py",
            RUNNER.ROOT / "tools/probe_private_backend_chardev.py",
            RUNNER.ROOT / "tools/probe_private_backend_module.py",
            RUNNER.ROOT / "tools/audit_uvm_pm_lifecycle.py",
            RUNNER.ROOT / "tools/audit_uvm_interface_ownership.py",
            RUNNER.ROOT / "build/experiments/r580-uvm-clean-v3-20261021/source/kernel-open/nvidia/nv.c",
            RUNNER.ROOT / "build/experiments/private-open-pm-recovery-provider-v3-20261021/NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia/nv.c",
            RUNNER.ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04/src/nvidia/src/kernel/rmapi/nv_gpu_ops.c",
        }
        required.update((RUNNER.ROOT / "patches/r580.178.04").glob("*.patch"))
        required.update(builder.PREVIOUS_SOURCE / relative for relative in (
            "common/inc/nv-linux.h", "common/inc/nv.h", "nvidia/export_nvswitch.h",
            "nvidia/nv-caps-imex.c", "nvidia/nv-caps.c", "nvidia/nv-mmap.c",
            "nvidia/nv-pci-table.c", "nvidia/nv-pci.c", "nvidia/nv-platform.c",
            "nvidia/nv-procfs.c", "nvidia/nv.c", "nvidia/nvidia.Kbuild",
            "nvidia/nvlink_linux.c", "nvidia/nvlink_linux.h", "nvidia/procfs_nvswitch.c",
        ))
        self.assertTrue(required <= paths)
        self.assertTrue(set(builder.PATCHES) <= paths)
        self.assertTrue(set(baseline.SOURCE_ROOT.rglob("*")) - {
            p for p in baseline.SOURCE_ROOT.rglob("*") if p.is_dir()} <= paths)
        self.assertTrue(all(p.is_file() and not p.is_symlink() for p in paths))

    def test_previous_source_evidence_paths_survive_vm_relocation(self):
        builder = RUNNER.load_module(RUNNER.ROOT / "tools/build_private_proprietary580.py",
                                     "private_legacy580_builder_path_test")
        report = {"source_changes": [{
            "path": "/run/media/pc1/Infrastructure/Naos/60_travaux/cuda13-volta-compat-20260927/driver-hybrid/build/experiments/private-proprietary-session-v2/nvidia-580.178.04/common/inc/nv-linux.h",
            "sha256": "a" * 64,
        }]}
        relocated_root = Path("/tmp/guest-run-123")
        relocated_snapshot = relocated_root / "build/experiments/private-proprietary-session-v2/nvidia-580.178.04"
        self.assertEqual(builder.previous_change_digests(
            report, relocated_root, relocated_snapshot), {"common/inc/nv-linux.h": "a" * 64})
        outside = {"source_changes": [{"path": "/tmp/other/file.c", "sha256": "b" * 64}]}
        with self.assertRaises(ValueError):
            builder.previous_change_digests(outside, relocated_root, relocated_snapshot)

    def test_guest_result_rejects_target_or_execution_boundary_mismatch(self):
        run_id = "1" * 32
        bundle_sha = "a" * 64
        base = {
            "schema": RUNNER.GUEST_RESULT_SCHEMA,
            "run_id": run_id,
            "bundle_sha256": bundle_sha,
            "hostname": "pc3-v100",
            "kernel_release": "6.8.0-147-generic",
            "status": "failed",
            "builder_exit_code": 2,
            "builder_stdout_sha256": "d" * 64,
            "builder_stderr_sha256": "e" * 64,
            "builder_output_bytes": 0,
            "builder_report": None,
            "builder_report_sha256": None,
            "artifacts": [],
            "artifact_archive_bytes": 0,
            "artifact_archive_sha256": hashlib.sha256(b"").hexdigest(),
            "artifact_archive_base64": "",
            "module_installed": False,
            "module_loaded": False,
            "gpu_accessed": False,
            "cuda_execution_tested": False,
            "scratch_removed": True,
            "staged_bundle_removed": True,
            "error": "expected test failure",
        }
        raw = (json.dumps(base) + "\n").encode()
        self.assertEqual(RUNNER.validate_guest_result(raw, run_id, bundle_sha)["status"], "failed")
        for field, value in (("kernel_release", "7.0.0-38-generic"),
                             ("gpu_accessed", True), ("module_loaded", True),
                             ("staged_bundle_removed", False)):
            altered = dict(base, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                RUNNER.validate_guest_result((json.dumps(altered) + "\n").encode(), run_id,
                                             bundle_sha)

    def test_failed_guest_build_preserves_the_builder_report_for_diagnosis(self):
        run_id = "3" * 32
        bundle_sha = "c" * 64
        builder_report = {
            "schema": "private-proprietary580-v1",
            "status": "failed",
            "error": "kernel symbol check rejected unresolved imports",
        }
        report_raw = (json.dumps(builder_report, indent=2, sort_keys=True) + "\n").encode()
        report_path = "evidence/private-proprietary580-guestkernel-test.json"
        archive_io = io.BytesIO()
        with tarfile.open(fileobj=archive_io, mode="w:gz") as archive:
            info = tarfile.TarInfo(report_path)
            info.size = len(report_raw)
            archive.addfile(info, io.BytesIO(report_raw))
        packed = archive_io.getvalue()
        report = {
            "schema": RUNNER.GUEST_RESULT_SCHEMA,
            "run_id": run_id,
            "bundle_sha256": bundle_sha,
            "hostname": "pc3-v100",
            "kernel_release": "6.8.0-147-generic",
            "status": "failed",
            "builder_exit_code": 2,
            "builder_stdout_sha256": hashlib.sha256(b"compile output").hexdigest(),
            "builder_stderr_sha256": hashlib.sha256(b"symbol mismatch").hexdigest(),
            "builder_output_bytes": len(b"compile output") + len(b"symbol mismatch"),
            "builder_report": builder_report,
            "builder_report_sha256": hashlib.sha256(report_raw).hexdigest(),
            "artifacts": [{"path": report_path, "bytes": len(report_raw),
                           "sha256": hashlib.sha256(report_raw).hexdigest()}],
            "artifact_archive_bytes": len(packed),
            "artifact_archive_sha256": hashlib.sha256(packed).hexdigest(),
            "artifact_archive_base64": __import__("base64").b64encode(packed).decode(),
            "module_installed": False,
            "module_loaded": False,
            "gpu_accessed": False,
            "cuda_execution_tested": False,
            "scratch_removed": True,
            "staged_bundle_removed": True,
            "error": builder_report["error"],
        }
        validated = RUNNER.validate_guest_result((json.dumps(report) + "\n").encode(),
                                                 run_id, bundle_sha)
        self.assertEqual(validated["status"], "failed")
        self.assertEqual(validated["builder_report"]["error"], builder_report["error"])
        self.assertEqual(validated["_artifact_archive_bytes"], packed)

    def test_successful_guest_report_binds_module_and_symvers_artifacts(self):
        raw, run_id, bundle_sha = successful_guest_result(1)
        validated = RUNNER.validate_guest_result(raw, run_id, bundle_sha)
        self.assertEqual(validated["builder_report"]["qualification"],
                         "compiled-module-and-CPU-model-only")
        self.assertEqual(validated["builder_report"]["conditional_exports"]["feature_value"], 1)

    def test_successful_guest_report_accepts_only_target_proven_144_export_variant(self):
        raw, run_id, bundle_sha = successful_guest_result(0)
        validated = RUNNER.validate_guest_result(raw, run_id, bundle_sha)
        self.assertEqual(len(validated["builder_report"]["exports"]), 144)
        report = json.loads(raw)
        report["builder_report"]["conditional_exports"]["feature_value"] = 0
        report["builder_report"]["conditional_exports"]["expected_present"] = False
        report["builder_report"]["conditional_exports"]["actual_present"] = False
        report["builder_report"]["exports"]["hybrid580_legacy_nv_vma_start_write"] = "EXPORT_SYMBOL"
        report["builder_report"]["exports"].pop("hybrid580_legacy_export_143")
        packed = base64.b64decode(report["artifact_archive_base64"])
        with tarfile.open(fileobj=io.BytesIO(packed), mode="r:gz") as archive:
            members = {member.name: archive.extractfile(member).read()
                       for member in archive.getmembers() if member.isfile()}
        report_path = "evidence/private-proprietary580-guestkernel-test.json"
        builder_raw = (json.dumps(report["builder_report"], indent=2, sort_keys=True) + "\n").encode()
        report["builder_report_sha256"] = hashlib.sha256(builder_raw).hexdigest()
        report["artifacts"] = [item for item in report["artifacts"] if item["path"] != report_path]
        report["artifacts"].append({"path": report_path, "bytes": len(builder_raw),
                                    "sha256": hashlib.sha256(builder_raw).hexdigest()})
        members[report_path] = builder_raw
        archive_io = io.BytesIO()
        with tarfile.open(fileobj=archive_io, mode="w:gz") as archive:
            for name, payload in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        repacked = archive_io.getvalue()
        report["artifact_archive_bytes"] = len(repacked)
        report["artifact_archive_sha256"] = hashlib.sha256(repacked).hexdigest()
        report["artifact_archive_base64"] = base64.b64encode(repacked).decode()
        with self.assertRaises(ValueError):
            RUNNER.validate_guest_result((json.dumps(report) + "\n").encode(),
                                         run_id, bundle_sha)

    def test_guest_report_cannot_override_captured_target_conftest_feature(self):
        raw, run_id, bundle_sha = successful_guest_result(1, symbols_feature_value=0)
        with self.assertRaisesRegex(ValueError, "differs from target conftest"):
            RUNNER.validate_guest_result(raw, run_id, bundle_sha)


if __name__ == "__main__":
    unittest.main()
