#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the full CPU/software suite against a pinned CUDA probe and save evidence."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.probe_r615_gv100_dispatch import write_private_evidence_report  # noqa: E402
from tools.run_openrm_hal_lookup_matrix import _write_private_raw_log  # noqa: E402


PROBE = ROOT / "build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_cuda_probe"
PINNED_PROBE_SHA256 = "c2c0aa30d26fe2fb7e61a5ef732bc1f659faa39eb4626e1d46689f2aa85e1422"
PROBE_MANIFEST = ROOT / "build/probe-cuda129-sm70v-sm120a-v3-host-staged/build-manifest.json"
PROBE_FATBIN = ROOT / "build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_probe.sm70-ptx_sm120a-cubin.fatbin"
PINNED_PROBE_FATBIN_SHA256 = "8dc12fa61f5ed270c3122f5516c2afce43d9c39f5fa9a16f9a7e313fe34f6f70"
PINNED_HOST_SOURCE_SHA256 = "947b734156b9d3f86b6e7f66d02a068dfaced47c8bd820e8d579c290abdb389a"
PINNED_KERNEL_SOURCE_SHA256 = "eb08482739ac2f601bb1954ac8a88035e7752b91e8188aaba6730b952c48c22a"
TEST_ROOT = ROOT / "tests"
IMPLEMENTATION_INPUTS = (
    ".gitlab-ci.yml",
    "kernels/experiments/concurrent_dispatch_v1/hybrid_probe.cu",
    "kernels/hybrid_probe.cu",
    "patches/r595.112.07/0001-open-core-rethunk-return-thunk.patch",
    "patches/r595.112.07/0002-open-modeset-rethunk-return-thunk.patch",
    "patches/r580.178.04/0048-private-open-sync-boost-groups.patch",
    "patches/r580.178.04/0050-private-open-debugger-bridge.patch",
    "patches/r580.178.04/proprietary/0046-private-legacy-sync-boost-groups.patch",
    "patches/r580.178.04/proprietary/0048-private-legacy-debugger-bridge.patch",
    "src/experiments/concurrent_dispatch_v1/hybrid_cuda_probe.cpp",
    "src/hybrid580-control-session.h",
    "src/hybrid580_uvm_callback_bridge.c",
    "src/hybrid_cuda_probe.cpp",
    "src/hybrid_frontend.c",
    "tests/run_hybrid_acceptance.py",
    "tools/aggregate_cuda_performance_references.py",
    "tools/analyze_v100_uvm_context_sequence.py",
    "tools/audit_transfer_document_links.py",
    "tools/verify_transfer_manifest.py",
    "tools/verify_compressed_evidence.py",
    "tools/summarize_ci_security_reports.py",
    "tools/probe_sonar_runner_endpoint.py",
    "tools/probe_sonar_token_access.py",
    "tools/audit_hybrid_candidate_bundle.py",
    "tools/summarize_hybrid_candidate_bundle.py",
    "tools/audit_nsys_concurrent_overlap.py",
    "tools/audit_pc3_canary_preflight.py",
    "tools/audit_pc3_candidate_signing_preconditions.py",
    "tools/audit_pc3_package_dependency_state.py",
    "tools/audit_pc3_r595_recovery_stage.py",
    "tools/audit_pc3_vm_gpu_assignment.py",
    "tools/audit_r580_uvm_isolated_service_phases.py",
    "tools/audit_r580_uvm_semaphore_mapping_api.py",
    "tools/audit_r595_uvm_p2p_consumer.py",
    "tools/audit_r595_uvm_candidate_preflight.py",
    "tools/audit_r595_uvm_hal_table_closure.py",
    "tools/audit_r595_uvm_symbol_closure.py",
    "tools/audit_uvm_ioctl_archives.py",
    "tools/audit_volta_uvm_candidate_paths.py",
    "tools/summarize_volta_uvm_candidate_paths.py",
    "tools/summarize_r595_uvm_ghidra_receipt.py",
    "tools/summarize_r595_uvm_add_gpu_ghidra_receipt.py",
    "tools/summarize_r595_gpu_info_hal_audit.py",
    "tools/summarize_r595_gv100_prefetch_contract.py",
    "tools/summarize_hybrid_bundle_depmod.py",
    "tools/summarize_hybrid_split_provider_build.py",
    "tools/summarize_volta_fault_init_host_harness.py",
    "tools/summarize_private_software_suite.py",
    "tools/audit_volta_uvm_capability_map.py",
    "tools/audit_volta_uvm_property_delta.py",
    "tools/audit_rethunk_warning_provenance.py",
    "tools/summarize_rethunk_ghidra_sample.py",
    "tools/build_hybrid_frontend.py",
    "tools/build_private_open580_wrapper.py",
    "tools/build_private_proprietary580.py",
    "tools/build_probe.py",
    "tools/build_probe_cuda129.py",
    "tools/build_proprietary580_wrapper_baseline.py",
    "tools/build_r58019607_proprietary_port.py",
    "tools/build_r595_hybrid_uvm_target.py",
    "tools/build_r595_open_linux68_full.py",
    "tools/build_replayed_r595_open.py",
    "tools/capture_pc3_v100_kernel_dependencies.py",
    "tools/collect_pc3_canary_host_state.py",
    "tools/collect_pc3_v100_package_inventory.py",
    "tools/compare_channel_alloc_observations.py",
    "tools/compare_cuda_node_open_lifecycle.py",
    "tools/compare_elf_loadable_sections.py",
    "tools/compare_ioctl_trace_evidence.py",
    "tools/compare_nv0080_device_alloc.py",
    "tools/compare_nv2080_subdevice_alloc.py",
    "tools/compare_nv2081_binapi_alloc.py",
    "tools/compare_observed_uvm_handler_bodies.py",
    "tools/compare_openrm_gv100.py",
    "tools/compare_rm_control_headers.py",
    "tools/compare_rm_root_protocols.py",
    "tools/compare_uvm_ioctl_routes.py",
    "tools/compare_uvm_payload_abi.py",
    "tools/create_r595_uvm_isolation_manifest.py",
    "tools/cuda_probe_contract.py",
    "tools/cuda_host_compat/gcc14_glibc243_cuda129.h",
    "tools/stage_cuda_toolchain.py",
    "configs/cuda-toolchains/cuda-12.9.2-linux-x86_64.json",
    "tools/verify_llama_cuda_artifacts.py",
    "configs/inference/llama.cpp-cuda129-sm70v-sm120a.json",
    "tools/inspect_pc3_v100_loaded_module_identity.py",
    "tools/inspect_pc3_v100_trace_capabilities.py",
    "tools/manage_pc3_v100_canary_watchdog.py",
    "tools/audit_nouveau_gv100_fault_lifecycle.py",
    "tools/nouveau_gv100_rea_audit.py",
    "tools/prepare_r595_hybrid_source.py",
    "tools/probe_r580_proprietary_source_port.py",
    "tools/probe_r595_gv100_complete_hal.py",
    "tools/probe_r615_gv100_dispatch.py",
    "tools/probe_volta_uvm_port.py",
    "tools/replay_r580_open_patches_on_r595.py",
    "tools/run_openrm_hal_lookup_matrix.py",
    "tools/run_volta_fault_decode_host_harness.py",
    "tools/run_volta_fault_ring_host_harness.py",
    "tools/run_pc3_rtx5080_ioctl_shape_reference.py",
    "tools/run_pc3_rtx_pmon_reference.py",
    "tools/run_pc3_v100_guest_reference.py",
    "tools/run_pc3_v100_kbuild_smoke.py",
    "tools/run_pc3_v100_private_open580_build.py",
    "tools/run_pc3_v100_private_proprietary580_build.py",
    "tools/run_pc3_v100_system_features_sensitivity.py",
    "tools/run_remote_selected_gpu.py",
    "tools/run_software_test_suite.py",
    "tools/stage_pc3_v100_r580_depmod.py",
    "tools/stage_r58017804_compute_userland.py",
    "tools/stage_r595_uvm_isolated_bundle.py",
    "tools/summarize_pc3_rtx_stock_phase.py",
    "tools/summarize_pc3_rtx_stock_benchmark.py",
    "tools/summarize_rm_alloc_headers.py",
    "tools/summarize_rusd_map_mmap_lifecycle.py",
    "tools/verify_hybrid_bundle_depmod.py",
    "tools/verify_nvcc_cuda_smoke.py",
    "tools/verify_r595_linux68_hybrid_depmod.py",
    "tools/verify_sm70_ptx_jit_evidence.py",
    "tools/llama_backend_ops_contract.py",
    "tools/run_llama_backend_ops.py",
    # Repository-local Python tools imported by the test modules and their
    # pinned helper chain. Keep these in the manifest even when a tool is
    # exercised only through a test import rather than a subprocess.
    "tools/audit_archive_subtree_integrity.py",
    "tools/audit_elf_symbol_references.py",
    "tools/audit_hybrid_uvm_abi.py",
    "tools/audit_p2p_branch_delta.py",
    "tools/audit_pc3_staged_nvidia_bundle.py",
    "tools/audit_r58017804_libcuda_package.py",
    "tools/audit_r58017804_v100_compute_package.py",
    "tools/audit_r580_helper_accessor.py",
    "tools/audit_r580_lookup_branch.py",
    "tools/audit_r580_lookup_callsite.py",
    "tools/audit_r580_module_dependency_graph.py",
    "tools/audit_r580_uvm_consumer_abi.py",
    "tools/audit_r580_uvm_isolated_init_cleanup.py",
    "tools/audit_r580_uvm_module_pair.py",
    "tools/audit_r580_uvm_pmm_wait_context.py",
    "tools/audit_r580_selector_state.py",
    "tools/audit_r580_uvm_semaphore_owner_contract.py",
    "tools/audit_r580_uvm_wait_lock_context.py",
    "tools/audit_r595_cross_provider_semaphore_init.py",
    "tools/audit_r595_noncoherent_bar1_consumers.py",
    "tools/audit_r595_p2p_producer.py",
    "tools/audit_r595_pmm_tracker_wait_context.py",
    "tools/audit_r595_uvm_proxy_paging_gate.py",
    "tools/audit_r615_gv100_kernel_object.py",
    "tools/audit_rm_gpu_probe_admission.py",
    "tools/audit_staged_libcuda_probe_exports.py",
    "tools/audit_uvm_interface_ownership.py",
    "tools/audit_uvm_owner_isolation_architecture.py",
    "tools/audit_uvm_pm_lifecycle.py",
    "tools/audit_volta_mmu_adapter_contract.py",
    "tools/audit_volta_uvm_hal_dispatch.py",
    "tools/build_rm_root_id_probe.py",
    "tools/create_r580_candidate_module_manifest.py",
    "tools/probe_r580_tracker_guard_r595_compatibility.py",
    "tools/probe_r580_uvm_isolated_execution.py",
    "tools/probe_r595_gv100_fault_hal.py",
    "tools/r595_large_page_table_host_harness.py",
    "tools/r595_pfn_backing_host_harness.py",
    "tools/run_pc3_live_root_id_probe.py",
    "tools/run_pc3_live_root_id_probe_reverse.py",
    "tools/run_pc3_rm_root_id_probe.py",
    "tools/run_pc3_rtx5080_r580196_crossminor.py",
    "tools/run_pc3_v100_rm_root_id_probe.py",
    "tools/run_r595_bar1_peer_host_harness.py",
    "tools/run_vmm_peer_probe.py",
    "tools/run_volta_mmu_host_harness.py",
    "tools/stage_nvidia_canary_packages.py",
    "tools/stage_r580_standard_stack.py",
    "tools/stage_r595_compute_userland.py",
    "tools/summarize_pc3_rtx_cuda_graphs.py",
    "tools/summarize_rm_ioctl_trace.py",
    "tools/vmm_peer_probe_contract.py",
)


def _hash_regular_nofollow(path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required to verify the pinned test binary")
    descriptor = os.open(path, flags | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"expected a regular file: {path}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _source_hashes(test_root=TEST_ROOT):
    """Hash every regular static test input, not only Python test modules.

    The suite compiles C/C++ fixtures and reads checked-in data files during
    execution. Exclude interpreter caches and special files, reject symlinks,
    then use the no-follow regular-file reader for the actual digest.
    """
    root = Path(test_root).resolve(strict=True)
    root_label = "tests" if root == TEST_ROOT.resolve(strict=True) else "test-inputs"
    hashes = {}
    def fail_on_walk_error(error):
        location = error.filename or root
        raise OSError(f"cannot traverse test input directory: {location}") from error

    for directory, dirnames, filenames in os.walk(root, topdown=True,
                                                  followlinks=False,
                                                  onerror=fail_on_walk_error):
        current = Path(directory)
        symlink_directories = [name for name in dirnames
                               if (current / name).is_symlink()]
        if symlink_directories:
            raise ValueError("test input tree contains a symlink directory")
        dirnames[:] = sorted(name for name in dirnames if name != "__pycache__")
        for name in sorted(filenames):
            if name.endswith(".pyc"):
                continue
            path = current / name
            try:
                mode = os.lstat(path).st_mode
            except FileNotFoundError as error:
                raise ValueError(f"test input disappeared during hashing: {path}") from error
            if stat.S_ISLNK(mode):
                raise ValueError(f"test input tree contains a symlink: {path}")
            if not stat.S_ISREG(mode):
                continue
            relative = path.relative_to(root).as_posix()
            hashes[f"{root_label}/{relative}"] = _hash_regular_nofollow(path)
    return dict(sorted(hashes.items()))


def _implementation_hashes():
    """Hash the pinned implementation inputs used by the software suite."""
    return {name: _hash_regular_nofollow(ROOT / name)
            for name in IMPLEMENTATION_INPUTS}


def _changed_source_hashes(before, after):
    """Return deterministic names for test inputs added, removed, or changed."""
    return sorted(name for name in before.keys() | after.keys()
                  if before.get(name) != after.get(name))


def _bundle_paths(bundle_dir=None):
    if bundle_dir is None:
        return PROBE, PROBE_MANIFEST
    directory = Path(bundle_dir).resolve(strict=True)
    if not directory.is_dir():
        raise ValueError("probe bundle path is not a directory")
    return directory / "hybrid_cuda_probe", directory / "build-manifest.json"


def _verify_probe_build(bundle_dir=None):
    probe_path, probe_manifest_path = _bundle_paths(bundle_dir)
    fatbin_path = probe_path.parent / PROBE_FATBIN.name
    probe_sha256 = _hash_regular_nofollow(probe_path)
    if probe_sha256 != PINNED_PROBE_SHA256:
        raise ValueError("CUDA probe binary differs from the pinned test input")
    fatbin_sha256 = _hash_regular_nofollow(fatbin_path)
    if fatbin_sha256 != PINNED_PROBE_FATBIN_SHA256:
        raise ValueError("CUDA probe fatbin differs from the pinned test input")
    manifest_sha256 = _hash_regular_nofollow(probe_manifest_path)
    manifest = json.loads(probe_manifest_path.read_text(encoding="utf-8"))
    expected_sources = {
        str((ROOT / "src/hybrid_cuda_probe.cpp").resolve()): PINNED_HOST_SOURCE_SHA256,
        str((ROOT / "kernels/hybrid_probe.cu").resolve()): PINNED_KERNEL_SOURCE_SHA256,
    }
    if manifest.get("schema") != "nvidia-hybrid-probe-build-v2":
        raise ValueError("CUDA probe build manifest has an unsupported schema")
    if manifest.get("probe") != {"path": str(probe_path.resolve()), "sha256": probe_sha256}:
        raise ValueError("CUDA probe build manifest does not identify the pinned probe")
    if manifest.get("fatbin") != {
            "path": str(fatbin_path.resolve()), "sha256": fatbin_sha256}:
        raise ValueError("CUDA probe build manifest does not identify the pinned fatbin")
    if manifest.get("source_inputs_sha256") != expected_sources:
        raise ValueError("CUDA probe build manifest does not match the pinned source files")
    builder_sha256 = manifest.get("build_tool_sha256")
    if builder_sha256 != _hash_regular_nofollow(ROOT / "tools/build_probe_cuda129.py"):
        raise ValueError("CUDA probe build manifest does not match a pinned builder")
    if (manifest.get("fatbin_images") != ["sm_70", "sm_120a"] or
            manifest.get("fatbin_image_kinds") != {"sm_70": "ptx", "sm_120a": "cubin"}):
        raise ValueError("CUDA probe build manifest lacks the required SM70-PTX/SM120a-cubin images")
    return probe_sha256, manifest_sha256, probe_path, probe_manifest_path


def run(report_path=None, log_path=None, bundle_dir=None, evidence_root=None):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_root = Path(evidence_root or ROOT).resolve(strict=True)
    if not evidence_root.is_dir():
        raise ValueError("evidence root is not a directory")
    evidence_directory = evidence_root / "evidence"
    report_path = Path(report_path) if report_path else (
        evidence_directory / f"software-verification-openrm-hal-matrix-v1-{timestamp}.json"
    )
    log_path = Path(log_path) if log_path else (
        evidence_directory / "logs" / f"software-verification-openrm-hal-matrix-v1-{timestamp}.log"
    )
    try:
        probe_sha256, probe_manifest_sha256, probe_path, probe_manifest_path = (
            _verify_probe_build(bundle_dir)
        )
        test_sources_before = _source_hashes()
        implementation_sources_before = _implementation_hashes()
        env = os.environ.copy()
        env.update({
            "HYBRID_PROBE": str(probe_path),
            "HYBRID_CUDA_PROBE": str(probe_path),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        command = [sys.executable, "-B", "-m", "unittest", "discover", "-v", "-s", "tests"]
        completed = subprocess.run(
            command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=900
        )
        test_sources_after = _source_hashes()
        changed_test_sources = _changed_source_hashes(
            test_sources_before, test_sources_after
        )
        implementation_sources_after = _implementation_hashes()
        changed_implementation_sources = _changed_source_hashes(
            implementation_sources_before, implementation_sources_after
        )
        raw_log = completed.stdout + completed.stderr
        match = re.search(r"^Ran (\d+) tests? in ([0-9.]+)s$", raw_log, re.M)
        passed = (
            completed.returncode == 0
            and match is not None
            and re.search(r"^OK$", raw_log, re.M) is not None
            and "FAILED" not in raw_log
            and "ERROR" not in raw_log
            and "skipped=" not in raw_log
            and not changed_test_sources
            and not changed_implementation_sources
        )
        log_bytes = raw_log.encode("utf-8")
        _write_private_raw_log(
            log_path, log_bytes, evidence_root=evidence_directory
        )
        report = {
            "schema": "software-verification-openrm-hal-matrix-v1",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "command": command,
            "test_source_sha256": test_sources_before,
            "test_source_sha256_after": test_sources_after,
            "test_source_changes": changed_test_sources,
            "implementation_sha256_after": implementation_sources_after,
            "implementation_source_changes": changed_implementation_sources,
            "implementation_sha256": implementation_sources_before,
            "hybrid_patch_sha256": {
                "patches/r580.178.04/0048-private-open-sync-boost-groups.patch":
                    _hash_regular_nofollow(
                        ROOT / "patches/r580.178.04/0048-private-open-sync-boost-groups.patch"),
                "patches/r580.178.04/0050-private-open-debugger-bridge.patch":
                    _hash_regular_nofollow(
                        ROOT / "patches/r580.178.04/0050-private-open-debugger-bridge.patch"),
                "patches/r580.178.04/proprietary/0046-private-legacy-sync-boost-groups.patch":
                    _hash_regular_nofollow(
                        ROOT / "patches/r580.178.04/proprietary/0046-private-legacy-sync-boost-groups.patch"),
                "patches/r580.178.04/proprietary/0048-private-legacy-debugger-bridge.patch":
                    _hash_regular_nofollow(
                        ROOT / "patches/r580.178.04/proprietary/0048-private-legacy-debugger-bridge.patch"),
            },
            "probe": {
                "path": str(probe_path),
                "sha256": probe_sha256,
                "build_manifest": {
                    "path": str(probe_manifest_path),
                    "sha256": probe_manifest_sha256,
                },
                "HYBRID_PROBE": str(probe_path),
                "HYBRID_CUDA_PROBE": str(probe_path),
            },
            "tests_run": int(match.group(1)) if match else None,
            "reported_seconds": float(match.group(2)) if match else None,
            "process_exit_code": completed.returncode,
            "status": "pass" if passed else "fail",
            "log": str(log_path),
            "log_sha256": hashlib.sha256(log_bytes).hexdigest(),
            "evidence_root": str(evidence_root),
            "qualification": "software-suite-only",
            "runtime_or_hardware_validated": False,
            "loaded_or_installed": False,
        }
        write_private_evidence_report(
            report_path, report, repository_root=evidence_root
        )
        print(json.dumps(report, indent=2))
        return 0 if passed else 1
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"software verification failed: {error}", file=sys.stderr)
        return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", type=Path,
                        help="use a specific directory containing the pinned probe and manifest")
    parser.add_argument("--evidence-root", type=Path,
                        help="project root containing the evidence directory for private outputs")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--log", type=Path)
    args = parser.parse_args()
    return run(args.report, args.log, args.bundle_dir, args.evidence_root)


if __name__ == "__main__":
    raise SystemExit(main())
