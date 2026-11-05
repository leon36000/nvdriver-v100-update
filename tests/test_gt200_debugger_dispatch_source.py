"""Static regression checks for the pinned R580/R595/R615 SM debugger dispatch."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import unittest
from functools import lru_cache


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = {
    "R580.178.04": ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04/src",
    "R595.99.02": ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/open-gpu-kernel-modules-595.99.02/src",
}
NULL_ROUTE_SOURCE_ROOTS = {
    **SOURCE_ROOTS,
    "R615.71.10": ROOT / ".cache/upstream/extracted-r615-71-10-20261023/open-gpu-kernel-modules-6f3be8c9c3fb4ed6ffc607a0d32d31ce4db7fba5/src",
    "R580.196.07": None,
    "R595.112.07": None,
    "R615.78.08": None,
}
PINNED_SOURCE_ARCHIVES = {
    "R580.196.07": (
        ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.196.07.tar.xz",
        "NVIDIA-kernel-module-source-580.196.07",
        "21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084",
    ),
    "R595.112.07": (
        ROOT / ".cache/upstream/open-gpu-kernel-modules-595.112.07-d8257d95.tar.gz",
        "open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2",
        "567d4ba082a54ef733e7ce87c87401da488a3aabe29837c92feb19011c8250c4",
    ),
    "R595.99.02": (
        ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source.tar.gz",
        "open-gpu-kernel-modules-595.99.02",
        "b8891cb617683e28ef1e4c3add8dbc30e648b8cd6429a3d521f20dde44633262",
    ),
    "R615.78.08": (
        ROOT / ".cache/upstream/open-gpu-kernel-modules-1a82fbfda8f321b056eb3568850f9316c5e465c5.tar.gz",
        "open-gpu-kernel-modules-1a82fbfda8f321b056eb3568850f9316c5e465c5",
        "590ee6a5a780f946322edd17f9d235c6664eb7e6839073ac0d68c0f263e7184f",
    ),
}


@lru_cache(maxsize=len(PINNED_SOURCE_ARCHIVES))
def read_pinned_source_archive(version: str, relative_path: str) -> str:
    """Read one source member from a hash-pinned archive without extracting it."""
    path, archive_root, expected_sha256 = PINNED_SOURCE_ARCHIVES[version]
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required to read pinned source archives")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OSError(f"pinned source archive is not a regular file: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            snapshot = stream.read()
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise OSError(f"pinned source archive changed while being read: {path}")
        if len(snapshot) != before.st_size:
            raise OSError(f"short read of pinned source archive: {path}")
    finally:
        os.close(descriptor)
    if hashlib.sha256(snapshot).hexdigest() != expected_sha256:
        raise ValueError(f"pinned source archive digest differs for {version}")

    member_name = f"{archive_root}/src/{relative_path}"
    with tarfile.open(fileobj=io.BytesIO(snapshot), mode="r:*") as archive:
        matches = [member for member in archive.getmembers() if member.name == member_name]
        if len(matches) != 1 or not matches[0].isfile():
            raise ValueError(f"expected one regular source member: {member_name}")
        member = archive.extractfile(matches[0])
        if member is None:
            raise ValueError(f"could not read source member: {member_name}")
        return member.read().decode("utf-8", errors="strict")


class GT200DebuggerDispatchSourceTests(unittest.TestCase):
    def read(self, version: str, relative_path: str) -> str:
        source_root = NULL_ROUTE_SOURCE_ROOTS[version]
        if source_root is None:
            return read_pinned_source_archive(version, relative_path)
        path = source_root / relative_path
        self.assertTrue(path.is_file(), f"pinned source input is missing: {path}")
        return path.read_text(encoding="utf-8")

    @staticmethod
    def extract_function(source: str, symbol: str) -> str:
        signatures = re.finditer(
            r"\bNV_STATUS\s+" + re.escape(symbol) + r"\s*\(",
            source,
        )
        found_signature = False
        for signature in signatures:
            found_signature = True
            start = signature.start()
            body_start = source.find("{", signature.end())
            declaration_end = source.find(";", signature.end())
            if body_start < 0 or (declaration_end >= 0 and declaration_end < body_start):
                continue
            depth = 0
            for index in range(body_start, len(source)):
                if source[index] == "{":
                    depth += 1
                elif source[index] == "}":
                    depth -= 1
                    if depth == 0:
                        return source[start:index + 1]
        if not found_signature:
            raise AssertionError(f"function signature is missing: {symbol}")
        raise AssertionError(f"unterminated function: {symbol}")

    @staticmethod
    def extract_gpu_manager_function(source: str, symbol: str) -> str:
        signature = re.search(
            r"\b(?:NV_STATUS|POBJGPU|NvU32)\s+" + re.escape(symbol) + r"\s*\(",
            source,
        )
        if signature is None:
            raise AssertionError(f"GPU-manager function signature is missing: {symbol}")
        body_start = source.index("{", signature.start())
        depth = 0
        for index in range(body_start, len(source)):
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    return source[signature.start():index + 1]
        raise AssertionError(f"unterminated GPU-manager function: {symbol}")

    def test_id_info_resolves_from_global_initialized_gpu_mask_in_both_providers(self):
        for version in ("R580.196.07", "R595.99.02"):
            with self.subTest(version=version):
                gpu_mgr = read_pinned_source_archive(
                    version, "nvidia/src/kernel/gpu_mgr/gpu_mgr.c")
                client_resource = read_pinned_source_archive(
                    version, "nvidia/src/kernel/rmapi/client_resource.c")
                attach_info = self.extract_gpu_manager_function(
                    gpu_mgr, "gpumgrGetGpuAttachInfo")
                gpu_from_id = self.extract_gpu_manager_function(
                    gpu_mgr, "gpumgrGetGpuFromId")
                id_info = self.extract_gpu_manager_function(
                    gpu_mgr, "gpumgrGetGpuIdInfoV2")
                instance_mask = self.extract_gpu_manager_function(
                    gpu_mgr, "gpumgrGetDeviceInstanceMask")
                device_ids_control = self.extract_function(
                    client_resource, "cliresCtrlCmdGpuGetDeviceIds_IMPL")

                self.assertRegex(attach_info, r"gpuMask\s*=\s*pGpuMgr->gpuAttachMask")
                self.assertIn("PDB_PROP_GPU_STATE_INITIALIZED", attach_info)
                self.assertRegex(
                    gpu_from_id,
                    r"gpumgrGetGpuAttachInfo\s*\(\s*&gpuAttachCnt\s*,\s*&gpuAttachMask\s*\)")
                self.assertRegex(gpu_from_id, r"gpuAttachMask\s*&\s*NVBIT\(i\)")
                self.assertRegex(gpu_from_id, r"pGpu->gpuId\s*==\s*gpuId")
                self.assertRegex(
                    id_info,
                    r"gpumgrGetGpuFromId\s*\(\s*pGpuInfo->gpuId\s*\)")
                self.assertIn("NV_ERR_INVALID_ARGUMENT", id_info)
                self.assertRegex(instance_mask,
                                 r"gpumgrIsDeviceInstanceValid\s*\(\s*i\s*\)")
                self.assertRegex(device_ids_control,
                                 r"gpumgrGetDeviceInstanceMask\s*\(\s*\)")

    def test_actual_resource_lookup_rejects_unmapped_null_internal_handle(self):
        harness = r"""
#include <stddef.h>

typedef unsigned int NvHandle;
typedef int NV_STATUS;
enum { NV_OK = 0, NV_ERR_OBJECT_NOT_FOUND = 1 };
typedef struct { int resourceMap; } RsClient;
typedef struct { int marker; } RsResourceRef;
static RsResourceRef stored_ref;
static RsResourceRef *mapFind(int *map, NvHandle handle)
{
    return (*map != 0 && handle == 9) ? &stored_ref : NULL;
}

__CLIENT_LOOKUP__

int main(void)
{
    RsClient client = {0};
    RsResourceRef *found = NULL;
    if (clientGetResourceRef_IMPL(&client, 0, &found) != NV_ERR_OBJECT_NOT_FOUND)
        return 1;
    if (found != NULL)
        return 2;
    client.resourceMap = 1;
    if (clientGetResourceRef_IMPL(&client, 9, &found) != NV_OK || found != &stored_ref)
        return 3;
    if (clientGetResourceRef_IMPL(&client, 9, NULL) != NV_OK)
        return 4;
    return 0;
}
"""
        for version in NULL_ROUTE_SOURCE_ROOTS:
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmp:
                client = self.read(version, "nvidia/src/libraries/resserv/src/rs_client.c")
                function = self.extract_function(client, "clientGetResourceRef_IMPL")
                c_file = Path(tmp) / "resource_lookup.c"
                binary = Path(tmp) / "resource_lookup"
                c_file.write_text(harness.replace("__CLIENT_LOOKUP__", function),
                                  encoding="utf-8")
                compile_result = subprocess.run(
                    ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                     str(c_file), "-o", str(binary)],
                    text=True, capture_output=True, check=False)
                self.assertEqual(compile_result.returncode, 0,
                                 compile_result.stdout + compile_result.stderr)
                run_result = subprocess.run([str(binary)], text=True,
                                            capture_output=True, check=False)
                self.assertEqual(run_result.returncode, 0,
                                 f"{version}: {run_result.stdout}{run_result.stderr}")

    def test_hybrid_exception_mask_bridges_reach_null_internal_handle_route(self):
        """Pin the composition that blocks debugger control in current providers.

        This is a source-level incompatibility finding, not a runtime test. The
        frontend bridge invokes each provider with the public debugger handle;
        each provider submits NV04_CONTROL, after which NVIDIA's debugger
        resource forwards internally with NV01_NULL_OBJECT. The pinned RM
        source resolves that zero handle through the client resource map before
        class dispatch, while allocated resource handles are nonzero.
        """
        frontend = (ROOT / "src/hybrid_frontend.c").read_text(encoding="utf-8")
        signature = re.search(
            r"static long\s+hybrid_front_debugger_exception_mask_ioctl\s*"
            r"\([^)]*\)\s*\{", frontend)
        self.assertIsNotNone(signature, "frontend exception-mask bridge is missing")
        body_start = signature.end() - 1
        depth = 0
        frontend_body = None
        for index in range(body_start, len(frontend)):
            if frontend[index] == "{":
                depth += 1
            elif frontend[index] == "}":
                depth -= 1
                if depth == 0:
                    frontend_body = frontend[body_start:index + 1]
                    break
        self.assertIsNotNone(frontend_body, "frontend bridge body is unterminated")
        self.assertIn("hybrid580_legacy_control_session_debugger_exception_mask_v1",
                      frontend_body)
        self.assertIn("hybrid580_open_control_session_debugger_exception_mask_v1",
                      frontend_body)

        providers = (
            ("R595.99.02",
             ROOT / "build/experiments/r595-debugger-bridge-provider-build-v4-20261101/"
                   "source/kernel-open/nvidia/nv.c",
             "hybrid580_open_control_session_debugger_exception_mask_v1",
             "f7ef137ac93e2afed2efb3a44348dba97436d496d67f65216d9c84ec6f331de5",
             ROOT / "evidence/r595-debugger-bridge-provider-build-v4-20261101.json",
             "67052f19d331f10f463f8b04dc8746819fbc4040487009fa7a079c97cd2d4d05"),
            ("R580.196.07",
             ROOT / "build/experiments/r58019607-debugger-bridge-provider-build-v3-20261101/"
                   "source/nvidia/nv.c",
             "hybrid580_legacy_control_session_debugger_exception_mask_v1",
             "6886fff8eed6d5869b3240860e61a1d9fddec8a9a77055a52ed71ebaebe13c11",
             ROOT / "evidence/r58019607-debugger-bridge-provider-build-v3-20261101.json",
             "f38e9bf452d4d28c6ac1281eaa5095523daf231a129721db2176a4e8fa2ee02f"),
        )
        for version, path, symbol, source_sha256, report_path, module_sha256 in providers:
            with self.subTest(provider=version):
                source = path.read_text(encoding="utf-8")
                self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),
                                 source_sha256)
                report = json.loads(report_path.read_text(encoding="utf-8"))
                self.assertEqual(report["module"]["sha256"], module_sha256)
                bridge = self.extract_function(source, symbol)
                self.assertRegex(bridge, r"\.hObject\s*=\s*h_debugger")
                self.assertRegex(bridge,
                                 r"\.cmd\s*=\s*NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK")
                self.assertRegex(bridge, r"\.op\s*=\s*NV04_CONTROL")
                self.assertIn("rm_kernel_rmapi_op(sp, &ops)", bridge)

        for version in ("R580.196.07", "R595.99.02"):
            with self.subTest(rm=version):
                debugger = self.read(
                    version, "nvidia/src/kernel/gpu/gr/kernel_sm_debugger_session.c")
                internal_handle = re.search(
                    r"\bNvHandle\s+ksmdbgssnGetInternalObjectHandle_IMPL\s*"
                    r"\([^)]*\)\s*\{(?P<body>[^}]*)\}",
                    debugger,
                    re.DOTALL,
                )
                self.assertIsNotNone(internal_handle,
                                     "debugger internal-object getter is missing")
                self.assertRegex(internal_handle.group("body"),
                                 r"return\s+NV01_NULL_OBJECT\s*;")
                forward = self.extract_function(
                    debugger, "ksmdbgssnInternalControlForward_IMPL")
                self.assertIn("gpuresInternalControlForward_IMPL", forward)

                client = self.read(
                    version, "nvidia/src/libraries/resserv/src/rs_client.c")
                lookup = self.extract_function(client, "clientGetResourceRef_IMPL")
                self.assertIn("mapFind(&pClient->resourceMap, hResource)", lookup)
                self.assertRegex(lookup,
                                 r"if\s*\(pResourceRef\s*==\s*NULL\)\s*"
                                 r"return\s+NV_ERR_OBJECT_NOT_FOUND\s*;")

                server = self.read(
                    version, "nvidia/src/libraries/resserv/src/rs_server.c")
                server_alloc_client = self.extract_function(server, "serverAllocClient")
                self.assertIn("pParams->hResource = hClient;", server_alloc_client)
                self.assertIn("clientAllocResource(pClient, pServer, pParams)",
                              server_alloc_client)
                create_client = self.extract_function(
                    server, "_serverCreateEntryAndLockForNewClient")
                self.assertIn("serverAllocClientHandleBase", create_client)
                self.assertIn("CLIENT_ENCODEHANDLE(handleBase, clientHandleIndex)",
                              create_client)
                self.assertRegex(
                    server,
                    r"pServer->clientHandleBase\s*=\s*RS_CLIENT_HANDLE_BASE\s*;")
                generated = self.read(
                    version, "nvidia/generated/g_resserv_nvoc.h")
                self.assertRegex(generated,
                                 r"#define\s+RS_CLIENT_HANDLE_BASE\s+0xC1D00000")

                client_alloc = self.extract_function(
                    client, "_clientConstructResourceRef")
                self.assertIn("mapInsertNew(&pClient->resourceMap, hResource)",
                              client_alloc)
                assign_handle = self.extract_function(
                    client, "clientAssignResourceHandle_IMPL")
                self.assertRegex(assign_handle,
                                 r"if\s*\(\*phResource\s*==\s*0\)\s*"
                                 r"\{\s*status\s*=\s*clientGenResourceHandle")
                generate_handle = self.extract_function(
                    client, "clientGenResourceHandle_IMPL")
                self.assertIn("NV_ASSERT(pClient->handleRangeStart != 0)",
                              generate_handle)
                self.assertIn("pClient->handleRangeStart +", generate_handle)

    def test_experimental_r580_mask_guard_stays_out_of_default_patch_series(self):
        """Keep the fail-closed variant isolated while Volta dispatch is unresolved."""
        spec = importlib.util.spec_from_file_location(
            "private_proprietary580_builder", ROOT / "tools/build_private_proprietary580.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        port_spec = importlib.util.spec_from_file_location(
            "r580_proprietary_source_port_probe",
            ROOT / "tools/probe_r580_proprietary_source_port.py")
        port_builder = importlib.util.module_from_spec(port_spec)
        port_spec.loader.exec_module(port_builder)
        patch_path = ROOT / (
            "patches/r580.178.04/proprietary/"
            "0049-private-legacy-debugger-mask-fail-closed.patch")
        self.assertTrue(patch_path.is_file(), "R580 fail-closed patch is missing")
        self.assertNotIn(patch_path, builder.PATCHES)
        self.assertNotIn(patch_path, port_builder.PATCHES)

        patches = builder.PM_CHANNEL_DEPTH_PREDECESSOR_PATCHES + [
            builder.PM_CHANNEL_DEPTH_PATCH,
            builder.PM_RECOVERY_PROVIDER_PATCH,
            builder.PM_CHANNEL_DPM_MODESET_PATCH,
            builder.SYS_PARAMS_PATCH,
        ]
        source = builder.apply_patches_to_text(
            (builder.PREVIOUS_SOURCE / "nvidia/nv.c").read_text(), patches,
            "nvidia/nv.c",
            extra_files=(("nvidia/hybrid580-control-session.h",
                          builder.PREVIOUS_CONTROL_HEADER),
                         ("nvidia/nv-procfs.c",
                          builder.PREVIOUS_SOURCE / "nvidia/nv-procfs.c")))
        source = builder.apply_patches_to_text(
            source, [builder.GPU_REGISTER_CONTROL_PATCH], "nvidia/nv.c",
            target_filter={"nvidia/nv.c"})
        for filename in (
                "0039-private-legacy-engine-object.patch",
                "0040-private-legacy-update-device-mapping-info.patch",
                "0043-private-legacy-version-check.patch",
                "0044-private-legacy-gpu-name-string.patch",
                "0045-private-legacy-client-share-policy.patch",
                "0046-private-legacy-sync-boost-groups.patch",
                "0047-private-legacy-gf100-master-object.patch",
                "0048-private-legacy-debugger-bridge.patch"):
            source = builder.apply_patches_to_text(
                source, [ROOT / "patches/r580.178.04/proprietary" / filename],
                "nvidia/nv.c", target_filter={"nvidia/nv.c"})
        default_bridge = self.extract_function(
            source, "hybrid580_legacy_control_session_debugger_exception_mask_v1")
        self.assertIn(".op = NV04_CONTROL", default_bridge)
        self.assertIn("rm_kernel_rmapi_op(sp, &ops)", default_bridge)

        patched_source = builder.apply_patches_to_text(
            source, [patch_path], "nvidia/nv.c", target_filter={"nvidia/nv.c"})
        patched = self.extract_function(
            patched_source,
            "hybrid580_legacy_control_session_debugger_exception_mask_v1")

        self.assertIn("*control_status = NV_ERR_NOT_SUPPORTED;", patched)
        self.assertRegex(patched, r"return\s+NV_OK\s*;")
        self.assertNotIn("NV04_CONTROL", patched)
        self.assertNotIn("rm_kernel_rmapi_op", patched)

        r595_source = ROOT / (
            "build/experiments/r595-debugger-bridge-provider-build-v4-20261101/"
            "source/kernel-open/nvidia/nv.c")
        r595 = self.extract_function(
            r595_source.read_text(encoding="utf-8"),
            "hybrid580_open_control_session_debugger_exception_mask_v1")
        self.assertIn(".op = NV04_CONTROL", r595)
        self.assertIn("rm_kernel_rmapi_op(sp, &ops)", r595)

    def test_public_exception_mask_control_id_and_payload_are_stable(self):
        for version in SOURCE_ROOTS:
            with self.subTest(version=version):
                header = self.read(
                    version, "common/sdk/nvidia/inc/ctrl/ctrl83de/ctrl83dedebug.h")
                self.assertRegex(
                    header,
                    r"#define\s+NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK\s+\(0x83de0309\)")
                self.assertRegex(
                    header,
                    r"typedef\s+struct\s+NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS\s*\{\s*"
                    r"NvU32\s+exceptionMask\s*;\s*\}")

    def test_public_kernel_rmapi_ops_do_not_expose_internal_handle_lookup(self):
        """Pin the provider API boundary; absence here is not a runtime proof."""
        header_path = "nvidia/arch/nvalloc/unix/include/nv-kernel-rmapi-ops.h"
        for version in ("R580.196.07", "R595.99.02"):
            with self.subTest(version=version):
                header = self.read(version, header_path)
                operations = re.search(
                    r"typedef\s+struct\s*\{.*?union\s*\{(?P<union>.*?)\}"
                    r"\s*params\s*;.*?\}"
                    r"\s*nvidia_kernel_rmapi_ops_t\s*;",
                    header,
                    re.DOTALL,
                )
                self.assertIsNotNone(operations,
                                     "kernel RMAPI operation contract is missing")
                union = operations.group("union")
                self.assertIn("NVOS64_PARAMETERS alloc", union)
                self.assertIn("NVOS54_PARAMETERS control", union)
                self.assertIn("NVOS55_PARAMETERS dupObject", union)
                self.assertNotRegex(
                    union,
                    r"(?i)(?:get|query|lookup|internal)[A-Za-z_]*(?:client|subdevice|handle)"
                    r"|(?:client|subdevice|handle)[A-Za-z_]*(?:get|query|lookup)")
                self.assertNotIn("hInternalClient", header)
                self.assertNotIn("hInternalSubdevice", header)

    def test_generated_method_table_keeps_public_id_and_payload_type(self):
        method_table_path = "nvidia/generated/g_kernel_sm_debugger_session_nvoc.c"
        for version in SOURCE_ROOTS:
            with self.subTest(version=version):
                source = self.read(version, method_table_path)
                entry = re.search(
                    r"/\*methodId=\*/\s*0x83de0309u(?P<entry>.{0,500})",
                    source,
                    re.DOTALL,
                )
                self.assertIsNotNone(entry, "public control is absent from the NVOC method table")
                self.assertIn("sizeof(NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS)",
                              entry.group("entry"))
                self.assertIn('"ksmdbgssnCtrlCmdDebugSetExceptionMask"', entry.group("entry"))

    def test_generated_wrapper_maps_to_internal_control_id(self):
        wrapper_path = "nvidia/generated/g_kernel_sm_debugger_session_nvoc.h"
        for version in SOURCE_ROOTS:
            with self.subTest(version=version):
                source = self.read(version, wrapper_path)
                method = re.search(
                    r"ksmdbgssnCtrlCmdDebugSetExceptionMask_fcf1ac\s*\([^)]*\)\s*"
                    r"\{(?P<body>[^}]*)\}",
                    source,
                    re.DOTALL,
                )
                self.assertIsNotNone(method, "generated public-method wrapper is missing")
                internal_id = re.search(
                    r"ksmdbgssnInternalControlForward\s*\([^,]+,\s*\(?\s*(\d+)U?\s*\)?\s*,",
                    method.group("body"),
                )
                self.assertIsNotNone(internal_id, "wrapper does not forward an internal command")
                self.assertEqual(int(internal_id.group(1)), 0x83DE0405)

    def test_internal_forwarding_and_object_handle_contract_are_explicit(self):
        implementation_path = "nvidia/src/kernel/gpu/gr/kernel_sm_debugger_session.c"
        for version in SOURCE_ROOTS:
            with self.subTest(version=version):
                source = self.read(version, implementation_path)
                forwarding = re.search(
                    r"ksmdbgssnInternalControlForward_IMPL\s*\([^)]*\)\s*"
                    r"\{(?P<body>[^}]*)\}",
                    source,
                    re.DOTALL,
                )
                self.assertIsNotNone(forwarding, "internal forwarding implementation is missing")
                self.assertRegex(
                    forwarding.group("body"),
                    r"gpuresInternalControlForward_IMPL\s*\(\s*"
                    r"staticCast\(pKernelSMDebuggerSession,\s*GpuResource\),\s*"
                    r"command,\s*pParams,\s*size\s*\)")

                object_handle = re.search(
                    r"ksmdbgssnGetInternalObjectHandle_IMPL\s*\([^)]*\)\s*"
                    r"\{(?P<body>[^}]*)\}",
                    source,
                    re.DOTALL,
                )
                self.assertIsNotNone(object_handle, "internal-object lookup is missing")
                self.assertRegex(object_handle.group("body"), r"return\s+NV01_NULL_OBJECT\s*;")

    def test_resource_forwarder_uses_physical_rm_client_and_object_handles(self):
        resource_path = "nvidia/src/kernel/gpu/gpu_resource.c"
        for version in SOURCE_ROOTS:
            with self.subTest(version=version):
                source = self.read(version, resource_path)
                forwarding = re.search(
                    r"gpuresInternalControlForward_IMPL\s*\([^)]*\)\s*"
                    r"\{(?P<body>[^}]*)\}",
                    source,
                    re.DOTALL,
                )
                self.assertIsNotNone(forwarding, "physical RM control forwarder is missing")
                body = forwarding.group("body")
                self.assertRegex(body, r"GPU_GET_PHYSICAL_RMAPI\s*\(")
                self.assertRegex(
                    body,
                    r"pRmApi->Control\s*\(\s*pRmApi,\s*"
                    r"RES_GET_CLIENT_HANDLE\s*\(pGpuResource\),\s*"
                    r"gpuresGetInternalObjectHandle\s*\(pGpuResource\),\s*"
                    r"command,\s*pParams,\s*size\s*\)")

    def test_null_internal_object_physical_rm_fallback_and_resource_lookup(self):
        for version in NULL_ROUTE_SOURCE_ROOTS:
            with self.subTest(version=version):
                debugger = self.read(
                    version, "nvidia/src/kernel/gpu/gr/kernel_sm_debugger_session.c")
                self.assertRegex(
                    debugger,
                    r"ksmdbgssnGetInternalObjectHandle_IMPL\s*\([^)]*\)\s*"
                    r"\{\s*return\s+NV01_NULL_OBJECT\s*;")

                class_header = self.read(version, "common/sdk/nvidia/inc/class/cl0000.h")
                self.assertRegex(class_header, r"#define\s+NV01_NULL_OBJECT\s+\(0x0\)")

                gpu = self.read(version, "nvidia/src/kernel/gpu/gpu.c")
                self.assertRegex(gpu,
                                 r"pGpu->physicalRmApi\.Control\s*=\s*_gpuRmApiControl\s*;")
                physical_control = self.extract_function(gpu, "_gpuRmApiControl")
                firmware_guard = re.search(
                    r"NV_ASSERT_OR_RETURN\s*\(\s*!IS_FW_CLIENT\(pGpu\),\s*"
                    r"NV_ERR_INVALID_STATE\s*\)",
                    physical_control,
                )
                self.assertIsNotNone(
                    firmware_guard,
                    "physical RM control must reject firmware-backed GPU clients")
                self.assertLess(
                    firmware_guard.start(),
                    physical_control.index("if (!IS_VIRTUAL(pGpu)"),
                    "firmware-client rejection must precede the internal-handle fast path")
                self.assertRegex(
                    physical_control,
                    r"if\s*\(\s*!IS_VIRTUAL\(pGpu\)\s*&&\s*"
                    r"hClient\s*==\s*pGpu->hInternalClient\s*&&\s*"
                    r"hObject\s*==\s*pGpu->hInternalSubdevice\s*\)")
                fallback = physical_control[physical_control.index("else\n    {"):]
                self.assertIn("rmapiGetInterface(RMAPI_GPU_LOCK_INTERNAL)", fallback)
                self.assertRegex(
                    fallback,
                    r"pInternalRmApi->Control\s*\(\s*pInternalRmApi,\s*"
                    r"hClient,\s*hObject,\s*cmd,\s*pParams,\s*paramsSize\s*\)")

                rmapi = self.read(version, "nvidia/src/kernel/rmapi/rmapi.c")
                self.assertRegex(
                    rmapi,
                    r"_rmapiInitInterface\(&g_RmApiList\[RMAPI_GPU_LOCK_INTERNAL\],"
                    r"\s*&secInfo,\s*NV_TRUE[^\n]*\);\s*")
                self.assertRegex(rmapi, r"pRmApi->Control\s*=\s*rmapiControl\s*;")
                rm_control = self.read(version, "nvidia/src/kernel/rmapi/control.c")
                self.assertIn("pRmApi->ControlWithSecInfo(pRmApi, hClient, hObject, cmd",
                              rm_control)
                self.assertIn("_rmapiRmControl(hClient, hObject, cmd, pParams",
                              rm_control)
                rm_control_body = self.extract_function(rm_control, "_rmapiRmControl")
                self.assertIn("rmCtrlParams.hObject = hObject;", rm_control_body)
                self.assertIn("serverControl(&g_resServ, &rmCtrlParams)", rm_control_body)

                server_path = "nvidia/src/libraries/resserv/src/rs_server.c"
                server = self.read(version, server_path)
                control_start = server.index("\nserverControl\n(")
                control_body_start = server.index("{", control_start)
                control_end = server.index("\n}\n", control_body_start)
                control_body = server[control_body_start:control_end]
                lookup = "clientGetResourceRef(pClient, pParams->hObject, &pResourceRef)"
                self.assertIn(lookup, control_body)
                self.assertRegex(
                    control_body,
                    re.escape(lookup) + r"\s*;\s*if\s*\(status\s*!=\s*NV_OK\)\s*goto\s+done\s*;")

                client_path = "nvidia/src/libraries/resserv/src/rs_client.c"
                client = self.read(version, client_path)
                ref_start = client.index("clientGetResourceRef_IMPL")
                ref_body_start = client.index("{", ref_start)
                ref_end = client.index("\n}\n", ref_body_start)
                ref_body = client[ref_body_start:ref_end]
                self.assertIn("mapFind(&pClient->resourceMap, hResource)", ref_body)
                self.assertRegex(
                    ref_body,
                    r"if\s*\(pResourceRef\s*==\s*NULL\)\s*"
                    r"return\s+NV_ERR_OBJECT_NOT_FOUND\s*;")

                # Root objects use a nonzero client handle; ordinary allocation
                # with hResource==0 is assigned a nonzero generated resource handle.
                generated = self.read(version, "nvidia/generated/g_resserv_nvoc.h")
                self.assertRegex(generated, r"#define\s+RS_CLIENT_HANDLE_BASE\s+0xC1D00000")
                server_alloc_start = server.index("\nserverAllocClient\n(")
                server_alloc_body_start = server.index("{", server_alloc_start)
                server_alloc_end = server.index("\n}\n", server_alloc_body_start)
                server_alloc_body = server[server_alloc_body_start:server_alloc_end]
                self.assertIn("pParams->hResource = hClient;", server_alloc_body)
                self.assertIn("clientAllocResource(pClient, pServer, pParams)", server_alloc_body)
                client_gen = self.read(version, client_path)
                self.assertRegex(
                    client_gen,
                    re.compile(
                        r"clientGenResourceHandle_IMPL\s*\([^)]*\)\s*\{"
                        r"(?:(?!\n\}).)*NV_ASSERT\(pClient->handleRangeStart != 0\)",
                        re.DOTALL),
                    "zero-valued resource handles are not generated")
                self.assertRegex(
                    client_gen,
                    re.compile(
                        r"clientAssignResourceHandle_IMPL\s*\([^)]*\)\s*\{"
                        r"(?:(?!\n\}).)*if\s*\(\*phResource\s*==\s*0\)\s*"
                        r"\{\s*status\s*=\s*clientGenResourceHandle",
                        re.DOTALL),
                    "an allocation with hResource==0 must receive a generated handle")

                self.assertLess(control_body.index(lookup),
                                control_body.index("resControl(pResourceRef->pResource"))


if __name__ == "__main__":
    unittest.main()
