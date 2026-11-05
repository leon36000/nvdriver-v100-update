#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small process-local Driver API probe for one pinned V100 SM70 cubin."""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import sys


LIBCUDA_PATH = "__LIBCUDA_PATH__"
CUBIN_B64 = "__CUBIN_B64__"
CUBIN_SHA256 = "__CUBIN_SHA256__"
EXPECTED_PCI = "0000:00:05.0"
EXPECTED_VALUE = 700


def main() -> int:
    result: dict[str, object] = {
        "schema": "nvidia-hybrid-v100-sm70-driver-api-kernel-v1",
        "status": "phase-failed",
        "phase": "kernel",
        "expected_pci": EXPECTED_PCI,
        "driver_library_path": None,
        "driver_api": None,
        "device": None,
        "cubin_sha256": CUBIN_SHA256,
        "cubin_digest_passed": False,
        "completed_operations": [],
        "numeric_result_passed": False,
        "result_value": None,
        "expected_result": EXPECTED_VALUE,
        "cleanup_passed": True,
        "cleanup_errors": [],
        "error": "",
    }
    operations: list[str] = []
    cleanup_errors: list[str] = []
    library = None
    context = ctypes.c_void_p()
    module = ctypes.c_void_p()
    device_pointer = ctypes.c_uint64(0)
    cubin_buffer = None
    try:
        cubin = base64.b64decode(CUBIN_B64, validate=True)
        if hashlib.sha256(cubin).hexdigest() != CUBIN_SHA256:
            raise RuntimeError("SM70 cubin digest mismatch")
        result["cubin_digest_passed"] = True
        library = ctypes.CDLL(LIBCUDA_PATH, mode=os.RTLD_NOW | os.RTLD_LOCAL)
        result["driver_library_path"] = os.path.realpath(LIBCUDA_PATH)
        i32, u32, u64, size = ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_size_t
        library.cuGetErrorName.argtypes = [i32, ctypes.POINTER(ctypes.c_char_p)]
        library.cuGetErrorName.restype = i32
        library.cuGetErrorString.argtypes = [i32, ctypes.POINTER(ctypes.c_char_p)]
        library.cuGetErrorString.restype = i32

        def checked(name: str, *args: object) -> None:
            function = getattr(library, name)
            status = int(function(*args))
            if status != 0:
                error_name = ctypes.c_char_p()
                error_string = ctypes.c_char_p()
                library.cuGetErrorName(status, ctypes.byref(error_name))
                library.cuGetErrorString(status, ctypes.byref(error_string))
                label = error_name.value.decode("ascii", "replace") if error_name.value else "unknown"
                detail = error_string.value.decode("utf-8", "replace") if error_string.value else ""
                raise RuntimeError(f"{name}={status}:{label}:{detail}"[:240])
            operations.append(name)

        library.cuInit.argtypes = [u32]
        library.cuInit.restype = i32
        library.cuDriverGetVersion.argtypes = [ctypes.POINTER(i32)]
        library.cuDriverGetVersion.restype = i32
        library.cuDeviceGetCount.argtypes = [ctypes.POINTER(i32)]
        library.cuDeviceGetCount.restype = i32
        library.cuDeviceGet.argtypes = [ctypes.POINTER(i32), i32]
        library.cuDeviceGet.restype = i32
        library.cuDeviceGetName.argtypes = [ctypes.c_char_p, i32, i32]
        library.cuDeviceGetName.restype = i32
        library.cuDeviceGetPCIBusId.argtypes = [ctypes.c_char_p, i32, i32]
        library.cuDeviceGetPCIBusId.restype = i32
        library.cuDeviceComputeCapability.argtypes = [ctypes.POINTER(i32), ctypes.POINTER(i32), i32]
        library.cuDeviceComputeCapability.restype = i32
        library.cuCtxCreate_v2.argtypes = [ctypes.POINTER(ctypes.c_void_p), u32, i32]
        library.cuCtxCreate_v2.restype = i32
        library.cuCtxSetCurrent.argtypes = [ctypes.c_void_p]
        library.cuCtxSetCurrent.restype = i32
        library.cuCtxGetDevice.argtypes = [ctypes.POINTER(i32)]
        library.cuCtxGetDevice.restype = i32
        library.cuCtxSynchronize.argtypes = []
        library.cuCtxSynchronize.restype = i32
        library.cuCtxDestroy_v2.argtypes = [ctypes.c_void_p]
        library.cuCtxDestroy_v2.restype = i32
        library.cuModuleLoadData.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        library.cuModuleLoadData.restype = i32
        library.cuModuleGetFunction.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                                ctypes.c_char_p]
        library.cuModuleGetFunction.restype = i32
        library.cuModuleUnload.argtypes = [ctypes.c_void_p]
        library.cuModuleUnload.restype = i32
        library.cuMemAlloc_v2.argtypes = [ctypes.POINTER(u64), size]
        library.cuMemAlloc_v2.restype = i32
        library.cuMemFree_v2.argtypes = [u64]
        library.cuMemFree_v2.restype = i32
        library.cuLaunchKernel.argtypes = [
            ctypes.c_void_p, u32, u32, u32, u32, u32, u32, u32, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ]
        library.cuLaunchKernel.restype = i32
        library.cuMemcpyDtoH_v2.argtypes = [ctypes.c_void_p, u64, size]
        library.cuMemcpyDtoH_v2.restype = i32

        checked("cuInit", 0)
        version = i32()
        checked("cuDriverGetVersion", ctypes.byref(version))
        result["driver_api"] = int(version.value)
        count = i32()
        checked("cuDeviceGetCount", ctypes.byref(count))
        if count.value != 1:
            raise RuntimeError("selected V100 guest must expose exactly one CUDA device")
        device = i32()
        checked("cuDeviceGet", ctypes.byref(device), 0)
        name = ctypes.create_string_buffer(256)
        pci = ctypes.create_string_buffer(32)
        major, minor = i32(), i32()
        checked("cuDeviceGetName", name, len(name), device.value)
        checked("cuDeviceGetPCIBusId", pci, len(pci), device.value)
        checked("cuDeviceComputeCapability", ctypes.byref(major), ctypes.byref(minor), device.value)
        result["device"] = {
            "name": name.value.decode("utf-8", "replace"),
            "pci_bus_id": pci.value.decode("ascii", "replace"),
            "sm": major.value * 10 + minor.value,
            "compute_capability": f"{major.value}.{minor.value}",
        }
        if (not result["device"]["name"].startswith("Tesla V100") or
                result["device"]["pci_bus_id"] != EXPECTED_PCI or
                result["device"]["sm"] != 70):
            raise RuntimeError("selected CUDA device is not the pinned V100 SM70")

        checked("cuCtxCreate_v2", ctypes.byref(context), 0, device.value)
        checked("cuCtxSetCurrent", context)
        current = i32()
        checked("cuCtxGetDevice", ctypes.byref(current))
        if current.value != device.value:
            raise RuntimeError("created CUDA context belongs to a different device")
        cubin_buffer = ctypes.create_string_buffer(cubin)
        checked("cuModuleLoadData", ctypes.byref(module), ctypes.cast(cubin_buffer, ctypes.c_void_p))
        function = ctypes.c_void_p()
        checked("cuModuleGetFunction", ctypes.byref(function), module, b"hybrid_arch")
        checked("cuMemAlloc_v2", ctypes.byref(device_pointer), ctypes.sizeof(i32))
        kernel_parameter = ctypes.cast(ctypes.byref(device_pointer), ctypes.c_void_p)
        kernel_parameters = (ctypes.c_void_p * 1)(kernel_parameter)
        checked("cuLaunchKernel", function, 1, 1, 1, 1, 1, 1, 0, None,
                kernel_parameters, None)
        checked("cuCtxSynchronize")
        value = i32()
        checked("cuMemcpyDtoH_v2", ctypes.byref(value), device_pointer, ctypes.sizeof(value))
        result["result_value"] = int(value.value)
        result["numeric_result_passed"] = value.value == EXPECTED_VALUE
        if not result["numeric_result_passed"]:
            raise RuntimeError("SM70 architecture kernel returned an unexpected value")
    except Exception as exc:
        result["error"] = str(exc)[:240]
    finally:
        if library is not None:
            for name, handle in (("cuMemFree_v2", device_pointer),
                                 ("cuModuleUnload", module),
                                 ("cuCtxDestroy_v2", context)):
                value = handle.value if isinstance(handle, (ctypes.c_void_p, ctypes.c_uint64)) else None
                if value:
                    try:
                        code = int(getattr(library, name)(value))
                        if code == 0:
                            operations.append(name)
                        else:
                            cleanup_errors.append(f"{name}={code}")
                    except Exception as exc:
                        cleanup_errors.append(f"{name}:{type(exc).__name__}")
        result["completed_operations"] = operations
        result["cleanup_errors"] = cleanup_errors
        result["cleanup_passed"] = not cleanup_errors
        passed = (result["numeric_result_passed"] is True and not result["error"] and
                  result["cleanup_passed"] is True)
        result["status"] = "phase-passed" if passed else "phase-failed"
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "phase-passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
