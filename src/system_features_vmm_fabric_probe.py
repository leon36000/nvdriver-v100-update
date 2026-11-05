#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded two-process CUDA VMM shareable-handle probe for the pinned V100."""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys


LIBCUDA_PATH = os.environ.get("NVIDIA_HYBRID_VMM_LIBCUDA_PATH", "__LIBCUDA_PATH__")
DEFAULT_EXPECTED_PCI = "0000:00:05.0"
DEFAULT_EXPECTED_DEVICE_NAME_PREFIX = "Tesla V100"
DEFAULT_EXPECTED_SM = 70
DEFAULT_EXPECTED_DRIVER_API = 13000
FABRIC_HANDLE_BYTES = 64
CU_MEM_HANDLE_TYPE_FABRIC = 0x8
FABRIC_SUPPORTED_ATTRIBUTE = 128
CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR = 0x1
POSIX_FD_SUPPORTED_ATTRIBUTE = 103
SHARE_KIND_ENV = "NVIDIA_HYBRID_VMM_SHARE_KIND"
POSIX_FD_ENV = "NVIDIA_HYBRID_VMM_POSIX_FD"
POSIX_SIZE_ENV = "NVIDIA_HYBRID_VMM_POSIX_ALLOCATION_BYTES"
CU_MEM_HANDLE_TYPE_BY_KIND = {
    "fabric": CU_MEM_HANDLE_TYPE_FABRIC,
    "posix_fd": CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR,
}
CU_MEM_ALLOCATION_TYPE_PINNED = 1
CU_MEM_LOCATION_TYPE_DEVICE = 1
CU_MEM_ACCESS_FLAGS_PROT_READWRITE = 0x3
CU_MEM_ALLOC_GRANULARITY_MINIMUM = 0
EXPECTED_WORDS = tuple(0x2468ACE0 ^ (index * 0x01020408) for index in range(16))
PAYLOAD_BYTES = len(EXPECTED_WORDS) * 4
MESSAGE_HEADER_BYTES = 8
FABRIC_MESSAGE_BYTES = MESSAGE_HEADER_BYTES + FABRIC_HANDLE_BYTES
MAX_ALLOCATION_BYTES = 4 * 1024 * 1024
FABRIC_SOURCE_ENV = "NVIDIA_HYBRID_VMM_CHILD_SOURCE_B64"


class CUmemLocation(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("id", ctypes.c_int)]


class CUmemAllocationFlags(ctypes.Structure):
    _fields_ = [
        ("compressionType", ctypes.c_ubyte),
        ("gpuDirectRDMACapable", ctypes.c_ubyte),
        ("usage", ctypes.c_ushort),
        ("reserved", ctypes.c_ubyte * 4),
    ]


class CUmemAllocationProp(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),
        ("requestedHandleTypes", ctypes.c_int),
        ("location", CUmemLocation),
        ("win32HandleMetaData", ctypes.c_void_p),
        ("allocFlags", CUmemAllocationFlags),
    ]


class CUmemAccessDesc(ctypes.Structure):
    _fields_ = [("location", CUmemLocation), ("flags", ctypes.c_int)]


class CUmemFabricHandle(ctypes.Structure):
    _fields_ = [("data", ctypes.c_ubyte * FABRIC_HANDLE_BYTES)]


class CudaCallFailure(RuntimeError):
    def __init__(self, operation: str, code: int, name: str):
        super().__init__(operation)
        self.operation = operation
        self.code = int(code)
        self.name = name


class CudaSymbolMissing(RuntimeError):
    def __init__(self, symbol: str):
        super().__init__(symbol)
        self.symbol = symbol


def expected_device_contract() -> dict[str, object]:
    """Read the caller-pinned identity, defaulting to the V100 guest contract."""
    pci = os.environ.get("NVIDIA_HYBRID_VMM_EXPECTED_PCI", DEFAULT_EXPECTED_PCI)
    name_prefix = os.environ.get(
        "NVIDIA_HYBRID_VMM_EXPECTED_DEVICE_NAME_PREFIX",
        DEFAULT_EXPECTED_DEVICE_NAME_PREFIX)
    sm_text = os.environ.get("NVIDIA_HYBRID_VMM_EXPECTED_SM", str(DEFAULT_EXPECTED_SM))
    api_text = os.environ.get("NVIDIA_HYBRID_VMM_EXPECTED_DRIVER_API",
                              str(DEFAULT_EXPECTED_DRIVER_API))
    if (not isinstance(pci, str) or
            re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", pci) is None or
            not isinstance(name_prefix, str) or not name_prefix or len(name_prefix) > 128 or
            any(ord(char) < 0x20 for char in name_prefix) or
            not sm_text.isascii() or not sm_text.isdigit() or
            not api_text.isascii() or not api_text.isdigit()):
        raise ValueError("vmm_expected_device_contract_invalid")
    sm, driver_api = int(sm_text), int(api_text)
    if sm <= 0 or driver_api <= 0:
        raise ValueError("vmm_expected_device_contract_invalid")
    return {"pci": pci, "device_name_prefix": name_prefix,
            "sm": sm, "driver_api": driver_api}


def share_kind() -> str:
    value = os.environ.get(SHARE_KIND_ENV, "fabric")
    if value not in CU_MEM_HANDLE_TYPE_BY_KIND:
        raise ValueError("unsupported_vmm_share_kind")
    return value


def share_handle_type(kind: str | None = None) -> int:
    return CU_MEM_HANDLE_TYPE_BY_KIND[kind or share_kind()]


def selected_support_attribute(kind: str | None = None) -> int:
    return FABRIC_SUPPORTED_ATTRIBUTE if (kind or share_kind()) == "fabric" else POSIX_FD_SUPPORTED_ATTRIBUTE


def selected_support_key(kind: str | None = None) -> str:
    return "fabric_handle_support" if (kind or share_kind()) == "fabric" else "posix_fd_handle_support"


def selected_phase(importer: bool = False, kind: str | None = None) -> str:
    return f"vmm-{kind or share_kind()}-{'importer' if importer else 'share'}"


def build_allocation_prop(device_ordinal: int,
                          handle_type: int = CU_MEM_HANDLE_TYPE_FABRIC) -> CUmemAllocationProp:
    prop = CUmemAllocationProp()
    prop.type = CU_MEM_ALLOCATION_TYPE_PINNED
    if handle_type not in CU_MEM_HANDLE_TYPE_BY_KIND.values():
        raise ValueError("unsupported_vmm_handle_type")
    prop.requestedHandleTypes = handle_type
    prop.location.type = CU_MEM_LOCATION_TYPE_DEVICE
    prop.location.id = int(device_ordinal)
    prop.win32HandleMetaData = None
    prop.allocFlags.compressionType = 0
    prop.allocFlags.gpuDirectRDMACapable = 0
    prop.allocFlags.usage = 0
    prop.allocFlags.reserved[:] = bytes(4)
    return prop


def build_access_desc(device_ordinal: int) -> CUmemAccessDesc:
    desc = CUmemAccessDesc()
    desc.location.type = CU_MEM_LOCATION_TYPE_DEVICE
    desc.location.id = int(device_ordinal)
    desc.flags = CU_MEM_ACCESS_FLAGS_PROT_READWRITE
    return desc


def encode_fabric_message(allocation_size: int, handle: bytes) -> bytes:
    if type(allocation_size) is not int or not 0 < allocation_size <= MAX_ALLOCATION_BYTES:
        raise ValueError("fabric_allocation_size_out_of_bounds")
    if not isinstance(handle, bytes) or len(handle) != FABRIC_HANDLE_BYTES:
        raise ValueError("fabric_handle_size_invalid")
    return struct.pack("<Q", allocation_size) + handle


def decode_fabric_message(message: bytes) -> tuple[int, bytes]:
    if not isinstance(message, bytes) or len(message) != FABRIC_MESSAGE_BYTES:
        raise ValueError("fabric_message_size_invalid")
    allocation_size = struct.unpack("<Q", message[:MESSAGE_HEADER_BYTES])[0]
    if not 0 < allocation_size <= MAX_ALLOCATION_BYTES:
        raise ValueError("fabric_allocation_size_out_of_bounds")
    return allocation_size, message[MESSAGE_HEADER_BYTES:]


def build_child_invocation(child_source: str, kind: str, allocation_size: int,
                           shareable_fd: int = -1,
                           fabric_handle: CUmemFabricHandle | None = None
                           ) -> tuple[list[str], dict[str, str], dict[str, object]]:
    if not isinstance(child_source, str) or not child_source:
        raise ValueError("vmm_child_source_invalid")
    if type(allocation_size) is not int or not 0 < allocation_size <= MAX_ALLOCATION_BYTES:
        raise ValueError("vmm_child_allocation_size_invalid")
    if kind not in CU_MEM_HANDLE_TYPE_BY_KIND:
        raise ValueError("unsupported_vmm_share_kind")
    child_env = dict(os.environ)
    child_env[SHARE_KIND_ENV] = kind
    child_kwargs: dict[str, object] = {}
    if kind == "fabric":
        if not isinstance(fabric_handle, CUmemFabricHandle):
            raise ValueError("fabric_shareable_handle_missing")
        child_kwargs["input"] = encode_fabric_message(allocation_size, bytes(fabric_handle.data))
    else:
        if fabric_handle is not None:
            raise ValueError("unexpected_fabric_handle_for_posix_fd")
        if type(shareable_fd) is not int or shareable_fd < 3:
            raise ValueError("posix_shareable_fd_invalid")
        os.fstat(shareable_fd)
        child_env[POSIX_FD_ENV] = str(shareable_fd)
        child_env[POSIX_SIZE_ENV] = str(allocation_size)
        child_kwargs["pass_fds"] = (shareable_fd,)
    argv = [sys.executable, "-c", child_source, "--importer"]
    return argv, child_env, child_kwargs


def pack_words(words: tuple[int, ...] | list[int]) -> bytes:
    if len(words) != len(EXPECTED_WORDS):
        raise ValueError("payload_word_count_invalid")
    return struct.pack("<" + "I" * len(EXPECTED_WORDS), *words)


def transform_words(words: tuple[int, ...] | list[int]) -> tuple[int, ...]:
    if len(words) != len(EXPECTED_WORDS):
        raise ValueError("payload_word_count_invalid")
    return tuple((value ^ 0xA5C39E71) & 0xFFFFFFFF for value in words)


def _error_name(lib: ctypes.CDLL, code: int) -> str:
    try:
        error = ctypes.c_char_p()
        if lib.cuGetErrorName(code, ctypes.byref(error)) == 0 and error.value:
            return error.value.decode("ascii", "replace")[:80]
    except Exception:
        pass
    return "CUDA_ERROR_UNKNOWN"


def load_cuda() -> tuple[ctypes.CDLL, object]:
    lib = ctypes.CDLL(LIBCUDA_PATH, mode=os.RTLD_NOW | os.RTLD_LOCAL)
    i32, u32 = ctypes.c_int, ctypes.c_uint
    u64, size = ctypes.c_uint64, ctypes.c_size_t
    signatures = {
        "cuInit": ([u32], i32),
        "cuDriverGetVersion": ([ctypes.POINTER(i32)], i32),
        "cuDeviceGetCount": ([ctypes.POINTER(i32)], i32),
        "cuDeviceGet": ([ctypes.POINTER(i32), i32], i32),
        "cuDeviceGetName": ([ctypes.c_char_p, i32, i32], i32),
        "cuDeviceGetPCIBusId": ([ctypes.c_char_p, i32, i32], i32),
        "cuDeviceComputeCapability": ([ctypes.POINTER(i32), ctypes.POINTER(i32), i32], i32),
        "cuDeviceGetAttribute": ([ctypes.POINTER(i32), i32, i32], i32),
        "cuCtxCreate_v2": ([ctypes.POINTER(ctypes.c_void_p), u32, i32], i32),
        "cuCtxSynchronize": ([], i32),
        "cuCtxDestroy_v2": ([ctypes.c_void_p], i32),
        "cuMemGetAllocationGranularity": ([ctypes.POINTER(size), ctypes.POINTER(CUmemAllocationProp), i32], i32),
        "cuMemCreate": ([ctypes.POINTER(u64), size, ctypes.POINTER(CUmemAllocationProp), ctypes.c_ulonglong], i32),
        "cuMemExportToShareableHandle": ([ctypes.c_void_p, u64, i32, ctypes.c_ulonglong], i32),
        "cuMemImportFromShareableHandle": ([ctypes.POINTER(u64), ctypes.c_void_p, i32], i32),
        "cuMemAddressReserve": ([ctypes.POINTER(u64), size, size, u64, ctypes.c_ulonglong], i32),
        "cuMemAddressFree": ([u64, size], i32),
        "cuMemMap": ([u64, size, size, u64, ctypes.c_ulonglong], i32),
        "cuMemUnmap": ([u64, size], i32),
        "cuMemSetAccess": ([u64, size, ctypes.POINTER(CUmemAccessDesc), size], i32),
        "cuMemRelease": ([u64], i32),
        "cuMemcpyHtoD_v2": ([u64, ctypes.c_void_p, size], i32),
        "cuMemcpyDtoH_v2": ([ctypes.c_void_p, u64, size], i32),
        "cuGetErrorName": ([i32, ctypes.POINTER(ctypes.c_char_p)], i32),
    }
    for name, (arguments, result) in signatures.items():
        try:
            function = getattr(lib, name)
        except AttributeError as exc:
            raise CudaSymbolMissing(name) from exc
        function.argtypes = arguments
        function.restype = result

    def checked(name: str, *args: object, operations: list[str]) -> None:
        code = int(getattr(lib, name)(*args))
        if code == 0:
            operations.append(name)
            return
        raise CudaCallFailure(name, code, _error_name(lib, code))

    return lib, checked


def inspect_imex_preflight() -> dict[str, object]:
    registered = False
    try:
        for line in Path("/proc/devices").read_text(encoding="ascii", errors="replace").splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1] == "nvidia-caps-imex-channels":
                registered = fields[0].isdigit()
                break
    except OSError:
        pass
    directory = Path("/dev/nvidia-caps-imex-channels")
    nodes: list[dict[str, object]] = []
    try:
        for entry in sorted(directory.iterdir(), key=lambda item: item.name)[:16]:
            if not entry.name.startswith("channel"):
                continue
            try:
                info = entry.stat(follow_symlinks=False)
                nodes.append({
                    "character_device": stat.S_ISCHR(info.st_mode),
                    "readable": os.access(entry, os.R_OK),
                    "writable": os.access(entry, os.W_OK),
                })
            except OSError:
                nodes.append({"character_device": False, "readable": False, "writable": False})
    except OSError:
        pass
    return {
        "driver_registered": registered,
        "directory_present": directory.is_dir(),
        "channel_nodes_seen": len(nodes),
        "character_nodes_seen": sum(item["character_device"] is True for item in nodes),
        "read_write_accessible_nodes": sum(item["character_device"] is True and
                                            item["readable"] is True and
                                            item["writable"] is True for item in nodes),
        "effective_uid": os.geteuid(),
    }


def query_device(lib: ctypes.CDLL, checked: object, operations: list[str]) -> tuple[int, dict[str, object], int]:
    expected = expected_device_contract()
    i32 = ctypes.c_int
    checked("cuInit", 0, operations=operations)
    version, count = i32(), i32()
    checked("cuDriverGetVersion", ctypes.byref(version), operations=operations)
    checked("cuDeviceGetCount", ctypes.byref(count), operations=operations)
    if count.value != 1:
        raise RuntimeError("unexpected_cuda_device_count")
    device = i32()
    checked("cuDeviceGet", ctypes.byref(device), 0, operations=operations)
    name, pci = ctypes.create_string_buffer(256), ctypes.create_string_buffer(32)
    major, minor, unified, fabric, posix_fd = i32(), i32(), i32(), i32(), i32()
    checked("cuDeviceGetName", name, len(name), device.value, operations=operations)
    checked("cuDeviceGetPCIBusId", pci, len(pci), device.value, operations=operations)
    checked("cuDeviceComputeCapability", ctypes.byref(major), ctypes.byref(minor), device.value,
            operations=operations)
    checked("cuDeviceGetAttribute", ctypes.byref(unified), 41, device.value, operations=operations)
    fabric_status = int(lib.cuDeviceGetAttribute(ctypes.byref(fabric), FABRIC_SUPPORTED_ATTRIBUTE,
                                                  device.value))
    posix_status = int(lib.cuDeviceGetAttribute(ctypes.byref(posix_fd), POSIX_FD_SUPPORTED_ATTRIBUTE,
                                                 device.value))
    fabric_support = {"status": fabric_status,
                      "value": int(fabric.value) if fabric_status == 0 else None}
    posix_support = {"status": posix_status,
                     "value": int(posix_fd.value) if posix_status == 0 else None}
    identity = {
        "name": name.value.decode("utf-8", "replace"),
        "pci_bus_id": pci.value.decode("ascii", "replace"),
        "sm": major.value * 10 + minor.value,
        "compute_capability": f"{major.value}.{minor.value}",
        "unified_addressing": int(unified.value),
        "fabric_handle_support": fabric_support,
        "posix_fd_handle_support": posix_support,
    }
    if (not identity["name"].startswith(expected["device_name_prefix"]) or
            identity["pci_bus_id"] != expected["pci"] or identity["sm"] != expected["sm"] or
            identity["unified_addressing"] != 1 or version.value != expected["driver_api"]):
        raise RuntimeError("unexpected_driver_api_device_identity")
    return device.value, identity, int(version.value)


def _base_phase(phase: str) -> dict[str, object]:
    expected = expected_device_contract()
    kind = share_kind()
    handle_type = share_handle_type(kind)
    return {
        "schema": "nvidia-hybrid-driver-api-vmm-share-v1",
        "phase": phase,
        "shareable_handle_kind": kind,
        "shareable_handle_type": handle_type,
        "shareable_handle_bytes": FABRIC_HANDLE_BYTES if kind == "fabric" else ctypes.sizeof(ctypes.c_int),
        "status": "phase-failed",
        "expected_pci": expected["pci"],
        "driver_library_path": os.path.realpath(LIBCUDA_PATH),
        "driver_api": None,
        "device": None,
        "imex_preflight": inspect_imex_preflight(),
        "allocation_bytes": None,
        "attribute_support": None,
        "observation_valid": False,
        "completed_operations": [],
        "failure_operation": None,
        "failure_code": None,
        "failure_name": None,
        "error_class": None,
        "posix_shareable_fd_opened": False,
        "posix_shareable_fd_closed": True,
        "cleanup_passed": True,
        "cleanup_errors": [],
    }


def _cleanup_call(lib: ctypes.CDLL, name: str, args: tuple[object, ...],
                  operations: list[str], errors: list[str]) -> None:
    try:
        status = int(getattr(lib, name)(*args))
        if status == 0:
            operations.append(name)
        else:
            errors.append(f"{name}={status}")
    except Exception as exc:
        errors.append(f"{name}:{type(exc).__name__}")


def run_importer(message: bytes = b"") -> dict[str, object]:
    kind = share_kind()
    result = _base_phase(selected_phase(importer=True, kind=kind))
    operations: list[str] = result["completed_operations"]
    errors: list[str] = result["cleanup_errors"]
    lib = None
    context = ctypes.c_void_p()
    allocation = ctypes.c_uint64(0)
    address = ctypes.c_uint64(0)
    posix_fd: int | None = None
    context_created = imported = reserved = mapped = False
    try:
        if kind == "fabric":
            allocation_size, handle_bytes = decode_fabric_message(message)
        else:
            allocation_size = int(os.environ[POSIX_SIZE_ENV])
            posix_fd = int(os.environ[POSIX_FD_ENV])
            if not 0 < allocation_size <= MAX_ALLOCATION_BYTES or posix_fd < 3:
                raise ValueError("posix_shareable_handle_metadata_invalid")
            os.fstat(posix_fd)
            result["posix_shareable_fd_opened"] = True
            result["posix_shareable_fd_closed"] = False
            handle_bytes = b""
        result["allocation_bytes"] = allocation_size
        lib, checked = load_cuda()
        device, identity, driver_api = query_device(lib, checked, operations)
        result["device"], result["driver_api"] = identity, driver_api
        result["attribute_support"] = identity[selected_support_key(kind)]
        result["observation_valid"] = True
        checked("cuCtxCreate_v2", ctypes.byref(context), 0, device, operations=operations)
        context_created = True
        result["import_attempted"] = True
        if kind == "fabric":
            shareable_handle = CUmemFabricHandle.from_buffer_copy(handle_bytes)
            os_handle = ctypes.cast(ctypes.byref(shareable_handle), ctypes.c_void_p)
        else:
            os_handle = ctypes.c_void_p(posix_fd)
        checked("cuMemImportFromShareableHandle", ctypes.byref(allocation), os_handle,
                share_handle_type(kind), operations=operations)
        imported = True
        result["import_succeeded"] = True
        checked("cuMemAddressReserve", ctypes.byref(address), allocation_size, 0, 0, 0,
                operations=operations)
        reserved = True
        checked("cuMemMap", address.value, allocation_size, 0, allocation.value, 0,
                operations=operations)
        mapped = True
        access = build_access_desc(device)
        checked("cuMemSetAccess", address.value, allocation_size, ctypes.byref(access), 1,
                operations=operations)
        readback = ctypes.create_string_buffer(PAYLOAD_BYTES)
        checked("cuMemcpyDtoH_v2", readback, address.value, PAYLOAD_BYTES, operations=operations)
        initial = pack_words(EXPECTED_WORDS)
        result["initial_values_match"] = readback.raw == initial
        result["initial_values_sha256"] = hashlib.sha256(readback.raw).hexdigest()
        if not result["initial_values_match"]:
            raise RuntimeError("fabric_import_initial_numeric_mismatch")
        updated = pack_words(transform_words(EXPECTED_WORDS))
        source = ctypes.create_string_buffer(updated)
        checked("cuMemcpyHtoD_v2", address.value, source, PAYLOAD_BYTES, operations=operations)
        checked("cuCtxSynchronize", operations=operations)
        result["writeback_sha256"] = hashlib.sha256(updated).hexdigest()
        result["numerical_phase_passed"] = True
    except CudaCallFailure as exc:
        result["failure_operation"], result["failure_code"], result["failure_name"] = (
            exc.operation, exc.code, exc.name)
        result["observation_valid"] = result["observation_valid"] or bool(result.get("import_attempted"))
    except CudaSymbolMissing as exc:
        result["failure_operation"], result["failure_name"] = "load_cuda", "missing:" + exc.symbol
    except Exception as exc:
        result["error_class"] = type(exc).__name__
        if result.get("device") is not None:
            result["observation_valid"] = True
    finally:
        if lib is not None:
            if mapped:
                _cleanup_call(lib, "cuMemUnmap", (address.value, result["allocation_bytes"]), operations, errors)
            if reserved:
                _cleanup_call(lib, "cuMemAddressFree", (address.value, result["allocation_bytes"]), operations, errors)
            if imported and allocation.value:
                _cleanup_call(lib, "cuMemRelease", (allocation.value,), operations, errors)
            if context_created and context.value:
                _cleanup_call(lib, "cuCtxDestroy_v2", (context,), operations, errors)
        if posix_fd is not None:
            try:
                os.close(posix_fd)
                operations.append("close_posix_shareable_fd")
                result["posix_shareable_fd_closed"] = True
            except OSError as exc:
                errors.append(f"close_posix_shareable_fd:{exc.errno}")
    result["cleanup_passed"] = not errors
    if (result.get("numerical_phase_passed") is True and result["cleanup_passed"] and
            result.get("initial_values_match") is True):
        result["status"] = "phase-passed"
    return result


def run_parent() -> dict[str, object]:
    kind = share_kind()
    result = _base_phase(selected_phase(kind=kind))
    operations: list[str] = result["completed_operations"]
    errors: list[str] = result["cleanup_errors"]
    lib = None
    context = ctypes.c_void_p()
    allocation = ctypes.c_uint64(0)
    address = ctypes.c_uint64(0)
    shareable_fd = -1
    context_created = created = reserved = mapped = False
    result.update({"allocation_created": False, "export_attempted": False,
                   "export_succeeded": False, "import_attempted": False,
                   "import_succeeded": False, "initial_values_match": None,
                   "child_writeback_match": None, "initial_values_sha256": hashlib.sha256(
                       pack_words(EXPECTED_WORDS)).hexdigest(), "child_writeback_sha256": None,
                   "parent_readback_sha256": None, "child": None})
    try:
        lib, checked = load_cuda()
        device, identity, driver_api = query_device(lib, checked, operations)
        result["device"], result["driver_api"] = identity, driver_api
        result["attribute_support"] = identity[selected_support_key(kind)]
        result["observation_valid"] = True
        checked("cuCtxCreate_v2", ctypes.byref(context), 0, device, operations=operations)
        context_created = True
        prop = build_allocation_prop(device, share_handle_type(kind))
        granularity = ctypes.c_size_t(0)
        checked("cuMemGetAllocationGranularity", ctypes.byref(granularity),
                ctypes.byref(prop), CU_MEM_ALLOC_GRANULARITY_MINIMUM, operations=operations)
        allocation_size = int(granularity.value)
        if not 0 < allocation_size <= MAX_ALLOCATION_BYTES or allocation_size < PAYLOAD_BYTES:
            raise RuntimeError("vmm_allocation_granularity_out_of_bounds")
        result["allocation_bytes"] = allocation_size
        checked("cuMemCreate", ctypes.byref(allocation), allocation_size,
                ctypes.byref(prop), 0, operations=operations)
        created = True
        result["allocation_created"] = True
        checked("cuMemAddressReserve", ctypes.byref(address), allocation_size, 0, 0, 0,
                operations=operations)
        reserved = True
        checked("cuMemMap", address.value, allocation_size, 0, allocation.value, 0,
                operations=operations)
        mapped = True
        access = build_access_desc(device)
        checked("cuMemSetAccess", address.value, allocation_size, ctypes.byref(access), 1,
                operations=operations)
        initial = pack_words(EXPECTED_WORDS)
        initial_buffer = ctypes.create_string_buffer(initial)
        checked("cuMemcpyHtoD_v2", address.value, initial_buffer, PAYLOAD_BYTES,
                operations=operations)
        checked("cuCtxSynchronize", operations=operations)
        result["export_attempted"] = True
        fabric_handle: CUmemFabricHandle | None = None
        if kind == "fabric":
            fabric_handle = CUmemFabricHandle()
            shareable_handle_pointer = ctypes.cast(ctypes.byref(fabric_handle), ctypes.c_void_p)
        else:
            posix_fd_out = ctypes.c_int(-1)
            shareable_handle_pointer = ctypes.cast(ctypes.byref(posix_fd_out), ctypes.c_void_p)
        checked("cuMemExportToShareableHandle", shareable_handle_pointer,
                allocation.value, share_handle_type(kind), 0, operations=operations)
        if kind != "fabric":
            shareable_fd = int(posix_fd_out.value)
            if shareable_fd < 3:
                raise RuntimeError("posix_export_returned_invalid_fd")
            os.fstat(shareable_fd)
            result["posix_shareable_fd_opened"] = True
            result["posix_shareable_fd_closed"] = False
        result["export_succeeded"] = True
        try:
            child_source = base64.b64decode(os.environ[FABRIC_SOURCE_ENV], validate=True)
        except Exception as exc:
            raise RuntimeError("vmm_child_source_missing_or_invalid") from exc
        expected_source_hash = os.environ.get(FABRIC_SOURCE_ENV + "_SHA256")
        if not expected_source_hash or hashlib.sha256(child_source).hexdigest() != expected_source_hash:
            raise RuntimeError("vmm_child_source_hash_mismatch")
        child_argv, child_env, child_kwargs = build_child_invocation(
            child_source.decode("utf-8", "strict"), kind, allocation_size,
            shareable_fd=shareable_fd, fabric_handle=fabric_handle)
        child = subprocess.run(child_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=45, check=False, env=child_env, **child_kwargs)
        if child.returncode not in (0, 2):
            raise RuntimeError("fabric_importer_process_failed")
        try:
            child_outcome = json.loads(child.stdout.decode("utf-8", "strict").strip())
        except Exception as exc:
            raise RuntimeError("fabric_importer_report_invalid") from exc
        if not isinstance(child_outcome, dict):
            raise RuntimeError("fabric_importer_report_invalid")
        result["child"] = child_outcome
        result["import_attempted"] = child_outcome.get("import_attempted") is True
        result["import_succeeded"] = child_outcome.get("import_succeeded") is True
        if child.returncode != 0 or child_outcome.get("cleanup_passed") is not True:
            errors.extend("child:" + str(item) for item in child_outcome.get("cleanup_errors", []))
        if result["import_attempted"] and child_outcome.get("observation_valid") is True:
            result["observation_valid"] = True
        result["initial_values_match"] = child_outcome.get("initial_values_match")
        result["child_writeback_sha256"] = child_outcome.get("writeback_sha256")
        if child_outcome.get("status") == "phase-passed":
            checked("cuCtxSynchronize", operations=operations)
            readback = ctypes.create_string_buffer(PAYLOAD_BYTES)
            checked("cuMemcpyDtoH_v2", readback, address.value, PAYLOAD_BYTES, operations=operations)
            expected = pack_words(transform_words(EXPECTED_WORDS))
            result["parent_readback_sha256"] = hashlib.sha256(readback.raw).hexdigest()
            result["child_writeback_match"] = readback.raw == expected
            if result["child_writeback_match"]:
                result["numerical_phase_passed"] = True
            else:
                result["failure_operation"], result["failure_name"] = (
                "parent:numeric-validation", "VMM_NUMERIC_MISMATCH")
        elif child_outcome.get("failure_operation"):
            result["failure_operation"] = "child:" + str(child_outcome["failure_operation"])
            result["failure_code"] = child_outcome.get("failure_code")
            result["failure_name"] = child_outcome.get("failure_name")
        elif child_outcome.get("error_class"):
            result["error_class"] = "importer:" + str(child_outcome["error_class"])
    except CudaCallFailure as exc:
        result["failure_operation"], result["failure_code"], result["failure_name"] = (
            exc.operation, exc.code, exc.name)
    except CudaSymbolMissing as exc:
        result["failure_operation"], result["failure_name"] = "load_cuda", "missing:" + exc.symbol
    except Exception as exc:
        result["error_class"] = type(exc).__name__
    finally:
        if shareable_fd >= 0:
            try:
                os.close(shareable_fd)
                operations.append("close_posix_shareable_fd")
                result["posix_shareable_fd_closed"] = True
            except OSError as exc:
                errors.append(f"close_posix_shareable_fd:{exc.errno}")
        if lib is not None:
            if mapped:
                _cleanup_call(lib, "cuMemUnmap", (address.value, result["allocation_bytes"]), operations, errors)
            if reserved:
                _cleanup_call(lib, "cuMemAddressFree", (address.value, result["allocation_bytes"]), operations, errors)
            if created and allocation.value:
                _cleanup_call(lib, "cuMemRelease", (allocation.value,), operations, errors)
            if context_created and context.value:
                _cleanup_call(lib, "cuCtxDestroy_v2", (context,), operations, errors)
    result["cleanup_passed"] = not errors
    if (result.get("numerical_phase_passed") is True and result["cleanup_passed"] and
            result.get("child_writeback_match") is True):
        result["status"] = "phase-passed"
    return result


def main() -> int:
    if sys.argv[1:] == ["--importer"]:
        result = run_importer(sys.stdin.buffer.read(FABRIC_MESSAGE_BYTES + 1)
                              if share_kind() == "fabric" else b"")
    else:
        result = run_parent()
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("cleanup_passed") is True and result.get("observation_valid") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
