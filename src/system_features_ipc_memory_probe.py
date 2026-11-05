#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded two-process CUDA Driver API memory-IPC probe for the pinned V100."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import subprocess
import sys


LIBCUDA_PATH = "__LIBCUDA_PATH__"
EXPECTED_PCI = "0000:00:05.0"
EXPECTED_WORDS = tuple(0x13579BDF ^ (index * 0x01010101) for index in range(16))
WORD_COUNT = len(EXPECTED_WORDS)
ALLOCATION_BYTES = WORD_COUNT * 4
IPC_HANDLE_BYTES = 64
LAZY_ENABLE_PEER_ACCESS = 1


class CudaCallFailure(RuntimeError):
    def __init__(self, operation: str, code: int, name: str):
        super().__init__(operation)
        self.operation = operation
        self.code = int(code)
        self.name = name


def load_cuda():
    lib = ctypes.CDLL(LIBCUDA_PATH, mode=os.RTLD_NOW | os.RTLD_LOCAL)
    i32, u32, u64, size = ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_size_t

    class IpcMemHandle(ctypes.Structure):
        _fields_ = [("reserved", ctypes.c_ubyte * IPC_HANDLE_BYTES)]

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
        "cuMemAlloc_v2": ([ctypes.POINTER(u64), size], i32),
        "cuMemFree_v2": ([u64], i32),
        "cuMemcpyHtoD_v2": ([u64, ctypes.c_void_p, size], i32),
        "cuMemcpyDtoH_v2": ([ctypes.c_void_p, u64, size], i32),
        "cuIpcGetMemHandle": ([ctypes.POINTER(IpcMemHandle), u64], i32),
        "cuIpcOpenMemHandle_v2": ([ctypes.POINTER(u64), IpcMemHandle, u32], i32),
        "cuIpcCloseMemHandle": ([u64], i32),
        "cuGetErrorName": ([i32, ctypes.POINTER(ctypes.c_char_p)], i32),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(lib, name)
        function.argtypes = arguments
        function.restype = result

    def checked(name: str, *args: object) -> None:
        status = int(getattr(lib, name)(*args))
        if status == 0:
            return
        error_name = ctypes.c_char_p()
        if lib.cuGetErrorName(status, ctypes.byref(error_name)) != 0 or not error_name.value:
            label = "CUDA_ERROR_UNKNOWN"
        else:
            label = error_name.value.decode("ascii", "replace")[:80]
        raise CudaCallFailure(name, status, label)

    return lib, IpcMemHandle, checked


def verify_device(lib, checked):
    i32 = ctypes.c_int
    version, count = i32(), i32()
    checked("cuInit", 0)
    checked("cuDriverGetVersion", ctypes.byref(version))
    checked("cuDeviceGetCount", ctypes.byref(count))
    if count.value != 1:
        raise RuntimeError("unexpected_cuda_device_count")
    device = i32()
    checked("cuDeviceGet", ctypes.byref(device), 0)
    name = ctypes.create_string_buffer(256)
    pci = ctypes.create_string_buffer(32)
    major, minor, unified = i32(), i32(), i32()
    checked("cuDeviceGetName", name, len(name), device.value)
    checked("cuDeviceGetPCIBusId", pci, len(pci), device.value)
    checked("cuDeviceComputeCapability", ctypes.byref(major), ctypes.byref(minor), device.value)
    checked("cuDeviceGetAttribute", ctypes.byref(unified), 41, device.value)
    memory_sharing_support = {}
    for label, attribute in (("virtual_memory_management", 102),
                             ("posix_file_descriptor", 103),
                             ("fabric_handle", 128)):
        value = i32()
        status = int(lib.cuDeviceGetAttribute(ctypes.byref(value), attribute, device.value))
        memory_sharing_support[label] = {
            "status": status,
            "value": int(value.value) if status == 0 else None,
        }
    identity = {
        "name": name.value.decode("utf-8", "replace"),
        "pci_bus_id": pci.value.decode("ascii", "replace"),
        "sm": major.value * 10 + minor.value,
        "compute_capability": f"{major.value}.{minor.value}",
        "unified_addressing": int(unified.value),
        "memory_sharing_support": memory_sharing_support,
    }
    if (not identity["name"].startswith("Tesla V100") or
            identity["pci_bus_id"] != EXPECTED_PCI or identity["sm"] != 70 or
            identity["unified_addressing"] != 1 or version.value != 13000):
        raise RuntimeError("unexpected_v100_or_driver_api_identity")
    return device.value, identity, int(version.value)


def pack_words(words: tuple[int, ...] | list[int]) -> bytes:
    return struct.pack("<" + "I" * WORD_COUNT, *words)


def transform_words(words: tuple[int, ...] | list[int]) -> tuple[int, ...]:
    return tuple((value ^ 0xA5A5A5A5) & 0xFFFFFFFF for value in words)


CHILD_SOURCE = r'''import ctypes,hashlib,json,os,struct,sys
LIBCUDA_PATH="__LIBCUDA_PATH__"
EXPECTED_PCI="0000:00:05.0"
HANDLE_SIZE=64
WORD_COUNT=16
ALLOCATION_BYTES=WORD_COUNT*4
LAZY_ENABLE_PEER_ACCESS=1
result={"status":"phase-failed","phase":"ipc-importer","driver_api":None,
 "device":None,"open_attempted":False,"open_succeeded":False,
 "initial_values_match":None,"child_writeback_sha256":None,
 "observation_valid":False,"failure_operation":None,"failure_code":None,
 "failure_name":None,"completed_operations":[],"cleanup_passed":True,
 "cleanup_errors":[]}
operations=result["completed_operations"]
cleanup_errors=result["cleanup_errors"]
lib=None
context=ctypes.c_void_p()
mapped=ctypes.c_uint64(0)
opened=False
context_created=False
failure=None
class CudaCallFailure(RuntimeError):
 def __init__(self,operation,code,name):
  self.operation=operation; self.code=int(code); self.name=name; super().__init__(operation)
def setup():
 global lib
 lib=ctypes.CDLL(LIBCUDA_PATH,mode=os.RTLD_NOW|os.RTLD_LOCAL)
 i32,u32,u64,size=ctypes.c_int,ctypes.c_uint,ctypes.c_uint64,ctypes.c_size_t
 class Handle(ctypes.Structure): _fields_=[("reserved",ctypes.c_ubyte*HANDLE_SIZE)]
 signatures={"cuInit":([u32],i32),"cuDriverGetVersion":([ctypes.POINTER(i32)],i32),
  "cuDeviceGetCount":([ctypes.POINTER(i32)],i32),"cuDeviceGet":([ctypes.POINTER(i32),i32],i32),
  "cuDeviceGetName":([ctypes.c_char_p,i32,i32],i32),
  "cuDeviceGetPCIBusId":([ctypes.c_char_p,i32,i32],i32),
  "cuDeviceComputeCapability":([ctypes.POINTER(i32),ctypes.POINTER(i32),i32],i32),
  "cuDeviceGetAttribute":([ctypes.POINTER(i32),i32,i32],i32),
  "cuCtxCreate_v2":([ctypes.POINTER(ctypes.c_void_p),u32,i32],i32),
  "cuCtxSynchronize":([],i32),"cuCtxDestroy_v2":([ctypes.c_void_p],i32),
  "cuMemcpyHtoD_v2":([u64,ctypes.c_void_p,size],i32),
  "cuMemcpyDtoH_v2":([ctypes.c_void_p,u64,size],i32),
  "cuIpcOpenMemHandle_v2":([ctypes.POINTER(u64),Handle,u32],i32),
  "cuIpcCloseMemHandle":([u64],i32),"cuGetErrorName":([i32,ctypes.POINTER(ctypes.c_char_p)],i32)}
 for name,(args,ret) in signatures.items():
  fn=getattr(lib,name); fn.argtypes=args; fn.restype=ret
 def checked(name,*args):
  code=int(getattr(lib,name)(*args))
  if code==0: operations.append(name); return
  err=ctypes.c_char_p()
  label=(err.value.decode("ascii","replace")[:80] if
         lib.cuGetErrorName(code,ctypes.byref(err))==0 and err.value else "CUDA_ERROR_UNKNOWN")
  raise CudaCallFailure(name,code,label)
 return Handle,checked
try:
 handle_bytes=sys.stdin.buffer.read(HANDLE_SIZE+1)
 if len(handle_bytes)!=HANDLE_SIZE: raise RuntimeError("ipc_handle_pipe_length")
 Handle,checked=setup()
 i32=ctypes.c_int
 checked("cuInit",0)
 version,count=i32(),i32()
 checked("cuDriverGetVersion",ctypes.byref(version)); result["driver_api"]=int(version.value)
 checked("cuDeviceGetCount",ctypes.byref(count))
 if count.value!=1: raise RuntimeError("unexpected_cuda_device_count")
 device=i32(); checked("cuDeviceGet",ctypes.byref(device),0)
 name=ctypes.create_string_buffer(256); pci=ctypes.create_string_buffer(32)
 major,minor,unified=i32(),i32(),i32()
 checked("cuDeviceGetName",name,len(name),device.value)
 checked("cuDeviceGetPCIBusId",pci,len(pci),device.value)
 checked("cuDeviceComputeCapability",ctypes.byref(major),ctypes.byref(minor),device.value)
 checked("cuDeviceGetAttribute",ctypes.byref(unified),41,device.value)
 support={}
 for label,attribute in (("virtual_memory_management",102),
                         ("posix_file_descriptor",103),("fabric_handle",128)):
  value=i32(); status=int(lib.cuDeviceGetAttribute(ctypes.byref(value),attribute,device.value))
  support[label]={"status":status,"value":int(value.value) if status==0 else None}
 result["device"]={"name":name.value.decode("utf-8","replace"),
  "pci_bus_id":pci.value.decode("ascii","replace"),"sm":major.value*10+minor.value,
  "compute_capability":f"{major.value}.{minor.value}","unified_addressing":int(unified.value),
  "memory_sharing_support":support}
 if (not result["device"]["name"].startswith("Tesla V100") or
     result["device"]["pci_bus_id"]!=EXPECTED_PCI or result["device"]["sm"]!=70 or
     result["device"]["unified_addressing"]!=1 or version.value!=13000):
  raise RuntimeError("unexpected_v100_or_driver_api_identity")
 checked("cuCtxCreate_v2",ctypes.byref(context),0,device.value); context_created=True
 if len(handle_bytes)!=ctypes.sizeof(Handle): raise RuntimeError("ipc_handle_abi_size")
 handle=Handle.from_buffer_copy(handle_bytes)
 result["open_attempted"]=True
 checked("cuIpcOpenMemHandle_v2",ctypes.byref(mapped),handle,LAZY_ENABLE_PEER_ACCESS)
 opened=True; result["open_succeeded"]=True; result["observation_valid"]=True
 readback=ctypes.create_string_buffer(ALLOCATION_BYTES)
 checked("cuMemcpyDtoH_v2",readback,mapped,ALLOCATION_BYTES)
 result["initial_values_sha256"]=hashlib.sha256(readback.raw).hexdigest()
 expected=struct.pack("<"+"I"*WORD_COUNT,
  *[0x13579BDF^(index*0x01010101) for index in range(WORD_COUNT)])
 result["initial_values_match"]=(readback.raw==expected)
 if not result["initial_values_match"]:
  raise RuntimeError("ipc_importer_initial_numeric_mismatch")
 words=struct.unpack("<"+"I"*WORD_COUNT,readback.raw)
 updated=struct.pack("<"+"I"*WORD_COUNT,
  *[((value^0xA5A5A5A5)&0xffffffff) for value in words])
 update_buffer=ctypes.create_string_buffer(updated)
 checked("cuMemcpyHtoD_v2",mapped,update_buffer,ALLOCATION_BYTES)
 checked("cuCtxSynchronize")
 result["child_writeback_sha256"]=hashlib.sha256(updated).hexdigest()
except CudaCallFailure as exc:
 failure=exc
 result["failure_operation"]=exc.operation
 result["failure_code"]=exc.code
 result["failure_name"]=exc.name
 result["observation_valid"]=(result["open_attempted"] and
  (result["open_succeeded"] or exc.operation=="cuIpcOpenMemHandle_v2"))
except Exception as exc:
 result["error_class"]=type(exc).__name__
 if result["open_succeeded"]:
  result["observation_valid"]=True
  if result["initial_values_match"] is False:
   result["failure_operation"]="numeric-validation-initial"
   result["failure_name"]="IPC_NUMERIC_MISMATCH"
finally:
 if lib is not None:
  if opened and mapped.value:
   try:
    code=int(lib.cuIpcCloseMemHandle(mapped))
    if code==0: operations.append("cuIpcCloseMemHandle")
    else: cleanup_errors.append("cuIpcCloseMemHandle="+str(code))
   except Exception as exc: cleanup_errors.append("cuIpcCloseMemHandle:"+type(exc).__name__)
  if context_created and context.value:
   try:
    code=int(lib.cuCtxDestroy_v2(context))
    if code==0: operations.append("cuCtxDestroy_v2")
    else: cleanup_errors.append("cuCtxDestroy_v2="+str(code))
   except Exception as exc: cleanup_errors.append("cuCtxDestroy_v2:"+type(exc).__name__)
 result["cleanup_passed"]=not cleanup_errors
if failure is None and result.get("error_class") is None and result["initial_values_match"] is True and result["child_writeback_sha256"]:
 result["status"]="phase-passed"
elif result["observation_valid"]:
 result["status"]="phase-failed"
print(json.dumps(result,sort_keys=True))
sys.exit(0 if result["cleanup_passed"] else 2)
'''


def importer_code() -> str:
    return CHILD_SOURCE.replace("__LIBCUDA_PATH__", LIBCUDA_PATH)


def run_parent() -> dict[str, object]:
    result: dict[str, object] = {
        "schema": "nvidia-hybrid-v100-driver-api-ipc-memory-v1",
        "status": "phase-failed", "phase": "ipc-memory-share",
        "expected_pci": EXPECTED_PCI, "driver_library_path": None,
        "driver_api": None, "device": None, "importer_device": None,
        "allocation_bytes": ALLOCATION_BYTES, "ipc_handle_bytes": IPC_HANDLE_BYTES,
        "export_attempted": False, "open_attempted": False, "open_succeeded": False,
        "ipc_succeeded": False, "initial_values_match": None,
        "child_writeback_match": None, "failure_operation": None,
        "failure_code": None, "failure_name": None,
        "observation_valid": False, "completed_operations": [],
        "cleanup_passed": True, "cleanup_errors": [], "error": "",
        "initial_values_sha256": hashlib.sha256(pack_words(EXPECTED_WORDS)).hexdigest(),
        "child_readback_sha256": None, "child_writeback_sha256": None,
        "parent_readback_sha256": None,
    }
    operations: list[str] = result["completed_operations"]
    cleanup_errors: list[str] = result["cleanup_errors"]
    lib = None
    context = ctypes.c_void_p()
    allocation = ctypes.c_uint64(0)
    context_created = False
    allocation_created = False
    child_outcome = None
    try:
        lib, IpcMemHandle, checked = load_cuda()
        result["driver_library_path"] = os.path.realpath(LIBCUDA_PATH)
        device, identity, driver_api = verify_device(lib, checked)
        operations.extend(["cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuDeviceGet",
                           "cuDeviceGetName", "cuDeviceGetPCIBusId",
                           "cuDeviceComputeCapability", "cuDeviceGetAttribute"])
        result["device"] = identity
        result["driver_api"] = driver_api
        checked("cuCtxCreate_v2", ctypes.byref(context), 0, device)
        operations.append("cuCtxCreate_v2")
        context_created = True
        checked("cuMemAlloc_v2", ctypes.byref(allocation), ALLOCATION_BYTES)
        operations.append("cuMemAlloc_v2")
        allocation_created = True
        initial = pack_words(EXPECTED_WORDS)
        initial_buffer = ctypes.create_string_buffer(initial)
        checked("cuMemcpyHtoD_v2", allocation, initial_buffer, ALLOCATION_BYTES)
        operations.append("cuMemcpyHtoD_v2")
        handle = IpcMemHandle()
        result["export_attempted"] = True
        checked("cuIpcGetMemHandle", ctypes.byref(handle), allocation)
        operations.append("cuIpcGetMemHandle")
        if ctypes.sizeof(handle) != IPC_HANDLE_BYTES:
            raise RuntimeError("ipc_handle_abi_size")
        child = subprocess.run(
            [sys.executable, "-c", importer_code()], input=bytes(handle.reserved),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=35, check=False,
            env=dict(os.environ),
        )
        if child.returncode not in (0, 2):
            raise RuntimeError("ipc_importer_process_failed")
        try:
            child_outcome = json.loads(child.stdout.decode("utf-8", "strict").strip())
        except Exception as exc:
            raise RuntimeError("ipc_importer_report_invalid") from exc
        if not isinstance(child_outcome, dict):
            raise RuntimeError("ipc_importer_report_invalid")
        child_operations = child_outcome.get("completed_operations")
        if isinstance(child_operations, list):
            operations.extend("child:" + value for value in child_operations
                              if isinstance(value, str))
        result["open_attempted"] = child_outcome.get("open_attempted") is True
        result["open_succeeded"] = child_outcome.get("open_succeeded") is True
        result["importer_device"] = child_outcome.get("device")
        result["initial_values_match"] = child_outcome.get("initial_values_match")
        result["child_readback_sha256"] = child_outcome.get("initial_values_sha256")
        result["child_writeback_sha256"] = child_outcome.get("child_writeback_sha256")
        if child_outcome.get("failure_operation"):
            result["failure_operation"] = "child:" + str(child_outcome["failure_operation"])
            result["failure_code"] = child_outcome.get("failure_code")
            result["failure_name"] = child_outcome.get("failure_name")
        if child.returncode != 0 or child_outcome.get("cleanup_passed") is not True:
            child_errors = child_outcome.get("cleanup_errors")
            cleanup_errors.extend("child:" + str(item) for item in child_errors or [])
        if result["open_attempted"] and child_outcome.get("observation_valid") is True:
            result["observation_valid"] = True
        if child_outcome.get("status") == "phase-passed":
            checked("cuCtxSynchronize")
            operations.append("cuCtxSynchronize")
            readback = ctypes.create_string_buffer(ALLOCATION_BYTES)
            checked("cuMemcpyDtoH_v2", readback, allocation, ALLOCATION_BYTES)
            operations.append("cuMemcpyDtoH_v2")
            observed = struct.unpack("<" + "I" * WORD_COUNT, readback.raw)
            expected = transform_words(EXPECTED_WORDS)
            result["parent_readback_sha256"] = hashlib.sha256(readback.raw).hexdigest()
            result["child_writeback_match"] = observed == expected
            result["observation_valid"] = True
            if result["child_writeback_match"]:
                result["ipc_succeeded"] = True
            else:
                result["failure_operation"] = "parent:numeric-validation"
                result["failure_name"] = "IPC_NUMERIC_MISMATCH"
        elif not result["failure_operation"] and child_outcome.get("error_class"):
            result["error"] = "ipc_importer:" + str(child_outcome["error_class"])
    except CudaCallFailure as exc:
        result["failure_operation"] = exc.operation
        result["failure_code"] = exc.code
        result["failure_name"] = exc.name
        result["observation_valid"] = exc.operation == "cuIpcGetMemHandle"
    except Exception as exc:
        result["error"] = type(exc).__name__
    finally:
        if lib is not None:
            if allocation_created and allocation.value:
                try:
                    code = int(lib.cuMemFree_v2(allocation))
                    if code == 0:
                        operations.append("cuMemFree_v2")
                    else:
                        cleanup_errors.append("cuMemFree_v2=" + str(code))
                except Exception as exc:
                    cleanup_errors.append("cuMemFree_v2:" + type(exc).__name__)
            if context_created and context.value:
                try:
                    code = int(lib.cuCtxDestroy_v2(context))
                    if code == 0:
                        operations.append("cuCtxDestroy_v2")
                    else:
                        cleanup_errors.append("cuCtxDestroy_v2=" + str(code))
                except Exception as exc:
                    cleanup_errors.append("cuCtxDestroy_v2:" + type(exc).__name__)
    result["cleanup_passed"] = not cleanup_errors
    if result["ipc_succeeded"] and result["cleanup_passed"]:
        result["status"] = "phase-passed"
    elif result["observation_valid"]:
        result["status"] = "phase-failed"
    return result


def main() -> int:
    if sys.argv[1:] == ["--ipc-importer"]:
        raise SystemExit(2)
    result = run_parent()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["cleanup_passed"] and result["observation_valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
