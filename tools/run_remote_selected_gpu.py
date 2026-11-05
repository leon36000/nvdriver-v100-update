#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Archive an isolated RTX 5080 CUDA reference over strict, noninteractive SSH.

Copies only project artifacts into a fresh remote temporary directory. Never
installs a driver, changes PCI ownership, resets a GPU, or accesses a guest.
"""
from __future__ import annotations
import argparse
import base64
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
import zlib

ROOT = Path(__file__).resolve().parents[1]
PINNED_ACCEPTANCE_ARTIFACTS = (
    ('runner', 'tests/run_hybrid_acceptance.py',
     '0384723a7962042137d6380a1db484ae112168d8384dc6662a00c7258d159840'),
    ('cuda_probe_contract.py', 'tools/cuda_probe_contract.py',
     '9f65e31214f0b323198460879e015967baa3feec855df1177d371a5b8cf28506'),
)
PINNED_PROBE_SHA256 = 'c2c0aa30d26fe2fb7e61a5ef732bc1f659faa39eb4626e1d46689f2aa85e1422'
PINNED_MODULE_SHA256 = '8dc12fa61f5ed270c3122f5516c2afce43d9c39f5fa9a16f9a7e313fe34f6f70'
REMOTE_QUALIFICATION_BY_PHASE_AND_EXIT = {
    None: {77: 'rtx5080-report-contract-valid-hybrid-incomplete'},
    'initialize': {0: 'rtx5080-cuda-phase-report-contract-valid'},
    'enumerate': {0: 'rtx5080-cuda-phase-report-contract-valid'},
    'context': {0: 'rtx5080-cuda-phase-report-contract-valid'},
    'allocation': {0: 'rtx5080-cuda-phase-report-contract-valid'},
    'module': {0: 'rtx5080-cuda-phase-report-contract-valid'},
    'kernel': {0: 'rtx5080-cuda-phase-report-contract-valid'},
    'system-pageable-memory': {
        0: 'rtx5080-system-pageable-memory-report-contract-valid',
        77: 'rtx5080-system-pageable-memory-unsupported-report-contract-valid',
    },
    'managed-accessed-by': {0: 'rtx5080-managed-accessed-by-report-contract-valid'},
}
LOCAL_CUDA_EXECUTION_VALIDATION_STATE = (
    'remote CUDA execution status is a report claim; no independent hardware attestation')
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.collect_pc3_canary_host_state import validate_direct_identity_file  # noqa: E402
_probe_contract_spec = importlib.util.spec_from_file_location(
    "nvidia_hybrid_probe_contract", ROOT / "tools/cuda_probe_contract.py")
if _probe_contract_spec is None or _probe_contract_spec.loader is None:
    raise RuntimeError("CUDA probe contract helper is unavailable")
_probe_contract_module = importlib.util.module_from_spec(_probe_contract_spec)
_probe_contract_spec.loader.exec_module(_probe_contract_module)
validate_probe_contract = _probe_contract_module.validate_probe_contract
SHARED = r'''
def validate_pinned_probe_artifacts(artifacts):
    probe = artifacts.get('probe', {}) if isinstance(artifacts, dict) else {}
    module = artifacts.get('module', {}) if isinstance(artifacts, dict) else {}
    if (not isinstance(probe, dict) or probe.get('sha256') != PINNED_PROBE_SHA256 or
            not isinstance(module, dict) or module.get('sha256') != PINNED_MODULE_SHA256):
        raise ValueError('probe/fatbin identity does not match the reviewed pinned artifacts')

def canonical_pci(value):
    import re
    match = re.fullmatch(r"([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", value)
    if not match:
        raise ValueError("invalid PCI identity")
    domain, bus, slot, function = [int(part, 16) for part in match.groups()]
    if domain > 65535 or slot > 31:
        raise ValueError("PCI identity out of supported range")
    return f"{domain:04x}:{bus:02x}:{slot:02x}.{function:x}"

def selected_device(report, pci):
    devices = report.get("devices", [])
    if len(devices) != 1:
        raise ValueError("expected exactly one visible GPU")
    device = devices[0]
    if canonical_pci(device.get("pci_bus_id", "")) != canonical_pci(pci):
        raise ValueError("visible PCI identity mismatch")
    if device.get("sm") != 120 or "RTX 5080" not in device.get("name", ""):
        raise ValueError("visible device is not RTX 5080 SM120")
    return device

def clean_environment(source, uuid):
    env = {key: value for key, value in source.items()
           if not key.startswith(("LD_", "CUDA_", "NVIDIA_", "PYTHON"))}
    env["CUDA_VISIBLE_DEVICES"] = uuid
    env["PATH"] = "/usr/bin:/bin"
    env["LC_ALL"] = "C"
    return env

def validate_probe_build_trust(acceptance, artifacts):
    trust = acceptance.get('probe_build_trust') if isinstance(acceptance, dict) else None
    if not isinstance(trust, dict) or trust.get('status') != 'trusted-pinned-build':
        raise ValueError('acceptance runner did not report a trusted pinned probe build')
    before, after = trust.get('before_run'), trust.get('after_run')
    if not isinstance(before, dict) or not isinstance(after, dict) or before != after:
        raise ValueError('probe build identity changed during execution')
    if before.get('status') != 'trusted-pinned-build':
        raise ValueError('probe build identity is not trusted')
    if before.get('probe_sha256') != artifacts.get('probe', {}).get('sha256'):
        raise ValueError('acceptance runner probe hash differs from the uploaded probe hash')
    if before.get('module_sha256') != artifacts.get('module', {}).get('sha256'):
        raise ValueError('acceptance runner fatbin hash differs from the uploaded module hash')
    if before.get('provenance') != 'pinned-probe-and-fatbin-sha256':
        raise ValueError('acceptance runner probe provenance is unsupported')
    validate_pinned_probe_artifacts({
        'probe': {'sha256': before.get('probe_sha256')},
        'module': {'sha256': before.get('module_sha256')},
    })

def correlated_gpu_mmap_count(records):
    count = 0
    for map_index, mapped in enumerate(records):
        if not isinstance(mapped, dict) or mapped.get('operation') != 'map_memory':
            continue
        entry, exit_payload = mapped.get('entry'), mapped.get('exit')
        if (mapped.get('syscall_return') != 0 or not isinstance(entry, dict) or
                not isinstance(exit_payload, dict) or exit_payload.get('status') != 0 or
                exit_payload.get('backendFdRole') != 'gpu' or
                exit_payload.get('linearAddressPresent') is not True or
                type(entry.get('backendFd')) is not int or
                entry.get('backendFd') != exit_payload.get('backendFd') or
                type(entry.get('backendFileId')) is not int or
                entry.get('backendFileId') <= 0 or
                entry.get('backendFileId') != exit_payload.get('backendFileId')):
            continue
        fd = exit_payload['backendFd']
        file_id = exit_payload['backendFileId']
        if not any(isinstance(row, dict) and row.get('operation') in ('fd_open', 'fd_dup') and
                   row.get('fd') == fd and row.get('fd_role') == 'gpu' and
                   row.get('fd_file_id') == file_id for row in records[:map_index]):
            continue
        for row in records[map_index + 1:]:
            if not isinstance(row, dict):
                continue
            if (row.get('operation') == 'close' and row.get('fd') == fd and
                    row.get('fd_role') == 'gpu' and row.get('fd_file_id') == file_id and
                    row.get('close_succeeded') is True):
                break
            if (row.get('operation') == 'map_memory' and isinstance(row.get('entry'), dict) and
                    row['entry'].get('backendFd') == fd and
                    row['entry'].get('backendFileId') == file_id):
                break
            payload = row.get('entry')
            if (row.get('operation') == 'mmap' and row.get('fd') == fd and
                    row.get('fd_role') == 'gpu' and row.get('fd_file_id') == file_id and
                    row.get('mmap_succeeded') is True and
                    isinstance(payload, dict) and payload.get('offsetZero') is True and
                    payload.get('length') == exit_payload.get('length')):
                count += 1
                break
    return count

def validate_map_fd_lifecycle(records):
    active, known_file_ids = {}, set()
    for row in records:
        if not isinstance(row, dict):
            continue
        operation = row.get('operation')
        fd, file_id, role = row.get('fd'), row.get('fd_file_id'), row.get('fd_role')
        if operation == 'fd_open':
            if (set(row) != {'tid','fd','fd_role','request','packet_size','operation',
                             'fd_file_id','entry','exit','syscall_return'} or
                    row.get('request') not in (2,257,437) or type(fd) is not int or fd < 0 or
                    role not in ('control','gpu') or type(file_id) is not int or file_id <= 0 or
                    row.get('entry') is not None or row.get('exit') is not None or
                    row.get('syscall_return') != fd or fd in active or file_id in known_file_ids):
                raise ValueError('selected open event has invalid file identity metadata')
            active[fd] = (file_id, role)
            known_file_ids.add(file_id)
        elif operation == 'fd_dup':
            source_fd = row.get('source_fd')
            if (set(row) != {'tid','fd','fd_role','request','packet_size','operation',
                             'fd_file_id','source_fd','entry','exit','syscall_return'} or
                    row.get('request') not in (32,33,72,292) or type(fd) is not int or fd < 0 or
                    type(source_fd) is not int or source_fd < 0 or role not in ('control','gpu') or
                    type(file_id) is not int or file_id <= 0 or
                    active.get(source_fd) != (file_id, role) or row.get('entry') is not None or
                    row.get('exit') is not None or row.get('syscall_return') != fd):
                raise ValueError('selected dup event does not preserve its source file identity')
            active[fd] = (file_id, role)
        elif operation == 'close':
            if (type(fd) is not int or fd < 0 or type(file_id) is not int or file_id <= 0 or
                    role not in ('control','gpu') or active.get(fd) != (file_id, role) or
                    row.get('entry') is not None or row.get('exit') is not None or
                    type(row.get('close_succeeded')) is not bool or
                    row.get('close_succeeded') != (row.get('syscall_return') == 0)):
                raise ValueError('close event does not match the selected open file identity')
            active.pop(fd, None)
        elif operation == 'fd_close_range':
            interval = row.get('entry')
            if (row.get('request') != 436 or fd != -1 or role != 'other' or
                    not isinstance(interval, dict) or set(interval) != {'first_fd','last_fd','flags'} or
                    type(interval.get('first_fd')) is not int or type(interval.get('last_fd')) is not int or
                    type(interval.get('flags')) is not int or row.get('exit') is not None or
                    type(row.get('syscall_return')) is not int):
                raise ValueError('close_range event has invalid descriptor-lifecycle metadata')
            if row['syscall_return'] == 0:
                for selected_fd in list(active):
                    if interval['first_fd'] <= selected_fd <= interval['last_fd']:
                        active.pop(selected_fd, None)
        elif operation == 'map_memory':
            payload = row.get('entry')
            if not isinstance(payload, dict):
                continue
            memory_class = payload.get('memoryObjectClass')
            if (not isinstance(memory_class, dict) or
                    set(memory_class) != {'resolution', 'classId'} or
                    memory_class.get('resolution') not in
                    ('absent', 'resolved', 'not-observed-live-object',
                     'invalid-root', 'ambiguous') or
                    (memory_class.get('resolution') == 'resolved' and
                     (type(memory_class.get('classId')) is not int or
                      not 0 < memory_class['classId'] <= 0xffffffff)) or
                    (memory_class.get('resolution') != 'resolved' and
                     memory_class.get('classId') is not None)):
                raise ValueError('RM map packet has invalid memory-object class metadata')
            exit_payload = row.get('exit')
            if (isinstance(exit_payload, dict) and
                    exit_payload.get('memoryObjectClass') != memory_class):
                raise ValueError('RM map packet memory-object class changed during ioctl')
            backend_fd, backend_id = payload.get('backendFd'), payload.get('backendFileId')
            if (active.get(fd) != (file_id, 'control') or type(backend_fd) is not int or
                    type(backend_id) is not int or
                    active.get(backend_fd) != (backend_id, payload.get('backendFdRole'))):
                raise ValueError('RM map packet references an untracked or mismatched backend file')
        elif operation == 'mmap':
            if type(fd) is not int or type(file_id) is not int or active.get(fd) != (file_id, role):
                raise ValueError('mmap descriptor does not match the observed open file identity')
        elif operation == 'unmap_memory':
            if active.get(fd) != (file_id, 'control'):
                raise ValueError('RM unmap packet uses an untracked control file')

def validate_binapi_control_observation(observed):
    """Validate only the fixed, redacted top-level BINAPI payload-shape capture."""
    expected_pointer_scope = (
        'exact 992-byte top-level NV2081_BINAPI control payload for command 0x20810108; '
        'no contained pointer is followed; raw bytes, addresses, and handles omitted')
    expected_class_scope = (
        'successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected '
        'control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed')
    snapshots = observed.get('binapi_payload_snapshots_read')
    rows = observed.get('records')
    if type(snapshots) is not int or snapshots < 0:
        raise ValueError('BINAPI observation has no valid payload-snapshot count')
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError('BINAPI observation records are malformed')
    if observed.get('gpu_path') != '/dev/nvidia0' or observed.get(
            'object_class_resolution_scope') != expected_class_scope:
        raise ValueError('BINAPI observer did not resolve live classes on both selected RM paths')
    if snapshots == 0:
        if (rows or observed.get('nested_pointers_read') is not False or
                'nested_pointer_scope' in observed):
            raise ValueError('empty BINAPI capture unexpectedly included records or nested reads')
        return False, 0
    if snapshots < 2 or snapshots % 2 or snapshots != 2 * len(rows):
        raise ValueError('BINAPI payload snapshots do not form complete entry/exit pairs')
    if (observed.get('nested_pointers_read') is not True or
            observed.get('nested_pointer_scope') != expected_pointer_scope):
        raise ValueError('BINAPI observer exceeded or misstated its fixed pointer scope')

    record_fields = {'tid', 'fd', 'fd_role', 'request', 'packet_size', 'operation',
                     'entry', 'exit', 'syscall_return'}
    outer_fields = {'command', 'flags', 'params_size', 'status', 'hClientPresent',
                    'hObjectPresent', 'client_object_equal',
                    'client_matches_prior_root_allocation',
                    'object_matches_prior_root_allocation', 'objectClass',
                    'binapiPayload'}
    payload_fields = {'payloadBytes', 'payloadValid', 'nonzeroU32Count',
                      'nonzeroU32MaskLsbFirst', 'changedByteCount',
                      'changedByteMaskLsbFirst', 'entryExitPayloadEqual'}
    for row in rows:
        if (set(row) != record_fields or type(row.get('tid')) is not int or row['tid'] <= 0 or
                type(row.get('fd')) is not int or row['fd'] < 0 or
                row.get('fd_role') != 'control' or row.get('operation') != 'binapi_control' or
                (row.get('request'), row.get('packet_size')) not in
                ((0xc020462a, 32), (0xc01046d3, 16)) or row.get('syscall_return') != 0):
            raise ValueError('BINAPI RM_CONTROL transport is malformed or unsuccessful')
        phases = [row.get('entry'), row.get('exit')]
        if not all(isinstance(phase, dict) and set(phase) == outer_fields for phase in phases):
            raise ValueError('BINAPI RM_CONTROL header is malformed or unredacted')
        command = phases[0].get('command')
        if command != 0x20810108:
            raise ValueError('BINAPI RM_CONTROL command differs from the fixed observed command')
        for phase_index, phase in enumerate(phases):
            if (phase.get('command') != command or phase.get('params_size') != 992 or
                    type(phase.get('flags')) is not int or type(phase.get('status')) is not int or
                    (phase_index == 1 and phase.get('status') != 0) or
                    any(type(phase.get(key)) is not bool for key in (
                        'hClientPresent', 'hObjectPresent', 'client_object_equal',
                        'client_matches_prior_root_allocation',
                        'object_matches_prior_root_allocation')) or
                    phase.get('hClientPresent') is not True or
                    phase.get('hObjectPresent') is not True):
                raise ValueError('BINAPI RM_CONTROL header fields are invalid')
            object_class = phase.get('objectClass')
            if (not isinstance(object_class, dict) or set(object_class) != {'resolution', 'classId'} or
                    object_class.get('resolution') != 'resolved' or
                    object_class.get('classId') != 0x2081):
                raise ValueError('BINAPI object class is not a resolved live NV2081_BINAPI')
            payload = phase.get('binapiPayload')
            if not isinstance(payload, dict) or set(payload) != payload_fields:
                raise ValueError('BINAPI payload-shape metadata is malformed')
            nonzero_mask = payload.get('nonzeroU32MaskLsbFirst')
            changed_mask = payload.get('changedByteMaskLsbFirst')
            if (payload.get('payloadBytes') != 992 or payload.get('payloadValid') is not True or
                    type(payload.get('nonzeroU32Count')) is not int or
                    type(payload.get('changedByteCount')) is not int or
                    not isinstance(nonzero_mask, str) or len(nonzero_mask) != 62 or
                    not re.fullmatch(r'[0-9a-f]{62}', nonzero_mask) or
                    not isinstance(changed_mask, str) or len(changed_mask) != 248 or
                    not re.fullmatch(r'[0-9a-f]{248}', changed_mask)):
                raise ValueError('BINAPI payload-shape metadata is malformed or contains raw values')
            nonzero_bits = sum(byte.bit_count() for byte in bytes.fromhex(nonzero_mask))
            changed_bits = sum(byte.bit_count() for byte in bytes.fromhex(changed_mask))
            equal = payload.get('entryExitPayloadEqual')
            if (not 0 <= payload['nonzeroU32Count'] <= 248 or
                    payload['nonzeroU32Count'] != nonzero_bits or
                    not 0 <= payload['changedByteCount'] <= 992 or
                    payload['changedByteCount'] != changed_bits):
                raise ValueError('BINAPI mask counts disagree with their fixed-size masks')
            if phase_index == 0:
                if (equal is not None or payload['changedByteCount'] != 0 or
                        any(bytes.fromhex(changed_mask))):
                    raise ValueError('BINAPI entry metadata contains an exit-only comparison')
            elif type(equal) is not bool or equal != (payload['changedByteCount'] == 0):
                raise ValueError('BINAPI entry/exit equality disagrees with the byte-change mask')
    return True, snapshots

def validate_binapi_alloc_capture(observed):
    """Validate only the optional fixed-size BINAPI allocation parameter."""
    scope = ('NV2081_BINAPI NV2081_ALLOC_PARAMETERS fixed 4-byte reserved zero predicate only; '
             'handles omitted')
    class_scope = ('NV2081_BINAPI fixed class parameters only; raw reserved value, handles omitted')
    snapshots = observed.get('binapi_alloc_payload_snapshots_read')
    rows = observed.get('records')
    if (observed.get('schema') != 'nvidia-hybrid-rm-ioctl-observer-v21' or
            observed.get('trace_complete') is not True or observed.get('errors') != [] or
            observed.get('control_path') != '/dev/nvidiactl' or
            observed.get('gpu_path') != '/dev/nvidia0' or
            observed.get('architecture') != 'x86_64' or observed.get('pointer_bits') != 64 or
            observed.get('payload_scope') != class_scope):
        raise ValueError('BINAPI allocation observer report identity or scope is invalid')
    if type(snapshots) is not int or snapshots < 0 or not isinstance(rows, list) or not rows:
        raise ValueError('BINAPI allocation observer has no valid records or snapshot count')
    if (observed.get('nested_pointers_read') is not (snapshots > 0) or
            observed.get('nested_pointer_scope') != scope):
        raise ValueError('BINAPI allocation observer exceeded or misstated its fixed payload scope')
    fields = {'layout', 'hClass', 'paramsSize', 'flags', 'status', 'hRootPresent',
              'hObjectParentPresent', 'hObjectNewPresent', 'pAllocParmsPresent',
              'pRightsRequestedPresent', 'binapiAlloc'}
    payload_fields = {'classPayloadBytes', 'reservedZero'}
    seen = 0
    success = False
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {'tid', 'fd', 'fd_role', 'request',
                'packet_size', 'operation', 'entry', 'exit', 'syscall_return'} or
                row.get('operation') != 'binapi_alloc' or row.get('request') != 0xc030462b or
                row.get('packet_size') != 48 or type(row.get('syscall_return')) is not int or
                row.get('fd_role') not in ('control', 'gpu')):
            raise ValueError('BINAPI allocation ioctl record is malformed')
        pairs = []
        for endpoint in ('entry', 'exit'):
            packet = row.get(endpoint)
            if (not isinstance(packet, dict) or set(packet) != fields or
                    packet.get('layout') != 'NVOS64' or packet.get('hClass') != 0x2081 or
                    type(packet.get('paramsSize')) is not int or packet['paramsSize'] not in (0, 4) or
                    not all(type(packet.get(key)) is bool for key in ('hRootPresent',
                        'hObjectParentPresent', 'hObjectNewPresent', 'pAllocParmsPresent',
                        'pRightsRequestedPresent')) or type(packet.get('status')) is not int):
                raise ValueError('BINAPI allocation packet is malformed or unredacted')
            value = packet.get('binapiAlloc')
            if value is None:
                if packet['pAllocParmsPresent'] or packet['paramsSize'] != 0:
                    raise ValueError('optional BINAPI allocation parameters are inconsistent')
            else:
                if (not packet['pAllocParmsPresent'] or not isinstance(value, dict) or
                        set(value) != payload_fields or value.get('classPayloadBytes') != 4 or
                        type(value.get('reservedZero')) is not bool):
                    raise ValueError('BINAPI allocation payload is malformed or unredacted')
                seen += 1
            pairs.append(value)
        if pairs[0] != pairs[1]:
            raise ValueError('BINAPI allocation payload changed between entry and exit')
        if row['syscall_return'] == 0 and row['exit']['status'] == 0:
            success = True
    if seen != snapshots or not success:
        raise ValueError('BINAPI allocation snapshot count or successful construction is invalid')
    return True, snapshots

def validate_gt200_debugger_alloc_capture(observed):
    """Validate the fixed, redacted GT200_DEBUGGER allocation payload."""
    scope = ('exact NV83DE_ALLOC_PARAMETERS 12-byte payload for GT200_DEBUGGER only; '
             'emits handle presence and within-root class relations including the debuggee direct-parent class; '
             'raw handles and addresses omitted')
    class_scope = ('NV83DE_ALLOC_PARAMETERS exact 12-byte fixed payload on GT200_DEBUGGER allocations only; '
                   'raw handles, pointers, and payload bytes omitted')
    rows = observed.get('records')
    snapshots = observed.get('debugger_alloc_payload_snapshots_read')
    if (observed.get('schema') != 'nvidia-hybrid-rm-ioctl-observer-v34' or
            observed.get('trace_complete') is not True or observed.get('errors') != [] or
            observed.get('control_path') != '/dev/nvidiactl' or
            observed.get('gpu_path') != '/dev/nvidia0' or
            observed.get('architecture') != 'x86_64' or observed.get('pointer_bits') != 64 or
            observed.get('payload_scope') != class_scope or
            observed.get('object_class_resolution_scope') != (
                'successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; '
                'lookup is keyed by NVOS64 root and handle and emits only object and direct-parent class IDs/presence; '
                'unresolved means no unique live object was observed')):
        raise ValueError('GT200_DEBUGGER observer report identity or scope is invalid')
    if (type(snapshots) is not int or snapshots <= 0 or not isinstance(rows, list) or not rows or
            observed.get('nested_pointers_read') is not True or
            observed.get('nested_pointer_scope') != scope):
        raise ValueError('GT200_DEBUGGER observer has no valid fixed-payload snapshots')
    row_fields = {'tid', 'fd', 'fd_role', 'request', 'packet_size', 'operation',
                  'entry', 'exit', 'syscall_return'}
    outer_fields = {'layout', 'hClass', 'paramsSize', 'flags', 'status',
                    'hRootPresent', 'hObjectParentPresent', 'hObjectNewPresent',
                    'pAllocParmsPresent', 'pRightsRequestedPresent', 'debuggerAlloc'}
    payload_fields = {'classPayloadBytes', 'obsoleteClientZero', 'appClientPresent',
                      'appClientMatchesRoot', 'appClientMatchesParent',
                      'appClientEqualsDebuggee', 'debuggee3dHandlePresent',
                      'appClientClassWithinRoot', 'debuggee3dClassWithinRoot',
                      'debuggee3dParentClassWithinRoot', 'parentClassWithinRoot'}
    class_ref_fields = {'resolution', 'classId'}
    valid_resolutions = {'resolved', 'not-observed-live-object', 'invalid-root', 'ambiguous', 'absent'}
    payload_snapshots = 0
    successful_alloc = False
    for row in rows:
        if (not isinstance(row, dict) or set(row) != row_fields or
                row.get('operation') != 'gt200_debugger_alloc' or
                row.get('request') != 0xc030462b or row.get('packet_size') != 48 or
                type(row.get('tid')) is not int or row['tid'] <= 0 or
                type(row.get('fd')) is not int or row['fd'] < 0 or
                row.get('fd_role') not in ('control', 'gpu') or
                type(row.get('syscall_return')) is not int):
            raise ValueError('GT200_DEBUGGER allocation record is malformed')
        snapshots_for_row = []
        for endpoint in ('entry', 'exit'):
            packet = row.get(endpoint)
            if (not isinstance(packet, dict) or set(packet) != outer_fields or
                    packet.get('layout') != 'NVOS64' or packet.get('hClass') != 0x83de or
                    type(packet.get('paramsSize')) is not int or packet['paramsSize'] not in (0, 12) or
                    type(packet.get('flags')) is not int or type(packet.get('status')) is not int or
                    not all(type(packet.get(key)) is bool for key in (
                        'hRootPresent', 'hObjectParentPresent', 'hObjectNewPresent',
                        'pAllocParmsPresent', 'pRightsRequestedPresent'))):
                raise ValueError('GT200_DEBUGGER allocation packet is malformed or unredacted')
            payload = packet.get('debuggerAlloc')
            if payload is None:
                if packet['pAllocParmsPresent']:
                    raise ValueError('GT200_DEBUGGER allocation omitted a required payload')
            else:
                if (not isinstance(payload, dict) or set(payload) != payload_fields or
                        payload.get('classPayloadBytes') != 12 or
                        not all(type(payload.get(key)) is bool for key in (
                            'obsoleteClientZero', 'appClientPresent', 'appClientMatchesRoot',
                            'appClientMatchesParent', 'appClientEqualsDebuggee',
                            'debuggee3dHandlePresent'))):
                    raise ValueError('GT200_DEBUGGER nested payload is malformed or unredacted')
                for key in ('appClientClassWithinRoot', 'debuggee3dClassWithinRoot',
                            'debuggee3dParentClassWithinRoot', 'parentClassWithinRoot'):
                    relation = payload.get(key)
                    if (not isinstance(relation, dict) or set(relation) != class_ref_fields or
                            relation.get('resolution') not in valid_resolutions or
                            (relation.get('resolution') == 'resolved' and
                             (type(relation.get('classId')) is not int or
                              not 0 <= relation['classId'] <= 0xffffffff)) or
                            (relation.get('resolution') != 'resolved' and
                             relation.get('classId') is not None)):
                        raise ValueError('GT200_DEBUGGER handle-to-class relation is malformed')
                payload_snapshots += 1
            snapshots_for_row.append(payload)
        if snapshots_for_row[0] != snapshots_for_row[1]:
            raise ValueError('GT200_DEBUGGER nested payload changed during RM_ALLOC')
        if row['syscall_return'] == 0 and row['exit']['status'] == 0 and snapshots_for_row[1] is not None:
            successful_alloc = True
    if payload_snapshots != snapshots or not successful_alloc:
        raise ValueError('GT200_DEBUGGER payload count or successful construction is invalid')
    return len(rows), snapshots

def validate_gt200_debugger_lifecycle_capture(observed):
    """Validate redacted GT200_DEBUGGER lifecycle records without trusting the child summary."""
    payload_scope = ('GT200_DEBUGGER allocations, class-resolved GT200_DEBUGGER frees, fixed NVOS54 headers plus a redacted hObject-to-prior-debugger-allocation equality, and exact 4-byte exceptionMask snapshots for resolved 0x83de0309 controls only; null pointers, size mismatch, and undocumented bits fail closed; unresolved command candidates are never dereferenced; raw handles and addresses omitted')
    nested_scope = ('exact NV83DE allocation parameters plus fixed NVOS54 headers for resolved GT200_DEBUGGER controls and unresolved 0x83de command candidates; only exact 4-byte exceptionMask for resolved 0x83de0309 controls is followed after fixed-size, non-null-pointer, and documented-bit checks; RM_FREE class resolution is root-scoped; a redacted hObject-to-prior-GT200_DEBUGGER-allocation equality is emitted; raw handles and addresses omitted')
    class_scope = ('successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU '
                   'paths; debugger control hClient is resolved to one observed root before resolving hObject; '
                   'a redacted hObject equality against prior successful GT200_DEBUGGER allocations is recorded; unresolved free classes and debugger-command candidates emit redacted fixed headers; raw handles are omitted')
    if (not isinstance(observed, dict) or
            observed.get('schema') != 'nvidia-hybrid-rm-ioctl-observer-v39' or
            observed.get('trace_complete') is not True or observed.get('errors') != [] or
            observed.get('control_path') != '/dev/nvidiactl' or
            observed.get('gpu_path') != '/dev/nvidia0' or
            observed.get('architecture') != 'x86_64' or observed.get('pointer_bits') != 64 or
            observed.get('payload_scope') != payload_scope or
            observed.get('nested_pointer_scope') != nested_scope or
            observed.get('object_class_resolution_scope') != class_scope):
        raise ValueError('GT200_DEBUGGER lifecycle observer identity or scope is invalid')
    rows = observed.get('records')
    snapshots = observed.get('debugger_alloc_payload_snapshots_read')
    mask_snapshots = observed.get('debugger_exception_mask_payload_snapshots_read')
    unresolved_free = observed.get('debugger_free_unresolved_class_count')
    unresolved_control = observed.get('debugger_control_unresolved_candidate_count')
    if (not isinstance(rows, list) or type(snapshots) is not int or not 0 <= snapshots <= 0xffffffff or
            type(mask_snapshots) is not int or not 0 <= mask_snapshots <= 0xffffffff or
            type(unresolved_free) is not int or not 0 <= unresolved_free <= 0xffffffff or
            type(unresolved_control) is not int or not 0 <= unresolved_control <= 0xffffffff or
            observed.get('nested_pointers_read') is not (snapshots > 0 or mask_snapshots > 0)):
        raise ValueError('GT200_DEBUGGER lifecycle counters are malformed')
    common = {'tid', 'fd', 'fd_role', 'request', 'packet_size', 'operation',
              'entry', 'exit', 'syscall_return'}
    control_fields = {'command', 'flags', 'params_size', 'status', 'hClientPresent',
                      'hObjectPresent', 'client_object_equal',
                      'client_matches_prior_root_allocation',
                      'object_matches_prior_root_allocation',
                      'object_handle_matches_prior_debugger_allocation'}
    alloc_fields = {'layout', 'hClass', 'paramsSize', 'flags', 'status', 'hRootPresent',
                    'hObjectParentPresent', 'hObjectNewPresent', 'pAllocParmsPresent',
                    'pRightsRequestedPresent', 'debuggerAlloc'}
    alloc_payload_fields = {'classPayloadBytes', 'obsoleteClientZero', 'appClientPresent',
                            'appClientMatchesRoot', 'appClientMatchesParent', 'appClientEqualsDebuggee',
                            'debuggee3dHandlePresent', 'appClientClassWithinRoot',
                            'debuggee3dClassWithinRoot', 'debuggee3dParentClassWithinRoot',
                            'parentClassWithinRoot'}
    free_fields = {'layout', 'status', 'hRootPresent', 'hObjectParentPresent',
                   'hObjectOldPresent', 'objectClassWithinRoot'}
    rel_fields = {'resolution', 'classId'}
    alloc_count = free_count = control_count = control_candidate_count = payload_count = 0
    mask_control_count = 0
    unresolved_mask_statuses = []
    for row in rows:
        if (not isinstance(row, dict) or
                set(row) not in (common, common | {'debuggerTargetObjectClassWithinRoot'}) or
                row.get('fd_role') not in ('control', 'gpu') or
                type(row.get('tid')) is not int or not 0 < row['tid'] <= 0x7fffffff or
                type(row.get('fd')) is not int or not 0 <= row['fd'] <= 0x7fffffff or
                type(row.get('request')) is not int or type(row.get('packet_size')) is not int or
                type(row.get('syscall_return')) is not int or
                not -(1 << 63) <= row['syscall_return'] < (1 << 63)):
            raise ValueError('GT200_DEBUGGER lifecycle record envelope is malformed or unredacted')
        operation = row['operation']
        if operation == 'gt200_debugger_alloc':
            alloc_count += 1
            if (set(row) != common or row['request'] != 0xc030462b or row['packet_size'] != 48):
                raise ValueError('GT200_DEBUGGER allocation request is invalid')
            nested = []
            packets = []
            for endpoint in ('entry', 'exit'):
                packet = row.get(endpoint)
                if (not isinstance(packet, dict) or set(packet) != alloc_fields or
                        packet.get('layout') != 'NVOS64' or packet.get('hClass') != 0x83de or
                        type(packet.get('paramsSize')) is not int or packet['paramsSize'] not in (0, 12) or
                        type(packet.get('flags')) is not int or not 0 <= packet['flags'] <= 0xffffffff or
                        type(packet.get('status')) is not int or not 0 <= packet['status'] <= 0xffffffff or
                        any(type(packet.get(key)) is not bool for key in (
                            'hRootPresent', 'hObjectParentPresent', 'hObjectNewPresent',
                            'pAllocParmsPresent', 'pRightsRequestedPresent'))):
                    raise ValueError('GT200_DEBUGGER allocation packet is malformed')
                payload = packet.get('debuggerAlloc')
                if (packet['pAllocParmsPresent'] is not True or
                        not isinstance(payload, dict) or set(payload) != alloc_payload_fields or
                        payload.get('classPayloadBytes') != 12 or
                        any(type(payload.get(key)) is not bool for key in (
                            'obsoleteClientZero', 'appClientPresent', 'appClientMatchesRoot',
                            'appClientMatchesParent', 'appClientEqualsDebuggee',
                            'debuggee3dHandlePresent'))):
                    raise ValueError('GT200_DEBUGGER fixed allocation payload is missing, malformed, or unredacted')
                for key in ('appClientClassWithinRoot', 'debuggee3dClassWithinRoot',
                            'debuggee3dParentClassWithinRoot', 'parentClassWithinRoot'):
                    relation = payload.get(key)
                    if (not isinstance(relation, dict) or set(relation) != rel_fields or
                            relation.get('resolution') not in
                            ('resolved', 'not-observed-live-object', 'invalid-root', 'ambiguous', 'absent') or
                            (relation['resolution'] == 'resolved' and
                             (type(relation.get('classId')) is not int or
                              not 0 <= relation['classId'] <= 0xffffffff)) or
                            (relation['resolution'] != 'resolved' and relation.get('classId') is not None)):
                        raise ValueError('GT200_DEBUGGER allocation relation is malformed')
                payload_count += 1
                nested.append(payload)
                packets.append(packet)
            if nested[0] != nested[1]:
                raise ValueError('GT200_DEBUGGER allocation payload changed across syscall')
            if ({key: value for key, value in packets[0].items()
                 if key not in ('status', 'hObjectNewPresent')} !=
                    {key: value for key, value in packets[1].items()
                     if key not in ('status', 'hObjectNewPresent')}):
                raise ValueError('GT200_DEBUGGER allocation identity changed across syscall')
        elif operation == 'gt200_debugger_free':
            free_count += 1
            if set(row) != common or row['request'] != 0xc0104629 or row['packet_size'] != 16:
                raise ValueError('GT200_DEBUGGER free request is invalid')
            packets = [row.get(endpoint) for endpoint in ('entry', 'exit')]
            if any(not isinstance(packet, dict) or set(packet) != free_fields or
                   packet.get('layout') != 'NVOS00' or type(packet.get('status')) is not int or
                   not 0 <= packet['status'] <= 0xffffffff or
                   any(type(packet.get(key)) is not bool for key in (
                       'hRootPresent', 'hObjectParentPresent', 'hObjectOldPresent')) or
                   packet.get('hRootPresent') is not True or packet.get('hObjectOldPresent') is not True or
                   packet.get('objectClassWithinRoot') != 0x83de for packet in packets):
                raise ValueError('GT200_DEBUGGER free packet is malformed or unresolved')
            if ({key: value for key, value in packets[0].items() if key != 'status'} !=
                    {key: value for key, value in packets[1].items() if key != 'status'}):
                raise ValueError('GT200_DEBUGGER free packet identity changed across syscall')
        elif operation == 'gt200_debugger_control':
            control_count += 1
            entry_control = row.get('entry')
            mask_command = (isinstance(entry_control, dict) and
                            entry_control.get('command') == 0x83de0309)
            if mask_command:
                mask_control_count += 1
            relation = row.get('debuggerTargetObjectClassWithinRoot')
            if (set(row) != common | {'debuggerTargetObjectClassWithinRoot'} or
                    (row['request'], row['packet_size']) not in ((0xc020462a, 32), (0xc01046d3, 16)) or
                    not isinstance(relation, dict) or set(relation) != rel_fields or
                    relation.get('resolution') != 'resolved' or relation.get('classId') != 0x83de):
                raise ValueError('GT200_DEBUGGER control target is malformed or unresolved')
            packets = [row.get(endpoint) for endpoint in ('entry', 'exit')]
            for endpoint, packet in zip(('entry', 'exit'), packets):
                expected_control_fields = control_fields | ({'exceptionMask'} if mask_command else set())
                if mask_command and endpoint == 'exit':
                    expected_control_fields = expected_control_fields | {'exceptionMaskUserBufferEntryExitEqual'}
                if (not isinstance(packet, dict) or set(packet) != expected_control_fields or
                        type(packet.get('command')) is not int or
                        not 0 <= packet['command'] <= 0xffffffff or
                        packet['command'] & 0xffff0000 != 0x83de0000 or
                        any(type(packet.get(key)) is not int or not 0 <= packet[key] <= 0xffffffff
                            for key in ('flags', 'params_size', 'status')) or
                        any(type(packet.get(key)) is not bool for key in (
                            'hClientPresent', 'hObjectPresent', 'client_object_equal',
                            'client_matches_prior_root_allocation',
                            'object_matches_prior_root_allocation',
                            'object_handle_matches_prior_debugger_allocation'))):
                    raise ValueError('GT200_DEBUGGER control header is malformed or unredacted')
                if mask_command:
                    mask = packet.get('exceptionMask')
                    if (type(mask) is not int or not 0 <= mask <= 0xffffffff or
                            (mask != 0xffff and mask & ~0x3f != 0)):
                        raise ValueError('GT200_DEBUGGER exception mask contains undocumented values')
                    if endpoint == 'exit' and (
                            type(packet.get('exceptionMaskUserBufferEntryExitEqual')) is not bool or
                            packet['exceptionMaskUserBufferEntryExitEqual'] is not
                            (mask == packets[0].get('exceptionMask'))):
                        raise ValueError('GT200_DEBUGGER exception-mask comparison is inconsistent')
                if packet['hClientPresent'] is not True or packet['hObjectPresent'] is not True:
                    raise ValueError('GT200_DEBUGGER control is missing handles required for class resolution')
                if packet['object_handle_matches_prior_debugger_allocation'] is not True:
                    raise ValueError('resolved GT200_DEBUGGER control does not match its observed allocation')
            if ({key: value for key, value in packets[0].items()
                 if key not in ('status', 'exceptionMaskUserBufferEntryExitEqual')} !=
                    {key: value for key, value in packets[1].items()
                     if key not in ('status', 'exceptionMaskUserBufferEntryExitEqual')}):
                raise ValueError('GT200_DEBUGGER control identity changed across syscall')
        elif operation == 'gt200_debugger_control_candidate':
            control_candidate_count += 1
            relation = row.get('debuggerTargetObjectClassWithinRoot')
            if (set(row) != common | {'debuggerTargetObjectClassWithinRoot'} or
                    (row['request'], row['packet_size']) not in ((0xc020462a, 32), (0xc01046d3, 16)) or
                    not isinstance(relation, dict) or set(relation) != rel_fields or
                    relation.get('resolution') not in ('not-observed-live-object', 'invalid-root',
                                                       'ambiguous', 'absent') or
                    relation.get('classId') is not None):
                raise ValueError('unresolved GT200_DEBUGGER command relation is malformed')
            packets = [row.get(endpoint) for endpoint in ('entry', 'exit')]
            for packet in packets:
                if (not isinstance(packet, dict) or set(packet) != control_fields or
                        type(packet.get('command')) is not int or
                        not 0 <= packet['command'] <= 0xffffffff or
                        packet['command'] & 0xffff0000 != 0x83de0000 or
                        any(type(packet.get(key)) is not int or not 0 <= packet[key] <= 0xffffffff
                            for key in ('flags', 'params_size', 'status')) or
                        any(type(packet.get(key)) is not bool for key in (
                            'hClientPresent', 'hObjectPresent', 'client_object_equal',
                            'client_matches_prior_root_allocation',
                            'object_matches_prior_root_allocation',
                            'object_handle_matches_prior_debugger_allocation')) or
                        packet['hClientPresent'] is not True):
                    raise ValueError('unresolved debugger candidate header is malformed or unredacted')
            if ({key: value for key, value in packets[0].items() if key != 'status'} !=
                    {key: value for key, value in packets[1].items() if key != 'status'}):
                raise ValueError('unresolved debugger candidate identity changed across syscall')
            if packets[0]['command'] == 0x83de0309:
                unresolved_mask_statuses.append(packets[1]['status'])
        else:
            raise ValueError('GT200_DEBUGGER lifecycle contains an unselected operation')
    if (payload_count != snapshots or snapshots != alloc_count * 2 or
            mask_snapshots != mask_control_count * 2 or
            control_candidate_count != unresolved_control):
        raise ValueError('GT200_DEBUGGER allocation snapshot count differs from records')
    return {'records': len(rows), 'allocations': alloc_count, 'frees': free_count,
            'controls': control_count, 'allocation_payload_snapshots': snapshots,
            'exception_mask_payload_snapshots': mask_snapshots,
            'resolved_exception_mask_controls': mask_control_count,
            'unresolved_exception_mask_candidates': len(unresolved_mask_statuses),
            'unresolved_exception_mask_rm_statuses': unresolved_mask_statuses,
            'unresolved_free_classes': unresolved_free,
            'unresolved_control_candidates': unresolved_control}

def validate_rm_control_headers_observation(observed):
    if (not isinstance(observed, dict) or
            observed.get('schema') != 'nvidia-hybrid-rm-ioctl-observer-v23' or
            observed.get('trace_complete') is not True or observed.get('errors') != [] or
            observed.get('control_path') != '/dev/nvidiactl' or
            observed.get('architecture') != 'x86_64' or observed.get('pointer_bits') != 64 or
            observed.get('nested_pointers_read') is not False or
            observed.get('fd_identity_tracking') is not False or
            observed.get('payload_scope') !=
            'fixed NVOS54 RM_CONTROL headers only; handles redacted; nested parameter payloads omitted'):
        raise ValueError('redacted RM_CONTROL header observer contract is invalid')
    records = observed.get('records')
    if not isinstance(records, list) or not records:
        raise ValueError('redacted RM_CONTROL header observation contains no records')
    row_fields = {'tid', 'fd', 'fd_role', 'request', 'packet_size', 'operation',
                  'entry', 'exit', 'syscall_return'}
    header_fields = {'command', 'flags', 'params_size', 'status', 'hClientPresent',
                     'hObjectPresent', 'client_object_equal',
                     'client_matches_prior_root_allocation',
                     'object_matches_prior_root_allocation'}
    uint32_max = (1 << 32) - 1
    for row in records:
        if (not isinstance(row, dict) or set(row) != row_fields or
                row.get('operation') != 'rm_control_header' or
                row.get('fd_role') != 'control' or
                (row.get('request'), row.get('packet_size')) not in
                ((0xc020462a, 32), (0xc01046d3, 16)) or
                type(row.get('tid')) is not int or row['tid'] <= 0 or
                type(row.get('fd')) is not int or row['fd'] < 0 or
                type(row.get('syscall_return')) is not int):
            raise ValueError('redacted RM_CONTROL header record has an invalid envelope')
        for endpoint in ('entry', 'exit'):
            packet = row.get(endpoint)
            if (not isinstance(packet, dict) or set(packet) != header_fields or
                    any(type(packet.get(key)) is not int or not 0 <= packet[key] <= uint32_max
                        for key in ('command', 'flags', 'params_size', 'status')) or
                    any(type(packet.get(key)) is not bool for key in (
                        'hClientPresent', 'hObjectPresent', 'client_object_equal',
                        'client_matches_prior_root_allocation',
                        'object_matches_prior_root_allocation'))):
                raise ValueError('redacted RM_CONTROL header snapshot is missing or unredacted')
    return len(records)
'''
SHARED_WITH_PINS = (
    f"PINNED_PROBE_SHA256 = {PINNED_PROBE_SHA256!r}\n"
    f"PINNED_MODULE_SHA256 = {PINNED_MODULE_SHA256!r}\n" + SHARED)
exec(SHARED_WITH_PINS)

REMOTE_SCRIPT = r'''
import base64, gzip, hashlib, json, os, re, shutil, socket, stat, subprocess, sys, tempfile
from pathlib import Path
''' + SHARED_WITH_PINS + r'''
def run(payload, proc_root=Path('/proc'), sys_root=Path('/sys'), invoke=subprocess.run):
    expected_libcuda_sha256 = payload.get('expected_libcuda_sha256')
    if (expected_libcuda_sha256 is not None and
            (not isinstance(expected_libcuda_sha256, str) or
             not re.fullmatch(r'[0-9a-f]{64}', expected_libcuda_sha256))):
        raise ValueError('expected libcuda SHA-256 must be lowercase hexadecimal')
    managed_requested = payload.get('managed_memory', False)
    if type(managed_requested) is not bool:
        raise ValueError('managed-memory selection must be boolean')
    prefetch_requested = payload.get('managed_prefetch', False)
    if type(prefetch_requested) is not bool:
        raise ValueError('managed-prefetch selection must be boolean')
    if prefetch_requested and not managed_requested:
        raise ValueError('managed-prefetch requires managed-memory mode')
    trace_requested = payload.get('ioctl_trace', False)
    if type(trace_requested) is not bool:
        raise ValueError('ioctl trace selection must be boolean')
    cuda_graphs_requested = payload.get('cuda_graphs', False)
    if type(cuda_graphs_requested) is not bool:
        raise ValueError('CUDA Graph selection must be boolean')
    performance_benchmark_requested = payload.get('performance_benchmark', False)
    if type(performance_benchmark_requested) is not bool:
        raise ValueError('performance benchmark selection must be boolean')
    requested_benchmark_samples = payload.get('benchmark_samples')
    if (requested_benchmark_samples is not None and
            (type(requested_benchmark_samples) is not int or
             not 9 <= requested_benchmark_samples <= 1001 or
             not performance_benchmark_requested)):
        raise ValueError('benchmark sample count must be 9..1001 and requires a benchmark')
    benchmark_samples = (requested_benchmark_samples
                         if requested_benchmark_samples is not None else 9)
    benchmark_transfer_samples = (requested_benchmark_samples
                                  if requested_benchmark_samples is not None else 7)
    if performance_benchmark_requested and (managed_requested or prefetch_requested or
                                              cuda_graphs_requested):
        raise ValueError('performance benchmark must be isolated')
    requested_phase = payload.get('phase')
    if requested_phase is not None and requested_phase not in ('initialize', 'enumerate', 'context', 'allocation', 'module', 'kernel', 'system-pageable-memory', 'managed-accessed-by'):
        raise ValueError('unsupported CUDA Driver API phase')
    if performance_benchmark_requested and requested_phase is not None:
        raise ValueError('performance benchmark cannot be combined with a phase-only run')
    rm_control_headers_capture = payload.get('rm_control_headers_capture', False)
    if type(rm_control_headers_capture) is not bool:
        raise ValueError('RM_CONTROL redacted-header capture selection must be boolean')
    debugger_lifecycle_capture = payload.get('gt200_debugger_lifecycle_capture', False)
    if type(debugger_lifecycle_capture) is not bool:
        raise ValueError('GT200_DEBUGGER lifecycle capture selection must be boolean')
    if requested_phase is not None:
        if cuda_graphs_requested:
            raise ValueError('CUDA Graph testing cannot be combined with a phase-only probe')
        system_pageable_phase = requested_phase == 'system-pageable-memory'
        enumerate_node_trace = requested_phase == 'enumerate' and trace_requested
        managed_accessed_by_trace = requested_phase == 'managed-accessed-by' and trace_requested
        enumerate_rm_control_headers = requested_phase == 'enumerate' and rm_control_headers_capture
        if requested_phase == 'managed-accessed-by' and not trace_requested:
            raise ValueError('managed-accessed-by phase requires its isolated ioctl trace')
        if system_pageable_phase:
            if ('observer' in payload.get('artifacts', {}) or any(payload.get(key, False) for key in (
                    'ioctl_trace', 'managed_memory', 'managed_prefetch', 'gpu_id_info_capture',
                    'attached_ids_capture', 'probed_ids_capture', 'rm_control_capture',
                    'rm_control_headers_capture', 'p2p_control_capture', 'binapi_control_capture',
                    'device_alloc_capture', 'subdevice_alloc_capture', 'binapi_alloc_capture',
                    'gt200_debugger_alloc_capture', 'gt200_debugger_lifecycle_capture',
                    'channel_alloc_capture', 'map_memory_capture', 'rusd_alloc_capture'))):
                raise ValueError('system-pageable-memory phase must be an isolated numeric kernel run')
        elif enumerate_node_trace:
            if ('observer' in payload.get('artifacts', {}) or any(payload.get(key, False) for key in (
                    'managed_memory', 'managed_prefetch', 'gpu_id_info_capture',
                    'attached_ids_capture', 'probed_ids_capture', 'rm_control_capture',
                    'rm_control_headers_capture', 'p2p_control_capture', 'binapi_control_capture', 'device_alloc_capture',
                    'subdevice_alloc_capture', 'binapi_alloc_capture', 'gt200_debugger_alloc_capture',
                    'gt200_debugger_lifecycle_capture',
                    'channel_alloc_capture',
                    'map_memory_capture', 'rusd_alloc_capture'))):
                raise ValueError('enumeration node trace must be the only capture mode')
        elif managed_accessed_by_trace:
            if ('observer' in payload.get('artifacts', {}) or any(payload.get(key, False) for key in (
                    'managed_memory', 'managed_prefetch', 'gpu_id_info_capture',
                    'attached_ids_capture', 'probed_ids_capture', 'rm_control_capture',
                    'rm_control_headers_capture', 'p2p_control_capture', 'binapi_control_capture',
                    'device_alloc_capture', 'subdevice_alloc_capture', 'binapi_alloc_capture',
                    'gt200_debugger_alloc_capture', 'gt200_debugger_lifecycle_capture',
                    'channel_alloc_capture', 'map_memory_capture', 'rusd_alloc_capture'))):
                raise ValueError('managed-accessed-by trace must be the only capture mode')
        elif enumerate_rm_control_headers:
            if ('observer' not in payload.get('artifacts', {}) or any(payload.get(key, False) for key in (
                    'ioctl_trace', 'managed_memory', 'managed_prefetch', 'gpu_id_info_capture',
                    'attached_ids_capture', 'probed_ids_capture', 'rm_control_capture',
                    'p2p_control_capture', 'binapi_control_capture', 'device_alloc_capture',
                    'subdevice_alloc_capture', 'binapi_alloc_capture', 'gt200_debugger_alloc_capture',
                    'gt200_debugger_lifecycle_capture',
                    'channel_alloc_capture',
                    'map_memory_capture', 'rusd_alloc_capture'))):
                raise ValueError('enumeration RM_CONTROL header capture must be the only observer mode')
        else:
            device_alloc_capture = payload.get('device_alloc_capture') is True
            subdevice_alloc_capture = payload.get('subdevice_alloc_capture') is True
            binapi_alloc_capture = payload.get('binapi_alloc_capture') is True
            debugger_alloc_capture = payload.get('gt200_debugger_alloc_capture') is True
            debugger_lifecycle_capture = payload.get('gt200_debugger_lifecycle_capture') is True
            binapi_control_capture = payload.get('binapi_control_capture') is True
            if ('observer' not in payload.get('artifacts', {}) or
                    sum((device_alloc_capture, subdevice_alloc_capture, binapi_alloc_capture,
                         debugger_alloc_capture, debugger_lifecycle_capture,
                         binapi_control_capture)) != 1 or
                    (binapi_control_capture and payload.get('rm_control_capture') is not True) or
                    any(payload.get(key, False) for key in (
                        'ioctl_trace', 'managed_memory', 'managed_prefetch', 'gpu_id_info_capture',
                        'attached_ids_capture', 'probed_ids_capture', 'p2p_control_capture',
                        'channel_alloc_capture',
                        'map_memory_capture', 'rusd_alloc_capture'))):
                raise ValueError('phase capture requires exactly one isolated allocation/control observer mode')
    rm_control_capture = payload.get('rm_control_capture', False)
    if type(rm_control_capture) is not bool:
        raise ValueError('RM_CONTROL capture selection must be boolean')
    if rm_control_capture and 'observer' not in payload.get('artifacts', {}):
        raise ValueError('RM_CONTROL capture requires the RM ioctl observer')
    if rm_control_headers_capture and requested_phase != 'enumerate':
        raise ValueError('redacted RM_CONTROL headers require the enumerate phase')
    p2p_control_capture = payload.get('p2p_control_capture', False)
    if type(p2p_control_capture) is not bool:
        raise ValueError('P2P control capture selection must be boolean')
    if p2p_control_capture and not rm_control_capture:
        raise ValueError('P2P control capture requires RM_CONTROL header capture')
    if p2p_control_capture and 'observer' not in payload.get('artifacts', {}):
        raise ValueError('P2P control capture requires the RM ioctl observer')
    if p2p_control_capture and any(payload.get(key, False) for key in (
            'ioctl_trace', 'managed_memory', 'managed_prefetch', 'gpu_id_info_capture',
            'attached_ids_capture', 'probed_ids_capture', 'channel_alloc_capture',
            'map_memory_capture', 'rusd_alloc_capture')):
        raise ValueError('P2P control capture must be isolated with RM_CONTROL headers')
    binapi_control_capture = payload.get('binapi_control_capture', False)
    if type(binapi_control_capture) is not bool:
        raise ValueError('BINAPI control capture selection must be boolean')
    if binapi_control_capture and not rm_control_capture:
        raise ValueError('BINAPI control capture requires RM_CONTROL header capture')
    if binapi_control_capture and 'observer' not in payload.get('artifacts', {}):
        raise ValueError('BINAPI control capture requires the RM ioctl observer')
    if binapi_control_capture and any(payload.get(key, False) for key in (
            'ioctl_trace', 'managed_memory', 'managed_prefetch', 'gpu_id_info_capture',
            'attached_ids_capture', 'probed_ids_capture', 'p2p_control_capture',
            'channel_alloc_capture', 'map_memory_capture', 'rusd_alloc_capture')):
        raise ValueError('BINAPI control capture must be isolated with RM_CONTROL headers')
    device_alloc_capture = payload.get('device_alloc_capture', False)
    if type(device_alloc_capture) is not bool:
        raise ValueError('NV01_DEVICE_0 allocation capture selection must be boolean')
    if device_alloc_capture and 'observer' not in payload.get('artifacts', {}):
        raise ValueError('NV01_DEVICE_0 allocation capture requires the RM ioctl observer')
    if device_alloc_capture and any(payload.get(key, False) for key in (
            'ioctl_trace', 'managed_memory', 'managed_prefetch', 'gpu_id_info_capture',
            'attached_ids_capture', 'probed_ids_capture', 'rm_control_capture',
            'binapi_control_capture', 'p2p_control_capture', 'channel_alloc_capture',
            'map_memory_capture', 'rusd_alloc_capture')):
        raise ValueError('NV01_DEVICE_0 allocation capture must be isolated')
    subdevice_alloc_capture = payload.get('subdevice_alloc_capture', False)
    if type(subdevice_alloc_capture) is not bool:
        raise ValueError('NV20_SUBDEVICE_0 allocation capture selection must be boolean')
    if subdevice_alloc_capture and 'observer' not in payload.get('artifacts', {}):
        raise ValueError('NV20_SUBDEVICE_0 allocation capture requires the RM ioctl observer')
    if subdevice_alloc_capture and any(payload.get(key, False) for key in (
            'ioctl_trace', 'managed_memory', 'managed_prefetch', 'gpu_id_info_capture',
            'attached_ids_capture', 'probed_ids_capture', 'rm_control_capture',
            'binapi_control_capture', 'device_alloc_capture', 'p2p_control_capture',
            'channel_alloc_capture', 'map_memory_capture', 'rusd_alloc_capture')):
        raise ValueError('NV20_SUBDEVICE_0 allocation capture must be isolated')
    binapi_alloc_capture = payload.get('binapi_alloc_capture', False)
    if type(binapi_alloc_capture) is not bool:
        raise ValueError('NV2081_BINAPI allocation capture selection must be boolean')
    if binapi_alloc_capture and 'observer' not in payload.get('artifacts', {}):
        raise ValueError('NV2081_BINAPI allocation capture requires the RM ioctl observer')
    if binapi_alloc_capture and any(payload.get(key, False) for key in (
            'ioctl_trace', 'managed_memory', 'managed_prefetch', 'gpu_id_info_capture',
            'attached_ids_capture', 'probed_ids_capture', 'rm_control_capture',
            'binapi_control_capture', 'device_alloc_capture', 'subdevice_alloc_capture',
            'p2p_control_capture', 'channel_alloc_capture', 'map_memory_capture',
            'rusd_alloc_capture')):
        raise ValueError('NV2081_BINAPI allocation capture must be isolated')
    debugger_alloc_capture = payload.get('gt200_debugger_alloc_capture', False)
    if type(debugger_alloc_capture) is not bool:
        raise ValueError('GT200_DEBUGGER allocation capture selection must be boolean')
    if debugger_alloc_capture and ('observer' not in payload.get('artifacts', {}) or
            requested_phase != 'context' or any(payload.get(key, False) for key in (
                'ioctl_trace', 'managed_memory', 'managed_prefetch', 'cuda_graphs',
                'gpu_id_info_capture', 'attached_ids_capture', 'probed_ids_capture',
                'rm_control_capture', 'rm_control_headers_capture', 'p2p_control_capture',
                'binapi_control_capture', 'device_alloc_capture', 'subdevice_alloc_capture',
                'binapi_alloc_capture', 'channel_alloc_capture', 'map_memory_capture',
                'rusd_alloc_capture'))):
        raise ValueError('GT200_DEBUGGER allocation capture requires an isolated context observer')
    if debugger_lifecycle_capture and ('observer' not in payload.get('artifacts', {}) or
            requested_phase != 'context' or any(payload.get(key, False) for key in (
                'ioctl_trace', 'managed_memory', 'managed_prefetch', 'cuda_graphs',
                'gpu_id_info_capture', 'attached_ids_capture', 'probed_ids_capture',
                'rm_control_capture', 'rm_control_headers_capture', 'p2p_control_capture',
                'binapi_control_capture', 'device_alloc_capture', 'subdevice_alloc_capture',
                'binapi_alloc_capture', 'gt200_debugger_alloc_capture', 'channel_alloc_capture',
                'map_memory_capture', 'rusd_alloc_capture'))):
        raise ValueError('GT200_DEBUGGER lifecycle capture requires an isolated context observer')
    probed_ids_capture = payload.get('probed_ids_capture', False)
    if type(probed_ids_capture) is not bool:
        raise ValueError('probed-ID capture selection must be boolean')
    if probed_ids_capture and 'observer' not in payload.get('artifacts', {}):
        raise ValueError('probed-ID capture requires the RM ioctl observer')
    channel_alloc_capture = payload.get('channel_alloc_capture', False)
    if type(channel_alloc_capture) is not bool:
        raise ValueError('channel allocation capture selection must be boolean')
    if channel_alloc_capture and 'observer' not in payload.get('artifacts', {}):
        raise ValueError('channel allocation capture requires the RM ioctl observer')
    if channel_alloc_capture and any(payload.get(key, False) for key in (
            'gpu_id_info_capture', 'attached_ids_capture', 'probed_ids_capture',
            'rm_control_capture')):
        raise ValueError('channel allocation capture must run separately from other captures')
    map_memory_capture = payload.get('map_memory_capture', False)
    if type(map_memory_capture) is not bool:
        raise ValueError('map-memory capture selection must be boolean')
    if map_memory_capture and 'observer' not in payload.get('artifacts', {}):
        raise ValueError('map-memory capture requires the RM ioctl observer')
    if map_memory_capture and any(payload.get(key, False) for key in (
            'gpu_id_info_capture', 'attached_ids_capture', 'probed_ids_capture',
            'rm_control_capture', 'channel_alloc_capture')):
        raise ValueError('map-memory capture may combine only with RUSD allocation capture')
    rusd_alloc_capture = payload.get('rusd_alloc_capture', False)
    if type(rusd_alloc_capture) is not bool:
        raise ValueError('RUSD allocation capture selection must be boolean')
    if rusd_alloc_capture and 'observer' not in payload.get('artifacts', {}):
        raise ValueError('RUSD allocation capture requires the RM ioctl observer')
    if rusd_alloc_capture and any(payload.get(key, False) for key in (
            'ioctl_trace', 'managed_memory', 'managed_prefetch', 'gpu_id_info_capture',
            'attached_ids_capture', 'probed_ids_capture', 'rm_control_capture',
            'channel_alloc_capture')):
        raise ValueError('RUSD allocation capture may combine only with map-memory capture')
    if performance_benchmark_requested and (trace_requested or 'observer' in payload.get('artifacts', {}) or
            any(payload.get(key, False) for key in (
                'gpu_id_info_capture', 'attached_ids_capture', 'probed_ids_capture',
                'rm_control_capture', 'rm_control_headers_capture', 'p2p_control_capture',
                'binapi_control_capture', 'device_alloc_capture',
                'subdevice_alloc_capture', 'binapi_alloc_capture', 'gt200_debugger_alloc_capture',
                'gt200_debugger_lifecycle_capture',
                'channel_alloc_capture',
                'rusd_alloc_capture', 'map_memory_capture'))):
        raise ValueError('performance benchmark requires an isolated CUDA run')
    report = {"schema": "nvidia-hybrid-remote-selected-gpu-v1", "host": socket.gethostname(),
              "kernel_release": os.uname().release, "commands": [], "hardware_acceptance": None,
              "report_contract_validated": False,
              "cuda_execution_validated": False,
              "cuda_execution_validation_state": "not-established; probe build identity is not trusted",
              "memory_mode": "managed" if managed_requested else "device",
              "managed_memory_validated": False,
              "managed_memory_report_contract_passed": False,
              "managed_prefetch_requested": prefetch_requested,
              "managed_prefetch_validated": False,
              "managed_prefetch_report_contract_passed": False,
              "cuda_graphs_requested": cuda_graphs_requested,
              "cuda_graphs_validated": False,
              "cuda_graphs_report_contract_passed": False,
              "performance_benchmark_requested": performance_benchmark_requested,
              "performance_benchmark_validated": False,
              "performance_benchmark_report_contract_passed": False,
              "managed_accessed_by_validated": False,
              "managed_accessed_by_report_contract_passed": False,
              "phase_capture_requested": requested_phase is not None,
              "phase": requested_phase,
              "expected_libcuda_sha256": expected_libcuda_sha256,
              "system_libcuda_before": None,
              "system_libcuda_after": None,
              "device_selection": {"uuid": payload["uuid"], "pci": payload["pci"]},
              "gpu_id_info_capture_requested": payload.get("gpu_id_info_capture", False),
              "attached_ids_capture_requested": payload.get("attached_ids_capture", False),
              "probed_ids_capture_requested": probed_ids_capture,
              "probed_ids_records_seen": None,
              "remote_work_cleanup": {"attempted": False, "passed": False,
                                       "removed": False, "retained_for_inspection": False},
              "channel_alloc_capture_requested": channel_alloc_capture,
              "channel_alloc_records_seen": None,
              "rusd_alloc_capture_requested": rusd_alloc_capture,
              "rusd_alloc_records_seen": None,
              "rusd_polled_data_masks": None,
              "map_memory_capture_requested": map_memory_capture,
              "map_memory_records_seen": None,
              "map_memory_success_count": None,
              "unmap_memory_success_count": None,
              "map_memory_mmap_success_count": None,
              "map_memory_gpu_fd_close_count": None,
              "rm_control_capture_requested": rm_control_capture,
              "rm_control_records_seen": None,
              "rm_control_headers_capture_requested": rm_control_headers_capture,
              "rm_control_headers_records_seen": None,
              "rm_control_headers_record_count": None,
              "binapi_control_capture_requested": binapi_control_capture,
              "binapi_control_records_seen": None,
              "device_alloc_capture_requested": device_alloc_capture,
              "device_alloc_records_seen": None,
              "device_alloc_payload_snapshots_read": None,
              "subdevice_alloc_capture_requested": subdevice_alloc_capture,
              "subdevice_alloc_records_seen": None,
              "binapi_alloc_capture_requested": binapi_alloc_capture,
              "binapi_alloc_records_seen": None,
              "binapi_alloc_payload_snapshots_read": None,
              "gt200_debugger_alloc_capture_requested": debugger_alloc_capture,
              "gt200_debugger_alloc_records_seen": None,
              "gt200_debugger_alloc_payload_snapshots_read": None,
              "gt200_debugger_lifecycle_capture_requested": debugger_lifecycle_capture,
              "gt200_debugger_lifecycle": None,
              "subdevice_alloc_payload_snapshots_read": None,
              "binapi_payload_snapshots_read": None,
              "p2p_control_capture_requested": p2p_control_capture,
              "p2p_control_records_seen": None,
              "p2p_control_payload_snapshots_read": None,
              "remote_script_sha256": payload["remote_script_sha256"],
              "execution_scope": {"vm_management_commands_issued": False,
                                  "v100_test_requested": False,
                                  "experimental_driver_change_requested": False,
                                  "official_module_autoload_observed": None,
                                  "basis": "script actions and recorded command scope; not independent attestation"}}
    try:
        pci = canonical_pci(payload['pci'])
        uuid = payload['uuid']
        work = Path(tempfile.mkdtemp(prefix='hybrid-rtx5080-'))
        report['remote_work_directory'] = str(work)
        before = {}
        names = ['probe', 'module', 'runner']
        if 'cuda_probe_contract.py' in payload['artifacts']:
            names.append('cuda_probe_contract.py')
        if 'observer' in payload['artifacts']:
            names.append('observer')
        if trace_requested:
            names.append('trace-helper')
        for name in names:
            item = payload['artifacts'][name]
            data = base64.b64decode(item['base64'], validate=True)
            digest = hashlib.sha256(data).hexdigest()
            if digest != item['sha256']:
                raise ValueError('uploaded artifact hash mismatch: ' + name)
            path = work / name
            with path.open('xb') as stream:
                stream.write(data)
            path.chmod(0o700 if name in ('probe', 'observer') else 0o600)
            before[name] = {"path": str(path), "sha256": digest, "bytes": len(data)}
        validate_pinned_probe_artifacts(before)
        report['artifacts_before'] = before
        # Only read the selected function's metadata before starting NVML/CUDA.
        alternatives = [pci, '0000' + pci]
        infos = [proc_root / 'driver/nvidia/gpus' / candidate / 'information' for candidate in alternatives]
        infos = [path for path in infos if path.is_file()]
        if len(infos) != 1:
            raise ValueError('selected GPU /proc identity unavailable or ambiguous')
        info = infos[0].read_text()
        fields = dict(line.split(':', 1) for line in info.splitlines() if ':' in line)
        fields = {key.strip(): value.strip() for key, value in fields.items()}
        driver_path = sys_root / 'bus/pci/devices' / pci / 'driver'
        binding = driver_path.resolve(strict=True).name
        report['selected_proc_information'] = {"path": str(infos[0]), "fields": fields, "binding": binding}
        if fields.get('GPU UUID') != uuid or 'RTX 5080' not in fields.get('Model', '') or binding != 'nvidia':
            raise ValueError('selected GPU UUID/model/driver binding mismatch')
        env = clean_environment(os.environ, uuid)
        report['child_environment_policy'] = {"CUDA_VISIBLE_DEVICES": uuid, "PATH": env['PATH'],
                                              "removed_prefixes": ['LD_', 'CUDA_', 'NVIDIA_', 'PYTHON']}
        def command(argv, timeout):
            try:
                result = invoke(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, timeout=timeout, check=False)
            except subprocess.TimeoutExpired:
                report['commands'].append({"argv": argv, "exit_code": 124, "timeout": True})
                raise ValueError('remote child timed out')
            recorded_stdout = result.stdout
            if argv == ['/sbin/ldconfig', '-p']:
                # The full loader cache contains hundreds of unrelated paths.
                # Keep only the CUDA loader entries used by the identity check.
                recorded_stdout = ''.join(
                    line for line in result.stdout.splitlines(keepends=True)
                    if 'libcuda.so.1' in line)
            report['commands'].append({"argv": argv, "exit_code": result.returncode,
                                       "stdout": recorded_stdout, "stderr": result.stderr})
            return result
        smi = command(['nvidia-smi', '-i', uuid, '--query-gpu=name,uuid,pci.bus_id,driver_version',
                       '--format=csv,noheader,nounits'], 15)
        if smi.returncode:
            raise ValueError('targeted nvidia-smi failed')
        rows = [row.strip().split(',') for row in smi.stdout.splitlines() if row.strip()]
        if len(rows) != 1 or len(rows[0]) != 4:
            raise ValueError('unexpected targeted nvidia-smi inventory')
        name, observed_uuid, observed_pci, driver = [part.strip() for part in rows[0]]
        if observed_uuid != uuid or canonical_pci(observed_pci) != pci or 'RTX 5080' not in name:
            raise ValueError('targeted nvidia-smi identity mismatch')
        report['selected_nvidia_smi'] = {"name": name, "uuid": observed_uuid, "pci": observed_pci, "driver": driver}
        if expected_libcuda_sha256 is not None:
            ldconfig = command(['/sbin/ldconfig', '-p'], 15)
            if ldconfig.returncode:
                raise ValueError('ldconfig failed while resolving pinned system libcuda')
            libcuda_rows = []
            for line in ldconfig.stdout.splitlines():
                if 'libcuda.so.1' not in line or 'x86-64' not in line or '=>' not in line:
                    continue
                libcuda_rows.append(Path(line.rsplit('=>', 1)[1].strip()))
            if len(libcuda_rows) != 1:
                raise ValueError('system libcuda loader resolution is ambiguous')
            libcuda_path = libcuda_rows[0].resolve(strict=True)
            libcuda_stat = libcuda_path.stat()
            if not stat.S_ISREG(libcuda_stat.st_mode):
                raise ValueError('resolved system libcuda is not a regular file')
            libcuda_digest = hashlib.sha256(libcuda_path.read_bytes()).hexdigest()
            system_libcuda = {"path": str(libcuda_path), "bytes": libcuda_stat.st_size,
                              "sha256": libcuda_digest}
            report['system_libcuda_before'] = system_libcuda
            if libcuda_digest != expected_libcuda_sha256:
                raise ValueError('system libcuda hash differs from the required staged R595 library')
        preflight = command([str(work / 'probe'), '--list', '--expected-pci', pci], 30)
        if preflight.returncode:
            raise ValueError('CUDA inventory preflight failed')
        report['preflight'] = json.loads(preflight.stdout)
        if report['preflight'].get('schema') != 'nvidia-hybrid-probe-v2' or report['preflight'].get('status') != 'inventory':
            raise ValueError('unexpected CUDA preflight report contract')
        if (expected_libcuda_sha256 is not None and
                report['preflight'].get('driver_library_path') != report['system_libcuda_before']['path']):
            raise ValueError('CUDA preflight loaded a different library than the pinned system libcuda')
        selected_device(report['preflight'], pci)
        argv = [sys.executable, str(work / 'runner'), '--probe', str(work / 'probe'),
                '--module', str(work / 'module'), '--evidence-dir', str(work / 'evidence'),
                '--expected-pci', pci,
                '--timeout', ('180' if performance_benchmark_requested else
                              ('90' if trace_requested else
                               ('80' if managed_requested else ('70' if 'observer' in names else '60'))))]
        if requested_phase is not None:
            argv += ['--phase', requested_phase]
        if managed_requested:
            argv.append('--managed-memory')
        if prefetch_requested:
            argv.append('--managed-prefetch')
        if cuda_graphs_requested:
            argv.append('--cuda-graphs')
        if performance_benchmark_requested:
            argv.append('--benchmark')
            if requested_benchmark_samples is not None:
                argv += ['--benchmark-samples', str(benchmark_samples)]
        if 'observer' in names:
            argv += ['--ioctl-observer', str(work / 'observer')]
            if payload.get('gpu_id_info_capture'):
                argv.append('--gpu-id-info')
            if payload.get('attached_ids_capture'):
                argv.append('--attached-ids')
            if probed_ids_capture:
                argv.append('--probed-ids')
            if rm_control_capture:
                argv.append('--rm-control')
            if rm_control_headers_capture:
                argv.append('--rm-control-headers')
            if p2p_control_capture:
                argv.append('--p2p-control')
            if binapi_control_capture:
                argv += ['--binapi-control', '--gpu-path', '/dev/nvidia0']
            if device_alloc_capture:
                argv += ['--device-alloc', '--gpu-path', '/dev/nvidia0']
            if subdevice_alloc_capture:
                argv += ['--subdevice-alloc', '--gpu-path', '/dev/nvidia0']
            if binapi_alloc_capture:
                argv += ['--binapi-alloc', '--gpu-path', '/dev/nvidia0']
            if debugger_alloc_capture:
                argv += ['--gt200-debugger-alloc', '--gpu-path', '/dev/nvidia0']
            if debugger_lifecycle_capture:
                argv += ['--gt200-debugger-lifecycle', '--gpu-path', '/dev/nvidia0']
            if channel_alloc_capture:
                argv.append('--channel-alloc')
            if map_memory_capture:
                argv.append('--map-memory')
            if rusd_alloc_capture:
                argv.append('--rusd-alloc')
        if trace_requested:
            argv += ['--ioctl-trace', '--trace-helper', str(work / 'trace-helper'),
                     '--strace-binary', '/usr/bin/strace', '--ioctl-trace-output',
                     str(work / 'cuda-ioctl.strace')]
        result = command(argv, 105 if trace_requested else
                         (95 if managed_requested else (85 if 'observer' in names else 75)))
        acceptance = json.loads(result.stdout)
        report['hardware_acceptance'] = acceptance
        validate_probe_build_trust(acceptance, payload.get('artifacts', {}))
        report['cuda_execution_validation_state'] = (
            'probe/fatbin identity is pinned; CUDA execution is not independently attested')
        phase_report = acceptance.get('probe')
        if (requested_phase is not None and
                requested_phase != 'system-pageable-memory' and
                phase_report is None):
            phase_stdout = acceptance.get('stdout')
            if not isinstance(phase_stdout, str):
                raise ValueError('CUDA phase report is missing from acceptance output')
            try:
                phase_report = json.loads(phase_stdout)
            except (TypeError, json.JSONDecodeError):
                raise ValueError('CUDA phase output is not valid JSON') from None
            if not isinstance(phase_report, dict):
                raise ValueError('CUDA phase output is not a JSON object')
        if expected_libcuda_sha256 is not None:
            accepted_probe = (phase_report if requested_phase is not None
                              else acceptance.get('probe'))
            if (not isinstance(accepted_probe, dict) or
                    accepted_probe.get('driver_library_path') != report['system_libcuda_before']['path']):
                raise ValueError('CUDA phase did not use the hash-pinned system libcuda')
            libcuda_after = report['system_libcuda_before']['path']
            after_stat = Path(libcuda_after).stat()
            after_digest = hashlib.sha256(Path(libcuda_after).read_bytes()).hexdigest()
            report['system_libcuda_after'] = {"path": libcuda_after, "bytes": after_stat.st_size,
                                              "sha256": after_digest}
            if report['system_libcuda_after'] != report['system_libcuda_before']:
                raise ValueError('system libcuda changed during the selected-GPU probe')
        if trace_requested:
            trace = acceptance.get('ioctl_trace')
            if not isinstance(trace, dict) or not isinstance(trace.get('trace'), dict):
                raise ValueError('requested CUDA ioctl trace is missing')
            trace_path = Path(trace['trace'].get('path', ''))
            expected_trace_path = work / 'cuda-ioctl.strace'
            if trace_path != expected_trace_path or not trace_path.is_file():
                raise ValueError('CUDA ioctl trace path is outside the private remote workspace')
            raw = trace_path.read_bytes()
            if len(raw) > 8 * 1024 * 1024:
                raise ValueError('CUDA ioctl trace exceeds the raw transport limit')
            compressed = gzip.compress(raw, mtime=0)
            if len(compressed) > 1024 * 1024:
                raise ValueError('compressed CUDA ioctl trace exceeds the transport limit')
            report['ioctl_trace_transport'] = {
                'gzip_base64': base64.b64encode(compressed).decode('ascii'),
                'gzip_bytes': len(compressed),
                'gzip_sha256': hashlib.sha256(compressed).hexdigest(),
                'raw_bytes': len(raw),
                'raw_sha256': hashlib.sha256(raw).hexdigest(),
            }
        if 'observer' in names:
            observed = (acceptance.get('ioctl_observation') or {}).get('report') or {}
            id_capture = bool(payload.get('gpu_id_info_capture'))
            attached_capture = bool(payload.get('attached_ids_capture'))
            probed_capture = probed_ids_capture
            p2p_snapshots = None
            if p2p_control_capture:
                p2p_snapshots = observed.get('p2p_control_payload_snapshots_read')
                if type(p2p_snapshots) is not int or p2p_snapshots < 0:
                    raise ValueError('P2P control observation has no valid nested-read count')
            binapi_snapshots = None
            if binapi_control_capture:
                binapi_snapshots = observed.get('binapi_payload_snapshots_read')
                if type(binapi_snapshots) is not int or binapi_snapshots < 0:
                    raise ValueError('BINAPI observation has no valid payload-snapshot count')
            binapi_alloc_snapshots = None
            if binapi_alloc_capture:
                binapi_alloc_snapshots = observed.get('binapi_alloc_payload_snapshots_read')
                if type(binapi_alloc_snapshots) is not int or binapi_alloc_snapshots < 0:
                    raise ValueError('BINAPI allocation observation has no valid payload-snapshot count')
            debugger_alloc_snapshots = None
            if debugger_alloc_capture:
                debugger_alloc_snapshots = observed.get('debugger_alloc_payload_snapshots_read')
                if type(debugger_alloc_snapshots) is not int or debugger_alloc_snapshots < 0:
                    raise ValueError('GT200_DEBUGGER observation has no valid payload-snapshot count')
            debugger_lifecycle_summary = None
            if debugger_lifecycle_capture:
                debugger_lifecycle_summary = validate_gt200_debugger_lifecycle_capture(observed)
                report['gt200_debugger_lifecycle'] = debugger_lifecycle_summary
            expected_schema = ('nvidia-hybrid-rm-ioctl-observer-v39' if debugger_lifecycle_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v34' if debugger_alloc_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v23' if rm_control_headers_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v22' if map_memory_capture and rusd_alloc_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v21' if binapi_alloc_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v20' if subdevice_alloc_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v19' if device_alloc_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v18' if binapi_control_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v17' if p2p_control_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v15' if map_memory_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v14' if rusd_alloc_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v9' if channel_alloc_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v6' if probed_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v5' if rm_control_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v4' if attached_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v3' if id_capture else
                               'nvidia-hybrid-rm-ioctl-observer-v1')
            selected_scopes = []
            if id_capture:
                selected_scopes.append('NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2')
            if attached_capture:
                selected_scopes.append('NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS')
            if probed_capture:
                selected_scopes.append('NV0000_CTRL_CMD_GPU_GET_PROBED_IDS')
            if channel_alloc_capture:
                scope = ('VOLTA_CHANNEL_GPFIFO_A and BLACKWELL_CHANNEL_GPFIFO_A class payloads parsed '
                         'using the byte-identical pinned R580.178.04/R595.99.02 '
                         'NV_CHANNEL_ALLOC_PARAMS layout; raw addresses and handles omitted')
            elif map_memory_capture and rusd_alloc_capture:
                scope = ('RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS fixed 8-byte polledDataMask only, '
                         'plus exact pinned R580 NVOS33/NVOS34 map packets and selected-file lifecycle '
                         'metadata; other allocation payloads and raw addresses/handles omitted')
            elif rusd_alloc_capture:
                scope = ('RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS only, parsed as the pinned '
                         '8-byte polledDataMask; raw addresses and handles omitted')
            elif len(selected_scopes) == 1:
                scope = 'exact ' + selected_scopes[0] + ' payload only; addresses omitted'
            elif len(selected_scopes) == 2:
                scope = 'exact ' + ' and '.join(selected_scopes) + ' payloads only; addresses omitted'
            elif len(selected_scopes) == 3:
                scope = ('exact ' + ', '.join(selected_scopes[:-1]) + ', and ' +
                         selected_scopes[-1] + ' payloads only; addresses omitted')
            else:
                scope = None
            if p2p_control_capture and p2p_snapshots:
                scope = ('exact NV503C register/unregister VA-space, register/unregister vidmem, and '
                         'register-PID fixed parameter structures; raw addresses, handles, and '
                         'VA-space tokens omitted')
            if binapi_control_capture and binapi_snapshots:
                scope = ('exact 992-byte top-level NV2081_BINAPI control payload for command '
                         '0x20810108; no contained pointer is followed; raw bytes, addresses, '
                         'and handles omitted')
            if device_alloc_capture:
                scope = ('NV01_DEVICE_0 NV0080_ALLOC_PARAMETERS fixed 56-byte payload only; '
                         'client handles are relational booleans; internal VA addresses are omitted')
            if subdevice_alloc_capture:
                scope = ('NV20_SUBDEVICE_0 NV2080_ALLOC_PARAMETERS fixed 4-byte subDeviceId only; '
                         'handles omitted')
            if binapi_alloc_capture:
                scope = ('NV2081_BINAPI NV2081_ALLOC_PARAMETERS fixed 4-byte reserved zero predicate only; '
                         'handles omitted')
            if debugger_alloc_capture:
                scope = ('exact NV83DE_ALLOC_PARAMETERS 12-byte payload for GT200_DEBUGGER only; '
                         'emits handle presence and within-root class relations including the debuggee direct-parent class; '
                         'raw handles and addresses omitted')
            if debugger_lifecycle_capture:
                scope = ('exact NV83DE allocation parameters plus fixed NVOS54 headers for resolved GT200_DEBUGGER controls and unresolved 0x83de command candidates; only exact 4-byte exceptionMask for resolved 0x83de0309 controls is followed after fixed-size, non-null-pointer, and documented-bit checks; RM_FREE class resolution is root-scoped; a redacted hObject-to-prior-GT200_DEBUGGER-allocation equality is emitted; raw handles and addresses omitted')
            scope_ok = observed.get('nested_pointer_scope') == scope
            nested_requested = (id_capture or attached_capture or probed_capture or
                                rusd_alloc_capture or
                                device_alloc_capture or
                                subdevice_alloc_capture or
                                debugger_alloc_capture or
                                (debugger_lifecycle_capture and
                                 (debugger_lifecycle_summary['allocation_payload_snapshots'] > 0 or
                                  debugger_lifecycle_summary['exception_mask_payload_snapshots'] > 0)) or
                                (binapi_alloc_capture and binapi_alloc_snapshots > 0) or
                                (p2p_control_capture and p2p_snapshots > 0) or
                                (binapi_control_capture and binapi_snapshots > 0))
            if channel_alloc_capture:
                if (observed.get('gpu_path') != '/dev/nvidia0' or
                    observed.get('object_class_resolution_scope') !=
                    'successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed'):
                    raise ValueError('channel observer did not capture both selected RM descriptor paths')
                snapshots = observed.get('channel_payload_snapshots_read')
                if type(snapshots) is not int or snapshots < 0:
                    raise ValueError('channel allocation observation has no nested-read count')
                nested_requested = nested_requested or snapshots > 0
            if map_memory_capture and observed.get('gpu_path') != '/dev/nvidia0':
                raise ValueError('map-memory observer did not classify the selected backend GPU path')
            if map_memory_capture and observed.get('object_class_resolution_scope') != (
                    'successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed'):
                raise ValueError('map-memory observer omitted transient RM object-class tracking scope')
            if rusd_alloc_capture and observed.get('gpu_path') != '/dev/nvidia0':
                raise ValueError('RUSD observer did not classify the selected backend GPU path')
            if rm_control_headers_capture:
                expected_payload_scope = (
                    'fixed NVOS54 RM_CONTROL headers only; handles redacted; nested parameter payloads omitted')
                payload_scope_ok = observed.get('payload_scope') == expected_payload_scope
            elif rm_control_capture:
                expected_payload_scope = ('RM_CONTROL headers plus exact NV503C P2P control payloads; '
                    'raw addresses, handles, and VA-space tokens omitted; other nested parameter payloads omitted'
                    if p2p_control_capture else
                    'RM_CONTROL headers plus exact 992-byte NV2081_BINAPI payload-shape metadata; '
                    'contained pointers are never followed; raw bytes, addresses, and handles omitted'
                    if binapi_control_capture else
                    'RM_CONTROL headers plus explicitly selected fixed metadata payloads; other nested parameters omitted'
                    if nested_requested else
                    'fixed NVOS54 RM_CONTROL headers only; nested parameter payloads omitted')
                payload_scope_ok = observed.get('payload_scope') == expected_payload_scope
            elif map_memory_capture:
                payload_scope = (
                    'exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device '
                    'open/dup/close/mmap metadata, transient RM_ALLOC/RM_FREE class resolution, and '
                    'fixed RM_USER_SHARED_DATA 8-byte polling-mask snapshots only; addresses, paths, '
                    'and handles omitted' if rusd_alloc_capture else
                    'exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device '
                    'open/dup/close/mmap metadata, and transient RM_ALLOC/RM_FREE class resolution; '
                    'no allocation payloads emitted; addresses, paths, and handles omitted')
                payload_scope_ok = observed.get('payload_scope') == payload_scope
            elif device_alloc_capture:
                payload_scope_ok = observed.get('payload_scope') == (
                    'NV01_DEVICE_0 fixed class parameters only; handles are redacted and internal VA addresses are omitted')
            elif subdevice_alloc_capture:
                payload_scope_ok = observed.get('payload_scope') == (
                    'NV20_SUBDEVICE_0 fixed class parameters only; handles omitted')
            elif binapi_alloc_capture:
                payload_scope_ok = observed.get('payload_scope') == (
                    'NV2081_BINAPI fixed class parameters only; raw reserved value, handles omitted')
            elif debugger_alloc_capture:
                payload_scope_ok = observed.get('payload_scope') == (
                    'NV83DE_ALLOC_PARAMETERS exact 12-byte fixed payload on GT200_DEBUGGER allocations only; '
                    'raw handles, pointers, and payload bytes omitted')
            elif debugger_lifecycle_capture:
                payload_scope_ok = observed.get('payload_scope') == (
                    'GT200_DEBUGGER allocations, class-resolved GT200_DEBUGGER frees, fixed NVOS54 headers plus a redacted hObject-to-prior-debugger-allocation equality, and exact 4-byte exceptionMask snapshots for resolved 0x83de0309 controls only; null pointers, size mismatch, and undocumented bits fail closed; unresolved command candidates are never dereferenced; raw handles and addresses omitted')
            else:
                payload_scope_ok = 'payload_scope' not in observed
            fd_lifecycle_scope_ok = (
                observed.get('fd_lifecycle_scope') ==
                'opaque file IDs assigned at observed open/openat/openat2 and dup/dup2/dup3/'
                'fcntl(F_DUPFD*) calls; close() removes an ID; close_range invalidates affected IDs; '
                'exec invalidates inherited IDs; io_uring and external fd injection are not tracked; '
                'VMA file references remain kernel-owned'
                if map_memory_capture else 'fd_lifecycle_scope' not in observed)
            if (observed.get('schema') != expected_schema or
                observed.get('trace_complete') is not True or observed.get('errors') != [] or
                observed.get('child_exit_code') != result.returncode or
                observed.get('control_path') != '/dev/nvidiactl' or
                observed.get('nested_pointers_read') is not nested_requested or
                ((nested_requested or channel_alloc_capture) and not scope_ok) or
                not payload_scope_ok or not fd_lifecycle_scope_ok or
                not isinstance(observed.get('records'), list)):
                raise ValueError('missing or incomplete ioctl observation')
            if map_memory_capture and observed.get('fd_identity_capture_complete') is not True:
                raise ValueError('map observation has incomplete selected-file identity tracking')
            rows = observed['records']
            if binapi_control_capture:
                records_seen, snapshots_seen = validate_binapi_control_observation(observed)
                report['binapi_control_records_seen'] = records_seen
                report['binapi_payload_snapshots_read'] = snapshots_seen
            if device_alloc_capture:
                rows = observed['records']
                snapshots_seen = observed.get('device_alloc_payload_snapshots_read')
                success_seen = any(
                    isinstance(row, dict) and row.get('operation') == 'device_alloc' and
                    row.get('syscall_return') == 0 and isinstance(row.get('exit'), dict) and
                    row['exit'].get('status') == 0 and
                    isinstance(row['exit'].get('deviceAlloc'), dict) for row in rows)
                if (observed.get('gpu_path') != '/dev/nvidia0' or
                    type(snapshots_seen) is not int or snapshots_seen <= 0 or
                    not rows or not success_seen or
                    acceptance.get('device_alloc_records_seen') is not True or
                    acceptance.get('device_alloc_payload_snapshots_read') != snapshots_seen or
                    acceptance.get('validation_errors') != []):
                    raise ValueError('NV01_DEVICE_0 capture does not contain one validated redacted successful allocation')
                report['device_alloc_records_seen'] = True
                report['device_alloc_payload_snapshots_read'] = snapshots_seen
            if subdevice_alloc_capture:
                rows = observed['records']
                snapshots_seen = observed.get('subdevice_alloc_payload_snapshots_read')
                success_seen = any(
                    isinstance(row, dict) and row.get('operation') == 'subdevice_alloc' and
                    row.get('syscall_return') == 0 and isinstance(row.get('exit'), dict) and
                    row['exit'].get('status') == 0 and
                    isinstance(row['exit'].get('subdeviceAlloc'), dict) for row in rows)
                if (observed.get('gpu_path') != '/dev/nvidia0' or
                    type(snapshots_seen) is not int or snapshots_seen <= 0 or
                    not rows or not success_seen or
                    acceptance.get('subdevice_alloc_records_seen') is not True or
                    acceptance.get('subdevice_alloc_payload_snapshots_read') != snapshots_seen or
                    acceptance.get('validation_errors') != []):
                    raise ValueError('NV20_SUBDEVICE_0 capture lacks a validated redacted successful allocation')
                report['subdevice_alloc_records_seen'] = True
                report['subdevice_alloc_payload_snapshots_read'] = snapshots_seen
            if binapi_alloc_capture:
                records_seen, snapshots_seen = validate_binapi_alloc_capture(observed)
                if (acceptance.get('binapi_alloc_records_seen') is not True or
                    acceptance.get('binapi_alloc_payload_snapshots_read') != snapshots_seen or
                    acceptance.get('validation_errors') != []):
                    raise ValueError('NV2081_BINAPI allocation differs from the shared redacted contract')
                report['binapi_alloc_records_seen'] = records_seen
                report['binapi_alloc_payload_snapshots_read'] = snapshots_seen
            if debugger_alloc_capture:
                records_seen, snapshots_seen = validate_gt200_debugger_alloc_capture(observed)
                if (acceptance.get('gt200_debugger_alloc_records_seen') is not True or
                    acceptance.get('gt200_debugger_alloc_payload_snapshots_read') != snapshots_seen or
                    acceptance.get('validation_errors') != []):
                    raise ValueError('GT200_DEBUGGER allocation differs from the shared redacted contract')
                report['gt200_debugger_alloc_records_seen'] = records_seen
                report['gt200_debugger_alloc_payload_snapshots_read'] = snapshots_seen
            if debugger_lifecycle_capture:
                if (acceptance.get('gt200_debugger_lifecycle_capture_requested') is not True or
                    acceptance.get('gt200_debugger_lifecycle') != debugger_lifecycle_summary or
                    acceptance.get('validation_errors') != []):
                    raise ValueError('GT200_DEBUGGER lifecycle differs from the validated redacted contract')
            if p2p_control_capture:
                p2p_commands = {0x503c0102: 16, 0x503c0103: 4, 0x503c0104: 32,
                                0x503c0105: 4, 0x503c0106: 4}
                p2p_fields = {
                    0x503c0102: {'command', 'payloadBytes', 'payloadValid',
                                 'inputHandlePresent', 'vaSpaceTokenNonzeroAtSnapshot'},
                    0x503c0103: {'command', 'payloadBytes', 'payloadValid',
                                 'inputHandlePresent'},
                    0x503c0104: {'command', 'payloadBytes', 'payloadValid',
                                 'inputHandlePresent', 'addressAligned64K', 'sizeNonzero',
                                 'sizeAligned64K', 'offsetAligned64K',
                                 'offsetAndSizeDoNotOverflow', 'addressAndSizeDoNotOverflow'},
                    0x503c0105: {'command', 'payloadBytes', 'payloadValid',
                                 'inputHandlePresent'},
                    0x503c0106: {'command', 'payloadBytes', 'payloadValid',
                                 'inputHandlePresent'},
                }
                outer_fields = {'command', 'flags', 'params_size', 'status',
                                'hClientPresent', 'hObjectPresent', 'client_object_equal',
                                'client_matches_prior_root_allocation',
                                'object_matches_prior_root_allocation', 'p2pControl',
                                'objectClass'}
                row_fields = {'tid', 'fd', 'fd_role', 'request', 'packet_size',
                              'operation', 'entry', 'exit', 'syscall_return'}
                p2p_rows = []
                snapshots_seen = 0
                for row in rows:
                    if not isinstance(row, dict):
                        raise ValueError('P2P control observation contains a malformed record')
                    phases = [row.get(phase) for phase in ('entry', 'exit')]
                    payloads = [phase.get('p2pControl') for phase in phases
                                if isinstance(phase, dict) and 'p2pControl' in phase]
                    if any(payload is not None and not isinstance(payload, dict)
                           for payload in payloads):
                        raise ValueError('P2P control observation contains malformed nested metadata')
                    if not any(isinstance(payload, dict) for payload in payloads):
                        continue
                    if (set(row) != row_fields or row.get('operation') != 'rm_control_header' or
                        row.get('fd_role') != 'control' or
                        (row.get('request'), row.get('packet_size')) not in
                        ((0xc020462a, 32), (0xc01046d3, 16)) or
                        row.get('syscall_return') != 0):
                        raise ValueError('P2P control RM transport is unexpected or failed')
                    p2p_rows.append(row)
                    if len(payloads) != 2 or not all(isinstance(payload, dict) for payload in payloads):
                        raise ValueError('P2P control entry/exit snapshots are incomplete')
                    commands_in_row = set()
                    for phase_name, outer in zip(('entry', 'exit'), phases):
                        if not isinstance(outer, dict) or set(outer) != outer_fields:
                            raise ValueError('P2P control RM header is malformed or unredacted')
                        command = outer.get('command')
                        if (command not in p2p_commands or type(outer.get('flags')) is not int or
                            type(outer.get('params_size')) is not int or
                            outer.get('params_size') != p2p_commands[command] or
                            type(outer.get('status')) is not int or
                            any(type(outer.get(key)) is not bool for key in (
                                'hClientPresent', 'hObjectPresent', 'client_object_equal',
                                'client_matches_prior_root_allocation',
                                'object_matches_prior_root_allocation')) or
                            outer.get('hClientPresent') is not True or
                            outer.get('hObjectPresent') is not True):
                            raise ValueError('P2P control RM header fields are invalid')
                        commands_in_row.add(command)
                        object_class = outer.get('objectClass')
                        if (not isinstance(object_class, dict) or set(object_class) !=
                            {'resolution', 'classId'} or
                            object_class.get('resolution') != 'resolved' or
                            object_class.get('classId') != 0x503c):
                            raise ValueError('P2P control object class did not resolve to NV50_THIRD_PARTY_P2P')
                        control = outer.get('p2pControl')
                        if (not isinstance(control, dict) or
                            set(control) != p2p_fields[command] or
                            control.get('command') != command or
                            control.get('payloadBytes') != p2p_commands[command] or
                            control.get('payloadValid') is not True or
                            control.get('inputHandlePresent') is not True or
                            any(type(value) is not bool for key, value in control.items()
                                if key not in ('command', 'payloadBytes'))):
                            raise ValueError('P2P control payload layout is malformed or unredacted')
                        if command == 0x503c0104 and any(control.get(key) is not True for key in (
                                'addressAligned64K', 'sizeNonzero', 'sizeAligned64K',
                                'offsetAligned64K', 'offsetAndSizeDoNotOverflow',
                                'addressAndSizeDoNotOverflow')):
                            raise ValueError('P2P registered vidmem range violates captured alignment constraints')
                        if phase_name == 'exit' and outer.get('status') != 0:
                            raise ValueError('P2P control returned a nonzero embedded RM status')
                        if command == 0x503c0102 and phase_name == 'exit' and \
                                control.get('vaSpaceTokenNonzeroAtSnapshot') is not True:
                            raise ValueError('P2P VA-space registration returned no token')
                        snapshots_seen += 1
                    if len(commands_in_row) != 1:
                        raise ValueError('P2P control command changed between entry and exit')
                if snapshots_seen != p2p_snapshots:
                    raise ValueError('P2P control snapshot count differs from the observed RM records')
                if p2p_snapshots and (p2p_snapshots % 2 or not p2p_rows):
                    raise ValueError('P2P control payload snapshots do not form entry/exit pairs')
                if not p2p_snapshots and ('nested_pointer_scope' in observed or
                                           observed.get('nested_pointers_read') is not False):
                    raise ValueError('empty P2P control capture unexpectedly read a nested pointer')
                report['p2p_control_records_seen'] = bool(p2p_rows)
                report['p2p_control_payload_snapshots_read'] = snapshots_seen
            else:
                unexpected_p2p = any(
                    isinstance(row, dict) and any(
                        isinstance(phase, dict) and isinstance(phase.get('p2pControl'), dict)
                        for phase in (row.get('entry'), row.get('exit')))
                    for row in rows)
                if unexpected_p2p:
                    raise ValueError('P2P control payloads were returned without requesting capture')
                report['p2p_control_records_seen'] = False
            if map_memory_capture:
                validate_map_fd_lifecycle(rows)
                class_counts = {}
                class_ids = set()
                for row in rows:
                    if not isinstance(row, dict) or row.get('operation') != 'map_memory':
                        continue
                    entry_payload = row.get('entry')
                    if not isinstance(entry_payload, dict):
                        continue
                    memory_class = entry_payload['memoryObjectClass']
                    resolution = memory_class['resolution']
                    class_counts[resolution] = class_counts.get(resolution, 0) + 1
                    if resolution == 'resolved':
                        class_ids.add(memory_class['classId'])
                report['map_memory_class_resolution_counts'] = dict(sorted(class_counts.items()))
                report['map_memory_class_ids'] = sorted(class_ids)
            probed_ids_seen = any(isinstance(row, dict) and
                                  row.get('operation') == 'gpu_probed_ids' for row in rows)
            report['probed_ids_records_seen'] = probed_ids_seen
            if probed_capture and not probed_ids_seen:
                raise ValueError('probed-ID capture contains no GPU_GET_PROBED_IDS record')
            channel_rows = [row for row in rows if isinstance(row, dict) and
                            row.get('operation') == 'channel_alloc']
            report['channel_alloc_records_seen'] = bool(channel_rows)
            if channel_alloc_capture and not channel_rows:
                raise ValueError('channel allocation observation contains no GPFIFO allocation record')
            if channel_alloc_capture and any(row.get('fd_role') not in ('control', 'gpu')
                                             for row in channel_rows):
                raise ValueError('channel allocation record has no selected descriptor role')
            rusd_rows = [row for row in rows if isinstance(row, dict) and
                         row.get('operation') == 'rusd_alloc']
            report['rusd_alloc_records_seen'] = bool(rusd_rows) if rusd_alloc_capture else None
            if rusd_alloc_capture:
                report['rusd_polled_data_masks'] = []
                snapshots = observed.get('rusd_payload_snapshots_read')
                if type(snapshots) is not int or snapshots != 2 * len(rusd_rows):
                    raise ValueError('RUSD payload snapshot count differs from the observer records')
                record_fields = {'tid', 'fd', 'fd_role', 'request', 'packet_size',
                                 'operation', 'entry', 'exit', 'syscall_return'}
                if map_memory_capture:
                    record_fields.add('fd_file_id')
                packet_fields = {'layout', 'hClass', 'paramsSize', 'flags', 'status',
                                 'hRootPresent', 'hObjectParentPresent', 'hObjectNewPresent',
                                 'pAllocParmsPresent', 'pRightsRequestedPresent',
                                 'rusdPayloadState', 'rusd'}
                if len(rusd_rows) != len(rows) and not map_memory_capture:
                    raise ValueError('RUSD observer returned records outside the selected class scope')
                for row in rusd_rows:
                    if (set(row) != record_fields or type(row.get('tid')) is not int or
                        row['tid'] <= 0 or type(row.get('fd')) is not int or row['fd'] < 0 or
                        row.get('fd_role') not in ('control', 'gpu') or
                        row.get('request') != 0xc030462b or row.get('packet_size') != 48 or
                        row.get('syscall_return') != 0):
                        raise ValueError('RUSD RM allocation transport has unexpected fields or failed')
                    masks = []
                    for phase in ('entry', 'exit'):
                        packet = row.get(phase)
                        if (not isinstance(packet, dict) or set(packet) != packet_fields or
                            packet.get('layout') != 'NVOS64' or packet.get('hClass') != 0xde or
                            type(packet.get('paramsSize')) is not int or packet['paramsSize'] != 0 or
                            type(packet.get('flags')) is not int or
                            type(packet.get('status')) is not int or packet['status'] != 0 or
                            any(type(packet.get(key)) is not bool for key in
                                ('hRootPresent', 'hObjectParentPresent', 'hObjectNewPresent')) or
                            packet.get('pAllocParmsPresent') is not True or
                            packet.get('pRightsRequestedPresent') is not False or
                            packet.get('rusdPayloadState') != 'r580-r595-class-layout-parsed'):
                            raise ValueError('RUSD class payload packet layout is malformed')
                        rusd = packet.get('rusd')
                        if (not isinstance(rusd, dict) or set(rusd) !=
                            {'classPayloadBytes', 'polledDataMask'} or
                            rusd.get('classPayloadBytes') != 8 or
                            type(rusd.get('polledDataMask')) is not int or
                            not 0 <= rusd['polledDataMask'] <= 0xffffffffffffffff):
                            raise ValueError('RUSD class payload is malformed or unredacted')
                        masks.append(rusd['polledDataMask'])
                    if masks[0] != masks[1]:
                        raise ValueError('RUSD polling mask changed during the observed allocation')
                    report['rusd_polled_data_masks'].append(masks[0])
            elif rusd_rows:
                raise ValueError('RUSD allocation records were returned without requesting capture')
            if rm_control_capture:
                rm_control_seen = any(isinstance(row, dict) and row.get('operation') in
                                      ('rm_control_header', 'gpu_id_info_v2', 'gpu_attached_ids',
                                       'gpu_probed_ids', 'binapi_control')
                                      for row in rows)
                if not rm_control_seen and not binapi_control_capture:
                    raise ValueError('RM_CONTROL observation contains no RM_CONTROL records')
                report['rm_control_records_seen'] = rm_control_seen
            if rm_control_headers_capture:
                header_count = validate_rm_control_headers_observation(observed)
                report['rm_control_headers_records_seen'] = True
                report['rm_control_headers_record_count'] = header_count
            if map_memory_capture:
                map_rows = [row for row in rows if isinstance(row, dict) and
                            row.get('operation') == 'map_memory']
                unmap_rows = [row for row in rows if isinstance(row, dict) and
                              row.get('operation') == 'unmap_memory']
                mmap_rows = [row for row in rows if isinstance(row, dict) and
                             row.get('operation') == 'mmap']
                close_rows = [row for row in rows if isinstance(row, dict) and
                              row.get('operation') == 'close']
                successful_maps = [row for row in map_rows
                                   if row.get('syscall_return') == 0 and
                                   isinstance(row.get('exit'), dict) and
                                   row['exit'].get('status') == 0 and
                                   row['exit'].get('backendFdRole') == 'gpu' and
                                   isinstance(row.get('entry'), dict) and
                                   type(row['entry'].get('backendFd')) is int and
                                   row['entry'].get('backendFd') == row['exit'].get('backendFd')]
                successful_unmaps = [row for row in unmap_rows
                                     if row.get('syscall_return') == 0 and
                                     isinstance(row.get('exit'), dict) and
                                     row['exit'].get('status') == 0]
                for row in mmap_rows:
                    entry = row.get('entry')
                    if (row.get('request') != 9 or row.get('packet_size') != 0 or
                        row.get('fd_role') not in ('control', 'gpu') or
                        row.get('syscall_return') is not None or row.get('exit') is not None or
                        type(row.get('mmap_succeeded')) is not bool or
                        not isinstance(entry, dict) or set(entry) != {'length', 'prot', 'flags', 'offsetZero'} or
                        type(entry.get('length')) is not int or entry['length'] <= 0 or
                        type(entry.get('prot')) is not int or type(entry.get('flags')) is not int or
                        type(entry.get('offsetZero')) is not bool):
                        raise ValueError('mmap observation contains invalid or unredacted syscall metadata')
                for row in close_rows:
                    if (row.get('request') != 3 or row.get('packet_size') != 0 or
                        row.get('fd_role') not in ('control', 'gpu') or
                        row.get('entry') is not None or row.get('exit') is not None or
                        type(row.get('syscall_return')) is not int or
                        type(row.get('close_succeeded')) is not bool or
                        row.get('close_succeeded') != (row.get('syscall_return') == 0)):
                        raise ValueError('close observation contains invalid descriptor-lifecycle metadata')
                successful_mmaps = correlated_gpu_mmap_count(rows)
                report['map_memory_records_seen'] = bool(map_rows)
                report['map_memory_success_count'] = len(successful_maps)
                report['unmap_memory_success_count'] = len(successful_unmaps)
                report['map_memory_mmap_success_count'] = successful_mmaps
                report['map_memory_gpu_fd_close_count'] = sum(
                    row.get('fd_role') == 'gpu' and row.get('close_succeeded') is True
                    for row in close_rows)
                if (not map_rows or not unmap_rows or not successful_maps or
                    not successful_unmaps or any(row.get('fd_role') != 'control'
                                                 for row in map_rows + unmap_rows)):
                    raise ValueError('map/unmap observation has no complete successful control-to-GPU mapping pair')
                if not successful_mmaps:
                    raise ValueError('map observation contains no successful mmap on the mapped GPU descriptor')
        if requested_phase is not None:
            if requested_phase == 'system-pageable-memory':
                if (acceptance.get('phase_capture_requested') is not True or
                        acceptance.get('phase') != requested_phase or
                        acceptance.get('validation_errors') != [] or
                        not isinstance(phase_report, dict) or
                        set(phase_report) != {'schema', 'status', 'phase', 'expected_pci',
                                              'driver_library_path', 'driver_api', 'selected_device',
                                              'allocators', 'cleanup_passed', 'cleanup_errors', 'error'} or
                        phase_report.get('schema') != 'nvidia-cuda-system-pageable-memory-v1' or
                        phase_report.get('phase') != requested_phase or
                        canonical_pci(phase_report.get('expected_pci', '')) != pci or
                        not isinstance(phase_report.get('driver_library_path'), str) or
                        not phase_report['driver_library_path'].startswith('/') or
                        type(phase_report.get('driver_api')) is not int or
                        phase_report['driver_api'] <= 0 or
                        phase_report.get('cleanup_passed') is not True or
                        phase_report.get('cleanup_errors') != []):
                    raise ValueError('pageable-memory phase report differs from its selected-device contract')
                selected = phase_report.get('selected_device')
                if (not isinstance(selected, dict) or set(selected) != {
                        'name', 'pci_bus_id', 'sm', 'compute_capability',
                        'concurrent_managed_access', 'pageable_memory_access',
                        'pageable_memory_access_uses_host_page_tables', 'unified_addressing'} or
                        canonical_pci(selected.get('pci_bus_id', '')) != pci or
                        type(selected.get('sm')) is not int or selected.get('sm') != 120 or
                        selected.get('compute_capability') != '12.0' or
                        not isinstance(selected.get('name'), str) or
                        'RTX 5080' not in selected['name'] or
                        any(type(selected.get(key)) is not bool for key in (
                            'concurrent_managed_access', 'pageable_memory_access',
                            'pageable_memory_access_uses_host_page_tables', 'unified_addressing'))):
                    raise ValueError('pageable-memory phase is not the selected RTX 5080')
                if phase_report.get('status') == 'validated':
                    allocators = phase_report.get('allocators')
                    sizes_ok = isinstance(allocators, dict) and set(allocators) == {'malloc', 'mmap'}
                    if sizes_ok:
                        for name, mode in (('malloc', 'context-synchronized'),
                                           ('mmap', 'stream-synchronized')):
                            item = allocators.get(name)
                            if (not isinstance(item, dict) or set(item) != {
                                    'tested', 'passed', 'execution_mode', 'sizes'} or
                                    item.get('tested') is not True or item.get('passed') is not True or
                                    item.get('execution_mode') != mode or
                                    item.get('sizes') != [1, 31, 256, 4096, 65537] or
                                    any(type(size) is not int for size in item.get('sizes', []))):
                                sizes_ok = False
                                break
                    if (result.returncode != 0 or acceptance.get('exit_code') != 0 or
                            acceptance.get('qualification') != 'system-pageable-memory-report-contract-pass' or
                            phase_report.get('error') != '' or
                            selected.get('pageable_memory_access') is not True or
                            selected.get('unified_addressing') is not True or
                            not sizes_ok):
                        raise ValueError('pageable-memory direct-pointer kernel validation did not pass')
                    report['qualification'] = 'rtx5080-system-pageable-memory-report-contract-valid'
                    report['report_contract_validated'] = True
                    report['cuda_execution_validation_state'] = (
                        'isolated system-pageable-memory CUDA phase passed; '
                        'same-process multi-GPU execution is not validated')
                    code = 0
                elif phase_report.get('status') == 'unsupported':
                    reason = phase_report.get('error')
                    capability_absent = (
                        reason == 'device does not report pageable memory access' and
                        selected.get('pageable_memory_access') is False) or (
                        reason == 'device does not report unified addressing' and
                        selected.get('unified_addressing') is False)
                    if (result.returncode != 77 or acceptance.get('exit_code') != 77 or
                            acceptance.get('qualification') != 'system-pageable-memory-unsupported-report-contract-valid' or
                            phase_report.get('allocators') != {'malloc': None, 'mmap': None} or
                            not capability_absent):
                        raise ValueError('unsupported pageable-memory result is inconsistent')
                    report['qualification'] = 'rtx5080-system-pageable-memory-unsupported-report-contract-valid'
                    report['report_contract_validated'] = True
                    report['cuda_execution_validation_state'] = (
                        'isolated system-pageable-memory capability reported unsupported; '
                        'same-process multi-GPU execution is not validated')
                    code = 77
                else:
                    raise ValueError('pageable-memory phase did not pass or report unsupported')
                report['phase_report'] = phase_report
                report['phase'] = requested_phase
            else:
                if (result.returncode != 0 or acceptance.get('exit_code') != 0 or
                    acceptance.get('qualification') != 'phase-report-contract-pass' or
                    acceptance.get('phase_capture_requested') is not True or
                    acceptance.get('phase') != requested_phase or
                    acceptance.get('validation_errors') != [] or
                    not isinstance(phase_report, dict) or
                    phase_report.get('schema') != 'nvidia-cuda-driver-phase-v1' or
                    phase_report.get('status') != 'phase-passed' or
                    phase_report.get('phase') != requested_phase or
                    canonical_pci(phase_report.get('expected_pci', '')) != pci or
                    phase_report.get('cleanup_passed') is not True or
                    phase_report.get('cleanup_errors') != [] or phase_report.get('error') != ''):
                    raise ValueError('requested CUDA phase did not pass its selected-device report contract')
                selected = phase_report.get('selected_device')
                if requested_phase == 'initialize':
                    if selected is not None:
                        raise ValueError('initialize-only phase unexpectedly enumerated a GPU')
                elif (not isinstance(selected, dict) or
                      canonical_pci(selected.get('pci_bus_id', '')) != pci or
                      selected.get('sm') != 120 or 'RTX 5080' not in selected.get('name', '')):
                    raise ValueError('CUDA phase report does not match the selected RTX 5080')
                if requested_phase == 'managed-accessed-by':
                    trace = acceptance.get('ioctl_trace')
                    trace_meta = trace.get('trace') if isinstance(trace, dict) else None
                    summary = trace_meta.get('summary') if isinstance(trace_meta, dict) else None
                    if (not isinstance(trace_meta, dict) or trace_meta.get('trace_complete') is not True or
                            trace_meta.get('size_limit_exceeded') is not False or
                            not isinstance(summary, dict) or
                            summary.get('schema') != 'nvidia-hybrid-ioctl-metadata-summary-v2' or
                            summary.get('trace_complete') is not True or
                            summary.get('unparsed_lines') != [] or
                            summary.get('negative_syscall_returns') != 0 or
                            not isinstance(summary.get('calls'), list)):
                        raise ValueError('managed-accessed-by trace is missing, partial, or malformed')
                    uvm_calls = [row for row in summary['calls'] if isinstance(row, dict) and
                                 row.get('node') == '/dev/nvidia-uvm' and
                                 row.get('request') in ('0x2e', '0x2f')]
                    sets = [row for row in uvm_calls if row.get('request') == '0x2e']
                    unsets = [row for row in uvm_calls if row.get('request') == '0x2f']
                    if (len(sets) != 1 or not unsets or
                            type(sets[0].get('pid')) is not int or sets[0]['pid'] <= 0 or
                            type(sets[0].get('line')) is not int or
                            sets[0].get('syscall_return') != 0 or
                            any(type(row.get('pid')) is not int or row.get('pid') != sets[0]['pid'] or
                                type(row.get('line')) is not int or row.get('line') <= sets[0]['line'] or
                                row.get('syscall_return') != 0 for row in unsets)):
                        raise ValueError('UVM accessed-by SET/UNSET ioctls are not a successful same-process ordered pair')
                    report['managed_accessed_by_report_contract_passed'] = True
                    report['qualification'] = 'rtx5080-managed-accessed-by-report-contract-valid'
                else:
                    report['qualification'] = 'rtx5080-cuda-phase-report-contract-valid'
                report['phase_report'] = phase_report
                report['report_contract_validated'] = True
                report['cuda_execution_validation_state'] = (
                    f'isolated {requested_phase} CUDA phase passed; '
                    'same-process multi-GPU execution is not validated')
                code = 0
        else:
            acceptance_probe = acceptance.get('probe') or {}
            targeted = selected_device(acceptance_probe, pci)
            expected_memory_mode = 'managed' if managed_requested else 'device'
            if (acceptance_probe.get('memory_mode') != expected_memory_mode or
                targeted.get('managed_memory_passed') is not managed_requested):
                raise ValueError('managed-memory result differs from the requested mode')
            report['managed_memory_report_contract_passed'] = managed_requested
            if (acceptance_probe.get('managed_prefetch_requested') is not prefetch_requested or
                targeted.get('managed_prefetch_passed') is not prefetch_requested):
                raise ValueError('managed-prefetch result differs from the requested mode')
            report['managed_prefetch_report_contract_passed'] = prefetch_requested
            if (acceptance_probe.get('cuda_graphs_requested') is not cuda_graphs_requested or
                targeted.get('cuda_graphs_passed') is not cuda_graphs_requested or
                targeted.get('cuda_graph_launches') != (2 if cuda_graphs_requested else 0)):
                raise ValueError('CUDA Graph result differs from the requested mode')
            report['cuda_graphs_report_contract_passed'] = cuda_graphs_requested
            if (acceptance_probe.get('performance_benchmark_requested', False) is not
                    performance_benchmark_requested or
                    (performance_benchmark_requested and
                     targeted.get('performance_benchmark_passed') is not True) or
                    (not performance_benchmark_requested and
                     targeted.get('performance_benchmark_passed', False) is not False)):
                raise ValueError('performance benchmark result differs from the request')
            if performance_benchmark_requested:
                benchmark = targeted.get('performance_benchmark')
                if (not isinstance(benchmark, dict) or
                        benchmark.get('samples') != benchmark_samples or
                        benchmark.get('transfer_samples', benchmark_transfer_samples) !=
                        benchmark_transfer_samples or
                        any(row.get('samples') != benchmark_transfer_samples
                            for row in benchmark.get('transfers', [])
                            if isinstance(row, dict))):
                    raise ValueError('performance benchmark sample count differs from the request')
            report['performance_benchmark_report_contract_passed'] = performance_benchmark_requested
            probe = acceptance['probe']
            if (result.returncode != 77 or acceptance.get('exit_code') != 77 or
                acceptance.get('qualification') != 'incomplete-hardware-missing' or
                acceptance.get('validation_errors') != [] or
                probe.get('hybrid_validated') is not False or probe.get('missing_sm') != [70] or
                probe.get('required_sm') != [70, 120]):
                raise ValueError('RTX-only result is not a truthful incomplete hybrid acceptance')
            report['qualification'] = 'rtx5080-report-contract-valid-hybrid-incomplete'
            report['report_contract_validated'] = True
            code = 77
    except Exception as error:
        report['qualification'] = 'failed'
        report['error'] = str(error)
        code = 2
    # Preserve the complete workspace when evidence is inconsistent or the run fails.
    if 'artifacts_before' in report:
        report['artifacts_after'] = {}
        for name, item in report['artifacts_before'].items():
            try:
                data = Path(item['path']).read_bytes()
                report['artifacts_after'][name] = {"path": item['path'], "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            except OSError as error:
                report['artifacts_after'][name] = {"error": str(error)}
        if report['artifacts_after'] != report['artifacts_before']:
            report['qualification'], report['error'], code = 'failed', 'artifacts changed during execution', 2
    if report.get('qualification') == 'failed':
        report['remote_work_cleanup'] = {
            'attempted': False, 'passed': False, 'removed': False,
            'retained_for_inspection': 'remote_work_directory' in report,
        }
    elif 'remote_work_directory' in report:
        report['remote_work_cleanup'] = {
            'attempted': True, 'passed': False, 'removed': False,
            'retained_for_inspection': False,
        }
        try:
            workspace = Path(report['remote_work_directory'])
            temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
            workspace_stat = workspace.lstat()
            if (not workspace.name.startswith('hybrid-rtx5080-') or
                    workspace.parent.resolve(strict=True) != temp_root or
                    not stat.S_ISDIR(workspace_stat.st_mode) or
                    stat.S_ISLNK(workspace_stat.st_mode) or
                    workspace_stat.st_uid != os.geteuid() or
                    workspace_stat.st_mode & 0o077):
                raise ValueError('workspace identity or private permissions changed')
            shutil.rmtree(workspace)
            if workspace.exists():
                raise OSError('workspace still exists after removal')
        except Exception as error:
            report['remote_work_cleanup'] = {
                'attempted': True, 'passed': False, 'removed': False,
                'retained_for_inspection': Path(report['remote_work_directory']).exists(),
            }
            report['qualification'] = 'failed'
            report['error'] = 'remote temporary workspace cleanup failed: ' + type(error).__name__
            code = 2
        else:
            report['remote_work_cleanup'] = {
                'attempted': True, 'passed': True, 'removed': True,
                'retained_for_inspection': False,
            }
    report['exit_code'] = code
    return report, code

if __name__ == '__main__':
    report, code = run(json.load(sys.stdin))
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(code)
'''

def identity(path):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'base64': base64.b64encode(data).decode('ascii')}


def pinned_acceptance_artifact(name, path):
    expected = next((digest for artifact_name, _, digest in PINNED_ACCEPTANCE_ARTIFACTS
                     if artifact_name == name), None)
    if expected is None:
        raise ValueError(f'no independent pin is defined for acceptance artifact {name}')
    artifact = identity(path)
    if artifact['sha256'] != expected:
        raise ValueError(f'{name} hash differs from its independent acceptance pin')
    return artifact


def transport_exit_code(remote_code, phase_requested=False):
    """Keep successful isolated phases successful without upgrading hybrid runs."""
    if phase_requested and remote_code == 0:
        return 0
    return remote_code if remote_code in (2, 77) else 2


def expected_remote_qualification(phase, remote_code):
    """Return the only report qualification valid for this requested operation/result."""
    return REMOTE_QUALIFICATION_BY_PHASE_AND_EXIT.get(phase, {}).get(remote_code)


def remote_script_command(script: str = REMOTE_SCRIPT) -> str:
    """Build a short remote python command; send source size through the SSH stdin channel."""
    source = script.encode('utf-8')
    compressed_b64 = base64.b64encode(zlib.compress(source, level=9)).decode('ascii')
    expected_sha256 = hashlib.sha256(source).hexdigest()
    bootstrap = (
        'import base64,hashlib,zlib;'
        f'_s=zlib.decompress(base64.b64decode({compressed_b64!r}));'
        f'assert hashlib.sha256(_s).hexdigest()=={expected_sha256!r};'
        "exec(compile(_s,'<nvidia-hybrid-remote>','exec'))"
    )
    return 'python3 -c ' + shlex.quote(bootstrap)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--host-key-alias', required=True)
    parser.add_argument('--identity-file', type=Path,
                        help='optional private SSH identity inside ~/.ssh; restricted to pc3@pc3')
    parser.add_argument('--gpu-uuid', required=True)
    parser.add_argument('--pci', required=True, type=canonical_pci)
    parser.add_argument('--probe', required=True, type=Path)
    parser.add_argument('--module', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--ioctl-observer', type=Path)
    parser.add_argument('--gpu-id-info', action='store_true',
                        help='with --ioctl-observer, capture the fixed GPU_GET_ID_INFO_V2 payload')
    parser.add_argument('--attached-ids', action='store_true',
                        help='with --ioctl-observer, capture the fixed GPU_GET_ATTACHED_IDS payload')
    parser.add_argument('--probed-ids', action='store_true',
                        help='with --ioctl-observer, capture the fixed GPU_GET_PROBED_IDS payload')
    parser.add_argument('--rm-control', action='store_true',
                        help='with --ioctl-observer, capture fixed NVOS54 RM_CONTROL headers only')
    parser.add_argument('--rm-control-headers', action='store_true',
                        help='with --phase enumerate, capture all RM_CONTROL headers with handles redacted')
    parser.add_argument('--p2p-control', action='store_true',
                        help='with --rm-control, capture redacted fixed NV503C P2P control payloads')
    parser.add_argument('--binapi-control', action='store_true',
                        help='with --rm-control, capture only redacted shape metadata for the fixed 992-byte NV2081_BINAPI payload')
    parser.add_argument('--device-alloc-capture', action='store_true',
                        help='capture fixed, redacted NV0080_ALLOC_PARAMETERS for NV01_DEVICE_0')
    parser.add_argument('--subdevice-alloc-capture', action='store_true',
                        help='capture only fixed, redacted NV2080_ALLOC_PARAMETERS subDeviceId')
    parser.add_argument('--binapi-alloc-capture', action='store_true',
                        help='capture only the optional, redacted NV2081_ALLOC_PARAMETERS reserved-zero predicate')
    parser.add_argument('--gt200-debugger-alloc-capture', action='store_true',
                        help='capture only fixed, redacted GT200_DEBUGGER allocation handle relations')
    parser.add_argument('--gt200-debugger-lifecycle-capture', action='store_true',
                        help='capture redacted GT200_DEBUGGER allocations, frees, and fixed control headers')
    parser.add_argument('--channel-alloc', action='store_true',
                        help='with --ioctl-observer, capture redacted fixed GPFIFO allocation fields')
    parser.add_argument('--rusd-alloc', action='store_true',
                        help='with --ioctl-observer, capture only the redacted RM_USER_SHARED_DATA polling mask')
    parser.add_argument('--map-memory', action='store_true',
                        help='with --ioctl-observer, capture redacted R580 map and unmap status')
    parser.add_argument('--ioctl-trace', action='store_true',
                        help='trace ioctls; with --phase enumerate, also capture redacted NVIDIA node-open lifecycle')
    parser.add_argument('--managed-memory', action='store_true',
                        help='run and verify the selected RTX 5080 kernel path using cuMemAllocManaged')
    parser.add_argument('--managed-prefetch', action='store_true',
                        help='with --managed-memory, prefetch test ranges to the GPU and CPU')
    parser.add_argument('--cuda-graphs', action='store_true',
                        help='run two opt-in CUDA Graph replays of the numeric kernel on the RTX 5080')
    parser.add_argument('--benchmark', action='store_true',
                        help='run isolated per-device launch and pinned-copy timings')
    parser.add_argument('--benchmark-samples', type=int,
                        help='samples per launch and transfer size (9..1001); requires --benchmark')
    parser.add_argument('--expected-libcuda-sha256',
                        help='require the exact system libcuda hash before CUDA preflight and verify its path after the run')
    parser.add_argument('--phase', choices=('initialize', 'enumerate', 'context', 'allocation', 'module', 'kernel', 'system-pageable-memory', 'managed-accessed-by'),
                        help='run one isolated CUDA Driver API phase; managed-accessed-by requires its bounded UVM ioctl trace')
    args = parser.parse_args(argv)
    if args.benchmark_samples is not None and (
            type(args.benchmark_samples) is not int or
            not 9 <= args.benchmark_samples <= 1001 or not args.benchmark):
        parser.error('--benchmark-samples must be 9..1001 and requires --benchmark')
    if args.benchmark and (
            args.phase or args.managed_memory or args.managed_prefetch or args.cuda_graphs or
            args.ioctl_observer is not None or args.gpu_id_info or args.attached_ids or
            args.probed_ids or args.rm_control or args.rm_control_headers or args.p2p_control or
            args.binapi_control or args.device_alloc_capture or args.subdevice_alloc_capture or
            args.binapi_alloc_capture or args.gt200_debugger_alloc_capture or args.gt200_debugger_lifecycle_capture or args.channel_alloc or args.map_memory or
            args.rusd_alloc or args.ioctl_trace):
        parser.error('--benchmark must run by itself on the selected PCI device')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+', args.target):
        parser.error('target must be a literal user@host')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', args.host_key_alias) or args.host_key_alias.startswith('-'):
        parser.error('invalid host key alias')
    if args.identity_file is not None:
        if args.target != 'pc3@pc3' or args.host_key_alias != 'pc3':
            parser.error('--identity-file is restricted to the pinned PC3 route')
        try:
            args.identity_file = validate_direct_identity_file(args.identity_file)
        except ValueError as error:
            parser.error(str(error))
    if not re.fullmatch(r'GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', args.gpu_uuid):
        parser.error('a full GPU UUID is required')
    if (args.expected_libcuda_sha256 is not None and
            not re.fullmatch(r'[0-9a-f]{64}', args.expected_libcuda_sha256)):
        parser.error('--expected-libcuda-sha256 must be 64 lowercase hexadecimal characters')
    if args.evidence.exists():
        parser.error('evidence destination already exists')
    if args.ioctl_trace and args.ioctl_observer is not None:
        parser.error('--ioctl-trace and --ioctl-observer are separate capture modes')
    if args.gpu_id_info and args.ioctl_observer is None:
        parser.error('--gpu-id-info requires --ioctl-observer')
    if args.attached_ids and args.ioctl_observer is None:
        parser.error('--attached-ids requires --ioctl-observer')
    if args.probed_ids and args.ioctl_observer is None:
        parser.error('--probed-ids requires --ioctl-observer')
    if args.rm_control and args.ioctl_observer is None:
        parser.error('--rm-control requires --ioctl-observer')
    if args.rm_control_headers and args.ioctl_observer is None:
        parser.error('--rm-control-headers requires --ioctl-observer')
    if args.rm_control_headers and args.phase != 'enumerate':
        parser.error('--rm-control-headers requires --phase enumerate')
    if args.p2p_control and args.ioctl_observer is None:
        parser.error('--p2p-control requires --ioctl-observer')
    if args.p2p_control and not args.rm_control:
        parser.error('--p2p-control requires --rm-control')
    if args.binapi_control and args.ioctl_observer is None:
        parser.error('--binapi-control requires --ioctl-observer')
    if args.binapi_control and not args.rm_control:
        parser.error('--binapi-control requires --rm-control')
    if args.device_alloc_capture and args.ioctl_observer is None:
        parser.error('--device-alloc-capture requires --ioctl-observer')
    if args.subdevice_alloc_capture and args.ioctl_observer is None:
        parser.error('--subdevice-alloc-capture requires --ioctl-observer')
    if args.binapi_alloc_capture and args.ioctl_observer is None:
        parser.error('--binapi-alloc-capture requires --ioctl-observer')
    if args.gt200_debugger_alloc_capture and args.ioctl_observer is None:
        parser.error('--gt200-debugger-alloc-capture requires --ioctl-observer')
    if args.gt200_debugger_alloc_capture and args.phase != 'context':
        parser.error('--gt200-debugger-alloc-capture requires --phase context')
    if args.gt200_debugger_alloc_capture and any((args.ioctl_trace, args.gpu_id_info,
            args.attached_ids, args.probed_ids, args.rm_control, args.rm_control_headers,
            args.p2p_control, args.binapi_control, args.device_alloc_capture,
            args.subdevice_alloc_capture, args.binapi_alloc_capture, args.channel_alloc,
            args.map_memory, args.rusd_alloc, args.managed_memory, args.managed_prefetch,
            args.cuda_graphs)):
        parser.error('--gt200-debugger-alloc-capture is an isolated observer mode')
    if args.gt200_debugger_lifecycle_capture and args.ioctl_observer is None:
        parser.error('--gt200-debugger-lifecycle-capture requires --ioctl-observer')
    if args.gt200_debugger_lifecycle_capture and args.phase != 'context':
        parser.error('--gt200-debugger-lifecycle-capture requires --phase context')
    if args.gt200_debugger_lifecycle_capture and any((args.gt200_debugger_alloc_capture,
            args.ioctl_trace, args.gpu_id_info, args.attached_ids, args.probed_ids,
            args.rm_control, args.rm_control_headers, args.p2p_control, args.binapi_control,
            args.device_alloc_capture, args.subdevice_alloc_capture, args.binapi_alloc_capture,
            args.channel_alloc, args.map_memory, args.rusd_alloc, args.managed_memory,
            args.managed_prefetch, args.cuda_graphs)):
        parser.error('--gt200-debugger-lifecycle-capture is an isolated observer mode')
    if args.device_alloc_capture and (args.subdevice_alloc_capture or any((args.ioctl_trace, args.gpu_id_info,
            args.attached_ids, args.probed_ids, args.rm_control, args.p2p_control,
            args.binapi_control, args.channel_alloc, args.map_memory, args.rusd_alloc,
            args.managed_memory, args.managed_prefetch))):
        parser.error('--device-alloc-capture is an isolated observer mode')
    if args.subdevice_alloc_capture and any((args.ioctl_trace, args.gpu_id_info,
            args.attached_ids, args.probed_ids, args.rm_control, args.p2p_control,
            args.binapi_control, args.device_alloc_capture, args.channel_alloc,
            args.map_memory, args.rusd_alloc, args.managed_memory, args.managed_prefetch)):
        parser.error('--subdevice-alloc-capture is an isolated observer mode')
    if args.binapi_alloc_capture and any((args.ioctl_trace, args.gpu_id_info,
            args.attached_ids, args.probed_ids, args.rm_control, args.p2p_control,
            args.binapi_control, args.device_alloc_capture, args.subdevice_alloc_capture,
            args.channel_alloc, args.map_memory, args.rusd_alloc, args.managed_memory,
            args.managed_prefetch)):
        parser.error('--binapi-alloc-capture is an isolated observer mode')
    if args.channel_alloc and args.ioctl_observer is None:
        parser.error('--channel-alloc requires --ioctl-observer')
    if args.map_memory and args.ioctl_observer is None:
        parser.error('--map-memory requires --ioctl-observer')
    if args.rusd_alloc and args.ioctl_observer is None:
        parser.error('--rusd-alloc requires --ioctl-observer')
    if args.channel_alloc and (args.gpu_id_info or args.attached_ids or args.probed_ids or
                               args.rm_control or args.rusd_alloc):
        parser.error('--channel-alloc must run separately from other captures')
    if args.map_memory and (args.gpu_id_info or args.attached_ids or args.probed_ids or
                            args.rm_control or args.channel_alloc):
        parser.error('--map-memory may combine only with --rusd-alloc')
    if args.rusd_alloc and (args.gpu_id_info or args.attached_ids or args.probed_ids or
                            args.rm_control or args.channel_alloc or
                            args.ioctl_trace or args.managed_memory or args.managed_prefetch):
        parser.error('--rusd-alloc may combine only with --map-memory')
    if args.p2p_control and (args.ioctl_trace or args.gpu_id_info or args.attached_ids or
                             args.probed_ids or args.channel_alloc or args.map_memory or
                             args.rusd_alloc or args.managed_memory or args.managed_prefetch or
                             args.binapi_control):
        parser.error('--p2p-control must be isolated with --rm-control')
    if args.binapi_control and (args.ioctl_trace or args.gpu_id_info or args.attached_ids or
                                args.probed_ids or args.p2p_control or args.channel_alloc or
                                args.map_memory or args.rusd_alloc or args.managed_memory or
                                args.managed_prefetch):
        parser.error('--binapi-control must be isolated with --rm-control')
    if args.managed_prefetch and not args.managed_memory:
        parser.error('--managed-prefetch requires --managed-memory')
    enumerate_node_trace = args.phase == 'enumerate' and args.ioctl_trace
    managed_accessed_by_trace = args.phase == 'managed-accessed-by' and args.ioctl_trace
    enumerate_rm_control_headers = args.phase == 'enumerate' and args.rm_control_headers
    system_pageable_phase = args.phase == 'system-pageable-memory'
    if args.phase == 'managed-accessed-by' and not args.ioctl_trace:
        parser.error('--phase managed-accessed-by requires --ioctl-trace')
    if managed_accessed_by_trace and (args.ioctl_observer is not None or args.gpu_id_info or
            args.attached_ids or args.probed_ids or args.rm_control or args.rm_control_headers or
            args.p2p_control or args.binapi_control or args.device_alloc_capture or
            args.subdevice_alloc_capture or args.binapi_alloc_capture or args.channel_alloc or
            args.map_memory or args.rusd_alloc or args.managed_memory or args.managed_prefetch or
            args.cuda_graphs):
        parser.error('--phase managed-accessed-by --ioctl-trace must be the only capture mode')
    if system_pageable_phase and (args.ioctl_observer is not None or args.ioctl_trace or
            args.gpu_id_info or args.attached_ids or args.probed_ids or args.rm_control or
            args.rm_control_headers or args.p2p_control or args.binapi_control or
            args.device_alloc_capture or args.subdevice_alloc_capture or
            args.binapi_alloc_capture or args.gt200_debugger_lifecycle_capture or args.channel_alloc or args.map_memory or
            args.rusd_alloc or args.managed_memory or args.managed_prefetch or args.cuda_graphs):
        parser.error('--phase system-pageable-memory must be an isolated numeric kernel run')
    if enumerate_node_trace and (args.ioctl_observer is not None or args.gpu_id_info or
            args.attached_ids or args.probed_ids or args.rm_control or args.rm_control_headers or args.p2p_control or
            args.binapi_control or args.device_alloc_capture or args.subdevice_alloc_capture or
            args.binapi_alloc_capture or args.gt200_debugger_lifecycle_capture or args.channel_alloc or args.rusd_alloc or
            args.map_memory or args.managed_memory or args.managed_prefetch or args.cuda_graphs):
        parser.error('--phase enumerate --ioctl-trace must be the only capture mode')
    if enumerate_rm_control_headers and (args.ioctl_observer is None or
            args.gpu_id_info or args.attached_ids or args.probed_ids or args.rm_control or
            args.p2p_control or args.binapi_control or args.device_alloc_capture or
            args.subdevice_alloc_capture or args.binapi_alloc_capture or args.channel_alloc or
            args.rusd_alloc or args.map_memory or args.ioctl_trace or args.managed_memory or
            args.managed_prefetch or args.cuda_graphs):
        parser.error('--phase enumerate --rm-control-headers must be the only capture mode')
    if args.phase and not (enumerate_node_trace or enumerate_rm_control_headers or system_pageable_phase or managed_accessed_by_trace) and (args.ioctl_observer is None or
                       sum((args.binapi_control, args.device_alloc_capture,
                            args.subdevice_alloc_capture, args.binapi_alloc_capture,
                            args.gt200_debugger_alloc_capture,
                            args.gt200_debugger_lifecycle_capture)) != 1 or
                       (args.binapi_control and not args.rm_control) or
                       args.ioctl_trace or args.gpu_id_info or
                       args.attached_ids or args.probed_ids or args.p2p_control or
                       args.channel_alloc or args.map_memory or args.rusd_alloc or
                       args.managed_memory or args.managed_prefetch or args.cuda_graphs):
        parser.error('--phase requires exactly one isolated BINAPI, NV01_DEVICE_0, NV20_SUBDEVICE_0, or NV2081_BINAPI allocation observer capture')
    sidecar = args.evidence.with_suffix(args.evidence.suffix + '.strace.gz')
    if args.ioctl_trace and sidecar.exists():
        parser.error('trace sidecar destination already exists')
    try:
        for name, relative_path, _ in PINNED_ACCEPTANCE_ARTIFACTS:
            pinned_acceptance_artifact(name, ROOT / relative_path)
    except (OSError, ValueError) as error:
        parser.error(f'acceptance input provenance check failed: {error}')
    return args


def main(argv=None):
    args = parse_args(argv)
    effective_benchmark_samples = (args.benchmark_samples
                                   if args.benchmark_samples is not None
                                   else (9 if args.benchmark else None))
    effective_benchmark_transfer_samples = (args.benchmark_samples
                                            if args.benchmark_samples is not None
                                            else (7 if args.benchmark else None))
    payload = {'pci': args.pci, 'uuid': args.gpu_uuid,
               'remote_script_sha256': hashlib.sha256(REMOTE_SCRIPT.encode()).hexdigest(),
               'ioctl_trace': args.ioctl_trace,
               'gpu_id_info_capture': args.gpu_id_info,
              'attached_ids_capture': args.attached_ids,
               'probed_ids_capture': args.probed_ids,
              'rm_control_capture': args.rm_control,
              'rm_control_headers_capture': args.rm_control_headers,
              'p2p_control_capture': args.p2p_control,
              'binapi_control_capture': args.binapi_control,
              'device_alloc_capture': args.device_alloc_capture,
              'subdevice_alloc_capture': args.subdevice_alloc_capture,
              'binapi_alloc_capture': args.binapi_alloc_capture,
              'gt200_debugger_alloc_capture': args.gt200_debugger_alloc_capture,
              'gt200_debugger_lifecycle_capture': args.gt200_debugger_lifecycle_capture,
              'channel_alloc_capture': args.channel_alloc,
              'rusd_alloc_capture': args.rusd_alloc,
              'map_memory_capture': args.map_memory,
               'managed_memory': args.managed_memory,
              'managed_prefetch': args.managed_prefetch,
              'cuda_graphs': args.cuda_graphs,
              'performance_benchmark': args.benchmark,
              **({'benchmark_samples': args.benchmark_samples}
                 if args.benchmark_samples is not None else {}),
               'expected_libcuda_sha256': args.expected_libcuda_sha256,
               'phase': args.phase,
               'artifacts': {name: identity(path) for name, path in
                             [('probe', args.probe), ('module', args.module)]}}
    for name, relative_path, _ in PINNED_ACCEPTANCE_ARTIFACTS:
        payload['artifacts'][name] = pinned_acceptance_artifact(name, ROOT / relative_path)
    if args.ioctl_trace:
        payload['artifacts']['trace-helper'] = identity(ROOT / 'tools/summarize_rm_ioctl_trace.py')
    if args.ioctl_observer is not None:
        payload['artifacts']['observer'] = identity(args.ioctl_observer)
    command = ['ssh', '-F', '/dev/null']
    if args.identity_file is not None:
        command += ['-i', str(args.identity_file), '-o', 'IdentitiesOnly=yes',
                    '-o', 'PreferredAuthentications=publickey',
                    '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no']
    command += ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
               '-o', 'HostKeyAlias=' + args.host_key_alias, '--', args.target,
               remote_script_command()]
    report = {'schema': 'nvidia-hybrid-remote-selected-gpu-transport-v1',
              'observed_at_utc': datetime.now(timezone.utc).isoformat(),
              'report_contract_validated': False,
              'cuda_execution_validated': False,
              'cuda_execution_validation_state': 'not-established; probe build identity is not trusted',
              'target': args.target, 'host_key_alias': args.host_key_alias,
              'ssh_identity_file_basename': (args.identity_file.name
                                             if args.identity_file is not None else None),
              'memory_mode': 'managed' if args.managed_memory else 'device',
              'gpu_id_info_capture_requested': args.gpu_id_info,
              'attached_ids_capture_requested': args.attached_ids,
              'probed_ids_capture_requested': args.probed_ids,
              'rm_control_capture_requested': args.rm_control,
              'rm_control_headers_capture_requested': args.rm_control_headers,
              'rm_control_headers_records_seen': None,
              'rm_control_headers_record_count': None,
              'p2p_control_capture_requested': args.p2p_control,
              'binapi_control_capture_requested': args.binapi_control,
              'device_alloc_capture_requested': args.device_alloc_capture,
              'subdevice_alloc_capture_requested': args.subdevice_alloc_capture,
              'binapi_alloc_capture_requested': args.binapi_alloc_capture,
              'gt200_debugger_alloc_capture_requested': args.gt200_debugger_alloc_capture,
              'gt200_debugger_alloc_records_seen': None,
              'gt200_debugger_alloc_payload_snapshots_read': None,
              'gt200_debugger_lifecycle_capture_requested': args.gt200_debugger_lifecycle_capture,
              'gt200_debugger_lifecycle': None,
              'channel_alloc_capture_requested': args.channel_alloc,
              'rusd_alloc_capture_requested': args.rusd_alloc,
              'map_memory_capture_requested': args.map_memory,
              'managed_prefetch_requested': args.managed_prefetch,
              'cuda_graphs_requested': args.cuda_graphs,
              'performance_benchmark_requested': args.benchmark,
              'benchmark_samples': effective_benchmark_samples,
              'benchmark_transfer_samples': effective_benchmark_transfer_samples,
              'expected_libcuda_sha256': args.expected_libcuda_sha256,
              'phase_capture_requested': args.phase is not None,
              'phase': args.phase,
              'ssh_argv': command, 'tool': {key: value for key, value in identity(__file__).items() if key != 'base64'},
              'remote_script_sha256': payload['remote_script_sha256'],
              'local_artifacts': {name: {key: value for key, value in item.items() if key != 'base64'}
                                  for name, item in payload['artifacts'].items()}}
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    # Reserve the new evidence destination before any remote operation.
    descriptor = os.open(args.evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        validate_pinned_probe_artifacts(payload['artifacts'])
        report['probe_contract'] = validate_probe_contract(
            args.probe,
            expected_sha256=payload['artifacts']['probe']['sha256'],
            invoke=subprocess.run,
            require_performance_benchmark=args.benchmark,
            require_exact_device_map=True,
        )
        result = subprocess.run(command, input=json.dumps(payload), text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=190 if args.ioctl_trace else 140, check=False)
        report.update({'ssh_exit_code': result.returncode, 'ssh_stderr': result.stderr})
        if args.ioctl_trace:
            stdout_bytes = result.stdout.encode()
            report['ssh_stdout_sha256'] = hashlib.sha256(stdout_bytes).hexdigest()
            report['ssh_stdout_bytes'] = len(stdout_bytes)
            # Trace-mode stdout can contain a base64 encoding of the private raw
            # trace. Retain only its digest and size before parsing any JSON so
            # malformed responses cannot leak the transport into evidence.
            report['ssh_stdout'] = ''
        else:
            report['ssh_stdout'] = result.stdout
        remote = json.loads(result.stdout)
        if not isinstance(remote, dict):
            raise ValueError('remote result must be a JSON object')
        if ('report_contract_validated' in remote and
                type(remote['report_contract_validated']) is not bool):
            raise ValueError('remote report-contract status must be boolean')
        if 'qualification' in remote and not isinstance(remote['qualification'], str):
            raise ValueError('remote qualification must be a string')
        if type(remote.get('exit_code')) is not int:
            raise ValueError('remote exit status must be an integer')
        if args.ioctl_trace:
            transport = remote.pop('ioctl_trace_transport', None)
            try:
                acceptance = remote.get('hardware_acceptance') or {}
                trace = acceptance.get('ioctl_trace') or {}
                trace_meta = trace.get('trace') or {}
                compressed = base64.b64decode(transport['gzip_base64'], validate=True)
                summary_helper = importlib.util.spec_from_file_location(
                    'trace_summary_local', ROOT / 'tools/summarize_rm_ioctl_trace.py')
                summary_module = importlib.util.module_from_spec(summary_helper)
                summary_helper.loader.exec_module(summary_module)
                sidecar = args.evidence.with_suffix(args.evidence.suffix + '.strace.gz')
                summary_fn = (summary_module.summarize_node_open_trace
                              if args.phase == 'enumerate' else None)
                trace_artifact = summary_module.write_trace_sidecar(
                    sidecar, compressed, transport, trace_meta['summary'], require_complete=False,
                    summary_fn=summary_fn)
                remote['ioctl_trace_artifact'] = trace_artifact
                if (trace_meta.get('trace_complete') is not True or
                        trace_artifact.get('summary', {}).get('trace_complete') is not True):
                    raise ValueError('captured ioctl trace is incomplete')
                if args.phase == 'enumerate':
                    summary = trace_meta['summary']
                    events = summary.get('events')
                    control_open = any(isinstance(row, dict) and row.get('operation') == 'open' and
                                       row.get('node') == 'nvidiactl' and row.get('succeeded') is True
                                       for row in events) if isinstance(events, list) else False
                    if (summary.get('schema') != 'nvidia-hybrid-node-open-trace-v1' or
                            summary.get('descriptor_lifecycle_scope') !=
                            'selected node descriptors only; ioctl payloads and syscall arguments omitted' or
                            not control_open or
                            summary.get('ioctl_counts_by_node', {}).get('nvidiactl', 0) < 1):
                        raise ValueError('enumeration trace lacks a successful nvidiactl open and ioctl')
            except (KeyError, TypeError, ValueError, OSError, AttributeError) as error:
                report['ioctl_trace_error'] = str(error)
                code = 2
            else:
                code = transport_exit_code(result.returncode, args.phase is not None)
        else:
            code = transport_exit_code(result.returncode, args.phase is not None)
        report['remote'] = remote
        remote_script_sha256 = remote.get('remote_script_sha256')
        if (not isinstance(remote_script_sha256, str) or
                not re.fullmatch(r'[0-9a-f]{64}', remote_script_sha256) or
                remote_script_sha256 != payload['remote_script_sha256'] or
                remote['exit_code'] != result.returncode):
            raise ValueError('remote script identity or exit status mismatch')
        expected_qualification = expected_remote_qualification(args.phase, result.returncode)
        report['report_contract_validated'] = (
            code == result.returncode and
            expected_qualification is not None and
            remote.get('report_contract_validated') is True and
            remote.get('qualification') == expected_qualification)
        report['cuda_execution_validated'] = False
        report['cuda_execution_validation_state'] = LOCAL_CUDA_EXECUTION_VALIDATION_STATE
        if (result.returncode in (0, 77) and not report['report_contract_validated']):
            raise ValueError('remote result lacks a supported, validated report qualification')
        if (remote.get('report_contract_validated') is True and
                not report['report_contract_validated']):
            raise ValueError('remote result lacks a supported, validated report qualification')
        report['local_artifacts_after'] = {name: {key: value for key, value in identity(item['path']).items() if key != 'base64'}
                                           for name, item in payload['artifacts'].items()}
        if report['local_artifacts_after'] != report['local_artifacts']:
            raise ValueError('local artifacts changed during execution')
        report['qualification'] = (remote['qualification']
                                   if report['report_contract_validated'] else 'failed')
        report['exit_code'] = code
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        report.update({'qualification': 'failed', 'report_contract_validated': False,
                       'cuda_execution_validated': False, 'error': str(error), 'exit_code': 2})
        code = 2
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'evidence': str(args.evidence), 'exit_code': code}))
    return code

if __name__ == '__main__':
    raise SystemExit(main())
