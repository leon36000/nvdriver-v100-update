#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the BDF-selected GPU-file frontend against both private backend symvers.

Never loads/installs modules or registers a device. Module insertion, if later
explicitly authorized, would load dependencies and initialize their RM globals.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
# Use the newest compiled providers that cover the current exact frontend ABI,
# including the mirrored client-share and sync-boost operations. R595 OpenRM
# is the modern backend; the same-version R580.196.07 pair is the Volta ABI.
OPEN = ROOT / 'build/experiments/r595-debugger-bridge-provider-build-v4-20261101/source'
LEGACY = ROOT / 'build/experiments/r58019607-debugger-bridge-provider-build-v3-20261101/source'
OPEN_R580 = (ROOT / 'build/experiments/r58019607-sync-boost-open-build-v1/private'
             / 'NVIDIA-kernel-module-source-580.196.07')
LEGACY_R580 = LEGACY
SHARED_BACKEND_API_HEADERS = (
    'hybrid580-file-projection.h',
    'hybrid580-gpu-catalog.h',
)
# These headers describe backend-specific implementations. In particular,
# control-session methods intentionally differ by architecture (for example,
# R580-only NV503C P2P methods), while the frontend compiles against the
# project's union API. Imported module-version CRCs below validate every
# actually linked declaration against its selected provider.
BACKEND_SPECIFIC_API_HEADERS = (
    'hybrid580-control-session.h',
    'hybrid580-gpu-session.h',
)
FAIL_CLOSED_UVM_APIS = frozenset({
    'nvUvmInterfacePagingChannelAllocate',
    'nvUvmInterfacePagingChannelDestroy',
    'nvUvmInterfacePagingChannelsMap',
    'nvUvmInterfacePagingChannelsUnmap',
    'nvUvmInterfacePagingChannelPushStream',
})
R595_OPEN_ONLY_UVM_APIS = frozenset({
    'nvUvmInterfaceAccessBitsBufAlloc',
    'nvUvmInterfaceAccessBitsBufFree',
    'nvUvmInterfaceAccessBitsDump',
})
HYBRID_ONLY_UVM_APIS = frozenset({
    # This dispatcher is implemented by the hybrid bridge itself. Neither
    # private RM provider owns a control-fd-aware import entrypoint.
    'nvUvmInterfaceDupMemoryWithControlFd',
    'nvUvmInterfaceDupAddressSpaceWithControlFd',
    'nvUvmInterfaceAreGpuProvidersSame',
    'nvUvmInterfaceGetGpuProvider',
})
FRONTEND_SOURCES = (
    'hybrid_frontend.c', 'rm_root_client.c', 'rm_root_client.h',
    'hybrid580_uvm_callback_bridge.c', 'hybrid580_uvm_callback_bridge.h',
    'hybrid580_uvm_abi_compat.h', 'hybrid580_uvm_event_compat.h',
    'hybrid580_uvm_session_pair.h', 'hybrid580_uvm_owner_map.h',
    'hybrid580_uvm_gpu_registry.h', 'hybrid580_uvm_gpu_route.h',
    'hybrid580_uvm_device_route.h',
    'hybrid580_uvm_address_space_route.h',
    'hybrid580_uvm_dup_memory_route.h',
    'hybrid580_uvm_control_fd_dispatch.h',
    'hybrid580_uvm_provider_dispatch.h',
    'hybrid580_uvm_pma_route.h',
    'hybrid580_uvm_external_mapping_route.h',
    'hybrid580_uvm_info_registry.h',
    'hybrid580_frontend_uvm_memory_owner.h',
    'hybrid580_frontend_uvm_address_space_owner.h',
    'rm_session_endpoint.h', 'hybrid580_ioctl.h',
    'hybrid580-gpu-catalog.h', 'hybrid580-gpu-catalog.c',
    'hybrid580-control-session.h', 'hybrid580-open-build-version.h',
    'hybrid580-device-instance-map.h',
    'hybrid580-device-instance-map.c',
    'hybrid580-standard-node-map.h', 'hybrid580-standard-node-map.c',
    'hybrid580-standard-node-devices.h', 'hybrid580-standard-node-devices.c',
    'hybrid580_frontend_admission.h', 'hybrid580_pm_provider_recovery.h',
    'hybrid580_system_pm_coordinator.h',
)
FRONTEND_MODULE_NAMES = ('hybrid580_frontend', 'nvidia')
FRONTEND_LINK_OBJECTS = (
    'hybrid_frontend.o', 'hybrid580_uvm_callback_bridge.o', 'rm_root_client.o',
    'hybrid580-gpu-catalog.o', 'hybrid580-device-instance-map.o',
    'hybrid580-standard-node-map.o', 'hybrid580-standard-node-devices.o',
)

UVM_EXPLICIT_PAYLOAD_ABI_ADAPTERS = {
    'nvUvmInterfaceRegisterUvmEvents': (
        'R595 UvmEventsLinux has five callbacks in a different order; the '
        'R580 UvmOpsUvmEvents adapter has seven slots and sets the removed '
        'startDevice/stopDevice callbacks to NULL.'),
    'nvUvmInterfaceDeRegisterUvmEvents': (
        'R595 DeRegisterUvmEvents maps to the renamed R580 DeRegisterUvmOps '
        'entry point; it carries no payload.'),
    'nvUvmInterfaceQueryCopyEnginesCaps': (
        'R580 and R595 layouts are both 8 bytes; copy known fields and '
        'default the R595-only scrub capability to false.'),
    'nvUvmInterfaceGetP2PCaps': (
        'Translate the 64-byte R580 payload into the 72-byte R595 payload, '
        'including link enum/BAR1 classification and unavailable atomics flags.'),
    'nvUvmInterfaceGetPmaObject': (
        'Preserve the live R580 48-byte statistics prefix; R595 runtime reads '
        'only the shared 64K/2M free-page counters.'),
    'nvUvmInterfaceRetainChannel': (
        'Translate the 1,120-byte R580 channel payload into the 1,128-byte '
        'R595 layout, including the runlist doorbell offset/token and shifted SMC fields.'),
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_kernel_build(release, kernel_build=None):
    """Resolve a complete kernel build tree and prove its release identity."""
    release = str(release)
    if not release or '/' in release or release in ('.', '..'):
        raise ValueError('invalid kernel release')
    requested = (Path(kernel_build) if kernel_build is not None else
                 Path('/lib/modules') / release / 'build')
    kernel = requested.resolve(strict=True)
    if not kernel.is_dir():
        raise ValueError('kernel build root is not a directory')
    for name in ('.config', 'Module.symvers', 'Makefile',
                 'include/config/kernel.release'):
        if not (kernel / name).is_file():
            raise ValueError('kernel build tree lacks ' + name)
    actual_release = (kernel / 'include/config/kernel.release').read_text().strip()
    if actual_release != release:
        raise ValueError('kernel.release does not match requested kernel release')
    return kernel


def frontend_compiler(environment=None):
    """Select an explicit CC override before falling back to the host compiler."""
    environment = os.environ if environment is None else environment
    requested = environment.get('CC')
    if requested is not None:
        words = shlex.split(requested)
        if not words:
            raise ValueError('CC override is empty')
        executable = shutil.which(words[0])
        if not executable:
            raise ValueError('CC override executable was not found')
        words[0] = executable
        return shlex.join(words)
    return shutil.which('x86_64-linux-gnu-gcc')


def validate_objtool_build_commands(work, module_name='nvidia'):
    """Validate either per-object objtool runs or Kbuild's delayed module pass.

    With CONFIG_X86_KERNEL_IBT/CONFIG_KLP_BUILD, Kbuild delays objtool until
    the composite module object is linked and invokes it with ``--link``.
    In that mode, prove that the exact frontend object manifest is the module
    input and that the composite link command carries the configured checks.
    Older Kbuild layouts record a separate objtool command for every object.
    """
    work = Path(work)
    required_flags = [
        '--retpoline', '--rethunk', '--sls', '--stackval', '--module']

    def command_segments(command):
        # Kbuild's saved commands do not need shell comments. Reject hashes
        # instead of letting shlex's comment rules reinterpret mid-word text.
        if '#' in command:
            raise ValueError('hash characters are unsupported in saved commands')
        # Shell expansion can change argv or hide nested command boundaries;
        # Kbuild's fully expanded saved commands do not need these markers.
        if '$' in command or '`' in command:
            raise ValueError('shell expansions are unsupported')
        if any(char in command for char in '*?[]{}()'):
            raise ValueError('shell pattern and grouping expansions are unsupported')
        segments = []
        current = []
        quote = None
        escaped = False
        for char in command:
            if escaped:
                current.append(char)
                escaped = False
            elif char == '\\' and quote != "'":
                current.append(char)
                escaped = True
            elif quote is not None:
                current.append(char)
                if char == quote:
                    quote = None
            elif char in ("'", '"'):
                current.append(char)
                quote = char
            elif char in ';&|<>':
                if char != ';':
                    raise ValueError(f'unsupported saved-command operator: {char}')
                segment = ''.join(current).strip()
                if not segment:
                    raise ValueError('empty shell command segment is unsupported')
                segments.append(shlex.split(segment, posix=True))
                current = []
            else:
                current.append(char)
        if escaped or quote is not None:
            raise ValueError('unterminated shell escape or quote in saved command')
        segment = ''.join(current).strip()
        if segment:
            segments.append(shlex.split(segment, posix=True))
        return segments

    def objtool_argv(command):
        try:
            candidates = [argv for argv in command_segments(command)
                          if argv and argv[0].rsplit('/', 1)[-1] == 'objtool']
        except ValueError:
            return None
        return candidates[0] if len(candidates) == 1 else None

    def saved_command(command_file, target):
        if not command_file.is_file():
            return None
        commands = []
        for line in command_file.read_text(errors='replace').splitlines():
            if not line.startswith('savedcmd_') or ' := ' not in line:
                continue
            lhs, command = line.split(' := ', 1)
            if lhs.endswith('/' + target) or lhs.endswith('_' + target):
                commands.append(command)
        return commands[-1] if commands else None

    def missing_flags(arguments):
        return [flag for flag in required_flags if flag not in arguments]

    def options_before_terminator(arguments):
        try:
            return arguments[:arguments.index('--')]
        except ValueError:
            return arguments

    composite_name = module_name + '.o'
    composite_command = saved_command(work / f'.{composite_name}.cmd', composite_name)
    try:
        composite_segments = command_segments(composite_command) if composite_command else []
    except ValueError:
        composite_segments = []
    composite_objtool = (
        composite_segments[1]
        if len(composite_segments) == 2 and composite_segments[1] and
        composite_segments[1][0].rsplit('/', 1)[-1] == 'objtool'
        else None)
    composite_objtool_options = (
        options_before_terminator(composite_objtool)
        if composite_objtool else [])
    if composite_objtool_options and '--link' in composite_objtool_options:
        linker_argv = composite_segments[0]
        linker_name = linker_argv[0].rsplit('/', 1)[-1] if linker_argv else ''
        linker_valid = bool(re.search(r'(?:^|-)ld(?:\.|$)', linker_name))
        output_switch_count = 0
        linked_outputs = []
        response_files = []
        unexpected_linker_arguments = []
        i = 1
        while i < len(linker_argv):
            token = linker_argv[i]
            if token == '--':
                if i != len(linker_argv) - 1:
                    unexpected_linker_arguments.append('arguments-after-terminator')
                break
            if token in ('-m', '-z'):
                if (i + 1 >= len(linker_argv) or
                        linker_argv[i + 1].startswith('-')):
                    unexpected_linker_arguments.append('missing-' + token + '-operand')
                    i += 1
                else:
                    i += 2
                continue
            if token in ('-o', '--output'):
                output_switch_count += 1
                if (i + 1 < len(linker_argv) and
                        not linker_argv[i + 1].startswith('-')):
                    linked_outputs.append(linker_argv[i + 1])
                    i += 2
                else:
                    unexpected_linker_arguments.append('missing-' + token + '-operand')
                    i += 1
                continue
            elif token.startswith('--output='):
                output_switch_count += 1
                linked_outputs.append(token.split('=', 1)[1])
            elif token.startswith('-o') and not token.startswith('--'):
                output_switch_count += 1
                linked_outputs.append(token[2:])
            elif token.startswith('@'):
                response_files.append(token)
            elif token not in ('-r', '--relocatable', '--no-warn-rwx-segments'):
                # The link input set must be exactly the response manifest.
                # Fail closed on unknown options, their operands, and stray
                # positional objects rather than treating them as harmless.
                unexpected_linker_arguments.append(token)
            i += 1
        output_valid = (linker_valid and not unexpected_linker_arguments and
                        output_switch_count == 1 and
                        linked_outputs == [composite_name])
        expected_response_file = '@' + module_name + '.mod'
        response_file_valid = response_files == [expected_response_file]
        manifest_path = work / (module_name + '.mod')
        try:
            manifest = manifest_path.read_text().split()
        except OSError:
            manifest = []
        expected_manifest = {f'./{name}' for name in FRONTEND_LINK_OBJECTS}
        manifest_valid = len(manifest) == len(expected_manifest) and set(manifest) == expected_manifest
        missing = missing_flags(composite_objtool_options)
        if not output_valid:
            missing.append('expected-linker-and-output')
        if not response_file_valid:
            missing.append('exact-linked-response-manifest')
        module_positions = [i for i, token in enumerate(composite_objtool_options)
                            if token == '--module']
        module_arg_valid = (len(module_positions) == 1 and
                            module_positions[0] + 1 < len(composite_objtool_options) and
                            composite_objtool_options[module_positions[0] + 1] == composite_name)
        if not module_arg_valid:
            missing.append('expected-module-target')
        if not manifest_valid:
            missing.append('exact-frontend-object-manifest')
        return {
            'active': not missing,
            'reason': None if not missing else 'delayed module objtool command or input manifest is incomplete',
            'validation_scope': 'delayed-module-link',
            'checked_object_count': len(manifest) if manifest_valid else 0,
            'required_flags': required_flags,
            'missing_object_commands': [],
            'missing_objtool_objects': [],
            'missing_required_flags': {composite_name: missing} if missing else {},
            'object_commands': [{
                'object': composite_name,
                'command_file': str(work / f'.{composite_name}.cmd'),
                'objtool_invoked': composite_objtool is not None,
                'delayed_link': True,
                'required_flags_present': [flag for flag in required_flags
                                           if flag in composite_objtool_options],
                'input_manifest': str(manifest_path),
                'input_manifest_valid': manifest_valid,
                'linker_executable': linker_argv[0] if linker_valid else None,
                'linked_output': linked_outputs[0] if output_valid else None,
                'linked_response_files': response_files,
                'linked_response_manifest_valid': response_file_valid,
            }],
        }

    missing_object_commands = []
    missing_objtool_objects = []
    missing_required_flags = {}
    object_commands = []

    for object_name in FRONTEND_LINK_OBJECTS:
        command_file = work / f'.{object_name}.cmd'
        command = saved_command(command_file, object_name)
        if command is None:
            missing_object_commands.append(object_name)
            missing_objtool_objects.append(object_name)
            continue
        object_objtool = objtool_argv(command)
        objtool_present = object_objtool is not None
        if not objtool_present:
            missing_objtool_objects.append(object_name)
        object_objtool_options = options_before_terminator(object_objtool or [])
        object_missing_flags = missing_flags(object_objtool_options)
        if object_missing_flags:
            missing_required_flags[object_name] = object_missing_flags
        object_commands.append({
            'object': object_name,
            'command_file': str(command_file),
            'saved_command_count': 1,
            'objtool_invoked': objtool_present,
            'required_flags_present': [
                flag for flag in required_flags if flag in object_objtool_options],
        })

    active = not (missing_object_commands or missing_objtool_objects or
                  missing_required_flags)
    return {
        'active': active,
        'reason': None if active else 'one or more frontend object commands lack configured objtool checks',
        'validation_scope': 'per-object',
        'checked_object_count': len(object_commands),
        'required_flags': required_flags,
        'missing_object_commands': missing_object_commands,
        'missing_objtool_objects': missing_objtool_objects,
        'missing_required_flags': missing_required_flags,
        'object_commands': object_commands,
    }


def standard_uvm_symbols_from_header(path):
    text = Path(path).read_text()
    names = re.findall(r'^(?:NV_STATUS|void)\s+(nvUvmInterface\w+)\s*\(',
                       text, re.MULTILINE)
    if not names or len(names) != len(set(names)):
        raise ValueError(f'UVM interface declarations are empty or duplicated: {path}')
    return tuple(names)


def default_provider_trees(uvm_abi):
    if uvm_abi == 'r580':
        return OPEN_R580, LEGACY_R580
    if uvm_abi == 'r595':
        return OPEN, LEGACY
    raise ValueError('unsupported UVM API ABI: ' + str(uvm_abi))


def expected_backend_imports(*, uvm_abi='r595', standard_uvm_symbols=None):
    common = {f'hybrid580_{kind}_{suffix}' for kind in ('open', 'legacy') for suffix in (
        'register_file_projection_v1', 'unregister_file_projection_v1', 'control_session_create_v1',
        'control_session_put_v1', 'control_session_file_v1', 'control_session_attach_v1',
        'control_session_gpu_id_info_v1', 'control_session_attached_ids_v1',
        'control_session_probed_ids_v1', 'control_session_device_ids_v1',
        'control_session_sync_boost_groups_v1',
        'control_session_client_share_policy_v1',
        'control_session_device_alloc_v1', 'control_session_device_free_v1',
        'control_session_memory_alloc_v1', 'control_session_object_free_v1',
        'control_session_vaspace_alloc_v1', 'control_session_channel_group_alloc_v1',
        'control_session_context_share_alloc_v1', 'control_session_channel_alloc_v1',
        'control_session_engine_alloc_v1',
        'control_session_subdevice_alloc_v1', 'control_session_gr_tpc_mask_v1',
        'control_session_binapi_alloc_v1', 'control_session_rusd_alloc_v1',
        'control_session_usermode_alloc_v1',
        'control_session_map_memory_v1', 'control_session_unmap_memory_v1',
        'control_session_update_device_mapping_info_v1',
        'control_session_sys_params_v1',
        'gpu_session_create_by_bdf_v1',
        'gpu_session_put_v1', 'gpu_session_file_v1', 'gpu_session_ioctl_v1',
        'gpu_session_register_control_v1',
        'gpu_inventory_v1', 'gpu_card_info_v1')}
    # The observed V100 BAR1 child is owned by the proprietary R580 RM only.
    # The Open backend must not import an API it deliberately does not export.
    common.add('hybrid580_legacy_control_session_p2p_alloc_v1')
    # GV100's observed master-register child and fixed ECC/NVLink interrupt
    # query are Volta-only; the frontend routes both exclusively to R580.
    common.update({
        'hybrid580_legacy_control_session_master_alloc_v1',
        'hybrid580_legacy_control_session_master_error_intr_offset_mask_v1',
    })
    # The R580 common CUDA ABI is validated by both same-release R580 RMs.
    # The experimental R595/R580 provider pair has no common version contract.
    if uvm_abi == 'r580':
        common.update({
            'hybrid580_legacy_control_session_debugger_alloc_v1',
            'hybrid580_legacy_control_session_debugger_exception_mask_v1',
            'hybrid580_open_control_session_gpu_name_string_v1',
            'hybrid580_legacy_control_session_gpu_name_string_v1',
            'hybrid580_open_control_session_check_version_v1',
            'hybrid580_legacy_control_session_check_version_v1',
        })
    else:
        common.update({
            f'hybrid580_{provider}_control_session_debugger_{operation}_v1'
            for provider in ('open', 'legacy')
            for operation in ('alloc', 'exception_mask')
        })
    # The legacy V1 system build-version ABI is safely adapted through the
    # Open provider's pointer-free V2 RM control; it is not GPU-owner routed.
    common.add('hybrid580_open_control_session_build_version_v1')
    # SYSTEM_GET_FEATURES is one root-global fixed-size answer. The frontend
    # deliberately selects the Open R580 provider instead of merging masks.
    common.add('hybrid580_open_control_session_system_features_v1')
    # Fabric readiness is also root-global; it is not a per-GPU NVLink query.
    common.add('hybrid580_open_control_session_fabric_status_v1')
    # Aggregate system-PM coordination is intentionally not wired yet, but
    # the frontend adapter must be linkable against the exact provider APIs
    # whose source contracts and CPU models have been audited.
    for provider in ('open', 'legacy'):
        common.update(f'hybrid580_{provider}_pm_{suffix}_v1' for suffix in (
            'recovery_begin', 'recovery_recover', 'recovery_end',
            'channels_suspend', 'channels_resume'))
    common.update({
        'hybrid580_open_pm_shared_uvm_suspend_v1',
        'hybrid580_open_pm_shared_uvm_resume_v1',
    })
    common.update('hybrid580_open_' + name for name in R595_OPEN_ONLY_UVM_APIS)
    # Installed R580 V100 traces show NV503C VA-space/vidmem registration.
    # Keep these P2P controls affine to the legacy RM; do not synthesize Open
    # exports or forward Blackwell requests through a Volta-only control path.
    common.update('hybrid580_legacy_control_session_p2p_' + operation + '_v1'
                  for operation in ('register_va_space', 'unregister_va_space',
                                    'register_vidmem', 'unregister_vidmem'))
    # The frontend accepts R595's Linux event table, forwards it unchanged to
    # Open, and supplies a lifetime-pinned R580 UvmOpsUvmEvents adapter to the
    # legacy RM. Registration rolls Open back if the legacy provider fails.
    # GPU registration and information queries route by the UUID owner's RM.
    common.update({
        'hybrid580_open_nvUvmInterfaceRegisterUvmEvents',
        'hybrid580_open_nvUvmInterfaceDeRegisterUvmEvents',
        'hybrid580_legacy_nvUvmInterfaceRegisterUvmCallbacks',
        'hybrid580_legacy_nvUvmInterfaceDeRegisterUvmOps',
        'hybrid580_open_nvUvmInterfaceSessionCreate',
        'hybrid580_open_nvUvmInterfaceSessionDestroy',
        'hybrid580_legacy_nvUvmInterfaceSessionCreate',
        'hybrid580_legacy_nvUvmInterfaceSessionDestroy',
        'hybrid580_open_nvUvmInterfaceRegisterGpu',
        'hybrid580_open_nvUvmInterfaceUnregisterGpu',
        'hybrid580_open_nvUvmInterfaceGetGpuInfo',
        'hybrid580_open_nvUvmInterfaceDeviceCreate',
        'hybrid580_open_nvUvmInterfaceDeviceDestroy',
        'hybrid580_open_nvUvmInterfaceGetFbInfo',
        'hybrid580_open_nvUvmInterfaceQueryCaps',
        'hybrid580_open_nvUvmInterfaceQueryCopyEnginesCaps',
        'hybrid580_open_nvUvmInterfaceGetEccInfo',
        'hybrid580_open_nvUvmInterfaceGetNvlinkInfo',
        'hybrid580_open_nvUvmInterfaceGetP2PCaps',
        'hybrid580_open_nvUvmInterfaceP2pObjectCreate',
        'hybrid580_open_nvUvmInterfaceP2pObjectDestroy',
        'hybrid580_open_nvUvmInterfaceAddressSpaceCreate',
        'hybrid580_open_nvUvmInterfaceDupAddressSpace',
        'hybrid580_open_nvUvmInterfaceDupAllocation',
        'hybrid580_open_nvUvmInterfaceAddressSpaceDestroy',
        'hybrid580_open_nvUvmInterfaceSetPageDirectory',
        'hybrid580_open_nvUvmInterfaceUnsetPageDirectory',
        'hybrid580_open_nvUvmInterfaceOwnPageFaultIntr',
        'hybrid580_open_nvUvmInterfaceServiceDeviceInterruptsRM',
        'hybrid580_legacy_nvUvmInterfaceRegisterGpu',
        'hybrid580_legacy_nvUvmInterfaceUnregisterGpu',
        'hybrid580_legacy_nvUvmInterfaceGetGpuInfo',
        'hybrid580_legacy_nvUvmInterfaceDeviceCreate',
        'hybrid580_legacy_nvUvmInterfaceDeviceDestroy',
        'hybrid580_legacy_nvUvmInterfaceGetFbInfo',
        'hybrid580_legacy_nvUvmInterfaceQueryCaps',
        'hybrid580_legacy_nvUvmInterfaceQueryCopyEnginesCaps',
        'hybrid580_legacy_nvUvmInterfaceGetEccInfo',
        'hybrid580_legacy_nvUvmInterfaceGetNvlinkInfo',
        'hybrid580_legacy_nvUvmInterfaceGetP2PCaps',
        'hybrid580_legacy_nvUvmInterfaceP2pObjectCreate',
        'hybrid580_legacy_nvUvmInterfaceP2pObjectDestroy',
        'hybrid580_legacy_nvUvmInterfaceAddressSpaceCreate',
        'hybrid580_legacy_nvUvmInterfaceDupAddressSpace',
        'hybrid580_legacy_nvUvmInterfaceDupAllocation',
        'hybrid580_legacy_nvUvmInterfaceAddressSpaceDestroy',
        'hybrid580_legacy_nvUvmInterfaceSetPageDirectory',
        'hybrid580_legacy_nvUvmInterfaceUnsetPageDirectory',
        'hybrid580_legacy_nvUvmInterfaceOwnPageFaultIntr',
        'hybrid580_legacy_nvUvmInterfaceServiceDeviceInterruptsRM',
    })
    common.update(
        f'hybrid580_{provider}_nvUvmInterface{api}'
        for provider in ('open', 'legacy')
        for api in ('MemoryAllocFB', 'MemoryAllocSys', 'MemoryFree',
                    'MemoryCpuMap', 'MemoryCpuUnMap', 'DupMemory',
                    'FreeDupedHandle'))
    common.update(
        f'hybrid580_{provider}_nvUvmInterface{api}'
        for provider in ('open', 'legacy')
        for api in ('GetPmaObject', 'PmaRegisterEvictionCallbacks',
                    'PmaUnregisterEvictionCallbacks', 'PmaAllocPages',
                    'PmaPinPages', 'PmaFreePages'))
    common.update(
        f'hybrid580_{provider}_nvUvmInterface{api}'
        for provider in ('open', 'legacy')
        for api in ('GetExternalAllocPtes', 'GetExternalAllocPhysAddrs'))
    common.update(
        f'hybrid580_{provider}_nvUvmInterface{api}'
        for provider in ('open', 'legacy')
        for api in ('InitFaultInfo', 'DestroyFaultInfo',
                    'HasPendingNonReplayableFaults',
                    'GetNonReplayableFaults', 'FlushReplayableFaultBuffer',
                    'TogglePrefetchFaults', 'InitAccessCntrInfo',
                    'DestroyAccessCntrInfo', 'EnableAccessCntr',
                    'DisableAccessCntr'))
    common.update(
        f'hybrid580_{provider}_nvUvmInterface{api}'
        for provider in ('open', 'legacy')
        for api in ('ReportNonReplayableFault', 'ReportFatalError'))
    common.update(
        f'hybrid580_{provider}_nvUvmInterface{api}'
        for provider in ('open', 'legacy')
        for api in ('CslInitContext', 'DeinitCslContext', 'CslRotateKey',
                    'CslRotateIv', 'CslEncrypt', 'CslDecrypt', 'CslSign',
                    'CslQueryMessagePool', 'CslIncrementIv',
                    'CslLogEncryption'))
    common.update(
        f'hybrid580_{provider}_nvUvmInterface{api}'
        for provider in ('open', 'legacy')
        for api in ('TsgAllocate', 'TsgDestroy',
                    'ChannelAllocate', 'ChannelDestroy'))
    common.update(
        f'hybrid580_{provider}_nvUvmInterface{api}'
        for provider in ('open', 'legacy')
        for api in ('RetainChannel', 'BindChannelResources',
                    'ReleaseChannel', 'StopChannel',
                    'GetChannelResourcePtes'))
    if uvm_abi == 'r595':
        return common
    if uvm_abi != 'r580':
        raise ValueError('unsupported UVM API ABI: ' + str(uvm_abi))
    if not standard_uvm_symbols:
        raise ValueError('R580 UVM API symbols must come from the pinned R580 header')

    # The R580 frontend and both private R580 providers use one exact public
    # interface. Preserve the existing fail-closed paging-channel boundary,
    # and otherwise require both backends to provide every imported API.
    non_uvm = {name for name in common if 'nvUvmInterface' not in name}
    r580_uvm = {
        f'hybrid580_{provider}_{name}'
        for provider in ('open', 'legacy')
        for name in standard_uvm_symbols
        if name not in FAIL_CLOSED_UVM_APIS and
        name not in HYBRID_ONLY_UVM_APIS
    }
    return non_uvm | r580_uvm


def symbols(path):
    result = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) >= 4:
            result[fields[1]] = {'crc': fields[0], 'module': fields[2], 'export': fields[3]}
    return result


def validate_frontend_module_name(module_name):
    if module_name not in FRONTEND_MODULE_NAMES:
        raise ValueError('unsupported frontend module name: ' + repr(module_name))
    return module_name


def validate_frontend_export_owners(frontend_exports, module_name, module_object_path=None):
    validate_frontend_module_name(module_name)
    expected_owners = {module_name}
    if module_object_path is not None:
        expected_owners.add(str(Path(module_object_path)))
    mismatches = {
        name: item.get('module')
        for name, item in frontend_exports.items()
        if item.get('module') not in expected_owners
    }
    if mismatches:
        raise ValueError('frontend Module.symvers owner mismatch: ' + repr(mismatches))
    return {
        'expected_module_name': module_name,
        'accepted_symvers_owners': sorted(expected_owners),
        'export_count': len(frontend_exports),
        'mismatches': {},
        'matches': True,
    }


def render_frontend_kbuild(module_name, include_dirs, open_symvers, legacy_symvers,
                           uvm_abi='r595'):
    validate_frontend_module_name(module_name)
    if uvm_abi not in ('r580', 'r595'):
        raise ValueError('unsupported UVM API ABI: ' + str(uvm_abi))
    target = module_name
    objects = ' '.join(FRONTEND_LINK_OBJECTS)
    abi_flag = ' -DHYBRID580_UVM_ABI_R580' if uvm_abi == 'r580' else ''
    return (f'obj-m += {target}.o\n'
            f'{target}-y := {objects}\n'
            'ccflags-y += -DNVRM -DNV_KERNEL_INTERFACE_LAYER -DNV_UVM_ENABLE -ffreestanding '
            + abi_flag + ' -fno-strict-aliasing -Werror\n'
            + 'ccflags-y += ' + ' '.join('-I' + str(path) for path in include_dirs) + '\n'
            + 'KBUILD_EXTRA_SYMBOLS := ' + str(open_symvers) + ' '
            + str(legacy_symvers) + '\n')


def validate_private_hybrid_dispatch_exports(open_exports, legacy_exports,
                                              frontend_owner='hybrid580_frontend'):
    """A hybrid-only public dispatcher must not also be exported by a provider."""
    collisions = {
        name: [provider for provider, table in (
            ('Open private module', open_exports),
            ('legacy private module', legacy_exports)) if name in table]
        for name in HYBRID_ONLY_UVM_APIS
    }
    collisions = {name: providers for name, providers in collisions.items() if providers}
    if collisions:
        raise ValueError('hybrid-only UVM dispatcher is also exported by private providers: ' +
                         repr(collisions))
    return {name: {'frontend_owner': frontend_owner,
                   'private_provider_exports': []}
            for name in sorted(HYBRID_ONLY_UVM_APIS)}


def validate_hybrid_dispatch_export_ownership(frontend_exports, open_exports,
                                              legacy_exports,
                                              frontend_owner='hybrid580_frontend'):
    ownership = validate_private_hybrid_dispatch_exports(
        open_exports, legacy_exports, frontend_owner=frontend_owner)
    missing = sorted(set(HYBRID_ONLY_UVM_APIS) - set(frontend_exports))
    if missing:
        raise ValueError('hybrid frontend is missing its hybrid-only UVM dispatcher exports: ' +
                         ','.join(missing))
    return ownership


def validate_backend_api_headers(open_header_dir, legacy_header_dir):
    open_header_dir = Path(open_header_dir)
    legacy_header_dir = Path(legacy_header_dir)
    all_headers = SHARED_BACKEND_API_HEADERS + BACKEND_SPECIFIC_API_HEADERS
    for name in all_headers:
        if not (open_header_dir / name).is_file() or not (legacy_header_dir / name).is_file():
            raise ValueError('missing private API header: ' + name)
    for name in SHARED_BACKEND_API_HEADERS:
        open_header = (open_header_dir / name).read_bytes()
        legacy_header = (legacy_header_dir / name).read_bytes()
        if open_header.replace(b'hybrid580_open', b'hybrid580_legacy') != legacy_header:
            raise ValueError('shared backend API mismatch: ' + name)
    return True


def parse_module_modversions(output):
    versions = {}
    for line_number, line in enumerate(output.splitlines(), 1):
        fields = line.split()
        if not fields:
            continue
        if len(fields) != 2:
            raise ValueError(f'malformed modversion line {line_number}')
        raw_crc, name = fields
        try:
            crc = f'0x{int(raw_crc, 16):08x}'
        except ValueError as error:
            raise ValueError(f'malformed modversion CRC on line {line_number}') from error
        prior = versions.get(name)
        if prior is not None and prior != crc:
            raise ValueError(f'conflicting modversion entries for {name}')
        versions[name] = crc
    return versions


def parse_extended_modversions(names_blob, crc_blob, byte_order):
    if byte_order not in ('little', 'big'):
        raise ValueError('invalid ELF byte order for extended modversions')
    if not names_blob or not names_blob.endswith(b'\0'):
        raise ValueError('extended modversion names are not NUL terminated')
    # The generated C string literals include a final explicit NUL and the C
    # compiler adds its own terminator, so allow repeated NUL padding only at
    # the end of the section.
    raw_names = names_blob.rstrip(b'\0').split(b'\0')
    if any(not name for name in raw_names):
        raise ValueError('extended modversion names contain an empty symbol')
    try:
        names = [name.decode('ascii') for name in raw_names]
    except UnicodeDecodeError as error:
        raise ValueError('extended modversion symbol name is not ASCII') from error
    if len(crc_blob) % 4:
        raise ValueError('extended modversion CRC section has a partial entry')
    crcs = struct.unpack(('<' if byte_order == 'little' else '>') +
                         f'{len(crc_blob) // 4}I', crc_blob)
    if len(names) != len(crcs):
        raise ValueError('extended modversion name/CRC count mismatch')
    versions = {}
    for name, crc in zip(names, crcs):
        if name in versions:
            raise ValueError(f'duplicate extended modversion symbol: {name}')
        versions[name] = f'0x{crc:08x}'
    return versions


def _validate_modversion_name(name_field, *, format_name):
    terminator = name_field.find(b'\0')
    if terminator <= 0 or any(name_field[terminator:]):
        raise ValueError(f'{format_name} kernel modversion record has malformed name padding')
    try:
        name = name_field[:terminator].decode('ascii')
    except UnicodeDecodeError as error:
        raise ValueError('kernel modversion symbol name is not ASCII') from error
    if any(not (character.isalnum() or character in '_.') for character in name):
        raise ValueError('kernel modversion symbol name contains invalid characters')
    return name


def _parse_variable_kernel_modversions_section(blob, byte_order):
    prefix = '<' if byte_order == 'little' else '>'
    versions = {}
    offset = 0
    while offset < len(blob):
        remaining = blob[offset:]
        if not any(remaining):
            break
        if len(remaining) < 8:
            raise ValueError('kernel modversion section has a partial record header')
        record_size, crc = struct.unpack_from(prefix + 'II', blob, offset)
        if record_size < 10 or record_size % 4 or offset + record_size > len(blob):
            raise ValueError('kernel modversion record has an invalid size')
        name = _validate_modversion_name(
            blob[offset + 8:offset + record_size], format_name='compact')
        crc_text = f'0x{crc:08x}'
        prior = versions.get(name)
        if prior is not None and prior != crc_text:
            raise ValueError(f'conflicting kernel modversion entries for {name}')
        versions[name] = crc_text
        offset += record_size
    return versions


def _parse_basic_kernel_modversions_section(blob, byte_order, word_size):
    if word_size not in (4, 8):
        raise ValueError('invalid ELF word size for basic kernel modversions')
    prefix = '<' if byte_order == 'little' else '>'
    record_size = 64  # sizeof(unsigned long) + MODULE_NAME_LEN
    crc_format = 'I' if word_size == 4 else 'Q'
    versions = {}
    offset = 0
    while offset < len(blob):
        remaining = blob[offset:]
        if not any(remaining):
            break
        if len(remaining) < record_size:
            raise ValueError('basic kernel modversion section has a partial record')
        crc = struct.unpack_from(prefix + crc_format, blob, offset)[0]
        if crc > 0xffffffff:
            raise ValueError('basic kernel modversion CRC exceeds 32 bits')
        name = _validate_modversion_name(
            blob[offset + word_size:offset + record_size], format_name='basic')
        crc_text = f'0x{crc:08x}'
        prior = versions.get(name)
        if prior is not None and prior != crc_text:
            raise ValueError(f'conflicting kernel modversion entries for {name}')
        versions[name] = crc_text
        offset += record_size
    return versions


def parse_kernel_modversions_section(blob, byte_order, word_size=None):
    """Parse compact or fixed ``struct modversion_info`` kernel records.

    Compact records begin with a byte size and CRC. ``CONFIG_BASIC_MODVERSIONS``
    stores an unsigned-long CRC followed by ``MODULE_NAME_LEN`` bytes; the ELF
    word size selects this format only when compact parsing fails. Trailing
    section alignment is accepted only when it is all zero.
    """
    if byte_order not in ('little', 'big'):
        raise ValueError('invalid ELF byte order for kernel modversions')
    try:
        return _parse_variable_kernel_modversions_section(blob, byte_order)
    except ValueError:
        if word_size is None:
            raise
        return _parse_basic_kernel_modversions_section(blob, byte_order, word_size)


def merge_module_modversions(compact, extended):
    versions = dict(compact)
    for name, crc in extended.items():
        prior = versions.get(name)
        if prior is not None and prior.lower() != crc.lower():
            raise ValueError(f'conflicting modversion CRC for {name}')
        versions[name] = crc.lower()
    return versions


def _elf_module_input(module, temp_dir):
    """Return an ELF input, materializing zstd-compressed modules privately."""
    module = Path(module)
    with module.open('rb') as stream:
        magic = stream.read(4)
    if magic != b'\x28\xb5\x2f\xfd':
        return module
    zstd = shutil.which('zstd')
    if not zstd:
        raise ValueError('zstd is unavailable for compressed kernel module validation')
    decompressed = Path(temp_dir) / 'consumer-module.ko'
    with decompressed.open('wb') as output:
        result = subprocess.run(
            [zstd, '-d', '-q', '-c', '--', str(module.resolve())],
            stdout=output, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode:
        raise ValueError('zstd could not decompress the kernel module: ' +
                         result.stderr.strip())
    return decompressed


def extract_extended_modversions(module, work):
    module = Path(module)
    work = Path(work)
    objcopy = shutil.which('objcopy')
    if not objcopy:
        raise ValueError('objcopy is unavailable for extended modversion validation')
    with tempfile.TemporaryDirectory(prefix='.modversions-', dir=work) as temp_dir:
        module_for_objcopy = _elf_module_input(module, temp_dir)
        with module_for_objcopy.open('rb') as stream:
            elf_header = stream.read(6)
        if len(elf_header) != 6 or elf_header[:4] != b'\x7fELF':
            raise ValueError('module is not a supported ELF file')
        encoding = elf_header[5]
        if encoding == 1:
            byte_order = 'little'
        elif encoding == 2:
            byte_order = 'big'
        else:
            raise ValueError('module has an invalid ELF data encoding')
        names_path = Path(temp_dir) / 'names.bin'
        crcs_path = Path(temp_dir) / 'crcs.bin'
        for section, output in (('__version_ext_names', names_path),
                                ('__version_ext_crcs', crcs_path)):
            rewritten_module = Path(temp_dir) / f'{section}.ko'
            result = subprocess.run(
                [objcopy, '--dump-section', f'{section}={output}',
                 str(module_for_objcopy), str(rewritten_module)],
                capture_output=True, text=True, check=False)
            if result.returncode:
                raise ValueError(
                    f'objcopy could not extract {section}: {result.stderr.strip()}')
            if not output.is_file():
                raise ValueError(f'objcopy did not produce {section}')
        return parse_extended_modversions(names_path.read_bytes(),
                                          crcs_path.read_bytes(), byte_order)


def extract_kernel_modversions_section(module, work):
    module = Path(module)
    work = Path(work)
    objcopy = shutil.which('objcopy')
    if not objcopy:
        raise ValueError('objcopy is unavailable for kernel modversion validation')
    with tempfile.TemporaryDirectory(prefix='.modversions-compact-', dir=work) as temp_dir:
        module_for_objcopy = _elf_module_input(module, temp_dir)
        with module_for_objcopy.open('rb') as stream:
            elf_header = stream.read(6)
        if len(elf_header) != 6 or elf_header[:4] != b'\x7fELF':
            raise ValueError('kernel consumer module is not a supported ELF file')
        if elf_header[4] == 1:
            word_size = 4
        elif elf_header[4] == 2:
            word_size = 8
        else:
            raise ValueError('kernel consumer module has an invalid ELF class')
        if elf_header[5] == 1:
            byte_order = 'little'
        elif elf_header[5] == 2:
            byte_order = 'big'
        else:
            raise ValueError('kernel consumer module has an invalid ELF data encoding')
        section_path = Path(temp_dir) / 'versions.bin'
        rewritten_module = Path(temp_dir) / 'module-copy.ko'
        result = subprocess.run(
            [objcopy, '--dump-section', f'__versions={section_path}',
             str(module_for_objcopy), str(rewritten_module)],
            capture_output=True, text=True, check=False)
        if result.returncode or not section_path.is_file():
            raise ValueError('objcopy could not extract the kernel __versions section: ' +
                             result.stderr.strip())
        return parse_kernel_modversions_section(section_path.read_bytes(), byte_order,
                                                word_size=word_size)


def check_backend_import_crcs(module_versions, backend_imports):
    checks = {}
    mismatches = []
    for name, provider in sorted(backend_imports.items()):
        module_crc = module_versions.get(name)
        provider_crc = f"0x{int(provider['crc'], 16):08x}"
        matches = module_crc == provider_crc
        checks[name] = {
            'module_crc': module_crc,
            'provider_crc': provider_crc,
            'provider': provider['provider'],
            'matches_provider': matches,
        }
        if not matches:
            mismatches.append(name)
    return checks, mismatches


def standard_api_r595_contract(frontend_item, open_item, legacy_item,
                               open_private_import_check,
                               legacy_private_import_check,
                               *, no_backend_implementation=False):
    """Validate public and private R595 UVM edges without cross-name CRC compares.

    A public ``nvUvmInterface*`` export and a backend-private
    ``hybrid580_{open,legacy}_nvUvmInterface*`` export have different symbol
    names. Kernel modversion CRCs include the exported symbol declaration,
    including that name, so comparing those CRCs is not a valid ABI check.
    The public consumer edge and each private frontend-to-provider edge are
    checked independently.
    """
    public_export_present = bool(
        frontend_item and frontend_item.get('export') == 'EXPORT_SYMBOL')
    open_private_export_present = bool(
        open_item and open_item.get('export') == 'EXPORT_SYMBOL')
    legacy_private_export_present = bool(
        legacy_item and legacy_item.get('export') == 'EXPORT_SYMBOL')
    open_import_matches = bool(
        open_private_import_check and
        open_private_import_check.get('matches_provider'))
    legacy_import_matches = bool(
        legacy_private_import_check and
        legacy_private_import_check.get('matches_provider'))
    private_contract = (
        not open_private_import_check and not legacy_private_import_check
        if no_backend_implementation else
        open_private_export_present and legacy_private_export_present and
        open_import_matches and legacy_import_matches)
    return {
        'crc_scope': (
            'public export presence is checked here; each differently named '
            'private frontend import CRC is checked against its provider. Public '
            'consumer binding is a separate check; CRCs do not prove payload '
            'layout or runtime semantics.'),
        'matches_frontend_and_open': None,
        'matches_both_providers': None,
        'public_frontend_export_present': public_export_present,
        'open_private_export_present': open_private_export_present,
        'legacy_private_export_present': legacy_private_export_present,
        'open_private_import_matches_provider': open_import_matches,
        'legacy_private_import_matches_provider': legacy_import_matches,
        'public_consumer_binding_required': True,
        'public_consumer_binding_in_this_build': False,
        'no_backend_implementation': no_backend_implementation,
        'matches_expected_contract': public_export_present and private_contract,
    }


def standard_api_r595_open_only_contract(frontend_item, open_item,
                                         open_private_import_check):
    public_export_present = bool(
        frontend_item and frontend_item.get('export') == 'EXPORT_SYMBOL')
    open_private_export_present = bool(
        open_item and open_item.get('export') == 'EXPORT_SYMBOL')
    open_import_matches = bool(
        open_private_import_check and
        open_private_import_check.get('matches_provider'))
    return {
        'crc_scope': (
            'public export presence and the differently named Open-private '
            'frontend import are checked independently; public consumer binding '
            'is separate and payload/runtime compatibility remains unverified.'),
        'matches_frontend_and_open': None,
        'public_frontend_export_present': public_export_present,
        'open_private_export_present': open_private_export_present,
        'open_private_import_matches_provider': open_import_matches,
        'legacy_private_import_matches_provider': None,
        'legacy_provider_required': False,
        'public_consumer_binding_required': True,
        'public_consumer_binding_in_this_build': False,
        'no_backend_implementation': False,
        'matches_expected_contract': (
            public_export_present and open_private_export_present and
            open_import_matches),
    }


def check_public_uvm_consumer_bindings(frontend_symvers,
                                       consumer_modversions,
                                       standard_uvm_symbols):
    checks = {}
    missing = []
    mismatches = []
    for name in standard_uvm_symbols:
        frontend = frontend_symvers.get(name)
        frontend_crc = frontend.get('crc') if frontend else None
        if frontend and frontend.get('export') != 'EXPORT_SYMBOL':
            frontend_crc = None
        consumer_crc = consumer_modversions.get(name)
        matches = bool(frontend_crc and consumer_crc and
                       frontend_crc.lower() == consumer_crc.lower())
        checks[name] = {
            'frontend_export_crc': frontend_crc,
            'consumer_import_crc': consumer_crc,
            'matches': matches,
        }
        if not frontend_crc or not consumer_crc:
            missing.append(name)
        elif not matches:
            mismatches.append(name)
    return {
        'api_count': len(standard_uvm_symbols),
        'matched_count': sum(1 for item in checks.values() if item['matches']),
        'missing': missing,
        'mismatches': mismatches,
        'checks': checks,
        'verified': bool(standard_uvm_symbols) and not missing and not mismatches,
    }


def standard_api_r580_contract(frontend_item, open_item, legacy_item,
                               open_private_import_check,
                               legacy_private_import_check,
                               *, no_backend_implementation=False):
    """Validate each R580 symbol-version edge at its actual module boundary.

    The public ``nvUvmInterface*`` export is consumed by ``nvidia-uvm``; the
    private namespaced exports are consumed by this frontend. Their CRCs are
    not compared to each other because the symbol names and consumers differ.
    A separate UVM-consumer build proves the public edge.
    """
    public_export_present = bool(
        frontend_item and frontend_item.get('export') == 'EXPORT_SYMBOL')
    open_private_export_present = bool(
        open_item and open_item.get('export') == 'EXPORT_SYMBOL')
    legacy_private_export_present = bool(
        legacy_item and legacy_item.get('export') == 'EXPORT_SYMBOL')
    open_import_matches = bool(
        open_private_import_check and
        open_private_import_check.get('matches_provider'))
    legacy_import_matches = bool(
        legacy_private_import_check and
        legacy_private_import_check.get('matches_provider'))
    if no_backend_implementation:
        private_contract = (
            open_private_import_check is None and
            legacy_private_import_check is None)
    else:
        private_contract = (
            open_private_export_present and legacy_private_export_present and
            open_import_matches and legacy_import_matches)
    return {
        'crc_scope': (
            'public CRC is checked against the nvidia-uvm consumer; each private '
            'CRC is checked against its importing frontend. CRC values across '
            'the differently named public/private symbols are not compared; '
            'payload layout and runtime semantics remain separate checks.'),
        'matches_frontend_and_open': None,
        'matches_both_providers': None,
        'public_frontend_export_present': public_export_present,
        'open_private_export_present': open_private_export_present,
        'legacy_private_export_present': legacy_private_export_present,
        'open_private_import_matches_provider': open_import_matches,
        'legacy_private_import_matches_provider': legacy_import_matches,
        'public_consumer_binding_required': True,
        'public_consumer_binding_in_this_build': False,
        'no_backend_implementation': no_backend_implementation,
        'matches_expected_contract': public_export_present and private_contract,
    }


def standard_api_payload_abi_assessment(name, uvm_abi='r595'):
    if name in HYBRID_ONLY_UVM_APIS:
        return {
            'classification': 'hybrid-only-control-fd-dispatch',
            'assessment': ('The bridge resolves source ownership from the exact '
                           'struct file pinned by the R580 UVM ioctl; '
                           'native provider imports remain the unchanged standard UVM ABI.'),
        }
    if uvm_abi == 'r580' and name not in FAIL_CLOSED_UVM_APIS:
        return {
            'classification': 'same-branch-r580-api',
            'assessment': ('Public frontend and both private providers use the pinned '
                           'R580 declaration/CRC; runtime payload semantics remain unverified.'),
        }
    adapter = UVM_EXPLICIT_PAYLOAD_ABI_ADAPTERS.get(name)
    if adapter is not None:
        return {'classification': 'explicitly-adapted', 'assessment': adapter}
    if name in R595_OPEN_ONLY_UVM_APIS:
        return {
            'classification': 'open-only-r595-native-payload',
            'assessment': ('This R595-only API uses the R595 payload unchanged with the '
                           'Open provider; the R580 legacy route returns NOT_SUPPORTED.'),
        }
    if name in FAIL_CLOSED_UVM_APIS:
        return {
            'classification': 'fail-closed-no-backend-call',
            'assessment': ('Physical-GPU frontend returns NOT_SUPPORTED or no-ops '
                           'these SR-IOV paging-channel APIs; no provider payload is forwarded.'),
        }
    return {
        'classification': 'unverified-payload-semantics',
        'assessment': ('Provider symbol-version CRCs are checked, but this API\'s '
                       'complete pointee layout and cross-release semantics have not '
                       'been independently audited.'),
    }


def build(work, open_tree=OPEN, legacy_tree=LEGACY, release=None,
          uvm_abi='r595', module_name='hybrid580_frontend', kernel_build=None,
          uvm_consumer_module=None):
    validate_frontend_module_name(module_name)
    if uvm_abi not in ('r580', 'r595'):
        raise ValueError('unsupported UVM API ABI: ' + str(uvm_abi))
    open_tree = open_tree.resolve(strict=True)
    legacy_tree = legacy_tree.resolve(strict=True)
    release = release or os.uname().release
    kernel = resolve_kernel_build(release, kernel_build)
    uvm_consumer_info = None
    if uvm_consumer_module is not None:
        uvm_consumer_module = Path(uvm_consumer_module).resolve(strict=True)
        consumer_name = subprocess.run(
            ['modinfo', '-F', 'name', str(uvm_consumer_module)],
            capture_output=True, text=True, check=True).stdout.strip()
        consumer_vermagic = subprocess.run(
            ['modinfo', '-F', 'vermagic', str(uvm_consumer_module)],
            capture_output=True, text=True, check=True).stdout.strip()
        if consumer_name != 'nvidia_uvm':
            raise ValueError('UVM consumer module name must be nvidia_uvm')
        if consumer_vermagic.split()[0] != release:
            raise ValueError('UVM consumer module vermagic does not match target kernel')
        uvm_consumer_info = {
            'path': str(uvm_consumer_module),
            'sha256': sha256(uvm_consumer_module),
            'bytes': uvm_consumer_module.stat().st_size,
            'name': consumer_name,
            'vermagic': consumer_vermagic,
            'role': ('public R595 UVM ABI reference consumer; this does not qualify '
                     'a separately patched hybrid UVM module'),
        }
    elif uvm_abi == 'r595':
        raise ValueError('R595 frontend build requires --uvm-consumer-module for public ABI validation')
    source_headers = open_tree / 'kernel-open/nvidia'
    legacy_headers = legacy_tree / 'nvidia'
    open_sym = open_tree / 'kernel-open/Module.symvers'
    legacy_sym = legacy_tree / 'Module.symvers'
    open_provider_symvers = symbols(open_sym)
    legacy_provider_symvers = symbols(legacy_sym)
    private_dispatch_ownership = validate_private_hybrid_dispatch_exports(
        open_provider_symvers, legacy_provider_symvers,
        frontend_owner=module_name)
    headers = (SHARED_BACKEND_API_HEADERS + BACKEND_SPECIFIC_API_HEADERS)
    validate_backend_api_headers(source_headers, legacy_headers)
    if (source_headers / 'rm_session_endpoint.h').read_bytes() != (ROOT / 'src/rm_session_endpoint.h').read_bytes():
        raise ValueError('Open session endpoint differs from project source')
    if (legacy_headers / 'rm_session_endpoint.h').read_bytes() != (ROOT / 'src/rm_session_endpoint.h').read_bytes():
        raise ValueError('legacy session endpoint differs from project source')
    conftest = open_tree / 'kernel-open/conftest'
    if release not in (conftest / 'headers.h').read_text():
        raise ValueError('conftest release mismatch')
    uvm_header = open_tree / 'kernel-open/common/inc/nv_uvm_interface.h'
    if uvm_abi == 'r580':
        legacy_uvm_header = legacy_tree / 'common/inc/nv_uvm_interface.h'
        if not legacy_uvm_header.is_file():
            raise ValueError('selected R580 proprietary backend lacks nv_uvm_interface.h')
        if uvm_header.read_bytes() != legacy_uvm_header.read_bytes():
            raise ValueError('selected R580 provider UVM API headers differ')
    standard_uvm_symbols = standard_uvm_symbols_from_header(uvm_header)
    inputs = [ROOT / 'src' / name for name in FRONTEND_SOURCES]
    inputs += [Path(__file__).resolve(), ROOT / 'tests/test_hybrid_frontend.py',
               uvm_header,
               ROOT / 'tests/test_hybrid_frontend_gpu.py',
               ROOT / 'tests/test_hybrid580_system_pm_coordinator.py',
               ROOT / 'tests/test_nvidia_hibernate_pm.py',
               ROOT / 'tests/test_uvm_pm_lifecycle_audit.py',
               ROOT / 'tests/test_hybrid580_frontend_admission.py',
               ROOT / 'tests/test_backend_device_ids_api.py',
               ROOT / 'tests/test_usermode_object.py',
               ROOT / 'tests/test_device_instance_map.py',
               ROOT / 'tests/test_standard_node_map.py',
               ROOT / 'tests/test_standard_node_devices.py',
               ROOT / 'tests/test_hybrid580_uvm_callback_bridge.py',
               ROOT / 'tests/test_hybrid580_uvm_event_compat.py',
               ROOT / 'tests/test_hybrid580_uvm_session_pair.py',
               ROOT / 'tests/test_hybrid580_uvm_gpu_registry.py',
               ROOT / 'tests/test_hybrid580_uvm_gpu_route.py',
               ROOT / 'tests/test_hybrid580_uvm_gpu_info_route.py',
               ROOT / 'tests/test_hybrid580_uvm_device_route.py',
               ROOT / 'tests/test_hybrid580_uvm_address_space_route.py',
               ROOT / 'tests/test_hybrid580_uvm_dup_memory_route.py',
               ROOT / 'tests/test_hybrid580_uvm_pma_route.py',
               ROOT / 'tests/test_hybrid580_uvm_external_mapping_route.py',
               ROOT / 'tests/test_hybrid580_uvm_info_registry.py',
               ROOT / 'tests/test_build_hybrid_frontend.py',
               ROOT / 'tests/fixtures/device_instance_map_contract.c',
               ROOT / 'tests/fixtures/hybrid580_uvm_callback_bridge_test.c',
               ROOT / 'tests/fixtures/hybrid580_uvm_event_compat_test.c',
               ROOT / 'tests/fixtures/hybrid580_uvm_session_pair_test.c',
               ROOT / 'tests/fixtures/hybrid580_uvm_gpu_registry_test.c',
               ROOT / 'tests/fixtures/hybrid580_uvm_gpu_route_test.c',
               ROOT / 'tests/fixtures/hybrid580_uvm_gpu_info_route_test.c',
               ROOT / 'tests/fixtures/hybrid580_uvm_device_route_test.c',
               ROOT / 'tests/fixtures/hybrid580_uvm_address_space_route_test.c',
               ROOT / 'tests/fixtures/hybrid580_uvm_dup_memory_route_test.c',
               ROOT / 'tests/fixtures/hybrid580_uvm_pma_route_test.c',
               ROOT / 'tests/fixtures/hybrid580_uvm_external_mapping_route_test.c',
               ROOT / 'tests/fixtures/hybrid580_uvm_info_registry_test.c',
               ROOT / 'tests/fixtures/standard_node_map_contract.c',
               ROOT / 'tests/fixtures/standard_node_devices_contract.c',
               ROOT / 'tests/fixtures/hybrid580_frontend_admission_test.c',
               open_sym, legacy_sym,
               kernel / '.config', kernel / 'Module.symvers',
               kernel / 'include/config/kernel.release']
    if uvm_consumer_module is not None:
        inputs.append(uvm_consumer_module)
    if uvm_abi == 'r580':
        inputs.append(legacy_uvm_header)
    inputs += [directory / name for directory in (source_headers, legacy_headers) for name in headers + ('rm_session_endpoint.h',)]
    inputs += sorted(conftest.glob('*.h'))
    work = work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'nvidia-hybrid-gpu-file-frontend-v1', 'observed_at_utc': datetime.now(timezone.utc).isoformat(),
              'qualification': 'failed', 'kernel_release': release, 'inputs_sha256': {str(p): sha256(p) for p in inputs},
              'module_name': module_name, 'module_filename': module_name + '.ko',
              'uvm_api_abi': uvm_abi,
              'uvm_api_count_from_selected_open_header': len(standard_uvm_symbols),
              'public_uvm_consumer_binding': {
                  'enabled': uvm_consumer_info is not None,
                  'verified': False,
                  'module': uvm_consumer_info,
                  'api_count': len(standard_uvm_symbols),
                  'matched_count': 0,
                  'missing': [],
                  'mismatches': [],
                  'checks': {},
              },
              'private_provider_hybrid_dispatch_exports_absent': private_dispatch_ownership,
              'shared_api_headers_match_after_backend_name_substitution': True,
              'backend_specific_api_headers': {
                  name: {
                      'open_sha256': sha256(source_headers / name),
                      'legacy_sha256': sha256(legacy_headers / name),
                      'match_after_backend_name_substitution': (
                          (source_headers / name).read_bytes().replace(
                              b'hybrid580_open', b'hybrid580_legacy') ==
                          (legacy_headers / name).read_bytes()),
                  }
                  for name in BACKEND_SPECIFIC_API_HEADERS
              },
              'loaded_or_installed': False, 'device_registered': False, 'real_rm_executed': False,
              'gpu_accessed': False, 'cuda_compatibility_established': False, 'steps': []}
    for name in FRONTEND_SOURCES:
        path = ROOT / 'src' / name
        shutil.copyfile(path, work / path.name)
    include_dirs = [source_headers, ROOT / 'src'] + [open_tree / part for part in (
        'kernel-open/common/inc', 'kernel-open', 'src/common/sdk/nvidia/inc', 'src/common/inc',
        'src/common/inc/swref', 'src/nvidia/arch/nvalloc/unix/include')]
    (work / 'Kbuild').write_text(render_frontend_kbuild(
        module_name, include_dirs, open_sym, legacy_sym, uvm_abi=uvm_abi))
    report['generated_kbuild_sha256'] = sha256(work / 'Kbuild')
    command = ['make', '-C', str(kernel), 'M=' + str(work)]
    compiler = frontend_compiler()
    if compiler:
        command += ['CC=' + compiler]
    command += ['modules']
    log = work / 'build.log'
    with log.open('x') as stream:
        try:
            code = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=90, check=False).returncode
        except subprocess.TimeoutExpired:
            code = 124
    report['steps'].append({'argv': command, 'exit_code': code, 'log': str(log), 'log_sha256': sha256(log)})
    module = work / (module_name + '.ko')
    if code == 0:
        undefined = subprocess.run(['nm', '-u', str(module)], capture_output=True, text=True, check=True).stdout
        imports = sorted({line.split()[-1] for line in undefined.splitlines() if line.split()})
        pools = [('kernel', symbols(kernel / 'Module.symvers')),
                 ('Open private module', symbols(open_sym)), ('legacy private module', symbols(legacy_sym))]
        providers, unresolved, duplicates = {}, [], {}
        for name in imports:
            candidates = [(label, table[name]) for label, table in pools if name in table]
            if not candidates:
                unresolved.append(name)
            elif len(candidates) != 1:
                duplicates[name] = candidates
            else:
                providers[name] = {'provider': candidates[0][0], **candidates[0][1]}
        info = subprocess.run(['modinfo', str(module)], capture_output=True, text=True, check=True).stdout
        module_identity = subprocess.run(
            ['modinfo', '-F', 'name', str(module)], capture_output=True,
            text=True, check=True).stdout.strip()
        report['built_module_identity'] = {
            'expected': module_name,
            'observed': module_identity,
            'matches': module_identity == module_name,
        }
        (work / 'module-info.log').write_text(info)
        (work / 'undefined-symbols.log').write_text(undefined)
        backend_imports = {name: item for name, item in providers.items() if item['provider'] != 'kernel'}
        kernel_config = (kernel / '.config').read_text()
        modversions_enabled = 'CONFIG_MODVERSIONS=y' in kernel_config
        extended_modversions_enabled = 'CONFIG_EXTENDED_MODVERSIONS=y' in kernel_config
        backend_import_crc_checks, backend_import_crc_mismatches = {}, []
        modversions_error = None
        version_dump_log = work / 'backend-import-modversions.log'
        if not modversions_enabled:
            modversions_error = 'kernel CONFIG_MODVERSIONS is disabled'
            version_dump_log.write_text('')
        else:
            modprobe = shutil.which('modprobe')
            if not modprobe:
                modversions_error = 'modprobe is unavailable for import ABI validation'
                version_dump_log.write_text('')
            else:
                version_dump = subprocess.run(
                    [modprobe, '--dump-modversions', str(module)],
                    capture_output=True, text=True, check=False)
                version_dump_log.write_text(version_dump.stdout)
                if version_dump.returncode:
                    try:
                        module_versions = extract_kernel_modversions_section(module, work)
                        version_dump_log.write_text(''.join(
                            f'{crc}\t{name}\n'
                            for name, crc in sorted(module_versions.items())))
                        backend_import_crc_checks, backend_import_crc_mismatches = (
                            check_backend_import_crcs(module_versions, backend_imports))
                    except ValueError as error:
                        modversions_error = (
                            f'modprobe --dump-modversions exited {version_dump.returncode}: '
                            f'{version_dump.stderr.strip()}; ELF __versions fallback failed: {error}')
                else:
                    try:
                        module_versions = parse_module_modversions(version_dump.stdout)
                        if extended_modversions_enabled:
                            # kmod 34.2's --dump-modversions reads only the
                            # legacy fixed-width __versions table. Linux's
                            # extended format carries additional long names
                            # in parallel ELF sections, so merge both and
                            # reject any disagreement on overlapping names.
                            module_versions = merge_module_modversions(
                                module_versions,
                                extract_extended_modversions(module, work))
                        version_dump_log.write_text(''.join(
                            f'{crc}\t{name}\n'
                            for name, crc in sorted(module_versions.items())))
                        backend_import_crc_checks, backend_import_crc_mismatches = (
                            check_backend_import_crcs(
                                module_versions,
                                backend_imports))
                    except ValueError as error:
                        modversions_error = str(error)
        frontend_symvers = symbols(work / 'Module.symvers')
        report['frontend_export_owner_check'] = validate_frontend_export_owners(
            frontend_symvers, module_name, work / module_name)
        open_symvers = open_provider_symvers
        legacy_symvers = legacy_provider_symvers
        hybrid_only_dispatch_ownership = validate_hybrid_dispatch_export_ownership(
            frontend_symvers, open_symvers, legacy_symvers,
            frontend_owner=module_name)
        if uvm_consumer_module is not None:
            consumer_work = work / '.public-uvm-consumer-modversions'
            consumer_work.mkdir()
            consumer_versions = extract_kernel_modversions_section(
                uvm_consumer_module, consumer_work)
            if 'CONFIG_EXTENDED_MODVERSIONS=y' in (kernel / '.config').read_text():
                consumer_versions = merge_module_modversions(
                    consumer_versions,
                    extract_extended_modversions(uvm_consumer_module, consumer_work))
            public_binding = check_public_uvm_consumer_bindings(
                frontend_symvers, consumer_versions, standard_uvm_symbols)
            report['public_uvm_consumer_binding'].update(public_binding)
            report['public_uvm_consumer_binding']['module'] = uvm_consumer_info
            report['public_uvm_consumer_binding']['verified'] = public_binding['verified']
        api_crc_checks = {}
        for name in standard_uvm_symbols:
            open_item = open_symvers.get('hybrid580_open_' + name)
            legacy_item = legacy_symvers.get('hybrid580_legacy_' + name)
            frontend_item = frontend_symvers.get(name)
            check = {
                'frontend_crc': frontend_item['crc'] if frontend_item else None,
                'open_crc': open_item['crc'] if open_item else None,
                'legacy_crc': legacy_item['crc'] if legacy_item else None,
                'matches_both_providers': bool(frontend_item and open_item and legacy_item and
                    frontend_item['crc'].lower() == open_item['crc'].lower() == legacy_item['crc'].lower()),
                'payload_abi_assessment': standard_api_payload_abi_assessment(
                    name, uvm_abi=uvm_abi),
            }
            if name in HYBRID_ONLY_UVM_APIS:
                check.update({
                    'crc_scope': ('hybrid dispatcher export only; provider-private '
                                  'imports remain the unchanged native DupMemory ABI'),
                    'matches_frontend_and_open': None if uvm_abi == 'r580' else bool(frontend_item),
                    'matches_both_providers': None if uvm_abi == 'r580' else check['matches_both_providers'],
                    'open_private_import_matches_provider': None,
                    'legacy_private_import_matches_provider': None,
                    'no_backend_implementation': True,
                    'matches_expected_contract': bool(frontend_item and
                        frontend_item.get('export') == 'EXPORT_SYMBOL'),
                    'contract': 'hybrid-only control-fd dispatcher; no private RM import',
                    'open_private_import': None,
                    'legacy_private_import': None,
                })
            elif uvm_abi == 'r580' and name in FAIL_CLOSED_UVM_APIS:
                check.update(standard_api_r580_contract(
                    frontend_item, open_item, legacy_item, None, None,
                    no_backend_implementation=True))
                check.update({
                    'contract': 'R580 standard export intentionally fails closed; no backend call',
                    'open_private_import': None,
                    'legacy_private_import': None,
                })
            elif uvm_abi == 'r580':
                open_symbol = 'hybrid580_open_' + name
                legacy_symbol = 'hybrid580_legacy_' + name
                check.update(standard_api_r580_contract(
                    frontend_item, open_item, legacy_item,
                    backend_import_crc_checks.get(open_symbol),
                    backend_import_crc_checks.get(legacy_symbol)))
                check.update({
                    'contract': ('R580 public export plus independently CRC-matched '
                                 'private frontend-to-provider imports; public consumer '
                                 'binding is verified by the separate UVM build'),
                    'open_private_import': open_symbol,
                    'legacy_private_import': legacy_symbol,
                })
            elif name in ('nvUvmInterfaceRegisterUvmEvents',
                        'nvUvmInterfaceDeRegisterUvmEvents'):
                legacy_symbol = {
                    'nvUvmInterfaceRegisterUvmEvents':
                        'hybrid580_legacy_nvUvmInterfaceRegisterUvmCallbacks',
                    'nvUvmInterfaceDeRegisterUvmEvents':
                        'hybrid580_legacy_nvUvmInterfaceDeRegisterUvmOps',
                }[name]
                legacy_adapter_item = legacy_symvers.get(legacy_symbol)
                open_symbol = 'hybrid580_open_' + name
                contract = standard_api_r595_contract(
                    frontend_item, open_item, legacy_adapter_item,
                    backend_import_crc_checks.get(open_symbol),
                    backend_import_crc_checks.get(legacy_symbol))
                check.update(contract)
                check['legacy_crc'] = (
                    legacy_adapter_item['crc'] if legacy_adapter_item else None)
                check.update({
                    'contract': ('R595 public export plus independently CRC-matched '
                                 'Open-private and R580 legacy-adapter imports'),
                    'open_private_import': open_symbol,
                    'legacy_adapter_import': legacy_symbol,
                })
            elif name in R595_OPEN_ONLY_UVM_APIS:
                open_symbol = 'hybrid580_open_' + name
                check.update(standard_api_r595_open_only_contract(
                    frontend_item, open_item,
                    backend_import_crc_checks.get(open_symbol)))
                check.update({
                    'contract': ('R595-only API; exact native payload is routed to Open; '
                                 'R580 legacy provider intentionally lacks this API'),
                    'open_private_import': open_symbol,
                    'legacy_private_import': None,
                })
            elif name in FAIL_CLOSED_UVM_APIS:
                open_symbol = 'hybrid580_open_' + name
                legacy_symbol = 'hybrid580_legacy_' + name
                check.update(standard_api_r595_contract(
                    frontend_item, open_item, legacy_item,
                    backend_import_crc_checks.get(open_symbol),
                    backend_import_crc_checks.get(legacy_symbol),
                    no_backend_implementation=True))
                check.update({
                    'contract': 'R595 export is an intentional fail-closed stub; no RM call',
                    'open_private_import': open_symbol,
                    'legacy_private_import': legacy_symbol,
                })
            else:
                open_symbol = 'hybrid580_open_' + name
                legacy_symbol = 'hybrid580_legacy_' + name
                check.update(standard_api_r595_contract(
                    frontend_item, open_item, legacy_item,
                    backend_import_crc_checks.get(open_symbol),
                    backend_import_crc_checks.get(legacy_symbol)))
                check.update({
                    'contract': ('R595 standard frontend ABI; backend-private symbol CRCs '
                                 'validated independently; payload ABI is separate'),
                    'open_private_import': open_symbol,
                    'legacy_private_import': legacy_symbol,
                })
            if uvm_consumer_module is not None:
                consumer_check = report['public_uvm_consumer_binding']['checks'][name]
                check['public_consumer_import_crc'] = consumer_check['consumer_import_crc']
                check['public_consumer_matches_frontend'] = consumer_check['matches']
                check['public_consumer_binding_in_this_build'] = True
                check['matches_expected_contract'] = bool(
                    check['matches_expected_contract'] and consumer_check['matches'])
            else:
                check['public_consumer_import_crc'] = None
                check['public_consumer_matches_frontend'] = None
            api_crc_checks[name] = check
        objtool_command_evidence = validate_objtool_build_commands(work, module_name)
        objtool_active = objtool_command_evidence['active']
        dependencies = set()
        for cmdfile in (work / '.hybrid_frontend.o.cmd', work / '.rm_root_client.o.cmd',
                        work / '.hybrid580_uvm_callback_bridge.o.cmd',
                        work / '.hybrid580-gpu-catalog.o.cmd',
                        work / '.hybrid580-device-instance-map.o.cmd',
                        work / '.hybrid580-standard-node-map.o.cmd',
                        work / '.hybrid580-standard-node-devices.o.cmd'):
            for line in cmdfile.read_text().splitlines():
                candidate = line.strip().removesuffix('\\').strip()
                if candidate.startswith('/') and Path(candidate).is_file():
                    dependencies.add(Path(candidate))
        logs = log.read_text()
        warnings = [line for line in logs.splitlines() if 'warning:' in line.lower()]
        report.update(module={'path': str(module), 'sha256': sha256(module), 'bytes': module.stat().st_size},
                      imports=providers, unresolved_imports=unresolved, duplicate_import_providers=duplicates,
                      hybrid_only_dispatch_ownership=hybrid_only_dispatch_ownership,
                      objtool_active=objtool_active,
                      objtool_command_evidence=objtool_command_evidence,
                      compiled_dependency_sha256={str(p): sha256(p) for p in sorted(dependencies)},
                      backend_imports=backend_imports, module_info=info, build_warnings=warnings,
                      backend_import_crc_validation={
                          'enabled': modversions_enabled,
                          'extended_format_enabled': extended_modversions_enabled,
                          'tool': ('modprobe --dump-modversions + objcopy extended ELF sections'
                                   if extended_modversions_enabled else
                                   'modprobe --dump-modversions'),
                          'verified': modversions_error is None and
                          not backend_import_crc_mismatches,
                          'error': modversions_error,
                          'checks': backend_import_crc_checks,
                          'mismatches': backend_import_crc_mismatches,
                          'dump_log': str(version_dump_log),
                          'dump_sha256': sha256(version_dump_log),
                      },
                      dual_provider_uvm_callback_exports={
                          name: item for name, item in symbols(work / 'Module.symvers').items()
                          if name in ('nvUvmInterfaceRegisterUvmEvents',
                                      'nvUvmInterfaceDeRegisterUvmEvents',
                                      'nvUvmInterfaceRegisterUvmCallbacks',
                                      'nvUvmInterfaceDeRegisterUvmOps')},
                      hybrid_uvm_session_exports={
                          name: item for name, item in symbols(work / 'Module.symvers').items()
                          if name in ('nvUvmInterfaceSessionCreate',
                                      'nvUvmInterfaceSessionDestroy')},
                      hybrid_uvm_gpu_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceRegisterGpu',
                                      'nvUvmInterfaceUnregisterGpu',
                                      'nvUvmInterfaceGetGpuInfo')},
                      hybrid_uvm_device_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceDeviceCreate',
                                      'nvUvmInterfaceDeviceDestroy')},
                      hybrid_uvm_device_query_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceGetFbInfo',
                                      'nvUvmInterfaceQueryCaps',
                                      'nvUvmInterfaceQueryCopyEnginesCaps',
                                      'nvUvmInterfaceGetEccInfo',
                                      'nvUvmInterfaceGetNvlinkInfo')},
                      hybrid_uvm_device_pair_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceGetP2PCaps',)},
                      hybrid_uvm_p2p_object_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceP2pObjectCreate',
                                      'nvUvmInterfaceP2pObjectDestroy')},
                      hybrid_uvm_pma_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceGetPmaObject',
                                      'nvUvmInterfacePmaRegisterEvictionCallbacks',
                                      'nvUvmInterfacePmaUnregisterEvictionCallbacks',
                                      'nvUvmInterfacePmaAllocPages',
                                      'nvUvmInterfacePmaPinPages',
                                      'nvUvmInterfacePmaFreePages')},
                      hybrid_uvm_external_mapping_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceGetExternalAllocPtes',
                                      'nvUvmInterfaceGetExternalAllocPhysAddrs')},
                      hybrid_uvm_fault_info_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceInitFaultInfo',
                                      'nvUvmInterfaceDestroyFaultInfo',
                                      'nvUvmInterfaceHasPendingNonReplayableFaults',
                                      'nvUvmInterfaceGetNonReplayableFaults',
                                      'nvUvmInterfaceFlushReplayableFaultBuffer',
                                      'nvUvmInterfaceTogglePrefetchFaults')},
                      hybrid_uvm_access_counter_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceInitAccessCntrInfo',
                                      'nvUvmInterfaceDestroyAccessCntrInfo',
                                      'nvUvmInterfaceEnableAccessCntr',
                                      'nvUvmInterfaceDisableAccessCntr')},
                      hybrid_uvm_error_reporting_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceReportNonReplayableFault',
                                      'nvUvmInterfaceReportFatalError')},
                      hybrid_uvm_paging_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfacePagingChannelAllocate',
                                      'nvUvmInterfacePagingChannelDestroy',
                                      'nvUvmInterfacePagingChannelsMap',
                                      'nvUvmInterfacePagingChannelsUnmap',
                                      'nvUvmInterfacePagingChannelPushStream')},
                      hybrid_uvm_csl_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceCslInitContext',
                                      'nvUvmInterfaceDeinitCslContext',
                                      'nvUvmInterfaceCslRotateKey',
                                      'nvUvmInterfaceCslRotateIv',
                                      'nvUvmInterfaceCslEncrypt',
                                      'nvUvmInterfaceCslDecrypt',
                                      'nvUvmInterfaceCslSign',
                                      'nvUvmInterfaceCslQueryMessagePool',
                                      'nvUvmInterfaceCslIncrementIv',
                                      'nvUvmInterfaceCslLogEncryption')},
                      hybrid_uvm_address_space_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceAddressSpaceCreate',
                                      'nvUvmInterfaceDupAddressSpace',
                                      'nvUvmInterfaceDupAddressSpaceWithControlFd',
                                      'nvUvmInterfaceDupAllocation',
                                      'nvUvmInterfaceAddressSpaceDestroy')},
                      hybrid_uvm_page_directory_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceSetPageDirectory',
                                      'nvUvmInterfaceUnsetPageDirectory')},
                      hybrid_uvm_device_interrupt_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceOwnPageFaultIntr',
                                      'nvUvmInterfaceServiceDeviceInterruptsRM')},
                      hybrid_uvm_memory_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceMemoryAllocFB',
                                      'nvUvmInterfaceMemoryAllocSys',
                                      'nvUvmInterfaceMemoryFree',
                                      'nvUvmInterfaceMemoryCpuMap',
                                      'nvUvmInterfaceMemoryCpuUnMap',
                                      'nvUvmInterfaceDupMemoryWithControlFd',
                                      'nvUvmInterfaceDupMemory',
                                      'nvUvmInterfaceFreeDupedHandle')},
                      hybrid_uvm_tsg_channel_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceTsgAllocate',
                                      'nvUvmInterfaceTsgDestroy',
                                      'nvUvmInterfaceChannelAllocate',
                                      'nvUvmInterfaceChannelDestroy')},
                      hybrid_uvm_retained_channel_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in ('nvUvmInterfaceRetainChannel',
                                      'nvUvmInterfaceBindChannelResources',
                                      'nvUvmInterfaceReleaseChannel',
                                      'nvUvmInterfaceStopChannel',
                                      'nvUvmInterfaceGetChannelResourcePtes')},
                      hybrid_uvm_access_bits_exports={
                          name: item for name, item in frontend_symvers.items()
                          if name in R595_OPEN_ONLY_UVM_APIS},
                      hybrid_uvm_api_crc_checks=api_crc_checks,
                      hybrid_uvm_api_contract_failures=sorted(
                          name for name, item in api_crc_checks.items()
                          if not item['matches_expected_contract']),
                      hybrid_uvm_payload_abi_classification_counts={
                          classification: sum(
                              1 for check in api_crc_checks.values()
                              if check['payload_abi_assessment']['classification'] == classification)
                          for classification in sorted({
                              check['payload_abi_assessment']['classification']
                              for check in api_crc_checks.values()})
                      },
                      hybrid_uvm_api_crc_mismatches=sorted(
                          name for name, item in api_crc_checks.items()
                          if not item['matches_expected_contract']),
                      naked_return_or_objtool_warnings=[w for w in warnings if 'objtool' in w.lower() or 'naked' in w.lower()],
                      generated_outputs_sha256={str(work / name): sha256(work / name) for name in (
                          'Kbuild', 'Module.symvers', 'module-info.log', 'undefined-symbols.log',
                          'backend-import-modversions.log',
                          '.hybrid_frontend.o.cmd', '.rm_root_client.o.cmd', '.hybrid580-gpu-catalog.o.cmd',
                          '.hybrid580_uvm_callback_bridge.o.cmd',
                          '.hybrid580-device-instance-map.o.cmd',
                          '.hybrid580-standard-node-map.o.cmd',
                          '.hybrid580-standard-node-devices.o.cmd',
                          f'.{module_name}.o.cmd', f'.{module_name}.ko.cmd')})
        expected_backend = expected_backend_imports(
            uvm_abi=uvm_abi, standard_uvm_symbols=standard_uvm_symbols)
        if unresolved or duplicates or set(backend_imports) != expected_backend:
            report['error'] = 'unexpected unresolved/duplicate/backend imports'
        elif any(item['export'] != 'EXPORT_SYMBOL' for item in backend_imports.values()):
            report['error'] = 'private backend API export flavor mismatch'
        elif modversions_error:
            report['error'] = 'private backend import ABI validation unavailable: ' + modversions_error
        elif backend_import_crc_mismatches:
            report['error'] = 'private backend import CRC differs from selected provider'
        elif 'license:        Dual MIT/GPL' not in info:
            report['error'] = 'frontend license mismatch'
        elif module_identity != module_name:
            report['error'] = 'built module identity does not match requested name'
        elif not ({
                'nvUvmInterfaceRegisterUvmCallbacks',
                'nvUvmInterfaceDeRegisterUvmOps',
        } if uvm_abi == 'r580' else {
                'nvUvmInterfaceRegisterUvmEvents',
                'nvUvmInterfaceDeRegisterUvmEvents',
        }) <= set(report['dual_provider_uvm_callback_exports']):
            report['error'] = 'dual-provider UVM callback exports are missing'
        elif not {
                'nvUvmInterfaceSessionCreate',
                'nvUvmInterfaceSessionDestroy',
        } <= set(report['hybrid_uvm_session_exports']):
            report['error'] = 'hybrid UVM session exports are missing'
        elif not {
                'nvUvmInterfaceRegisterGpu',
                'nvUvmInterfaceUnregisterGpu',
                'nvUvmInterfaceGetGpuInfo',
        } <= set(report['hybrid_uvm_gpu_exports']):
            report['error'] = 'hybrid UVM GPU identity/info exports are missing'
        elif not {
                'nvUvmInterfaceDeviceCreate',
                'nvUvmInterfaceDeviceDestroy',
        } <= set(report['hybrid_uvm_device_exports']):
            report['error'] = 'hybrid UVM device lifecycle exports are missing'
        elif not {
                'nvUvmInterfaceGetFbInfo',
                'nvUvmInterfaceQueryCaps',
                'nvUvmInterfaceQueryCopyEnginesCaps',
                'nvUvmInterfaceGetEccInfo',
                'nvUvmInterfaceGetNvlinkInfo',
        } <= set(report['hybrid_uvm_device_query_exports']):
            report['error'] = 'hybrid UVM device metadata exports are missing'
        elif 'nvUvmInterfaceGetP2PCaps' not in report['hybrid_uvm_device_pair_exports']:
            report['error'] = 'hybrid UVM P2P capability export is missing'
        elif not {
                'nvUvmInterfaceP2pObjectCreate',
                'nvUvmInterfaceP2pObjectDestroy',
        } <= set(report['hybrid_uvm_p2p_object_exports']):
            report['error'] = 'hybrid UVM P2P-object lifecycle exports are missing'
        elif not {
                'nvUvmInterfaceGetPmaObject',
                'nvUvmInterfacePmaRegisterEvictionCallbacks',
                'nvUvmInterfacePmaUnregisterEvictionCallbacks',
                'nvUvmInterfacePmaAllocPages',
                'nvUvmInterfacePmaPinPages',
                'nvUvmInterfacePmaFreePages',
        } <= set(report['hybrid_uvm_pma_exports']):
            report['error'] = 'hybrid UVM PMA exports are missing'
        elif not {
                'nvUvmInterfaceGetExternalAllocPtes',
                'nvUvmInterfaceGetExternalAllocPhysAddrs',
        } <= set(report['hybrid_uvm_external_mapping_exports']):
            report['error'] = 'hybrid UVM external-allocation mapping exports are missing'
        elif not {
                'nvUvmInterfaceInitFaultInfo',
                'nvUvmInterfaceDestroyFaultInfo',
                'nvUvmInterfaceHasPendingNonReplayableFaults',
                'nvUvmInterfaceGetNonReplayableFaults',
                'nvUvmInterfaceFlushReplayableFaultBuffer',
                'nvUvmInterfaceTogglePrefetchFaults',
        } <= set(report['hybrid_uvm_fault_info_exports']):
            report['error'] = 'hybrid UVM fault-info exports are missing'
        elif not {
                'nvUvmInterfaceInitAccessCntrInfo',
                'nvUvmInterfaceDestroyAccessCntrInfo',
                'nvUvmInterfaceEnableAccessCntr',
                'nvUvmInterfaceDisableAccessCntr',
        } <= set(report['hybrid_uvm_access_counter_exports']):
            report['error'] = 'hybrid UVM access-counter exports are missing'
        elif not {
                'nvUvmInterfaceReportNonReplayableFault',
                'nvUvmInterfaceReportFatalError',
        } <= set(report['hybrid_uvm_error_reporting_exports']):
            report['error'] = 'hybrid UVM error-reporting exports are missing'
        elif not {
                'nvUvmInterfacePagingChannelAllocate',
                'nvUvmInterfacePagingChannelDestroy',
                'nvUvmInterfacePagingChannelsMap',
                'nvUvmInterfacePagingChannelsUnmap',
                'nvUvmInterfacePagingChannelPushStream',
        } <= set(report['hybrid_uvm_paging_exports']):
            report['error'] = 'hybrid UVM paging-channel exports are missing'
        elif not {
                'nvUvmInterfaceCslInitContext',
                'nvUvmInterfaceDeinitCslContext',
                'nvUvmInterfaceCslRotateKey',
                'nvUvmInterfaceCslRotateIv',
                'nvUvmInterfaceCslEncrypt',
                'nvUvmInterfaceCslDecrypt',
                'nvUvmInterfaceCslSign',
                'nvUvmInterfaceCslQueryMessagePool',
                'nvUvmInterfaceCslIncrementIv',
                'nvUvmInterfaceCslLogEncryption',
        } <= set(report['hybrid_uvm_csl_exports']):
            report['error'] = 'hybrid UVM CSL exports are missing'
        elif not {
                'nvUvmInterfaceAddressSpaceCreate',
                'nvUvmInterfaceDupAddressSpace',
                'nvUvmInterfaceDupAddressSpaceWithControlFd',
                'nvUvmInterfaceDupAllocation',
                'nvUvmInterfaceAddressSpaceDestroy',
        } <= set(report['hybrid_uvm_address_space_exports']):
            report['error'] = 'hybrid UVM address-space exports are missing'
        elif not {
                'nvUvmInterfaceSetPageDirectory',
                'nvUvmInterfaceUnsetPageDirectory',
        } <= set(report['hybrid_uvm_page_directory_exports']):
            report['error'] = 'hybrid UVM page-directory exports are missing'
        elif not {
                'nvUvmInterfaceOwnPageFaultIntr',
                'nvUvmInterfaceServiceDeviceInterruptsRM',
        } <= set(report['hybrid_uvm_device_interrupt_exports']):
            report['error'] = 'hybrid UVM device interrupt exports are missing'
        elif not {
                'nvUvmInterfaceMemoryAllocFB',
                'nvUvmInterfaceMemoryAllocSys',
                'nvUvmInterfaceMemoryFree',
                'nvUvmInterfaceMemoryCpuMap',
                'nvUvmInterfaceMemoryCpuUnMap',
                'nvUvmInterfaceDupMemoryWithControlFd',
                'nvUvmInterfaceDupMemory',
                'nvUvmInterfaceFreeDupedHandle',
        } <= set(report['hybrid_uvm_memory_exports']):
            report['error'] = 'hybrid UVM memory exports are missing'
        elif not {
                'nvUvmInterfaceTsgAllocate',
                'nvUvmInterfaceTsgDestroy',
                'nvUvmInterfaceChannelAllocate',
                'nvUvmInterfaceChannelDestroy',
        } <= set(report['hybrid_uvm_tsg_channel_exports']):
            report['error'] = 'hybrid UVM TSG/channel exports are missing'
        elif not {
                'nvUvmInterfaceRetainChannel',
                'nvUvmInterfaceBindChannelResources',
                'nvUvmInterfaceReleaseChannel',
                'nvUvmInterfaceStopChannel',
                'nvUvmInterfaceGetChannelResourcePtes',
        } <= set(report['hybrid_uvm_retained_channel_exports']):
            report['error'] = 'hybrid UVM retained-channel exports are missing'
        elif (uvm_abi == 'r595' and
              not R595_OPEN_ONLY_UVM_APIS <= set(report['hybrid_uvm_access_bits_exports'])):
            report['error'] = 'R595 access-bits UVM exports are missing'
        elif (report['public_uvm_consumer_binding']['enabled'] and
              not report['public_uvm_consumer_binding']['verified']):
            report['error'] = 'R595 public UVM consumer ABI mismatch'
        elif report['hybrid_uvm_api_contract_failures']:
            report['error'] = 'hybrid UVM standard/backend ABI contract mismatch'
        elif not report['objtool_active']:
            report['error'] = 'objtool mitigation checks not established'
        elif report['naked_return_or_objtool_warnings']:
            report['error'] = 'objtool warning'
        else:
            report['qualification'] = 'compiled-bdf-selected-gpu-file-frontend-kernel-module'
    else:
        report['error'] = f'Kbuild exited {code}; see {log}'
    report['inputs_unchanged'] = all(sha256(Path(path)) == digest for path, digest in report['inputs_sha256'].items())
    if not report['inputs_unchanged']:
        report.update(qualification='failed', error='input changed during build')
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--kernel-release', default=os.uname().release)
    parser.add_argument('--kernel-build', type=Path,
                        help='explicit kernel build/header tree; defaults to /lib/modules/<release>/build')
    parser.add_argument('--uvm-abi', choices=('r580', 'r595'), default='r595',
                        help='public UVM ABI; R580 uses same-version R580 providers')
    parser.add_argument('--module-name', choices=FRONTEND_MODULE_NAMES,
                        default='hybrid580_frontend',
                        help='kernel module identity; nvidia matches stock helper checks')
    parser.add_argument('--open-backend', type=Path,
                        help='private Open backend source tree (default depends on --uvm-abi)')
    parser.add_argument('--legacy-backend', type=Path,
                        help='private proprietary backend source tree (default depends on --uvm-abi)')
    parser.add_argument('--uvm-consumer-module', type=Path,
                        help=('exact-target nvidia_uvm.ko used to verify public UVM '
                              'export/import CRC binding; required for R595'))
    args = parser.parse_args()
    if args.report.exists():
        parser.error('report already exists')
    default_open, default_legacy = default_provider_trees(args.uvm_abi)
    report = build(args.work, args.open_backend or default_open,
                   args.legacy_backend or default_legacy, release=args.kernel_release,
                   uvm_abi=args.uvm_abi, module_name=args.module_name,
                   kernel_build=args.kernel_build,
                   uvm_consumer_module=args.uvm_consumer_module)
    with args.report.open('x') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report.get(key) for key in ('qualification', 'error')}))
    return 0 if report['qualification'] == 'compiled-bdf-selected-gpu-file-frontend-kernel-module' else 1


if __name__ == '__main__':
    raise SystemExit(main())
