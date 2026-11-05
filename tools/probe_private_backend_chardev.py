#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile the private Open R580 backend with dynamic character-device ownership; never load it."""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('private_backend',ROOT/'tools/probe_private_backend_module.py')
private=importlib.util.module_from_spec(spec)
spec.loader.exec_module(private)
PCI_PATCH=ROOT/'patches/r580.178.04/0003-private-open-pci-guard.patch'
PATCH=ROOT/'patches/r580.178.04/0004-private-open-chardev.patch'
RESOURCE_PATCHES=[ROOT/('patches/r580.178.04/'+name) for name in (
    '0005-private-open-procfs-path.patch',
    '0006-private-open-resource-names.patch',
    '0007-private-open-pci-only-lifecycle.patch')]
PROJECTION_PATCH=ROOT/'patches/r580.178.04/0008-private-open-file-projection.patch'
SESSION_PATCH=ROOT/'patches/r580.178.04/0009-private-open-control-session.patch'
CONTROL_ATTACH_PATCH=ROOT/'patches/r580.178.04/0013-private-control-attach.patch'
CONTROL_ATTACH_GPU_PATCH=ROOT/'patches/r580.178.04/0014-private-control-attach-after-gpu.patch'
CARD_INFO_PATCH=ROOT/'patches/r580.178.04/0015-private-open-card-info.patch'
GPU_ID_INFO_PATCH=ROOT/'patches/r580.178.04/0016-private-open-gpu-id-info.patch'
ATTACHED_IDS_PATCH=ROOT/'patches/r580.178.04/0017-private-open-attached-ids.patch'
PROBED_IDS_PATCH=ROOT/'patches/r580.178.04/0018-private-open-probed-ids.patch'
DEVICE_IDS_PATCH=ROOT/'patches/r580.178.04/0019-private-open-device-ids.patch'
DEVICE_OBJECT_PATCH=ROOT/'patches/r580.178.04/0020-private-open-device-object.patch'
MEMORY_OBJECT_PATCH=ROOT/'patches/r580.178.04/0021-private-open-memory-object.patch'
VASPACE_OBJECT_PATCH=ROOT/'patches/r580.178.04/0022-private-open-vaspace-object.patch'
CHANNEL_GROUP_OBJECT_PATCH=ROOT/'patches/r580.178.04/0023-private-open-channel-group-object.patch'
CONTEXT_SHARE_OBJECT_PATCH=ROOT/'patches/r580.178.04/0024-private-open-context-share-object.patch'
CHANNEL_OBJECT_PATCH=ROOT/'patches/r580.178.04/0025-private-open-channel-object.patch'
SUBDEVICE_TPC_MASK_PATCH=ROOT/'patches/r580.178.04/0026-private-open-subdevice-and-tpc-mask.patch'
BINAPI_OBJECT_PATCH=ROOT/'patches/r580.178.04/0027-private-open-binapi-object.patch'
USERMODE_OBJECT_PATCH=ROOT/'patches/r580.178.04/0028-private-open-usermode-object.patch'
MAP_MEMORY_PATCH=ROOT/'patches/r580.178.04/0029-private-open-map-memory.patch'
RUSD_OBJECT_PATCH=ROOT/'patches/r580.178.04/0030-private-open-rusd-object.patch'
SYS_PARAMS_PATCH=ROOT/'patches/r580.178.04/0037-private-open-sys-params.patch'
BUILD_VERSION_PATCH=ROOT/'patches/r580.178.04/0038-private-open-build-version-v1.patch'
OPEN_BUILD_VERSION_HEADER=ROOT/'src/hybrid580-open-build-version.h'
PM_CHANNEL_DEPTH_ENUM_PATCH=ROOT/'patches/r580.178.04/0001-private-open-pm-channel-depth-enum.patch'
PM_CHANNEL_DEPTH_PATCH=ROOT/'patches/r580.178.04/0031-private-open-pm-channel-depth.patch'
PM_VMA_ACCESS_PATCH=ROOT/'patches/r580.178.04/0033-private-open-pm-vma-access-guard.patch'
PM_VMA_FREE_LIST_PATCH=ROOT/'patches/r580.178.04/0034-private-open-vma-free-list-lock.patch'
PM_RECOVERY_PROVIDER_PATCH=ROOT/'patches/r580.178.04/0035-private-open-pm-recovery-provider.patch'
PM_CHANNEL_DPM_MODESET_PATCH=ROOT/'patches/r580.178.04/0036-private-open-pm-channel-dpm-modeset.patch'
GPU_SESSION_PATCHES=[ROOT/'patches/r580.178.04/0010-private-open-gpu-session.patch',
    ROOT/'patches/r580.178.04/0011-private-open-gpu-session-bdf-lookup.patch',
    ROOT/'patches/r580.178.04/0012-private-open-gpu-inventory.patch']
GPU_REGISTER_CONTROL_PATCH=ROOT/'patches/r580.178.04/0039-private-open-gpu-register-control.patch'
ENGINE_OBJECT_PATCH=ROOT/'patches/r580.178.04/0040-private-open-engine-object.patch'
SESSION_HEADER=ROOT/'src/rm_session_endpoint.h'
CONTROL_SESSION_HEADER=ROOT/'src/hybrid580-control-session.h'
GPU_SESSION_HEADER=ROOT/'src/hybrid580-gpu-session.h'
GPU_CATALOG_HEADER=ROOT/'src/hybrid580-gpu-catalog.h'

def validate_backend_exports(original, actual, projection, control_session=False,
                             gpu_session=False, pm_recovery=False,
                             sys_params=False, build_version=False,
                             client_share_policy=False):
    expected={private.PREFIX+name:flavor for name,flavor in original.items()}
    if projection:
        for operation in ('register','unregister'):
            expected['hybrid580_open_'+operation+'_file_projection_v1']='EXPORT_SYMBOL'
    if control_session:
        for operation in ('create','get','put','file','attach'):
            expected['hybrid580_open_control_session_'+operation+'_v1']='EXPORT_SYMBOL'
    if gpu_session:
        for operation in ('create','create_by_bdf','get','put','file','ioctl','register_control'):
            expected['hybrid580_open_gpu_session_'+operation+'_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_gpu_inventory_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_gpu_card_info_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_gpu_id_info_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_attached_ids_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_probed_ids_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_device_ids_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_device_alloc_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_device_free_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_memory_alloc_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_object_free_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_vaspace_alloc_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_channel_group_alloc_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_context_share_alloc_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_channel_alloc_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_engine_alloc_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_subdevice_alloc_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_gr_tpc_mask_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_gpu_name_string_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_binapi_alloc_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_rusd_alloc_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_usermode_alloc_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_map_memory_v1']='EXPORT_SYMBOL'
        expected['hybrid580_open_control_session_unmap_memory_v1']='EXPORT_SYMBOL'
    if pm_recovery:
        for operation in ('begin', 'recover', 'end'):
            expected['hybrid580_open_pm_recovery_' + operation + '_v1']='EXPORT_SYMBOL'
        for operation in ('suspend', 'resume'):
            expected['hybrid580_open_pm_channels_' + operation + '_v1']='EXPORT_SYMBOL'
        for operation in ('suspend', 'resume'):
            expected['hybrid580_open_pm_shared_uvm_' + operation + '_v1']='EXPORT_SYMBOL'
    if sys_params:
        expected['hybrid580_open_control_session_sys_params_v1']='EXPORT_SYMBOL'
    if build_version:
        expected['hybrid580_open_control_session_build_version_v1']='EXPORT_SYMBOL'
    if client_share_policy:
        expected['hybrid580_open_control_session_client_share_policy_v1']='EXPORT_SYMBOL'
    if actual!=expected:
        raise ValueError('backend exports differ from exact private API/flavor contract')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir',type=Path,default=ROOT/'build/experiments/private-open-chardev-v1')
    parser.add_argument('--report',type=Path,default=ROOT/'evidence/private-open-chardev-20261019.json')
    parser.add_argument('--jobs',type=int,default=4)
    parser.add_argument('--kernel-release',default=os.uname().release)
    parser.add_argument('--resource-isolation',action='store_true',
        help='also patch procfs/capability names and restrict registration to PCI GPUs')
    parser.add_argument('--file-projection',action='store_true',
        help='also compile the versioned frontend file-projection hook (requires resource isolation)')
    parser.add_argument('--control-session',action='store_true',
        help='also compile exclusive private control sessions (requires file projection)')
    parser.add_argument('--gpu-session',action='store_true',
        help='also compile pinned-BDF private GPU-file sessions (requires control sessions)')
    parser.add_argument('--hybrid-pm-depth',action='store_true',
        help='also compile the private channels-only PM phase (requires GPU sessions)')
    parser.add_argument('--hybrid-sys-params',action='store_true',
        help='compile the typed NV_ESC_SYS_PARAMS control-device bridge (requires GPU sessions)')
    parser.add_argument('--hybrid-build-version',action='store_true',
        help='compile the pointer-free R580 V2 build-version RM bridge (requires GPU sessions)')
    parser.add_argument('--core',type=Path,help='alternative Open-only compiled core, with explicit digest')
    parser.add_argument('--core-sha256',help='expected SHA-256 of the alternative Open core')
    args=parser.parse_args()
    if (args.core is None)!=(args.core_sha256 is None):
        parser.error('--core and --core-sha256 must be provided together')
    if args.core_sha256 is not None and not re.fullmatch('[0-9a-f]{64}',args.core_sha256):
        parser.error('--core-sha256 must contain 64 lowercase hexadecimal characters')
    if args.file_projection and not args.resource_isolation:
        parser.error('--file-projection requires --resource-isolation')
    if args.control_session and not args.file_projection:
        parser.error('--control-session requires --file-projection')
    if args.gpu_session and not args.control_session:
        parser.error('--gpu-session requires --control-session')
    if args.hybrid_pm_depth and not args.gpu_session:
        parser.error('--hybrid-pm-depth requires --gpu-session')
    if args.hybrid_sys_params and not args.gpu_session:
        parser.error('--hybrid-sys-params requires --gpu-session')
    if args.hybrid_build_version and not args.gpu_session:
        parser.error('--hybrid-build-version requires --gpu-session')
    core=args.core.resolve() if args.core is not None else private.CORE
    core_sha=args.core_sha256 or private.CORE_SHA
    work=args.work_dir.resolve();reportpath=args.report.resolve()
    if work.exists() or reportpath.exists(): parser.error('existing scratch/report refused')
    if args.jobs<1: parser.error('positive jobs required')
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    report={'schema':'private-open-chardev-v1','observed_at_utc':datetime.now(timezone.utc).isoformat(),
        'qualification':'not-started','loaded_or_installed':False,'hardware_validated':False,
        'runtime_isolation_validated':False,'module_license_changed':False,'steps':[],
        'scope':'dynamic character major, source PCI selection and private exports; Open-only core',
        'resource_isolation_requested':args.resource_isolation,
        'file_projection_requested':args.file_projection,
        'control_session_requested':args.control_session,
        'gpu_session_requested':args.gpu_session,
        'hybrid_pm_depth_requested':args.hybrid_pm_depth,
        'hybrid_sys_params_requested':args.hybrid_sys_params,
        'hybrid_build_version_requested':args.hybrid_build_version,
        'selected_core':{'path':str(core),'sha256':core_sha,'alternative':args.core is not None},
        'character_devices':{'allocation':'alloc_chrdev_region','first_minor':0,'count':256,'regular_count':248,'control_minor':255,'name':'hybrid580_open','public_major_alias':False,'automatic_devnodes':False},
        'selector':{'parameter':'hybrid_gpu_pci','type':'charp','permission':'0400','default':None,
                    'format':'exact lowercase dddd:bb:ss.f; slots 00..1f; functions 0..7'},
        'remaining_boundaries':['device nodes/procfs/capabilities/NVLink namespaces','private-major discovery and frontend routing',
             'backend-specific frontend/event/file lifetime','matching UVM/modeset import routing',
             'common CUDA handle/control ownership','platform(non-PCI) GPU probe paths untouched',
             'module-wide early initialization before PCI registration not guarded by BDF selector'],
        'existing_mechanism_rejected':{'name':'ExcludedGpus/GpuBlacklist','reason':'UUID read through RM by nv_check_and_exclude_gpu after PCI/RM setup; not an early deny-by-default BDF selector'}}
    patches=[private.PATCH,PCI_PATCH,PATCH]
    contracts=['test_private_backend_chardev.py']
    if args.resource_isolation:
        patches.extend(RESOURCE_PATCHES)
        contracts.extend(['test_private_backend_pci.py','test_private_backend_procfs.py',
                          'test_private_backend_resource_names.py','test_private_backend_pci_scope.py'])
        report.update(scope='private Open wrapper resources and PCI-GPU-only registration; Open core unchanged',
            remaining_boundaries=['private-major discovery and common frontend ioctl routing',
                'backend-specific event/file/container lifetime','matching UVM/modeset imports and namespaces',
                'common CUDA handle/control ownership','independent initialized RM state at runtime',
                'module-wide RM initialization still precedes BDF-filtered PCI registration',
                'vendor user-space utilities do not discover private resource names'],
            disabled_in_prototype=['NVSwitch driver initialization and presence override',
                'platform GPU driver registration and counting','public PCI/OF hardware autoload aliases'])
    if args.file_projection:
        patches.append(PROJECTION_PATCH)
        contracts.append('test_private_backend_file_projection.py')
        report['remaining_boundaries'].append(
            'frontend/provider and private backend control files are not implemented or registered at runtime')
    if args.control_session:
        patches.append(SESSION_PATCH)
        contracts.append('test_private_backend_control_session.py')
        report['remaining_boundaries']=[entry for entry in report['remaining_boundaries']
            if entry!='frontend/provider and private backend control files are not implemented or registered at runtime']
        report['remaining_boundaries'].extend([
            'private control construction/invocation is compiled and CPU-modeled only',
            'real frontend/provider and dual-backend broker wiring are not installed or runtime tested',
            'fput can defer RM cleanup; final file-reference drainage is not hardware validated'])
    if args.gpu_session:
        patches.extend(GPU_SESSION_PATCHES)
        contracts.append('test_private_backend_gpu_session.py')
        report['remaining_boundaries']=[entry for entry in report['remaining_boundaries']
            if entry!='backend-specific event/file/container lifetime']
        report['remaining_boundaries'].extend([
            'GPU-file session creation, ioctl forwarding and BDF checks are compiled and CPU/source-tested only',
            'typed RM map/unmap backend APIs and frontend mmap projection are compiled and CPU-modeled only',
            'standard CUDA device-node enumeration, general RM controls, events and UVM routing remain absent'])
    if args.control_session:
        # The GPU-session patch inserts code before the native ioctl block and
        # shifts the later attach helper context. Keep this patch after both
        # session slices, matching the proprietary backend's incremental order.
        patches.append(CONTROL_ATTACH_GPU_PATCH if args.gpu_session else CONTROL_ATTACH_PATCH)
    if args.gpu_session:
        patches.append(CARD_INFO_PATCH)
        contracts.append('test_usermode_object.py')
        patches.extend([GPU_ID_INFO_PATCH, ATTACHED_IDS_PATCH])
        patches.append(PROBED_IDS_PATCH)
        patches.extend((DEVICE_IDS_PATCH, DEVICE_OBJECT_PATCH, MEMORY_OBJECT_PATCH, VASPACE_OBJECT_PATCH,
                        CHANNEL_GROUP_OBJECT_PATCH, CONTEXT_SHARE_OBJECT_PATCH,
                        CHANNEL_OBJECT_PATCH, SUBDEVICE_TPC_MASK_PATCH,
                        BINAPI_OBJECT_PATCH, USERMODE_OBJECT_PATCH, MAP_MEMORY_PATCH,
                        RUSD_OBJECT_PATCH))
        # Keep the GPU-session API header patches together before extending
        # the authored interface; this patch follows the completed R580 API.
        patches.append(GPU_REGISTER_CONTROL_PATCH)
        patches.append(ENGINE_OBJECT_PATCH)
    if args.hybrid_sys_params:
        patches.append(SYS_PARAMS_PATCH)
        contracts.append('test_hybrid_frontend.py')
    if args.hybrid_build_version:
        patches.append(BUILD_VERSION_PATCH)
        contracts.extend(('test_hybrid_frontend.py', 'test_private_backend_build_contract.py'))
    if args.hybrid_pm_depth:
        patches.extend((PM_CHANNEL_DEPTH_ENUM_PATCH, PM_CHANNEL_DEPTH_PATCH,
                        PM_VMA_ACCESS_PATCH, PM_VMA_FREE_LIST_PATCH,
                        PM_RECOVERY_PROVIDER_PATCH,
                        PM_CHANNEL_DPM_MODESET_PATCH))
        contracts.extend(('test_hybrid_pm_channel_depth.py',
                          'test_hybrid580_pm_provider_recovery.py',
                          'test_hybrid580_pm_shared_uvm.py',
                          'test_private_pm_recovery_provider.py'))
    if args.hybrid_sys_params:
        report['typed_control_bridges'] = [
            'NV_ESC_SYS_PARAMS: fixed NvU64, set-once control-device state, dual-provider routing']
        report['remaining_boundaries'].append(
            'NV_ESC_SYS_PARAMS is compiled and CPU/source-tested only; no live frontend or CUDA validation')
    if args.hybrid_build_version:
        report.setdefault('typed_control_bridges', []).append(
            'NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION V1 to pointer-free V2 on the Open R580 provider')
        report['remaining_boundaries'].append(
            'build-version V1 user-pointer adaptation and Open V2 provider are CPU/source/build-only')
    # Multiple opt-in bridges may share a CPU contract; preserve first-use
    # order but execute and log each distinct test exactly once.
    contracts=list(dict.fromkeys(contracts))
    def step(name,argv,cwd=ROOT,timeout=1200):
        log=ROOT/'evidence/logs'/('private-open-chardev-'+name+'-'+stamp+'.log')
        log.parent.mkdir(parents=True,exist_ok=True)
        start=time.monotonic()
        with log.open('x') as out:
            # Commands/cwd are recorded in the step metadata. Keep stdout clean
            # so modinfo's field parser never admits our log preamble as data.
            try:code=subprocess.run(argv,cwd=cwd,stdout=out,stderr=subprocess.STDOUT,timeout=timeout).returncode
            except subprocess.TimeoutExpired:code=124
        report['steps'].append({'name':name,'argv':argv,'cwd':str(cwd),'exit_code':code,'log':str(log),
             'log_sha256':private.sha(log),'duration_seconds':round(time.monotonic()-start,3)})
        if code:raise RuntimeError(name+' failed; see '+str(log))
        return log.read_text(errors='replace')
    try:
        kernel=(Path('/lib/modules')/args.kernel_release/'build').resolve(strict=True)
        for path,expected in ((private.ARCHIVE,private.ARCHIVE_SHA),(core,core_sha),
                              (private.BASE/'nvidia.ko',private.BASE_MODULE_SHA)):
            if private.sha(path)!=expected: raise ValueError('input hash mismatch: '+str(path))
        inputs=[private.ARCHIVE,core,private.BASE/'nvidia.ko',*patches,
                *(ROOT/'tests'/name for name in contracts),ROOT/'tools/probe_private_backend_module.py',
                kernel/'.config',kernel/'Module.symvers',Path(__file__)]
        if args.control_session:
            inputs.extend([SESSION_HEADER, CONTROL_SESSION_HEADER])
        if args.hybrid_build_version:
            inputs.append(OPEN_BUILD_VERSION_HEADER)
        if args.gpu_session:
            inputs.append(GPU_SESSION_HEADER)
            inputs.append(GPU_CATALOG_HEADER)
        if args.hybrid_pm_depth:
            inputs.extend((ROOT/'src/hybrid580_pm_provider_recovery.h',
                           ROOT/'src/hybrid580_pm_provider_kernel.h',
                           ROOT/'src/hybrid580_pm_shared_uvm.h',
                           ROOT/'tests/fixtures/hybrid580_pm_shared_uvm_test.c'))
        report.update(inputs=[{'path':str(p),'sha256':private.sha(p)} for p in inputs],
                      work_dir=str(work),kernel_release=args.kernel_release)
        for contract in contracts:
            step('cpu-'+Path(contract).stem,['python3','-B','-m','unittest','discover','-s','tests','-p',contract,'-v'])
        original=private.parse_exports((private.BASE/'Module.symvers').read_text())
        work.mkdir(parents=True)
        with tarfile.open(private.ARCHIVE,'r:xz') as archive:
            if {m.name.split('/')[0] for m in archive.getmembers() if m.name}!={private.TOP}:raise ValueError('archive root mismatch')
            archive.extractall(work,filter='data')
        source=work/private.TOP
        for index,patch in enumerate(patches):
            step('patch-'+str(index+2),['patch','--batch','--fuzz=0','-p1','-i',str(patch)],source)
        if args.control_session:
            destination=source/'kernel-open/nvidia/rm_session_endpoint.h'
            if destination.exists():
                raise ValueError('unexpected existing session endpoint header')
            shutil.copy2(SESSION_HEADER,destination)
            # nvos.h quotes rs_access.h. The SDK and wrapper copies of that
            # latter header use pragma once rather than a common include guard.
            # Keep the SDK header byte-identical, but compile it beside the
            # wrapper's access types so those declarations are reused once.
            sdk_header=source/'src/common/sdk/nvidia/inc/nvos.h'
            sdk_overlay=source/'kernel-open/common/inc/nvos.h'
            if sdk_overlay.exists():
                raise ValueError('unexpected existing wrapper nvos.h overlay')
            overlay_sha=private.sha(sdk_header)
            shutil.copy2(sdk_header,sdk_overlay)
            control_header=source/'kernel-open/nvidia/hybrid580-control-session.h'
            if not control_header.is_file():
                raise ValueError('control session API header missing after patching')
            # The project API is a generated/authored interface, not vendor
            # source. Refresh it from the exact pinned project header after
            # applying the incremental code patches so legacy-only methods
            # can be declared without becoming Open-backend imports.
            control_header.write_bytes(CONTROL_SESSION_HEADER.read_bytes())
            if control_header.read_bytes()!=CONTROL_SESSION_HEADER.read_bytes():
                raise ValueError('control session API header differs from project source')
        if args.hybrid_build_version:
            destination=source/'kernel-open/nvidia/hybrid580-open-build-version.h'
            if destination.exists():
                raise ValueError('unexpected existing Open build-version API header')
            shutil.copy2(OPEN_BUILD_VERSION_HEADER, destination)
            if destination.read_bytes()!=OPEN_BUILD_VERSION_HEADER.read_bytes():
                raise ValueError('Open build-version API header differs from project source')
        if args.gpu_session:
            destination=source/'kernel-open/nvidia/hybrid580-gpu-session.h'
            if not destination.is_file() or destination.read_bytes()!=GPU_SESSION_HEADER.read_bytes():
                raise ValueError('GPU session header patch differs from project API header')
            catalog_header=source/'kernel-open/nvidia/hybrid580-gpu-catalog.h'
            if catalog_header.exists():
                raise ValueError('unexpected existing GPU catalog API header')
            shutil.copy2(GPU_CATALOG_HEADER,catalog_header)
        if args.hybrid_pm_depth:
            recovery_header=source/'kernel-open/nvidia/hybrid580-pm-provider-recovery.h'
            kernel_header=source/'kernel-open/nvidia/hybrid580-pm-provider-kernel.h'
            shared_uvm_header=source/'kernel-open/nvidia/hybrid580-pm-shared-uvm.h'
            if recovery_header.exists() or kernel_header.exists() or shared_uvm_header.exists():
                raise ValueError('unexpected existing provider recovery headers')
            shutil.copy2(ROOT/'src/hybrid580_pm_provider_recovery.h', recovery_header)
            shutil.copy2(ROOT/'src/hybrid580_pm_provider_kernel.h', kernel_header)
            shutil.copy2(ROOT/'src/hybrid580_pm_shared_uvm.h', shared_uvm_header)
            if shared_uvm_header.read_bytes() != (ROOT/'src/hybrid580_pm_shared_uvm.h').read_bytes():
                raise ValueError('shared UVM PM contract header differs from project source')
        nv_pci=source/'kernel-open/nvidia/nv-pci.c'
        text=nv_pci.read_text()
        if text.index('if (!hybrid_pci_bdf_selected(hybrid_gpu_pci, pci_name(pci_dev)))',text.index('nv_pci_probe\n')) > text.index('regs_bar_index = nv_bar_index_to_os_bar_index',text.index('nv_pci_probe\n')):
            raise ValueError('guard after BAR helper')
        shutil.copy2(core,source/'kernel-open/nvidia/nv-kernel.o_binary')
        build_output=step('module-build',['make','-C',str(source/'kernel-open'),'KERNEL_UNAME='+args.kernel_release,
              'NV_KERNEL_MODULES=nvidia','-j'+str(args.jobs),'modules'])
        module=source/'kernel-open/hybrid580_open.ko'
        exports=private.parse_exports((source/'kernel-open/Module.symvers').read_text())
        validate_backend_exports(original,exports,args.file_projection,args.control_session,
                                 args.gpu_session,args.hybrid_pm_depth,
                                 args.hybrid_sys_params,args.hybrid_build_version)
        info=step('modinfo',['modinfo',str(module)])
        metadata={}
        for line in info.splitlines():
            if ':' in line:
                key,value=line.split(':',1);metadata.setdefault(key,[]).append(value.strip())
        if metadata.get('name')!=['hybrid580_open'] or metadata.get('license')!=['Dual MIT/GPL']:
            raise ValueError('module name/license changed')
        if not metadata.get('vermagic',[''])[0].startswith(args.kernel_release+' '):
            raise ValueError('module kernel release mismatch')
        parameter_types=step('parameter-types',['modinfo','-F','parmtype',str(module)]).splitlines()
        if 'hybrid_gpu_pci:charp' not in parameter_types:raise ValueError('selector parameter missing')
        metadata['measured_parmtype']=parameter_types
        strings=step('export-strings',['readelf','-p','__ksymtab_strings',str(module)])
        actual={line.split(']',1)[1].strip() for line in strings.splitlines() if ']' in line}
        if actual!=set(exports):raise ValueError('actual ELF export strings differ')
        step('symvers',['cat',str(source/'kernel-open/Module.symvers')])
        step('elf-symbols',['readelf','-W','-s',str(module)])
        defined,undefined=private.symbols(module)
        kernel_exports={fields[1]:fields[3] for line in (kernel/'Module.symvers').read_text().splitlines()
                        if len(fields:=line.split())>=4}
        missing=undefined-set(kernel_exports)
        if missing:
            raise ValueError('kernel import exports absent: '+','.join(sorted(missing)))
        _,baseline_undefined=private.symbols(private.BASE/'nvidia.ko')
        added_imports={name:kernel_exports[name] for name in sorted(undefined-baseline_undefined)}
        if args.file_projection and any('GPL' in flavor for flavor in added_imports.values()):
            raise ValueError('new projection import requires GPL-only kernel interface')
        if set(original)&defined:raise ValueError('original exported definition retained')
        nv_c=source/'kernel-open/nvidia/nv.c'
        source_text=nv_c.read_text()
        if source_text.split('#include',1)[0]!=(private.BASE/'nvidia/nv.c').read_text().split('#include',1)[0]:
            raise ValueError('source copyright/license header changed')
        if 'NV_MAJOR_DEVICE_NUMBER' in source_text or 'char-major-195' in '\n'.join(metadata.get('alias',[])):
            raise ValueError('public character major retained')
        if not {'alloc_chrdev_region','unregister_chrdev_region'} <= undefined:
            raise ValueError('dynamic major lifecycle imports absent')
        if 'register_chrdev_region' in undefined:
            raise ValueError('fixed major registration import retained')
        if args.resource_isolation and metadata.get('alias'):
            raise ValueError('hardware autoload aliases retained')
        if private.sha(source/'kernel-open/nvidia/nv-kernel.o_binary')!=core_sha:
            raise ValueError('selected Open core changed')
        if args.control_session:
            if private.sha(sdk_header)!=overlay_sha or private.sha(sdk_overlay)!=overlay_sha:
                raise ValueError('SDK overlay differs from original nvos.h bytes')
            report['sdk_header_overlay']={'source':str(sdk_header),'path':str(sdk_overlay),
                'sha256':overlay_sha,'source_and_overlay_byte_identical':True}
        report.update(qualification='compiled-private-dynamic-chardev-only',
             module={'path':str(module),'sha256':private.sha(module),'bytes':module.stat().st_size},
             modified_pci_source={'path':str(nv_pci),'sha256':private.sha(nv_pci)},
             metadata=metadata,export_count=len(exports),exports=exports,actual_elf_export_strings_match=True,
             original_export_collisions=[],undefined_count=len(undefined),cpu_contract_passed=True,
             kernel_imports_with_exports=len(undefined),
             gpl_only_kernel_imports=sum('GPL' in kernel_exports[name] for name in undefined),
             added_kernel_imports_vs_official_open_baseline=added_imports,
             modified_nv_c={'path':str(nv_c),'sha256':private.sha(nv_c)},source_license_header_unchanged=True,core_unchanged=True,public_character_major_alias_absent=True,dynamic_major_imports_present=True)
        warning_lines=[line for line in build_output.splitlines() if 'warning:' in line.lower()]
        report['build_warnings']={'total_warning_lines':len(warning_lines),
            'objtool_warning_lines':sum('objtool' in line for line in warning_lines),
            'naked_return_rethunk':sum("'naked' return found in MITIGATION_RETHUNK build" in line for line in warning_lines),
            'warnings_suppressed_by_tool':False,'full_kernel_mitigation_qualification':False}
        if args.resource_isolation:
            changed=['nvidia/nv.c','nvidia/nv-pci.c','nvidia/nv-procfs.c','nvidia/nv-caps.c',
                'nvidia/nvlink_linux.c','nvidia/nvlink_linux.h','nvidia/procfs_nvswitch.c',
                'nvidia/export_nvswitch.h','nvidia/nv-caps-imex.c','nvidia/nv-platform.c','nvidia/nv-pci-table.c']
            if args.file_projection:
                changed.append('nvidia/hybrid580-file-projection.h')
            if args.control_session:
                changed.extend(['nvidia/hybrid580-control-session.h','nvidia/rm_session_endpoint.h',
                                'nvidia/nvidia.Kbuild','common/inc/nvos.h'])
            if args.gpu_session:
                changed.extend(['nvidia/hybrid580-gpu-session.h','nvidia/hybrid580-gpu-catalog.h'])
            if args.hybrid_pm_depth:
                changed.append('common/inc/nv.h')
            report.update(qualification='compiled-private-PCI-only-resources',
                hardware_autoload_aliases_absent=True,
                modified_sources=[{'path':str(source/'kernel-open'/name),
                    'sha256':private.sha(source/'kernel-open'/name)} for name in changed])
        if args.file_projection:
            report['qualification']='compiled-private-file-projection-hook'
        if args.control_session:
            report['qualification']='compiled-private-control-session-adapter'
        if args.gpu_session:
            report['qualification']='compiled-private-gpu-file-session-adapter'
        if args.hybrid_pm_depth:
            report['qualification']='compiled-private-gpu-file-session-with-channels-only-pm-phase'
            report['hybrid_pm_depth']={
                'source_contract_tested':True,
                'channels_are_preempted_before_return':True,
                'uvm_is_skipped_for_channels_phase':True,
                'gpu_power_transition_is_deferred_to_linux_dpm':True,
                'cross_provider_sleep_coordinator_implemented':False,
                'qualification':'source-and-module-build-only'}
    except Exception as error:report.update(qualification='failed',error=f'{type(error).__name__}: {error}')
    unreadable=[]
    def input_matches(path,expected):
        try:
            return private.sha(Path(path))==expected
        except OSError as error:
            unreadable.append({'path':str(path),'error':f'{type(error).__name__}: {error}'})
            return False
    # Evaluate every input even after an earlier mismatch; failed builds must
    # retain evidence instead of raising a second exception while reporting.
    report['inputs_unchanged']=all([input_matches(p,h) for p,h in (
        (private.ARCHIVE,private.ARCHIVE_SHA),(core,core_sha),
        (private.BASE/'nvidia.ko',private.BASE_MODULE_SHA))])
    report['all_recorded_inputs_unchanged']=all([
        input_matches(item['path'],item['sha256']) for item in report.get('inputs',[])])
    report['unreadable_inputs']=unreadable
    if not report['inputs_unchanged'] or not report['all_recorded_inputs_unchanged']:
        report['qualification']='failed'
        report.setdefault('error','recorded build inputs changed or became unreadable during execution')
    reportpath.parent.mkdir(parents=True,exist_ok=True)
    with reportpath.open('x') as out:json.dump(report,out,indent=2,sort_keys=True);out.write('\n')
    print(json.dumps({'qualification':report['qualification'],'report':str(reportpath),'error':report.get('error')}))
    return 0 if report['qualification'] in {'compiled-private-dynamic-chardev-only','compiled-private-PCI-only-resources','compiled-private-file-projection-hook','compiled-private-control-session-adapter','compiled-private-gpu-file-session-adapter','compiled-private-gpu-file-session-with-channels-only-pm-phase'} else 1

if __name__=='__main__':raise SystemExit(main())
