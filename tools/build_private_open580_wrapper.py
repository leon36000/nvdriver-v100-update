#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a native, private Open R580 provider, compile/link only.

Reuses the authored R580 patch series without a R595 source adapter. Never
installs, loads, signs, registers a device, invokes RM, or accesses a GPU.
The source/ELF/API checks establish compile compatibility, never runtime ABI.
"""
from __future__ import annotations
import argparse
import difflib
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import tarfile
import time

ROOT=Path(__file__).resolve().parents[1]
ARCHIVE=ROOT/'.cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz'
ARCHIVE_SHA='060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8'
SOURCE_TOP='NVIDIA-kernel-module-source-580.178.04'
CORE=ROOT/'build/experiments/openrm580-baseline-v1'/SOURCE_TOP/'src/nvidia/_out/Linux_x86_64/nv-kernel.o'
CORE_SHA='5e9219a4a263315d20757159852b35be61dfd2ce75dcd2ca90b1cd1764d6bb8a'
SOURCE_RELEASES={
 '580.178.04':{'archive':ARCHIVE,'archive_sha256':ARCHIVE_SHA,
               'source_top':SOURCE_TOP,'core_mode':'pinned',
               'core':CORE,'core_sha256':CORE_SHA},
 '580.196.07':{'archive':ROOT/'.cache/upstream/NVIDIA-kernel-module-source-580.196.07.tar.xz',
               'archive_sha256':'21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084',
               'source_top':'NVIDIA-kernel-module-source-580.196.07',
               'core_mode':'build-from-source'},
}
LEGACY_REPORT=ROOT/'evidence/r58019607-sync-boost-legacy-build-v2.json'
LEGACY_REPORT_SHA='595fc1d3541fe61efab02d3ba19fd0ae1ef359c58384089eaef545b95e6e8e88'
LEGACY_PROVIDER_VERSION='580.196.07'
PATCH_DIR=ROOT/'patches/r580.178.04'
UVM_CONTROL_FD_PATCH=PATCH_DIR/'uvm/0003-pass-control-fd-to-dup-memory.patch'
PREFIX='hybrid580_open_'
KERNEL_BUILD_INPUTS=('Makefile','Module.symvers','include/config/auto.conf',
    'include/generated/autoconf.h','include/generated/utsrelease.h',
    'scripts/Makefile.build','scripts/Makefile.modpost','scripts/mod/modpost',
    'scripts/basic/fixdep')
# 0014 supersedes 0013 at the post-GPU-session source position. Later features
# precede PM lifetime patches, whose native anchors include those methods.
PATCH_NUMBERS=(2,3,4,5,6,7,8,9,10,11,12,14,15,16,17,18,19,20,21,22,23,24,25,26,
               27,28,29,30,39,40,37,38,41,42,1,31,33,34,35,36,43,44,45,46,47,48)
AUTHORED_HEADERS={
 'rm_session_endpoint.h':'rm_session_endpoint.h',
 'hybrid580-gpu-catalog.h':'hybrid580-gpu-catalog.h',
 'hybrid580-control-session.h':'hybrid580-control-session.h',
 'hybrid580-open-build-version.h':'hybrid580-open-build-version.h',
 'hybrid580_pm_provider_kernel.h':'hybrid580-pm-provider-kernel.h',
 'hybrid580_pm_provider_recovery.h':'hybrid580-pm-provider-recovery.h',
 'hybrid580_pm_shared_uvm.h':'hybrid580-pm-shared-uvm.h',
}

def sha(path):
    d=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):d.update(chunk)
    return d.hexdigest()

def source_release(version):
    """Return a copy of one explicitly pinned public R580 source release."""
    try:release=SOURCE_RELEASES[version].copy()
    except KeyError as error:raise ValueError('unsupported R580 source version: '+str(version)) from error
    release['version']=version
    return release

def validate_kernel_release(value):
    """Accept one exact uname release without permitting path or shell syntax."""
    if (not isinstance(value,str) or value in ('.','..') or
            not re.fullmatch(r'[A-Za-z0-9._+~-]{1,128}',value)):
        raise ValueError('invalid target kernel release')
    return value

def target_kernel_input_fingerprints(kernel_release,build_root=None):
    """Pin generated Kbuild inputs before/after one target-kernel build."""
    kernel_release=validate_kernel_release(kernel_release)
    explicit_root=build_root is not None
    root=(Path(build_root) if explicit_root else
          Path('/lib/modules')/kernel_release/'build').resolve(strict=True)
    if not root.is_dir() or (not explicit_root and
            not str(root).startswith(('/usr/src/','/lib/modules/','/usr/lib/modules/'))):
        raise ValueError('target kernel build tree is outside system header locations')
    allowed_roots=[root]
    if not explicit_root and kernel_release.endswith('-generic'):
        common=Path('/usr/src')/('linux-headers-'+kernel_release[:-len('-generic')])
        if common.is_dir() and not common.is_symlink():
            allowed_roots.append(common.resolve(strict=True))
    files={}
    for relative in KERNEL_BUILD_INPUTS:
        path=root/relative
        try:resolved=path.resolve(strict=True)
        except OSError:
            raise ValueError('required target kernel build input is missing or not a regular file: '+relative) from None
        if not resolved.is_file() or not any(resolved.is_relative_to(allowed) for allowed in allowed_roots):
            raise ValueError('required target kernel build input is outside the pinned header trees or not a regular file: '+relative)
        files[relative]={'bytes':resolved.stat().st_size,'sha256':sha(resolved),'resolved_path':str(resolved)}
    return {'kernel_release':kernel_release,'resolved_build_path':str(root),'files':files}

def canonical_project_destination(value,allowed):
    """Normalize one new output path and reject traversal or symlink parents."""
    raw=Path(value)
    if '..' in raw.parts:raise ValueError('destination contains a parent traversal component')
    project=Path(os.path.abspath(ROOT))
    candidate=raw if raw.is_absolute() else project/raw
    candidate=Path(os.path.abspath(candidate))
    allowed=Path(os.path.abspath(allowed))
    if not allowed.is_relative_to(project):raise ValueError('allowed directory is outside the canonical project')
    if not candidate.is_relative_to(allowed):raise ValueError('destination is outside its allowed project directory')
    cursor=project
    for part in candidate.relative_to(project).parts:
        cursor=cursor/part
        try:info=cursor.lstat()
        except FileNotFoundError:continue
        if stat.S_ISLNK(info.st_mode):raise ValueError('destination contains a symlink path component')
    return candidate

def run_process_group(argv,cwd,env,stdout,stderr,timeout,termination_grace=5):
    """Run one command in an isolated process group and terminate all children on timeout."""
    process=subprocess.Popen(argv,cwd=cwd,env=env,stdout=stdout,stderr=stderr,
        start_new_session=True)
    try:return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        try:process.wait(timeout=termination_grace)
        except subprocess.TimeoutExpired:pass
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        process.wait()
        return 124

def rm_core_build_command(source,jobs):
    if type(jobs) is not int or jobs<1:raise ValueError('jobs must be a positive integer')
    return ['make','-C',str(Path(source)/'src/nvidia'),'-j'+str(jobs),
            'NV_VERBOSE=1','EXTRA_CFLAGS=-mfunction-return=thunk-extern']

def audit_rm_compile_commands(text):
    """Verify the requested return-thunk flag reached every verbose C compile."""
    commands=[]
    for line in text.splitlines():
        if line.startswith(('$ ','cwd:')):continue
        try:parts=shlex.split(line)
        except ValueError:continue
        if '-c' not in parts:continue
        at=parts.index('-c')
        if at+1>=len(parts) or not parts[at+1].endswith('.c'):continue
        if '-mfunction-return=thunk-extern' not in parts:
            raise ValueError('RM C compilation missing return-thunk flag: '+line[:200])
        commands.append(line)
    if not commands:raise ValueError('no verbose RM C compilation commands observed')
    return {'c_compile_count':len(commands),'all_have_return_thunk_flag':True,
            'commands_sha256':hashlib.sha256('\n'.join(commands).encode()).hexdigest(),
            'first_command':commands[0]}

def patch_paths():
    result=[]
    for number in PATCH_NUMBERS:
        matches=sorted(PATCH_DIR.glob(f'{number:04d}-*.patch'))
        if len(matches)!=1:raise ValueError('missing/ambiguous native patch '+str(number))
        result.append(matches[0])
    if not UVM_CONTROL_FD_PATCH.is_file():
        raise ValueError('missing control-fd UVM integration patch')
    result.append(UVM_CONTROL_FD_PATCH)
    return result

def share_rs_access_sdk(sdk,kernel):
    """Reuse the canonical kernel-open declarations, preserving SDK notices.

    Same build boundary used by the R595 builder: pragma-once on two physical
    generated files cannot prevent duplicate declarations. No vendor type is
    altered; both copies must differ only by the pinned MSVC warning block.
    """
    warning='#if defined(_MSC_VER)\n#pragma warning(disable:4324)\n#endif\n'
    if kernel.count(warning)!=1 or kernel.replace(warning,'',1)!=sdk:
        raise ValueError('R580 RS_ACCESS declarations differ beyond MSVC warning')
    if sdk.count('#pragma once\n')!=1:raise ValueError('R580 SDK pragma anchor missing')
    return (sdk.split('#pragma once\n',1)[0]+'#pragma once\n\n'+
            '/* Private compile adapter: share the unchanged kernel-open RS_ACCESS types. */\n'+
            '#include "../../../../../kernel-open/common/inc/rs_access.h"\n')

def rebase_map_update_context(text):
    """Relocate the unchanged NVOS56 block after SYS_PARAMS/build-version.

    Only one unchanged context line changes; every added C/header line stays
    byte-identical. This resolves overlapping insertion anchors 0037/0041.
    """
    old=' EXPORT_SYMBOL(hybrid580_open_control_session_unmap_memory_v1);\n'
    new=' EXPORT_SYMBOL(hybrid580_open_control_session_build_version_v1);\n'
    if text.count(old)!=1 or new in text:raise ValueError('NVOS56 unique context anchor missing')
    changed=text.replace(old,new,1)
    hunk='@@ -4447,6 +4447,62 @@\n'
    boundary=new+' \n'
    if changed.count(hunk)!=1 or changed.count(boundary)!=1:raise ValueError('NVOS56 hunk shape changed')
    start=hunk+' }\n'
    if changed.count(start)!=1:raise ValueError('NVOS56 context prefix changed')
    # Keep three leading/trailing context lines: unequal counts can make GNU
    # patch interpret a hunk as touching a file boundary. No C additions change.
    changed=changed.replace(start,'@@ -4448,6 +4448,62 @@\n',1).replace(boundary,boundary+' \n',1)
    additions=lambda s:[l for l in s.splitlines(keepends=True) if l.startswith('+') and not l.startswith('+++')]
    if additions(text)!=additions(changed):raise ValueError('NVOS56 rebase changed instructions')
    return changed

def verify_literal_hunk_contexts(source,patch,require_unique=True):
    """Require unique exact old text, independent of stale line numbers."""
    target=None; lines=patch.read_text().splitlines(keepends=True); index=0; counts=[]
    while index<len(lines):
        line=lines[index]
        if line.startswith('+++ b/'):
            relative=Path(line[6:].strip())
            if relative.is_absolute() or '..' in relative.parts:raise ValueError('unsafe patch path')
            target=source/relative
        elif line.startswith('@@ '):
            if target is None:raise ValueError('patch hunk lacks a target')
            old=[];index+=1
            while index<len(lines) and not lines[index].startswith(('@@ ','--- ','diff --git ')):
                if lines[index].startswith((' ','-')):old.append(lines[index][1:])
                index+=1
            if old:
                count=target.read_text().count(''.join(old)) if target.is_file() else 0
                counts.append(count)
                if count==0 or (require_unique and count!=1):
                    raise RuntimeError('native patch context missing/ambiguous: '+patch.name+' '+str(target)+' '+line.strip()+' old_prefix='+repr(''.join(old)[:150]))
            elif target.exists():raise RuntimeError('native patch new-file target already exists: '+str(target))
            continue
        index+=1
    return counts

def apply_patches(source,paths,runner=None):
    records=[]
    for original_patch in paths:
        patch=original_patch
        overlay=None
        if patch.name=='0044-private-open-system-features.patch':
            nv_source=source/'kernel-open/nvidia/nv.c'
            if not nv_source.is_file():
                raise RuntimeError('SYSTEM_GET_FEATURES target source is missing')
            nv_text=nv_source.read_text()
            definition_count=nv_text.count(
                'NV_STATUS hybrid580_open_control_session_system_features_v1(')
            export_count=nv_text.count(
                'EXPORT_SYMBOL(hybrid580_open_control_session_system_features_v1);')
            if definition_count or export_count:
                if definition_count==1 and export_count==1:
                    raise RuntimeError('SYSTEM_GET_FEATURES provider already applied')
                raise RuntimeError('SYSTEM_GET_FEATURES provider is partially present or duplicated')
        if patch.name=='0045-private-open-fabric-status.patch':
            nv_source=source/'kernel-open/nvidia/nv.c'
            if not nv_source.is_file():
                raise RuntimeError('SYSTEM_GET_FABRIC_STATUS target source is missing')
            nv_text=nv_source.read_text()
            definition_count=nv_text.count(
                'NV_STATUS hybrid580_open_control_session_fabric_status_v1(')
            export_count=nv_text.count(
                'EXPORT_SYMBOL(hybrid580_open_control_session_fabric_status_v1);')
            if definition_count or export_count:
                if definition_count==1 and export_count==1:
                    raise RuntimeError('SYSTEM_GET_FABRIC_STATUS provider already applied')
                raise RuntimeError('SYSTEM_GET_FABRIC_STATUS provider is partially present or duplicated')
        if patch.name.startswith('0041-'):
            directory=source/'.hybrid-local-overlays';directory.mkdir(exist_ok=True,mode=0o700)
            patch=directory/original_patch.name
            with patch.open('x') as stream:stream.write(rebase_map_update_context(original_patch.read_text()))
            overlay={'original_path':str(original_patch),'original_sha256':sha(original_patch),
                     'overlay_path':str(patch),'overlay_sha256':sha(patch),
                     'only_context_changed':True,'added_C_lines_unchanged':True,
                     'placement':'after0037SYS_PARAMS+0038build_version,beforecontrol_session_release'}
        native=bool(re.fullmatch(r'\d{4}-private.*\.patch',patch.name))
        counts=verify_literal_hunk_contexts(source,patch,require_unique=bool(overlay) or not native)
        argv=['patch','--batch','--fuzz=0','-p1','-i',str(patch)]
        if runner is None:
            result=subprocess.run(argv,cwd=source,capture_output=True,text=True,timeout=30)
            output=result.stdout+result.stderr
            if result.returncode:raise RuntimeError('native patch failed: '+patch.name+'\n'+output)
        else:output=runner(patch.stem,argv,source)
        if re.search(r'(?im)^Hunk #\d+ succeeded[^\n]*fuzz',output):
            raise RuntimeError('native patch used fuzz: '+patch.name+'\n'+output)
        offsets=re.findall(r'(?im)^Hunk #\d+ succeeded[^\n]*offset[^\n]*',output)
        records.append({'patch':str(patch),'sha256':sha(patch),'literal_context_verified':True,'context_occurrence_counts':counts,
                        'overlay_unique_context_verified':bool(overlay),
                        'fuzz_used':False,'offset_messages':offsets,'local_context_overlay':overlay})
    return records

def source_contract(source):
    k=source/'kernel-open'
    nv=(k/'nvidia/nv.c').read_text();pci=(k/'nvidia/nv-pci.c').read_text()
    header=(k/'common/inc/nv-linux.h').read_text()
    export=(k/'nvidia/hybrid580-open-exports.h').read_text()
    spdm=(k/'nvidia/libspdm_ecc.c').read_text()
    checks={
      'dynamic_major':'alloc_chrdev_region(&hybrid_chrdev_base' in nv and
          'MAJOR(rdev) != MAJOR(hybrid_chrdev_base)' in nv and
          'filp->f_op != &nvidia_fops' in nv and 'MODULE_ALIAS_CHARDEV_MAJOR' not in nv,
      'deny_by_default_pci':'static char *hybrid_gpu_pci;' in pci and
          'module_param_named(hybrid_gpu_pci, hybrid_gpu_pci, charp, 0400);' in pci and
          pci.index('if (!hybrid_pci_bdf_selected(hybrid_gpu_pci, pci_name(pci_dev)))') <
          pci.index('regs_bar_index = nv_bar_index_to_os_bar_index',pci.index('nv_pci_probe\n')),
      'public_hardware_aliases_removed':'MODULE_DEVICE_TABLE(pci,' not in (k/'nvidia/nv-pci-table.c').read_text() and
          'MODULE_DEVICE_TABLE(of,' not in (k/'nvidia/nv-platform.c').read_text(),
      'resource_names_private':'#define MODULE_BASE_NAME "hybrid580_open"' in header and
          '"driver/" MODULE_NAME "-nvlink"' in (k/'nvidia/nvlink_linux.c').read_text(),
      'module_identity_private':'obj-m += hybrid580_open.o' in (k/'nvidia/nvidia.Kbuild').read_text(),
      'module_license_intact':'MODULE_LICENSE("Dual MIT/GPL")' in nv,
      'kmod_softdep_space_delimiters':spdm.count('MODULE_SOFTDEP("pre: ecdh_generic ecdsa_generic");')==1 and
          'MODULE_SOFTDEP("pre: ecdh_generic,ecdsa_generic");' not in spdm,
      'sys_params_single_definition':nv.count('\nint hybrid580_open_control_session_sys_params_v1(')==1,
      'version_check_single_definition':nv.count('\nNV_STATUS hybrid580_open_control_session_check_version_v1(')==1 and
          'rm_perform_version_check(sp, params, size)' in nv,
      'system_features_single_definition':nv.count('\nNV_STATUS hybrid580_open_control_session_system_features_v1(')==1 and
          'KERNEL_POINTER_TO_NvP64(&result)' in nv and
          'NV0000_CTRL_CMD_SYSTEM_GET_FEATURES' in nv and
          'EXPORT_SYMBOL(hybrid580_open_control_session_system_features_v1);' in nv,
      'fabric_status_single_definition':nv.count('\nNV_STATUS hybrid580_open_control_session_fabric_status_v1(')==1 and
          'KERNEL_POINTER_TO_NvP64(&result)' in nv and
          'NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS' in nv and
          'EXPORT_SYMBOL(hybrid580_open_control_session_fabric_status_v1);' in nv,
      'gpu_name_string_single_definition':nv.count('\nNV_STATUS hybrid580_open_control_session_gpu_name_string_v1(')==1 and
          'KERNEL_POINTER_TO_NvP64(&result)' in nv and
          'NV2080_CTRL_CMD_GPU_GET_NAME_STRING' in nv and
          'NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_UNICODE' in nv and
          'EXPORT_SYMBOL(hybrid580_open_control_session_gpu_name_string_v1);' in nv,
      'client_share_policy_single_definition':nv.count('\nNV_STATUS hybrid580_open_control_session_client_share_policy_v1(')==1 and
          '.cmd = 0x00000d04U' in nv and 'paramsSize = sizeof(result)' in nv and
          'KERNEL_POINTER_TO_NvP64(&result)' in nv and
          'EXPORT_SYMBOL(hybrid580_open_control_session_client_share_policy_v1);' in nv,
      'sync_boost_groups_single_definition':nv.count('\nNV_STATUS hybrid580_open_control_session_sync_boost_groups_v1(')==1 and
          'NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO' in nv and
          'NV0000_SYNC_GPU_BOOST_MAX_GROUPS' in nv and
          'kzalloc(sizeof(*result), GFP_KERNEL)' in nv and 'kfree(result)' in nv and
          'EXPORT_SYMBOL(hybrid580_open_control_session_sync_boost_groups_v1);' in nv,
      'mapping_update_single_definition':nv.count('\nNV_STATUS hybrid580_open_control_session_update_device_mapping_info_v1(')==1,
    }
    if not all(checks.values()):raise ValueError('native isolation source contract failed: '+str(checks))
    checks['private_baseline_export_macros']=re.findall(r'^#define (\w+) hybrid580_open_\w+$',export,re.M)
    if len(checks['private_baseline_export_macros'])!=94:raise ValueError('expected 93 baseline plus one supplemental private export macro')
    if '#define nvUvmInterfaceDupMemoryWithControlFd hybrid580_open_nvUvmInterfaceDupMemoryWithControlFd' not in export:
        raise ValueError('control-fd UVM export is not namespaced in the private backend')
    interface=(k/'nvidia/nv_uvm_interface.c').read_text()
    checks['control_fd_dispatch_private']='NV_STATUS nvUvmInterfaceDupMemoryWithControlFd(' in interface
    if not checks['control_fd_dispatch_private']:
        raise ValueError('control-fd UVM dispatch implementation is missing from the private backend source')
    return checks

def parse_exports(text):
    result={}
    for line in text.splitlines():
        parts=line.split()
        if not parts:continue
        if len(parts)<4 or parts[1] in result or parts[3] not in {'EXPORT_SYMBOL','EXPORT_SYMBOL_GPL'}:
            raise ValueError('invalid/duplicate export record')
        result[parts[1]]=parts[3]
    if not result:raise ValueError('empty exports')
    return result

def validate_legacy_provider_report(report,requested_version):
    """Require a compiled, isolated legacy provider from the exact Open RM release."""
    metadata=report.get('module',{}).get('metadata',{}) if isinstance(report,dict) else {}
    if (not isinstance(report,dict) or
            report.get('schema')!='r58019607-proprietary-port-build-v1' or
            report.get('status')!='compiled-private-proprietary-backend' or
            metadata.get('version')!=LEGACY_PROVIDER_VERSION or
            metadata.get('name')!='hybrid580_legacy' or
            report.get('loaded_or_installed') is not False or
            report.get('runtime_or_hardware_validated') is not False):
        raise ValueError('pinned legacy backend report is not an isolated R580.196.07 compile')
    if requested_version!=LEGACY_PROVIDER_VERSION:
        raise ValueError('Open and legacy providers must use the same pinned R580 release')
    return LEGACY_PROVIDER_VERSION

def parse_readelf_modinfo(text):
    """Read kernel module key/value strings from readelf's .modinfo dump."""
    result={}
    for line in text.splitlines():
        match=re.match(r'^\s*\[\s*[0-9a-fA-F]+\]\s*(.*?)\s*$',line)
        if not match or '=' not in match.group(1):continue
        key,value=match.group(1).split('=',1)
        if key and value:result.setdefault(key,[]).append(value)
    return result

def validate_exports(original,actual):
    if any(not name.startswith(PREFIX) for name in actual):raise ValueError('public export retained')
    for name,flavor in original.items():
        if actual.get(PREFIX+name)!=flavor:raise ValueError('baseline export missing or flavor changed: '+name)

def symbol_sets(path):
    defined=set();undefined=set()
    for line in subprocess.check_output(['nm','-g',str(path)],text=True).splitlines():
        p=line.split()
        if len(p)>1:(undefined if p[-2] in {'U','w','v'} else defined).add(p[-1])
    return defined,undefined

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--jobs',type=int,default=4)
    parser.add_argument('--source-version',choices=sorted(SOURCE_RELEASES),default=LEGACY_PROVIDER_VERSION)
    parser.add_argument('--kernel-release',default='7.0.0-38-generic')
    parser.add_argument('--legacy-module',type=Path,
        help='exact pinned legacy module path override for a staged isolated build bundle')
    args=parser.parse_args()
    release=source_release(args.source_version)
    try:kernel_release=validate_kernel_release(args.kernel_release)
    except ValueError as error:parser.error(str(error))
    source_archive=Path(release['archive'])
    source_top=release['source_top']
    if args.jobs<1:parser.error('positive jobs required')
    try:
        work=canonical_project_destination(args.work,ROOT/'build/experiments')
        reportpath=canonical_project_destination(args.report,ROOT/'evidence')
    except ValueError as error:parser.error(str(error))
    legacy_override=None
    if args.legacy_module is not None:
        try:legacy_override=canonical_project_destination(args.legacy_module,ROOT)
        except ValueError as error:parser.error(str(error))
        if legacy_override.is_symlink() or not legacy_override.is_file():
            parser.error('legacy module override must be a regular file below the canonical project')
    for path in (work,reportpath):
        if path.exists():parser.error('destination exists; refusing overwrite: '+str(path))
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    legacy_source_version=LEGACY_PROVIDER_VERSION
    report={'schema':'private-open580-native-wrapper-v2','source_version':args.source_version,
        'kernel_release':kernel_release,
        'qualification':'failed','observed_at_utc':datetime.now(timezone.utc).isoformat(),
        'loaded_or_installed':False,'signed':False,'device_registered':False,'real_rm_executed':False,
        'gpu_accessed':False,'runtime_or_binary_abi_validated':False,'steps':[],
        'scope':('exact-source-version Open580 RM and baseline/private module compile/link only; '
                 'legacy provider remains pinned to '+legacy_source_version),
        'provider_version_comparison':{'open_source_version':args.source_version,
            'open_rm_core_version':args.source_version,
            'legacy_proprietary_provider_source_version':legacy_source_version,
            'same_release_provider_pair':args.source_version==legacy_source_version},
        'remaining_boundaries':['module initialization/coexistence and VFS/RM lifetime unexecuted',
            'stock Open580 GV100 physical HAL absent; Volta remains proprietary backend',
            'common frontend/libcuda/UVM integration untested on hardware',
            'objtool mitigation warnings remain unqualified']}
    tracked={}
    target_kernel_inputs_before=None
    def step(name,argv,cwd=ROOT,timeout=1200,env=None):
        log=work/'logs'/(name+'.log');log.parent.mkdir(parents=True,exist_ok=True)
        start=time.monotonic()
        with log.open('x') as out:
            out.write('$ '+shlex.join(argv)+'\ncwd: '+str(cwd)+'\n');out.flush()
            code=run_process_group(argv,cwd=cwd,env=env,stdout=out,
                stderr=subprocess.STDOUT,timeout=timeout)
            if code==124:out.write('\nTIMEOUT after '+str(timeout)+'s\n')
        os.chmod(log,0o600)
        report['steps'].append({'name':name,'argv':argv,'cwd':str(cwd),'exit_code':code,'log':str(log),
            'log_sha256':sha(log),'duration_seconds':round(time.monotonic()-start,3)})
        if code:raise RuntimeError(name+' failed; see '+str(log))
        return log.read_text(errors='replace')
    try:
        pins=[(source_archive,release['archive_sha256']),(LEGACY_REPORT,LEGACY_REPORT_SHA)]
        if release['core_mode']=='pinned':pins.append((Path(release['core']),release['core_sha256']))
        for path,expected in pins:
            if sha(path)!=expected:raise ValueError('pinned input mismatch: '+str(path))
        patches=patch_paths()
        files=[p for p,_ in pins]+patches+[ROOT/'src'/name for name in AUTHORED_HEADERS]
        files += [Path(__file__),ROOT/'tests/test_private_open580_wrapper.py']
        tracked={str(p):sha(p) for p in files};report['inputs_sha256']=tracked
        work.mkdir(parents=True,mode=0o700)
        inputs=work/'inputs';inputs.mkdir(mode=0o700)
        archivecopy=inputs/('open580-'+args.source_version+'.tar.xz');shutil.copy2(source_archive,archivecopy)
        if sha(archivecopy)!=release['archive_sha256']:raise ValueError('archive private snapshot mismatch')
        with tarfile.open(archivecopy,'r:xz') as archive:
            if {m.name.split('/')[0] for m in archive.getmembers() if m.name}!={source_top}:
                raise ValueError('archive top mismatch')
            archive.extractall(work/'baseline',filter='data')
        baseline=work/'baseline'/source_top;source=work/'private'/source_top
        source.parent.mkdir();shutil.copytree(baseline,source,symlinks=True)
        snap=[]
        for p in patches:
            target=inputs/p.name;shutil.copy2(p,target)
            if sha(target)!=tracked[str(p)]:raise ValueError('patch snapshot mismatch')
            snap.append(target)
        report['native_patches']=apply_patches(source,snap,step)
        report['source_isolation_contract']=source_contract(source)
        # The current common ABI declarations are copied verbatim, as in the
        # proprietary builder. Source equality is not proprietary binary ABI.
        for name,target in AUTHORED_HEADERS.items():
            shutil.copy2(ROOT/'src'/name,source/'kernel-open/nvidia'/target)
        legacy=json.loads(LEGACY_REPORT.read_text())
        validate_legacy_provider_report(legacy,args.source_version)
        legacymodule=legacy_override or Path(legacy['module']['path'])
        if sha(legacymodule)!=legacy['module']['sha256']:raise ValueError('existing proprietary provider hash mismatch')
        legacy_source=legacymodule.parent
        report['shared_header_comparison']={}
        for header in ('hybrid580-control-session.h','hybrid580-gpu-session.h','hybrid580-file-projection.h'):
            a=(source/'kernel-open/nvidia'/header).read_bytes()
            b=(legacy_source/'nvidia'/header).read_bytes()
            # Canonical header deliberately leaves legacy-only P2P declarations
            # bound to legacy. Normalize Open->legacy, never the reverse.
            if a.replace(b'hybrid580_open',b'hybrid580_legacy')!=b:raise ValueError('same-version provider header mismatch: '+header)
            report['shared_header_comparison'][header]={'sha256':hashlib.sha256(a).hexdigest(),'match_after_prefix_substitution':True}
        sdk_access=source/'src/common/sdk/nvidia/inc/rs_access.h'
        sdk_access.write_text(share_rs_access_sdk(sdk_access.read_text(),
            (source/'kernel-open/common/inc/rs_access.h').read_text()))
        report['compile_adapter']={'path':str(sdk_access),'sha256':sha(sdk_access),
            'declarations_unchanged':True,'reason':'duplicate pragma-once SDK/kernel RS_ACCESS'}
        changes=[];diffs=[]
        diff_candidates=list((source/'kernel-open').rglob('*'))+[sdk_access]
        for file in sorted(diff_candidates):
            if not file.is_file() or file.suffix not in {'.c','.h','.Kbuild'}:continue
            relative=file.relative_to(source);old=baseline/relative
            before=old.read_bytes() if old.is_file() else b'';after=file.read_bytes()
            if before==after:continue
            changes.append({'path':str(relative),'original_sha256':hashlib.sha256(before).hexdigest(),
                            'prepared_sha256':sha(file)})
            diffs.extend(difflib.unified_diff(before.decode().splitlines(True),after.decode().splitlines(True),
                fromfile='a/'+str(relative) if old.is_file() else '/dev/null',tofile='b/'+str(relative)))
        diff=work/'prepared-source-changes.patch'
        with diff.open('x') as stream:stream.writelines(diffs)
        os.chmod(diff,0o600)
        report['source_changes']={'files':changes,'diff':str(diff),'diff_sha256':sha(diff)}
        if release['core_mode']=='pinned':
            core_object=Path(release['core'])
            core_record={'mode':'pinned-prebuilt','source_version':args.source_version,
                'path':str(core_object),'sha256':release['core_sha256'],
                'bytes':core_object.stat().st_size}
        elif release['core_mode']=='build-from-source':
            core_object=baseline/'src/nvidia/_out/Linux_x86_64/nv-kernel.o'
            clean_env=os.environ.copy();removed=[]
            for name in ('CFLAGS','CPPFLAGS','CXXFLAGS','LDFLAGS','EXTRA_CFLAGS','MAKEFLAGS','MFLAGS',
                         'MAKEOVERRIDES','CC','CXX','LD','OBJCOPY','TARGET_ARCH','NV_VERBOSE','NV_SPECTRE_V2'):
                if name in clean_env:removed.append(name);del clean_env[name]
            clean_env['LC_ALL']='C'
            compiler=step('rm-core-compiler-version',['cc','--version'])
            core_log=step('rm-core-build',rm_core_build_command(baseline,args.jobs),
                          timeout=1200,env=clean_env)
            compile_audit=audit_rm_compile_commands(core_log)
            if core_object.is_symlink() or not core_object.is_file() or core_object.stat().st_size==0:
                raise ValueError('exact-version RM build did not produce a regular nv-kernel.o')
            core_record={'mode':'built-from-pinned-source','source_version':args.source_version,
                'path':str(core_object),'sha256':sha(core_object),'bytes':core_object.stat().st_size,
                'build_command':rm_core_build_command(baseline,args.jobs),
                'compile_commands':compile_audit,'compiler_version':compiler.splitlines()[:4],
                'removed_build_environment_names':removed}
        else:raise ValueError('unsupported RM core mode: '+str(release['core_mode']))
        core_sha=core_record['sha256'];report['rm_core_object']=core_record
        for tree in (baseline,source):shutil.copy2(core_object,tree/'kernel-open/nvidia/nv-kernel.o_binary')
        target_kernel_inputs_before=target_kernel_input_fingerprints(kernel_release)
        kernel_symvers=Path(target_kernel_inputs_before['resolved_build_path'])/'Module.symvers'
        if kernel_symvers.is_symlink() or not kernel_symvers.is_file():
            raise ValueError('target kernel Module.symvers is unavailable or not a regular file')
        kernel_symvers_before={'path':str(kernel_symvers),
            **target_kernel_inputs_before['files']['Module.symvers']}
        report['target_kernel_symvers']={**kernel_symvers_before,'unchanged_after_build':False}
        report['target_kernel_inputs_before']=target_kernel_inputs_before
        common=['KERNEL_UNAME='+kernel_release,'NV_KERNEL_MODULES=nvidia','-j'+str(args.jobs),'modules']
        step('baseline-build',['make','-C',str(baseline/'kernel-open'),*common])
        baseline_module=baseline/'kernel-open/nvidia.ko'
        if shutil.which('modinfo'):
            baseline_info=step('baseline-modinfo',['modinfo',str(baseline_module)])
            baseline_metadata={}
            for line in baseline_info.splitlines():
                if ':' in line:
                    k,v=line.split(':',1);baseline_metadata.setdefault(k,[]).append(v.strip())
            baseline_metadata_source='modinfo'
        else:
            baseline_info=step('baseline-modinfo-readelf',['readelf','-p','.modinfo',str(baseline_module)])
            baseline_metadata=parse_readelf_modinfo(baseline_info)
            baseline_metadata_source='readelf-.modinfo'
        if baseline_metadata.get('name')!=['nvidia']:
            raise ValueError('baseline module identity mismatch')
        if not baseline_metadata.get('vermagic') or not baseline_metadata['vermagic'][0].startswith(kernel_release+' '):
            raise ValueError('baseline module vermagic does not match the requested target kernel')
        original=parse_exports((baseline/'kernel-open/Module.symvers').read_text())
        coredefined,coreundefined=symbol_sets(core_object)
        if set(original)&(coredefined|coreundefined):raise ValueError('core directly references baseline exports')
        report['baseline']={'module_sha256':sha(baseline_module),'export_count':len(original),
            'module_bytes':baseline_module.stat().st_size,'metadata':baseline_metadata,
            'metadata_source':baseline_metadata_source}
        step('private-build',['make','-C',str(source/'kernel-open'),*common])
        module=source/'kernel-open/hybrid580_open.ko';symvers=source/'kernel-open/Module.symvers'
        actual=parse_exports(symvers.read_text());validate_exports(original,actual)
        private_control_fd_symbol=PREFIX+'nvUvmInterfaceDupMemoryWithControlFd'
        if actual.get(private_control_fd_symbol)!='EXPORT_SYMBOL' or 'nvUvmInterfaceDupMemoryWithControlFd' in actual:
            raise ValueError('control-fd UVM dispatch is not uniquely namespaced in the private Open module')
        if shutil.which('modinfo'):
            info=step('modinfo',['modinfo',str(module)]);metadata={}
            for line in info.splitlines():
                if ':' in line:
                    k,v=line.split(':',1);metadata.setdefault(k,[]).append(v.strip())
            metadata_source='modinfo'
        else:
            info=step('modinfo-readelf',['readelf','-p','.modinfo',str(module)])
            metadata=parse_readelf_modinfo(info)
            metadata_source='readelf-.modinfo'
        if metadata.get('name')!=['hybrid580_open'] or metadata.get('license')!=['Dual MIT/GPL']:
            raise ValueError('module identity/license mismatch')
        if not metadata.get('vermagic') or not metadata['vermagic'][0].startswith(kernel_release+' '):
            raise ValueError('private module vermagic does not match the requested target kernel')
        if any(x.startswith(('pci:','of:','char-major-195')) for x in metadata.get('alias',[])):
            raise ValueError('public hardware autoload alias retained')
        exports_text=step('elf-export-strings',['readelf','-p','__ksymtab_strings',str(module)])
        strings={l.split(']',1)[1].strip() for l in exports_text.splitlines() if ']' in l}
        if strings!=set(actual):raise ValueError('ELF export strings differ from symvers')
        defined,undefined=symbol_sets(module)
        if set(original)&defined:raise ValueError('public baseline export definition retained')
        kernel_exports=parse_exports(kernel_symvers.read_text())
        if not undefined<=set(kernel_exports):raise ValueError('unresolved non-kernel imports: '+str(sorted(undefined-set(kernel_exports))))
        legacyexports=parse_exports((legacy_source/'Module.symvers').read_text())
        collisions=set(actual)&set(legacyexports)
        if collisions:raise ValueError('private providers export collisions: '+str(sorted(collisions)))
        for tree in (baseline,source):
            if sha(tree/'kernel-open/nvidia/nv-kernel.o_binary')!=core_sha:raise ValueError('core copy changed')
        module_source=source/'kernel-open'
        report.update(qualification='compiled-native-private-open580-provider-only',
            module={'path':str(module),'sha256':sha(module),'bytes':module.stat().st_size},
            module_metadata_source=metadata_source,
            control_fd_dispatch_export={
                'public_symbol':'nvUvmInterfaceDupMemoryWithControlFd',
                'private_symbol':private_control_fd_symbol,
                'private_export_flavor':actual[private_control_fd_symbol],
                'public_symbol_absent':True},
            private_source=str(source),metadata=metadata,exports=actual,export_count=len(actual),
            imports={name:kernel_exports[name] for name in sorted(undefined)},import_count=len(undefined),
            gpl_only_import_count=sum(kernel_exports[n]=='EXPORT_SYMBOL_GPL' for n in undefined),
            provider_export_collisions=[],actual_export_strings_match=True,
            core_unchanged=True,existing_proprietary_provider={**legacy['module'],
                'source_version':legacy_source_version},
            prepared_source_sha256={str(p.relative_to(source)):sha(p) for p in module_source.rglob('*') if p.is_file() and p.suffix in {'.c','.h'}},
            source_archives_unchanged=True)
    except Exception as exc:report['error']=f'{type(exc).__name__}: {exc}'
    if target_kernel_inputs_before is not None:
        try:
            target_kernel_inputs_after=target_kernel_input_fingerprints(kernel_release)
            report['target_kernel_inputs_after']=target_kernel_inputs_after
            kernel_inputs_unchanged=target_kernel_inputs_before==target_kernel_inputs_after
            target_symvers_after={'path':str(kernel_symvers),
                **target_kernel_inputs_after['files']['Module.symvers']}
            report['target_kernel_symvers_after']=target_symvers_after
            report['target_kernel_symvers']['unchanged_after_build']=kernel_symvers_before==target_symvers_after
        except Exception as exc:
            kernel_inputs_unchanged=False
            report['target_kernel_inputs_after_error']=f'{type(exc).__name__}: {exc}'
        report['target_kernel_inputs_unchanged_after_build']=kernel_inputs_unchanged
        if not kernel_inputs_unchanged:
            report.update(qualification='failed',error='target kernel build inputs changed during build')
    report['inputs_unchanged']=all(sha(Path(p))==h for p,h in tracked.items())
    if not report['inputs_unchanged']:report.update(qualification='failed',error='input changed during build')
    reportpath.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(reportpath,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'w') as out:json.dump(report,out,indent=2,sort_keys=True);out.write('\n')
    print(json.dumps({'qualification':report['qualification'],'report':str(reportpath),'error':report.get('error'),'module':report.get('module')}))
    return 0 if report['qualification']=='compiled-native-private-open580-provider-only' else 1

if __name__=='__main__':raise SystemExit(main())
