#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile-only private Open R580 module/export namespace experiment.

No module is loaded, installed, signed, or mixed with proprietary objects.
Runtime major numbers, PCI claiming, event callbacks and device nodes remain
unqualified. This patch is not an installation candidate.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time

ROOT=Path(__file__).resolve().parents[1]
ARCHIVE=ROOT/'.cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz'
ARCHIVE_SHA='060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8'
TOP='NVIDIA-kernel-module-source-580.178.04'
CORE=ROOT/'build/experiments/openrm580-baseline-v1'/TOP/'src/nvidia/_out/Linux_x86_64/nv-kernel.o'
CORE_SHA='5e9219a4a263315d20757159852b35be61dfd2ce75dcd2ca90b1cd1764d6bb8a'
BASE=ROOT/'build/experiments/open580-wrapper-baseline-v1'/TOP/'kernel-open'
BASE_MODULE_SHA='8133a7fb0428c00b70f37dede97e94c68274b4d3de7fa957888147ec6f377af2'
PATCH=ROOT/'patches/r580.178.04/0002-private-open-module.patch'
PREFIX='hybrid580_open_'
SUPPLEMENTAL_PRIVATE_EXPORTS=('nvUvmInterfaceDupMemoryWithControlFd',)
MODULE='hybrid580_open'

def sha(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''): digest.update(chunk)
    return digest.hexdigest()

def parse_exports(text):
    result={}
    for line in text.splitlines():
        fields=line.split()
        if not fields: continue
        if len(fields)<4 or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',fields[1]):
            raise ValueError('invalid Module.symvers row')
        name=fields[1]
        if name in result: raise ValueError('duplicate exported name: '+name)
        if fields[3] not in {'EXPORT_SYMBOL','EXPORT_SYMBOL_GPL'}: raise ValueError('unexpected export flavor')
        result[name]=fields[3]
    if not result: raise ValueError('no exports found')
    return result

def private_header(exports,defined):
    names=set(exports)|set(SUPPLEMENTAL_PRIVATE_EXPORTS)
    for name in names:
        if PREFIX+name in defined or name.startswith(PREFIX): raise ValueError('private destination collision: '+name)
    return ('/* SPDX-License-Identifier: MIT */\n'
            '/* Compile-only R580 Open backend export names. No ABI/runtime claim. */\n'
            '#ifndef HYBRID580_OPEN_EXPORTS_H\n#define HYBRID580_OPEN_EXPORTS_H\n'+
            ''.join('#define '+name+' '+PREFIX+name+'\n' for name in sorted(names))+
            '#endif\n')

def validate_exports(original,private):
    expected={PREFIX+name:flavor for name,flavor in original.items()}
    if private!=expected: raise ValueError('private export set/flavors differ from exact prefixed baseline')

def symbols(path):
    text=subprocess.check_output(['nm','-g',str(path)],text=True)
    defined=set(); undefined=set()
    for line in text.splitlines():
        fields=line.split()
        if len(fields)<2: continue
        (undefined if fields[-2] in {'U','w','v'} else defined).add(fields[-1])
    return defined,undefined

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir',type=Path,default=ROOT/'build/experiments/private-open-backend-v1')
    parser.add_argument('--report',type=Path,default=ROOT/'evidence/private-open-backend-20261019.json')
    parser.add_argument('--jobs',type=int,default=4)
    parser.add_argument('--kernel-release',default=os.uname().release)
    args=parser.parse_args()
    work=args.work_dir.resolve(); reportpath=args.report.resolve()
    if work.exists() or reportpath.exists(): parser.error('existing scratch/report refused')
    if args.jobs<1: parser.error('positive jobs required')
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    report={'schema':'private-open-r580-module-v1','qualification':'not-started',
            'source_tag':'580.178.04','observed_at_utc':datetime.now(timezone.utc).isoformat(),
            'loaded_or_installed':False,'hardware_validated':False,'module_license_changed':False,
            'scope':'Open-only module source namespace; no proprietary object linked',
            'runtime_isolation_validated':False,'steps':[],
            'remaining_runtime_boundaries':['character-device major 195','control/device minors and frontend routing',
             'PCI driver match/claim policy','class/devnode registration and fixed internal names',
             'backend-specific nv_get_file_private/event container lifetime','independent initialized RM state',
             'UVM/modeset consumers require matching private imports','CUDA client/handle/control routing']}
    def step(name,argv,cwd=ROOT,timeout=1200):
        log=ROOT/'evidence/logs'/('private-open-'+name+'-'+stamp+'.log')
        log.parent.mkdir(parents=True,exist_ok=True)
        start=time.monotonic()
        with log.open('x') as out:
            out.write('$ '+' '.join(argv)+'\ncwd: '+str(cwd)+'\n');out.flush()
            try: code=subprocess.run(argv,cwd=cwd,stdout=out,stderr=subprocess.STDOUT,timeout=timeout).returncode
            except subprocess.TimeoutExpired: code=124
        report['steps'].append({'name':name,'argv':argv,'cwd':str(cwd),'exit_code':code,
                              'log':str(log),'log_sha256':sha(log),'duration_seconds':round(time.monotonic()-start,3)})
        if code: raise RuntimeError(name+' failed; see '+str(log))
        return log.read_text(errors='replace')
    try:
        for path,expected in ((ARCHIVE,ARCHIVE_SHA),(CORE,CORE_SHA),(BASE/'nvidia.ko',BASE_MODULE_SHA)):
            if sha(path)!=expected: raise ValueError('pinned input hash mismatch: '+str(path))
        original=parse_exports((BASE/'Module.symvers').read_text())
        defined,_=symbols(BASE/'nvidia.ko')
        core_defined,core_undefined=symbols(CORE)
        if set(original)&(core_defined|core_undefined): raise ValueError('core directly references exported API; wrapper-only mapping insufficient')
        report.update(work_dir=str(work),kernel_release=args.kernel_release,
                      source_archive={'path':str(ARCHIVE),'sha256':ARCHIVE_SHA},
                      core={'path':str(CORE),'sha256':CORE_SHA},
                      baseline_module={'path':str(BASE/'nvidia.ko'),'sha256':BASE_MODULE_SHA},
                      baseline_symvers={'path':str(BASE/'Module.symvers'),'sha256':sha(BASE/'Module.symvers')},
                      patch={'path':str(PATCH),'sha256':sha(PATCH)},tool_sha256=sha(Path(__file__)))
        work.mkdir(parents=True)
        with tarfile.open(ARCHIVE,'r:xz') as archive:
            if {m.name.split('/')[0] for m in archive.getmembers() if m.name}!={TOP}: raise ValueError('archive root mismatch')
            archive.extractall(work,filter='data')
        source=work/TOP
        step('source-patch',['patch','--batch','--fuzz=0','-p1','-i',str(PATCH)],source)
        header=source/'kernel-open/nvidia/hybrid580-open-exports.h'
        if header.read_text()!=private_header(original,defined): raise ValueError('patch export header differs from baseline contract')
        if (source/'kernel-open/nvidia/nv.c').read_bytes()!=(BASE/'nvidia/nv.c').read_bytes():
            raise ValueError('module source/license changed unexpectedly')
        shutil.copy2(CORE,source/'kernel-open/nvidia/nv-kernel.o_binary')
        step('module-build',['make','-C',str(source/'kernel-open'),
             'KERNEL_UNAME='+args.kernel_release,'NV_KERNEL_MODULES=nvidia','-j'+str(args.jobs),'modules'])
        module=source/'kernel-open'/(MODULE+'.ko')
        if not module.is_file(): raise RuntimeError('successful make lacks private .ko')
        private=parse_exports((source/'kernel-open/Module.symvers').read_text())
        validate_exports(original,private)
        modinfo=step('modinfo',['modinfo',str(module)])
        metadata={}
        for line in modinfo.splitlines():
            if ':' in line:
                key,value=line.split(':',1);metadata.setdefault(key,[]).append(value.strip())
        if metadata.get('name')!=[MODULE] or metadata.get('license')!=['Dual MIT/GPL']:
            raise ValueError('private module name/license contract failed')
        private_defined,private_undefined=symbols(module)
        if set(original)&private_defined: raise ValueError('unprefixed export symbol definition retained')
        if not {PREFIX+name for name in original}<=private_defined: raise ValueError('private definition missing')
        step('elf-symbols',['readelf','-W','-s',str(module)])
        elf_sections=step('elf-sections',['readelf','-W','-S',str(module)])
        step('module-symvers',['cat',str(source/'kernel-open/Module.symvers')])
        if '__this_module' not in private_defined or 'init_module' not in private_defined:
            raise ValueError('kernel module metadata/entry missing')
        # init_module and __this_module are module-local loader conventions, not exports.
        report.update(qualification='compiled-private-Open-module-only',
            module={'path':str(module),'sha256':sha(module),'bytes':module.stat().st_size},
            metadata=metadata,export_count=len(private),exports=private,
            original_export_collisions=[],module_loader_symbols=['init_module','cleanup_module','__this_module'],
            module_loader_symbols_are_exported=False,undefined_count=len(private_undefined),
            source_nv_c_unchanged=True,source_patch_applied=True)
    except Exception as error:
        report.update(qualification='failed',error=f'{type(error).__name__}: {error}')
    report['inputs_unchanged']=all(sha(p)==h for p,h in ((ARCHIVE,ARCHIVE_SHA),(CORE,CORE_SHA),(BASE/'nvidia.ko',BASE_MODULE_SHA)))
    reportpath.parent.mkdir(parents=True,exist_ok=True)
    with reportpath.open('x') as out: json.dump(report,out,indent=2,sort_keys=True);out.write('\n')
    print(json.dumps({'qualification':report['qualification'],'report':str(reportpath),'error':report.get('error')}))
    return 0 if report['qualification']=='compiled-private-Open-module-only' else 1

if __name__=='__main__': raise SystemExit(main())
