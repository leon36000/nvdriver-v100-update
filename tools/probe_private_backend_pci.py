#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a source-gated, deny-by-default private Open R580 backend; never load it."""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('private_backend',ROOT/'tools/probe_private_backend_module.py')
private=importlib.util.module_from_spec(spec)
spec.loader.exec_module(private)
PATCH=ROOT/'patches/r580.178.04/0003-private-open-pci-guard.patch'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir',type=Path,default=ROOT/'build/experiments/private-open-pci-v1')
    parser.add_argument('--report',type=Path,default=ROOT/'evidence/private-open-pci-20261019.json')
    parser.add_argument('--jobs',type=int,default=4)
    parser.add_argument('--kernel-release',default=os.uname().release)
    args=parser.parse_args()
    work=args.work_dir.resolve();reportpath=args.report.resolve()
    if work.exists() or reportpath.exists(): parser.error('existing scratch/report refused')
    if args.jobs<1: parser.error('positive jobs required')
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    report={'schema':'private-open-pci-guard-v1','observed_at_utc':datetime.now(timezone.utc).isoformat(),
        'qualification':'not-started','loaded_or_installed':False,'hardware_validated':False,
        'runtime_isolation_validated':False,'module_license_changed':False,'steps':[],
        'scope':'source PCI-probe selection only; Open core, private module/exports',
        'selector':{'parameter':'hybrid_gpu_pci','type':'charp','permission':'0400','default':None,
                    'format':'exact lowercase dddd:bb:ss.f; slots 00..1f; functions 0..7'},
        'remaining_boundaries':['major195 and fixed control/device minors','device nodes/procfs/classes',
             'backend-specific frontend/event/file lifetime','matching UVM/modeset import routing',
             'common CUDA handle/control ownership','platform(non-PCI) GPU probe paths untouched',
             'module-wide early initialization before PCI registration not guarded by BDF selector'],
        'existing_mechanism_rejected':{'name':'ExcludedGpus/GpuBlacklist','reason':'UUID read through RM by nv_check_and_exclude_gpu after PCI/RM setup; not an early deny-by-default BDF selector'}}
    def step(name,argv,cwd=ROOT,timeout=1200):
        log=ROOT/'evidence/logs'/('private-open-pci-'+name+'-'+stamp+'.log')
        log.parent.mkdir(parents=True,exist_ok=True)
        start=time.monotonic()
        with log.open('x') as out:
            out.write('$ '+' '.join(argv)+'\ncwd: '+str(cwd)+'\n');out.flush()
            try:code=subprocess.run(argv,cwd=cwd,stdout=out,stderr=subprocess.STDOUT,timeout=timeout).returncode
            except subprocess.TimeoutExpired:code=124
        report['steps'].append({'name':name,'argv':argv,'cwd':str(cwd),'exit_code':code,'log':str(log),
             'log_sha256':private.sha(log),'duration_seconds':round(time.monotonic()-start,3)})
        if code:raise RuntimeError(name+' failed; see '+str(log))
        return log.read_text(errors='replace')
    try:
        for path,expected in ((private.ARCHIVE,private.ARCHIVE_SHA),(private.CORE,private.CORE_SHA),
                              (private.BASE/'nvidia.ko',private.BASE_MODULE_SHA)):
            if private.sha(path)!=expected: raise ValueError('input hash mismatch: '+str(path))
        inputs=[private.ARCHIVE,private.CORE,private.BASE/'nvidia.ko',private.PATCH,PATCH,
                ROOT/'tests/test_private_backend_pci.py',ROOT/'tools/probe_private_backend_module.py',Path(__file__)]
        report.update(inputs=[{'path':str(p),'sha256':private.sha(p)} for p in inputs],
                      work_dir=str(work),kernel_release=args.kernel_release)
        step('cpu-contract',['python3','-m','unittest','discover','-s','tests','-p','test_private_backend_pci.py','-v'])
        original=private.parse_exports((private.BASE/'Module.symvers').read_text())
        work.mkdir(parents=True)
        with tarfile.open(private.ARCHIVE,'r:xz') as archive:
            if {m.name.split('/')[0] for m in archive.getmembers() if m.name}!={private.TOP}:raise ValueError('archive root mismatch')
            archive.extractall(work,filter='data')
        source=work/private.TOP
        for index,patch in enumerate((private.PATCH,PATCH)):
            step('patch-'+str(index+2),['patch','--batch','--fuzz=0','-p1','-i',str(patch)],source)
        nv_pci=source/'kernel-open/nvidia/nv-pci.c'
        text=nv_pci.read_text()
        if text.index('if (!hybrid_pci_bdf_selected(hybrid_gpu_pci, pci_name(pci_dev)))',text.index('nv_pci_probe\n')) > text.index('regs_bar_index = nv_bar_index_to_os_bar_index',text.index('nv_pci_probe\n')):
            raise ValueError('guard after BAR helper')
        shutil.copy2(private.CORE,source/'kernel-open/nvidia/nv-kernel.o_binary')
        step('module-build',['make','-C',str(source/'kernel-open'),'KERNEL_UNAME='+args.kernel_release,
              'NV_KERNEL_MODULES=nvidia','-j'+str(args.jobs),'modules'])
        module=source/'kernel-open/hybrid580_open.ko'
        exports=private.parse_exports((source/'kernel-open/Module.symvers').read_text())
        private.validate_exports(original,exports)
        info=step('modinfo',['modinfo',str(module)])
        metadata={}
        for line in info.splitlines():
            if ':' in line:
                key,value=line.split(':',1);metadata.setdefault(key,[]).append(value.strip())
        if metadata.get('name')!=['hybrid580_open'] or metadata.get('license')!=['Dual MIT/GPL']:
            raise ValueError('module name/license changed')
        parameter_types=step('parameter-types',['modinfo','-F','parmtype',str(module)]).splitlines()
        if 'hybrid_gpu_pci:charp' not in parameter_types:raise ValueError('selector parameter missing')
        metadata['measured_parmtype']=parameter_types
        strings=step('export-strings',['readelf','-p','__ksymtab_strings',str(module)])
        actual={line.split(']',1)[1].strip() for line in strings.splitlines() if ']' in line}
        if actual!=set(exports):raise ValueError('actual ELF export strings differ')
        step('symvers',['cat',str(source/'kernel-open/Module.symvers')])
        step('elf-symbols',['readelf','-W','-s',str(module)])
        defined,undefined=private.symbols(module)
        if set(original)&defined:raise ValueError('original exported definition retained')
        if (source/'kernel-open/nvidia/nv.c').read_bytes()!=(private.BASE/'nvidia/nv.c').read_bytes():
            raise ValueError('module source/license changed')
        report.update(qualification='compiled-source-PCI-guard-only',
             module={'path':str(module),'sha256':private.sha(module),'bytes':module.stat().st_size},
             modified_pci_source={'path':str(nv_pci),'sha256':private.sha(nv_pci)},
             metadata=metadata,export_count=len(exports),exports=exports,actual_elf_export_strings_match=True,
             original_export_collisions=[],undefined_count=len(undefined),cpu_contract_passed=True,
             source_nv_c_unchanged=True)
    except Exception as error:report.update(qualification='failed',error=f'{type(error).__name__}: {error}')
    report['inputs_unchanged']=all(private.sha(p)==h for p,h in ((private.ARCHIVE,private.ARCHIVE_SHA),
        (private.CORE,private.CORE_SHA),(private.BASE/'nvidia.ko',private.BASE_MODULE_SHA)))
    reportpath.parent.mkdir(parents=True,exist_ok=True)
    with reportpath.open('x') as out:json.dump(report,out,indent=2,sort_keys=True);out.write('\n')
    print(json.dumps({'qualification':report['qualification'],'report':str(reportpath),'error':report.get('error')}))
    return 0 if report['qualification']=='compiled-source-PCI-guard-only' else 1

if __name__=='__main__':raise SystemExit(main())
