#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a deterministic local canary archive; never install or load anything."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
from verify_canary_bundle import SCHEMA, MAX_MEMBERS, MAX_TOTAL_BYTES, safe_name, digest_file, verify_bundle

ROOT=Path(__file__).resolve().parents[1]
REPORTS={
    'open':'private-open-control-session-v2-20261019.json',
    'legacy':'private-proprietary-notices-v3-20261019.json',
    'frontend':'frontend-control-v4-20261019.json',
    'canary':'frontend-canary-v3-20261019.json',
    'firmware':'canary-firmware580-20261019.json',
}


FIRMWARE={
    'nvidia/580.178.04/gsp_tu10x.bin':('369602eb3c63a398c0532052317938389a3d29e0f5660179dd15b47cda177df2',30483544),
    'nvidia/580.178.04/gsp_ga10x.bin':('3b89a63f2e7a0b496113d6e727564e902456fd81017b21d35d3eaba76b24dab2',75028464),
}


def firmware_contract(report):
    if (report.get('schema')!='nvidia-hybrid-canary-firmware-v1' or
        report.get('status')!='acquired-original-firmware-data-only' or
        any(report.get(key) is not False for key in ('loaded_or_installed','hardware_validated',
                                                     'blob_executed','system_firmware_modified')) or
        not report.get('license_files')):
        raise ValueError('unqualified original firmware snapshot')
    rows=report.get('firmware_blobs',[])
    if len(rows)!=len(FIRMWARE) or {r['request'] for r in rows}!=set(FIRMWARE):
        raise ValueError('firmware request coverage mismatch')
    for row in rows:
        if (row['sha256'],row['bytes'])!=FIRMWARE[row['request']]:
            raise ValueError('firmware original digest/size mismatch')
    return set(FIRMWARE)


def encode(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def regular_identity(path):
    if not stat.S_ISREG(Path(path).lstat().st_mode):raise ValueError('regular non-symlink source required: '+str(path))
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(descriptor,'rb') as stream:
        info=os.fstat(stream.fileno());h=hashlib.sha256();size=0
        for data in iter(lambda:stream.read(1024*1024),b''):size+=len(data);h.update(data)
        if size!=info.st_size:raise ValueError('source changed while reading: '+str(path))
    return {'sha256':h.hexdigest(),'bytes':size}


def create_bundle(files,metadata,output,expected_files=None):
    output=Path(output)
    if output.exists() or output.is_symlink():raise FileExistsError(str(output))
    if not files or len(files)+1>MAX_MEMBERS:raise ValueError('invalid file count')
    if set(metadata)&{'files','schema'}:raise ValueError('reserved manifest field')
    manifest={'schema':SCHEMA,**metadata,'files':{}}
    for name,(path,mode) in sorted(files.items()):
        if not safe_name(name) or name=='manifest.json' or mode not in (0o644,0o755):
            raise ValueError('unsafe member name or mode')
        record={**regular_identity(path),'mode':mode}
        if expected_files is not None and record['sha256']!=expected_files.get(name):
            raise ValueError('producer/source digest changed: '+name)
        manifest['files'][name]=record
    if sum(item['bytes'] for item in manifest['files'].values())>MAX_TOTAL_BYTES:
        raise ValueError('payload too large')
    # Write/verify a private sibling, then publish with a no-clobber hard link.
    # A failed producer never leaves a final archive that could look complete.
    descriptor,temp=tempfile.mkstemp(prefix='.canary-bundle-',dir=output.parent)
    temporary=Path(temp)
    try:
        with os.fdopen(descriptor,'wb') as raw:
            with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0,compresslevel=6) as zipped:
                with tarfile.open(mode='w|',fileobj=zipped,format=tarfile.USTAR_FORMAT) as archive:
                    entries={'manifest.json':(None,0o644),**files}
                    for name,(path,mode) in sorted(entries.items()):
                        data=encode(manifest) if path is None else None
                        member=tarfile.TarInfo(name);member.mode=mode
                        member.size=len(data) if data is not None else manifest['files'][name]['bytes']
                        if data is not None:archive.addfile(member,io.BytesIO(data))
                        else:
                            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                            with os.fdopen(fd,'rb') as stream:archive.addfile(member,stream)
            raw.flush();os.fsync(raw.fileno())
        digest=digest_file(temporary)
        validation=verify_bundle(temporary,digest,metadata.get('kernel_release'))
        os.link(temporary,output)
        return {'path':str(output),'sha256':digest,'bytes':output.stat().st_size,
                'manifest_sha256':hashlib.sha256(encode(manifest)).hexdigest(),
                'verification':validation}
    finally:
        temporary.unlink(missing_ok=True)


def query(argv):
    result=subprocess.run(argv,text=True,capture_output=True,timeout=30,check=False,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    if result.returncode:raise ValueError('read-only query failed: '+repr(argv)+': '+result.stderr.strip())
    return result.stdout


def symbol_versions(path):
    rows={}
    for line in Path(path).read_text().splitlines():
        f=line.split()
        if len(f)<4 or f[1] in rows:raise ValueError('invalid or duplicate symvers record')
        rows[f[1]]={'crc':int(f[0],16),'module':f[2],'export':f[3]}
    return rows


def module_info(path,name,license_,kernel):
    fields={key:query(['modinfo','-F',key,str(path)]).strip() for key in
            ('name','license','vermagic','depends','alias','signer','version','parmtype','firmware')}
    if fields['name']!=name or fields['license']!=license_ or fields['vermagic'].split()[0]!=kernel:
        raise ValueError('module name/license/kernel mismatch: '+name)
    if name!='hybrid580_frontend' and fields['version']!='580.178.04':
        raise ValueError('backend version mismatch')
    if fields['alias']:raise ValueError('unexpected hardware autoload alias: '+name)
    if fields['signer']:raise ValueError('signature state changed; requalify packaging metadata')
    expected_deps={'hybrid580_legacy','hybrid580_open'} if name=='hybrid580_frontend' else set()
    if set(filter(None,fields['depends'].split(',')))!=expected_deps:
        raise ValueError('unexpected module dependencies: '+name)
    parameter='enable_control:bool' if name=='hybrid580_frontend' else 'hybrid_gpu_pci:charp'
    if parameter not in fields['parmtype'].splitlines():raise ValueError('private selector/enable parameter absent')
    versions={}
    # This exact kmod option is a query: it dumps ELF symbol CRCs and exits.
    for line in query(['modprobe','--show-modversions',str(path)]).splitlines():
        f=line.split()
        if len(f)!=2 or f[1] in versions:raise ValueError('invalid modversion query')
        versions[f[1]]=int(f[0],16)
    imports={line.split()[-1] for line in query(['nm','-u',str(path)]).splitlines() if line.split()}
    return {'metadata':fields,'modversions':versions,'imports':sorted(imports)}


def check_report_inputs(report):
    maps=('input_sha256','inputs_sha256','compiled_dependency_sha256','generated_outputs_sha256')
    for key in maps:
        for path,expected in report.get(key,{}).items():
            if digest_file(path)!=expected:raise ValueError('stale build input/output: '+path)
    for key in ('inputs','source_changes','modified_sources'):
        items=report.get(key,[])
        if isinstance(items,dict):items=[{'path':p,'sha256':h} for p,h in items.items()]
        for item in items:
            if digest_file(item['path'])!=item['sha256']:raise ValueError('stale build source: '+item['path'])
    for item in report.get('steps',[]):
        if item.get('exit_code')!=0:raise ValueError('producer contains failed step')
        if 'log'in item and digest_file(item['log'])!=item['log_sha256']:raise ValueError('build log changed')


def prepare_plan(verification_report,generated):
    verification_report=Path(verification_report).resolve(strict=True)
    verification=json.loads(verification_report.read_text())
    if (verification.get('exit_code')!=0 or verification.get('tests_skipped')!=0 or
        not verification.get('source_inputs_unchanged') or verification.get('tests_run',0)<=0):
        raise ValueError('successful fresh verification report required')
    for mandatory in ('tools/package_hybrid_canary.py','tools/verify_canary_bundle.py','tests/test_canary_bundle.py'):
        if mandatory not in verification['source_inputs_sha256_before_and_after']:
            raise ValueError('verification predates packaging code')
    for p,h in verification['source_inputs_sha256_before_and_after'].items():
        if digest_file(ROOT/p)!=h:raise ValueError('software verification source drift: '+p)
    if digest_file(verification['log'])!=verification['log_sha256']:raise ValueError('verification log drift')
    files={};expected={};reports={};producer_index={}
    def add(name,path,mode=0o644,sha=None):
        if name in files:raise ValueError('duplicate plan member: '+name)
        path=Path(path)
        if path.is_symlink():raise ValueError('symlink plan source refused')
        path=path.resolve(strict=True)
        identity=regular_identity(path)
        if sha is not None and identity['sha256']!=sha:raise ValueError('producer artifact drift: '+str(path))
        files[name]=(path,mode);expected[name]=identity['sha256']
    add('evidence/software-verification.json',verification_report)
    add('evidence/software-verification.log',verification['log'],sha=verification['log_sha256'])
    for role,filename in REPORTS.items():
        path=ROOT/'evidence'/filename
        pinned=verification.get('build_reports_sha256',{}).get('evidence/'+filename)
        if pinned!=digest_file(path):raise ValueError('producer not pinned by verification: '+filename)
        report=json.loads(path.read_text());check_report_inputs(report)
        if report.get('qualification')=='failed':raise ValueError('failed producer report')
        reports[role]=report;add('evidence/'+role+'-producer.json',path)
        if role=='firmware':
            firmware_contract(report)
            if report['package']['sha256']!='e79b39a7e395ffc02696de453f302cdaae31d193b5d81c0b9562a3af2dd94636':
                raise ValueError('firmware package provenance mismatch')
            for item in [report['package'],report['tool'],report['test_source']]:
                if regular_identity(item['path'])!={'sha256':item['sha256'],'bytes':item['bytes']}:
                    raise ValueError('firmware producer input changed')
            for item in report['firmware_blobs']:
                add('firmware/'+item['request'],item['path'],sha=item['sha256'])
            for index,item in enumerate(report['license_files']+report.get('provenance_files',[])):
                add(f'licenses/firmware-{index:02d}-'+Path(item['path']).name,item['path'],sha=item['sha256'])
            producer_index[role]={'artifacts':['firmware/'+r for r in sorted(FIRMWARE)],
                                  'producer':'evidence/firmware-producer.json'}
        else:
            if role!='canary':artifact=report['module'];member='modules/'+Path(artifact['path']).name
            else:artifact=report['executable'];member='bin/hybrid_frontend_canary'
            add(member,artifact['path'],0o755 if role=='canary' else 0o644,artifact['sha256'])
            producer_index[role]={'artifact':member,'producer':'evidence/'+role+'-producer.json'}
        for index,step in enumerate(report['steps']):
            if 'log'in step:add(f'evidence/{role}-step-{index:02d}.log',step['log'],sha=step['log_sha256'])
            elif role=='firmware':add(f'evidence/{role}-step-{index:02d}.log',step['path'],sha=step['sha256'])
    kernel=reports['open']['kernel_release']
    if reports['frontend']['kernel_release']!=kernel or reports['canary']['expected_kernel_release']!=kernel:
        raise ValueError('producer target kernel disagreement')
    pools={
        'open':Path(reports['open']['module']['path']).parent/'Module.symvers',
        'legacy':Path(reports['legacy']['module']['path']).parent/'Module.symvers',
        'kernel':Path('/lib/modules')/kernel/'build/Module.symvers'}
    tables={role:symbol_versions(path) for role,path in pools.items()}
    for role,path in pools.items():add('abi/'+role+'-Module.symvers',path)
    inspections={}
    for role,name,license_,exports,imports in (
        ('open','hybrid580_open','Dual MIT/GPL',99,435),
        ('legacy','hybrid580_legacy','NVIDIA',100,303),
        ('frontend','hybrid580_frontend','Dual MIT/GPL',0,32)):
        record=module_info(reports[role]['module']['path'],name,license_,kernel)
        if len(record['imports'])!=imports or role in tables and len(tables[role])!=exports:
            raise ValueError('unexpected symbol counts: '+role)
        if not set(record['imports'])<=set(record['modversions']):
            raise ValueError('import without recorded modversion')
        for symbol,crc in record['modversions'].items():
            providers=[table[symbol] for table in tables.values() if symbol in table]
            if len(providers)!=1 or crc!=providers[0]['crc']:
                raise ValueError('ambiguous/missing provider or CRC mismatch: '+symbol)
            if role=='legacy' and 'GPL'in providers[0]['export']:
                raise ValueError('proprietary backend imports GPL-only symbol')
        requests=set(record['metadata']['firmware'].splitlines())
        if requests!=(set(FIRMWARE) if role!='frontend' else set()):
            raise ValueError('module firmware declarations differ from pinned snapshot')
        inspections[role]=record
    for role,count in (('open',104),('legacy',0),('frontend',0)):
        actual=sum('GPL'in tables['kernel'][n]['export'] for n in inspections[role]['imports'] if n in tables['kernel'])
        if actual!=count:raise ValueError('kernel import flavor count changed')
    licenses={
        'licenses/project-MIT.txt':(ROOT/'LICENSE','6aa3e88c5301cfbbda99218456ca33763c9af89880251feb73a017263caaef0e'),
        'licenses/NVIDIA-Open-COPYING.txt':(ROOT/'build/experiments/private-open-control-session-v2/NVIDIA-kernel-module-source-580.178.04/COPYING','d8e96d29bc323000e7ba56102d77c88226a7a3d0d94e2081cb4b071ae9de4a06'),
        'licenses/Ubuntu-NVIDIA-copyright.txt':(ROOT/'.cache/vendor-proprietary/r580.178.04-ubuntu/usr/share/doc/nvidia-kernel-source-580/copyright','d088d505751b1a2246744d16bdb5846d0df1a804700ab8d09330b6e79165edef')}
    for member,(path,digest) in licenses.items():add(member,path,sha=digest)
    add('notices/MODIFICATIONS.md',ROOT/'build/experiments/private-proprietary-notices-v3/MODIFICATIONS.md')
    # Preserve individual attribution blocks, including original DMTF/BSD notices.
    vendor=ROOT/'.cache/vendor-proprietary/r580.178.04-ubuntu/usr/src/nvidia-580.178.04'
    notices=[]
    for path in sorted(vendor.rglob('*')):
        if path.suffix not in ('.c','.h') or not path.is_file():continue
        raw=path.read_bytes();text=raw.decode('utf-8')
        match=re.match(r'(?:\s+|/\*.*?\*/|//[^\n]*(?:\n|$))*',text,re.S)
        prefix=match.group()
        if prefix.strip():notices.append('\n=== '+str(path.relative_to(vendor))+' | SHA256 '+hashlib.sha256(raw).hexdigest()+' ===\n'+prefix)
    notice_file=generated/'vendor-source-notices.txt';notice_file.write_text('Original source notice prefixes; not a redistribution license assessment.\n'+''.join(notices))
    add('notices/vendor-source-notices.txt',notice_file)
    for name in ('STATE.md','INSTALL_ROLLBACK.md','VALIDATION.md'):add('docs/'+name,ROOT/'docs'/name)
    add('verify_canary_bundle.py',ROOT/'tools/verify_canary_bundle.py',0o755)
    add('source/package_hybrid_canary.py',Path(__file__))
    add('source/acquire_canary_firmware.py',ROOT/'tools/acquire_canary_firmware.py')
    add('source/hybrid_frontend.c',ROOT/'src/hybrid_frontend.c')
    add('source/hybrid_frontend_canary.c',ROOT/'src/hybrid_frontend_canary.c')
    for path in sorted((ROOT/'patches/r580.178.04/proprietary').glob('*.patch')):add('patches/legacy/'+path.name,path)
    for path in sorted((ROOT/'patches/r580.178.04').glob('*.patch')):add('patches/open/'+path.name,path)
    metadata={'kernel_release':kernel,'runtime_validated':False,'qualification':'compile-only-local-canary',
              'redistribution_assessed':False,'publication_requested':False,'firmware_requests':sorted(FIRMWARE),'module_inspections':inspections,
              'producer_index':producer_index,'limitations':[
                  'Local private canary preparation only; no installation or module loading.',
                  'No V100/private-RM/VFS/CUDA validation. Default frontend disabled.',
                  'Proprietary naked-return/frame warnings remain; no mitigation certification.',
                  'Original license texts/notice prefixes retained; redistribution not assessed.',
                  'Expected SHA256 must come from a separately trusted source; no signature is supplied.']}
    return files,metadata,expected


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verification-report',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args()
    if args.output.exists() or args.report.exists():parser.error('new archive/report paths required')
    if not args.output.resolve().is_relative_to(ROOT/'build/packages') or not args.report.resolve().is_relative_to(ROOT/'evidence'):
        parser.error('archive/report must remain under canonical build/packages and evidence')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    descriptor=os.open(args.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    result={'schema':'nvidia-hybrid-canary-package-build-v1','observed_at_utc':datetime.now(timezone.utc).isoformat(),
            'loaded_or_installed':False,'gpu_accessed':False,'runtime_validated':False,'qualification':'failed'}
    try:
        with tempfile.TemporaryDirectory(prefix='canary-package-inputs-',dir=args.output.parent) as tmp:
            files,metadata,expected=prepare_plan(args.verification_report,Path(tmp))
            result['archive']=create_bundle(files,metadata,args.output,expected)
            result['producer_inputs_sha256']=expected
            result['kernel_release']=metadata['kernel_release']
            result['qualification']='reproducible-local-compile-only-canary-package'
        code=0
    except (ValueError,OSError,KeyError,subprocess.SubprocessError) as error:
        result['error']=str(error);code=2
    with os.fdopen(descriptor,'w') as stream:stream.write(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'qualification':result['qualification'],'archive':result.get('archive'),'error':result.get('error')}))
    return code


if __name__=='__main__':raise SystemExit(main())
