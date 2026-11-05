#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep an RTX5080 ROOT live while the V100/R580 guest requests that ID."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import inspect
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import uuid

if __package__:
    from .run_pc3_live_root_id_probe import (
        DEFAULT_PROBE, RTX_DRIVER, RTX_PCI, RTX_UUID, V100_DRIVER, V100_PCI,
        V100_UUID, sha256_bytes,
    )
    from .run_pc3_v100_guest_reference import (
        DEFAULT_CREDENTIAL_FILE, DEFAULT_CREDENTIAL_HOST,
        DEFAULT_HOST_KEY_ALIAS, DEFAULT_PC3_TARGET,
        EXPECTED_GUEST_HOSTKEY_FINGERPRINT, cleanup_pc3_payload,
        fetch_pc3_sudo_secret, payload_staging_path, payload_writer_code,
        pc3_ssh_base, sudo_auth_stdin, verify_guest_host_key,
    )
    from .run_pc3_v100_rm_root_id_probe import GUEST_SCRIPT as V100_MIRROR_SCRIPT
else:
    from run_pc3_live_root_id_probe import (
        DEFAULT_PROBE, RTX_DRIVER, RTX_PCI, RTX_UUID, V100_DRIVER, V100_PCI,
        V100_UUID, sha256_bytes,
    )
    from run_pc3_v100_guest_reference import (
        DEFAULT_CREDENTIAL_FILE, DEFAULT_CREDENTIAL_HOST,
        DEFAULT_HOST_KEY_ALIAS, DEFAULT_PC3_TARGET,
        EXPECTED_GUEST_HOSTKEY_FINGERPRINT, cleanup_pc3_payload,
        fetch_pc3_sudo_secret, payload_staging_path, payload_writer_code,
        pc3_ssh_base, sudo_auth_stdin, verify_guest_host_key,
    )
    from run_pc3_v100_rm_root_id_probe import GUEST_SCRIPT as V100_MIRROR_SCRIPT

ROOT = Path(__file__).resolve().parents[1]
GUEST_KEY = '/var/lib/pc3-v100-vm/id_ed25519'
GUEST_KNOWN = '/tmp/codex-pc3-vm-known_hosts'
GUEST_FINGERPRINT = EXPECTED_GUEST_HOSTKEY_FINGERPRINT

ROOT_REMOTE = r'''import base64,hashlib,json,os,re,select,shlex,stat,subprocess,sys,tempfile
from pathlib import Path

GUEST_KEY='/var/lib/pc3-v100-vm/id_ed25519'
GUEST_KNOWN='/tmp/codex-pc3-vm-known_hosts'
GUEST_FINGERPRINT='###GUEST_FINGERPRINT###'
stage='input'; payload_path=None; probe_path=None; holder=None; target_guest=None
env={k:v for k,v in os.environ.items() if not k.startswith(('LD_','CUDA_','NVIDIA_','PYTHON'))}
env.update({'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
report={'schema':'nvidia-hybrid-pc3-live-root-id-reverse-transport-v1','host':os.uname().nodename,
 'host_kernel_release':os.uname().release,'qualification':'failed','source':None,'target_guest':None,
 'payload_file_cleanup_passed':False,'probe_helper_removed':False,'probe_cleanup_passed':False,
 'guest_hostkey_fingerprint':None,'execution_scope':{'driver_changed':False,'module_loaded':False,
  'vm_management_issued':False,'pci_binding_changed':False,'cuda_context_opened':False}}
def fail(message): raise ValueError(message)
def call(argv,input_data=None,timeout=30):
 return subprocess.run(argv,input=input_data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False,env=env)
def canonical_pci(value):
 m=re.fullmatch(r'([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])',value)
 if not m or int(m.group(3),16)>31: fail('invalid PCI identity')
 return f'{int(m.group(1),16)&0xffff:04x}:{int(m.group(2),16):02x}:{int(m.group(3),16):02x}.{int(m.group(4),16)}'
def inventory():
 r=call(['nvidia-smi','-i','GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77','--query-gpu=name,uuid,pci.bus_id,driver_version','--format=csv,noheader,nounits'],timeout=15)
 if r.returncode: fail('targeted RTX5080 inventory failed')
 rows=[[x.strip() for x in line.split(',')] for line in r.stdout.decode().splitlines() if line.strip()]
 if len(rows)!=1 or len(rows[0])!=4: fail('unexpected RTX5080 inventory')
 name,u,pci,driver=rows[0]
 if u!='GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77' or 'RTX 5080' not in name or canonical_pci(pci)!='0000:02:00.0' or driver!='595.99.02':
  fail('RTX5080 identity or installed R595 version mismatch')
 node=Path('/dev/nvidiactl'); st=node.lstat()
 if not stat.S_ISCHR(st.st_mode) or not os.access(node,os.R_OK|os.W_OK): fail('RTX5080 control device unavailable')
 return {'name':name,'uuid':u,'pci':'0000:02:00.0','driver_version':driver,
  'control_path':str(node),'control_is_character_device':True,'control_rw_access':True}
def remote_command(argv): return ' '.join(shlex.quote(str(x)) for x in argv)
def guest_base():
 return ['ssh','-F','/dev/null','-T','-oBatchMode=yes','-oIdentitiesOnly=yes',
  '-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+GUEST_KNOWN,'-oConnectTimeout=8',
  '-oConnectionAttempts=1','-i',GUEST_KEY,'-p','22223','ubuntu@127.0.0.1']
def read_line(stream,seconds):
 ready,_,_=select.select([stream],[],[],seconds)
 if not ready: fail('RTX5080 ROOT holder did not respond before its deadline')
 line=stream.readline()
 if not line: fail('RTX5080 ROOT holder closed its output early')
 return json.loads(line)
###GUEST_HOSTKEY_VERIFIER###
try:
 if os.uname().nodename!='pc3': fail('unexpected PC3 host identity')
 if len(sys.argv)!=3: fail('payload arguments missing')
 payload_path=Path(sys.argv[1]); payload_digest=sys.argv[2]
 if not re.fullmatch(r'/tmp/codex-v100-payload-[0-9a-f]{32}\.json',str(payload_path)) or not re.fullmatch(r'[0-9a-f]{64}',payload_digest): fail('payload path or digest invalid')
 st=payload_path.lstat()
 if not stat.S_ISREG(st.st_mode) or st.st_uid==0 or stat.S_IMODE(st.st_mode)!=0o600: fail('payload owner or mode invalid')
 raw=payload_path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=payload_digest: fail('payload hash mismatch')
 payload=json.loads(raw.decode('utf-8')); payload_path.unlink()
 report['payload_file_cleanup_passed']=not payload_path.exists()
 if payload.get('target_uuid')!='GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77' or payload.get('target_pci')!='0000:02:00.0': fail('payload identity mismatch')
 binary=base64.b64decode(payload['binary_base64'],validate=True); digest=hashlib.sha256(binary).hexdigest()
 if digest!=payload.get('binary_sha256'): fail('probe helper hash mismatch')
 report['source_device_before']=inventory()
 fd,name=tempfile.mkstemp(prefix='codex-pc3-live-root-reverse-',dir='/tmp'); probe_path=Path(name)
 with os.fdopen(fd,'wb') as f: f.write(binary)
 probe_path.chmod(0o700)
 if hashlib.sha256(probe_path.read_bytes()).hexdigest()!=digest: fail('staged host helper mismatch')
 report['probe_helper']={'bytes':len(binary),'sha256':digest}
 holder=subprocess.Popen([str(probe_path),'--hold-root'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
  stderr=subprocess.PIPE,text=True,bufsize=1,env=env)
 ready=read_line(holder.stdout,20)
 if ready.get('event')!='root-held' or type(ready.get('allocated_id')) is not int or not (0<ready['allocated_id']<=0xffffffff):
  fail('RTX5080 did not confirm a held ROOT allocation')
 root_id=ready['allocated_id']
 report['source']={'device':report['source_device_before'],'root_id':root_id,'holder_ready':ready,'binary_sha256':digest}
 key=Path(GUEST_KEY); ks=key.lstat()
 if not stat.S_ISREG(ks.st_mode) or ks.st_uid!=0 or stat.S_IMODE(ks.st_mode)!=0o600: fail('pinned V100 key ownership or mode invalid')
 verify_guest_host_key(Path(GUEST_KNOWN),GUEST_FINGERPRINT,0,call)
 report['guest_hostkey_fingerprint']=GUEST_FINGERPRINT
 stage='v100_mirror_while_rtx_root_live'
 guest_payload={'binary_base64':payload['binary_base64'],'binary_sha256':digest,
  'root_id':root_id,'gpu_uuid':'GPU-42d06a85-027a-75ea-7857-a8de27ad465e'}
 guest_command=remote_command(['python3','-c',###V100_MIRROR_SCRIPT_REPR###])
 result=call(guest_base()+[guest_command],input_data=json.dumps(guest_payload,separators=(',',':')).encode(),timeout=75)
 try: target_guest=json.loads(result.stdout.decode('utf-8','strict'))
 except (UnicodeDecodeError,ValueError): target_guest=None
 report['target_guest']={'exit_code':result.returncode,'report':target_guest,
  'stderr':result.stderr.decode('utf-8','replace')[-1500:]}
 if (result.returncode!=0 or not isinstance(target_guest,dict) or
     target_guest.get('qualification')!='installed-R580-root-ID-mirror-request-and-free-passed' or
     target_guest.get('helper_removed') is not True or
     target_guest.get('helper_result',{}).get('report',{}).get('allocated_id')!=root_id):
  fail('V100 did not accept and free the RTX5080 ID while its ROOT was live')
 report['qualification']='V100-accepted-and-freed-RTX5080-root-ID-while-RTX5080-root-was-live'
except Exception as e:
 report['error']=str(e)[:700]; report['failure_stage']=stage
finally:
 if holder is not None:
  try:
   if holder.stdin and not holder.stdin.closed:
    try: holder.stdin.write('release\n'); holder.stdin.flush()
    except (BrokenPipeError,OSError): pass
    holder.stdin.close()
   try: final=read_line(holder.stdout,40)
   except Exception as e: final={'error':str(e)}
   report.setdefault('source',{})['final']=final
   holder.wait(timeout=5)
   err=holder.stderr.read()
   if err: report['holder_stderr']=err[-1200:]
   report['source']['exit_code']=holder.returncode
   if (holder.returncode!=0 or final.get('action')!='hold-root' or
       final.get('release_received') is not True or final.get('free',{}).get('passed') is not True or
       final.get('control_close_succeeded') is not True or final.get('success') is not True):
    report['qualification']='failed'; report['source_cleanup_error']='RTX5080 source ROOT cleanup failed'
  except Exception as e:
   report['qualification']='failed'; report['source_cleanup_error']=str(e)[:400]
 if probe_path is not None:
  try:
   probe_path.unlink(missing_ok=False); report['probe_helper_removed']=not probe_path.exists()
  except OSError as e:
   report['probe_cleanup_error']=str(e); report['qualification']='failed'
 try:
  report['source_device_after']=inventory()
  before=report.get('source_device_before')
  if isinstance(before,dict) and any(before.get(k)!=report['source_device_after'].get(k) for k in ('name','uuid','pci','driver_version')):
   report['qualification']='failed'; report['error']='RTX5080 identity changed during test'
 except Exception as e:
  report['postflight_error']=str(e); report['qualification']='failed'
report['probe_cleanup_passed']=bool(probe_path is None or not probe_path.exists())
print(json.dumps(report,sort_keys=True))
'''
ROOT_REMOTE = ROOT_REMOTE.replace('###GUEST_FINGERPRINT###', GUEST_FINGERPRINT)
ROOT_REMOTE = ROOT_REMOTE.replace('###GUEST_HOSTKEY_VERIFIER###', inspect.getsource(verify_guest_host_key))
ROOT_REMOTE = ROOT_REMOTE.replace('###V100_MIRROR_SCRIPT_REPR###', repr(V100_MIRROR_SCRIPT))


def validate_reverse_live_result(remote: object, exit_code: int) -> bool:
    if not isinstance(remote, dict) or exit_code != 0:
        return False
    if (remote.get('schema') != 'nvidia-hybrid-pc3-live-root-id-reverse-transport-v1' or
            remote.get('qualification') != 'V100-accepted-and-freed-RTX5080-root-ID-while-RTX5080-root-was-live' or
            remote.get('host') != 'pc3' or remote.get('failure_stage') or
            remote.get('guest_hostkey_fingerprint') != GUEST_FINGERPRINT or
            remote.get('payload_file_cleanup_passed') is not True or
            remote.get('probe_helper_removed') is not True or
            remote.get('probe_cleanup_passed') is not True):
        return False
    scope = remote.get('execution_scope')
    if not isinstance(scope, dict) or any(scope.get(key) is not False for key in
            ('driver_changed', 'module_loaded', 'vm_management_issued',
             'pci_binding_changed', 'cuda_context_opened')):
        return False
    before, after = remote.get('source_device_before'), remote.get('source_device_after')
    expected_source = {'uuid': RTX_UUID, 'pci': RTX_PCI, 'driver_version': RTX_DRIVER}
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    if any(before.get(k) != v or after.get(k) != v for k, v in expected_source.items()):
        return False
    source = remote.get('source')
    target = remote.get('target_guest')
    guest = target.get('report') if isinstance(target, dict) else None
    mirror = guest.get('helper_result', {}).get('report') if isinstance(guest, dict) else None
    root_id = source.get('root_id') if isinstance(source, dict) else None
    expected_target = {'uuid': V100_UUID, 'pci': V100_PCI, 'driver_version': V100_DRIVER}
    return (
        type(root_id) is int and 0 < root_id <= 0xffffffff and
        isinstance(source.get('device'), dict) and
        all(source['device'].get(k) == v for k, v in expected_source.items()) and
        isinstance(source.get('holder_ready'), dict) and source['holder_ready'].get('event') == 'root-held' and
        source['holder_ready'].get('allocated_id') == root_id and
        source['holder_ready'].get('gpu_context_opened') is False and
        source.get('exit_code') == 0 and isinstance(source.get('final'), dict) and
        source['final'].get('action') == 'hold-root' and source['final'].get('release_received') is True and
        source['final'].get('allocated_id') == root_id and
        source['final'].get('allocation', {}).get('passed') is True and
        source['final'].get('free', {}).get('passed') is True and
        source['final'].get('control_close_succeeded') is True and source['final'].get('success') is True and
        isinstance(guest, dict) and guest.get('qualification') == 'installed-R580-root-ID-mirror-request-and-free-passed' and
        type(guest.get('euid')) is int and guest['euid'] > 0 and
        all(guest.get('device_before', {}).get(k) == v and guest.get('device_after', {}).get(k) == v
            for k, v in expected_target.items()) and
        guest.get('helper_removed') is True and guest.get('helper_result', {}).get('exit_code') == 0 and
        isinstance(mirror, dict) and mirror.get('requested_id') == root_id and
        mirror.get('allocated_id') == root_id and mirror.get('returned_requested_id') is True and
        mirror.get('allocation', {}).get('passed') is True and mirror.get('free', {}).get('passed') is True and
        mirror.get('control_close_succeeded') is True and mirror.get('gpu_context_opened') is False and
        mirror.get('success') is True and isinstance(target, dict) and target.get('exit_code') == 0
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, default=DEFAULT_PROBE)
    parser.add_argument('--target', default=DEFAULT_PC3_TARGET)
    parser.add_argument('--host-key-alias', default=DEFAULT_HOST_KEY_ALIAS)
    parser.add_argument('--credential-host', default=DEFAULT_CREDENTIAL_HOST)
    parser.add_argument('--credential-file', default=DEFAULT_CREDENTIAL_FILE)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output.resolve()
    if output.exists():
        print(json.dumps({'error': 'refusing to overwrite existing report', 'path': str(output)}), file=sys.stderr)
        return 2
    runner = Path(__file__).resolve()
    report = {'schema':'nvidia-hybrid-pc3-live-root-id-reverse-run-v1',
        'observed_at_utc':datetime.now(timezone.utc).isoformat(),'qualification':'failed',
        'target':args.target,'credential_host':args.credential_host,
        'credential_value_logged':False,'credential_value_persisted':False,
        'runner_path':str(runner),'runner_sha256':sha256_bytes(runner.read_bytes()),
        'root_remote_sha256':sha256_bytes(ROOT_REMOTE.encode()),
        'guest_script_sha256':sha256_bytes(V100_MIRROR_SCRIPT.encode()),
        'probe':None,'remote':None,'payload_staging':None,'payload_cleanup_passed':False,
        'pc3_ssh_exit_code':None,'pc3_stderr':''}
    secret=None; payload_path=None; payload_digest=None; cleanup_done=False
    try:
        if args.target!=DEFAULT_PC3_TARGET or args.host_key_alias!=DEFAULT_HOST_KEY_ALIAS:
            raise ValueError('hardware test is restricted to the pinned PC3 SSH target')
        probe_path=args.probe.resolve(strict=True); binary=probe_path.read_bytes(); digest=sha256_bytes(binary)
        report['probe']={'path':str(probe_path),'bytes':len(binary),'sha256':digest}
        payload={'binary_base64':base64.b64encode(binary).decode('ascii'),'binary_sha256':digest,
                 'target_uuid':RTX_UUID,'target_pci':RTX_PCI}
        payload_bytes=json.dumps(payload,separators=(',',':')).encode(); payload_digest=sha256_bytes(payload_bytes)
        payload_path=payload_staging_path(uuid.uuid4().hex)
        report['payload_staging']={'path':payload_path,'bytes':len(payload_bytes),'sha256':payload_digest,'uploaded':False}
        secret=fetch_pc3_sudo_secret(args.credential_host,args.credential_file)
        writer=' '.join(shlex.quote(item) for item in ['python3','-c',payload_writer_code(),payload_path,payload_digest])
        upload=subprocess.run(pc3_ssh_base(args.target,args.host_key_alias)+[writer],input=payload_bytes,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
        if upload.returncode!=0:
            report['payload_staging']['exit_code']=upload.returncode
            report['payload_staging']['stderr']=upload.stderr.decode('utf-8','replace')[-1500:]
            raise RuntimeError('PC3 payload staging failed')
        receipt=json.loads(upload.stdout.decode('utf-8','strict'))
        if receipt!={'bytes':len(payload_bytes),'sha256':payload_digest}: raise RuntimeError('payload receipt mismatch')
        report['payload_staging']['uploaded']=True
        command='sudo -S -p \'\' python3 -c '+shlex.quote(ROOT_REMOTE)+' '+shlex.quote(payload_path)+' '+shlex.quote(payload_digest)
        result=subprocess.run(pc3_ssh_base(args.target,args.host_key_alias)+[command],input=sudo_auth_stdin(secret),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,check=False)
        report['pc3_ssh_exit_code']=result.returncode
        report['pc3_stderr']=result.stderr.decode('utf-8','replace').replace(secret,'[REDACTED]')[-2000:]
        try: remote=json.loads(result.stdout.decode('utf-8','strict'))
        except (UnicodeDecodeError,ValueError): remote=None
        report['remote']=remote
        if not validate_reverse_live_result(remote,result.returncode):
            raise RuntimeError('PC3 did not confirm live RTX ROOT, V100 mirror and cleanup')
        report['payload_cleanup_passed']=True; cleanup_done=True
        report['qualification']='live-RTX5080-to-V100-root-ID-co-lifecycle-passed'
    except Exception as e:
        report['error']=str(e)[:700]
    finally:
        if payload_path and payload_digest and not cleanup_done:
            report['payload_cleanup_passed']=cleanup_pc3_payload(args.target,args.host_key_alias,payload_path,payload_digest)
        secret=None
    output.parent.mkdir(parents=True,exist_ok=True)
    try: fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
    except FileExistsError:
        print(json.dumps({'error':'refusing to overwrite existing report','path':str(output)}),file=sys.stderr); return 2
    with os.fdopen(fd,'w',encoding='utf-8') as stream: json.dump(report,stream,indent=2,sort_keys=True); stream.write('\n')
    print(json.dumps({'evidence':str(output),'qualification':report['qualification'],
        'source_root_id':((report.get('remote') or {}).get('source') or {}).get('root_id'),
        'target_root_id':((((report.get('remote') or {}).get('target_guest') or {}).get('report') or {}).get('helper_result') or {}).get('report',{}).get('allocated_id'),
        'payload_cleanup_passed':report['payload_cleanup_passed']}))
    return 0 if report['qualification']!='failed' else 2


if __name__=='__main__':
    raise SystemExit(main())
