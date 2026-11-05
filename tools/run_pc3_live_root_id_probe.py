#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep a V100 ROOT live while RTX5080/R595 requests the same numeric ID."""
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
    from .run_pc3_v100_guest_reference import (
        DEFAULT_CREDENTIAL_FILE, DEFAULT_CREDENTIAL_HOST,
        DEFAULT_HOST_KEY_ALIAS, DEFAULT_PC3_TARGET,
        EXPECTED_GUEST_HOSTKEY_FINGERPRINT,
        cleanup_pc3_payload, fetch_pc3_sudo_secret, payload_staging_path,
        payload_writer_code, pc3_ssh_base, sudo_auth_stdin,
        verify_guest_host_key,
    )
else:
    from run_pc3_v100_guest_reference import (
        DEFAULT_CREDENTIAL_FILE, DEFAULT_CREDENTIAL_HOST,
        DEFAULT_HOST_KEY_ALIAS, DEFAULT_PC3_TARGET,
        EXPECTED_GUEST_HOSTKEY_FINGERPRINT,
        cleanup_pc3_payload, fetch_pc3_sudo_secret, payload_staging_path,
        payload_writer_code, pc3_ssh_base, sudo_auth_stdin,
        verify_guest_host_key,
    )

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROBE = ROOT / 'build/experiments/rm-root-id-probe-hold-v1/rm_root_id_probe'
RTX_UUID = 'GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77'
RTX_PCI = '0000:02:00.0'
RTX_DRIVER = '595.99.02'
V100_UUID = 'GPU-42d06a85-027a-75ea-7857-a8de27ad465e'
V100_PCI = '0000:00:05.0'
V100_DRIVER = '580.178.04'
GUEST_KEY = '/var/lib/pc3-v100-vm/id_ed25519'
GUEST_KNOWN = '/tmp/codex-pc3-vm-known_hosts'
GUEST_FINGERPRINT = EXPECTED_GUEST_HOSTKEY_FINGERPRINT

GUEST_SCRIPT = r'''import base64,hashlib,json,os,select,stat,subprocess,sys,tempfile
from pathlib import Path

def fail(message): raise ValueError(message)
payload=json.loads(sys.stdin.readline())
report={'schema':'nvidia-hybrid-live-root-id-guest-v1','host':os.uname().nodename,
 'kernel_release':os.uname().release,'euid':os.geteuid(),'device_before':None,
 'device_after':None,'helper_before':None,'helper_after':None,'holder_ready':None,
 'holder_final':None,'helper_removed':False,'qualification':'failed','error':''}
path=None; holder=None; env={k:v for k,v in os.environ.items() if not k.startswith(('LD_','CUDA_','NVIDIA_','PYTHON'))}
env.update({'PATH':'/usr/bin:/bin','LC_ALL':'C'})
def inventory():
 r=subprocess.run(['nvidia-smi','--query-gpu=name,uuid,pci.bus_id,driver_version','--format=csv,noheader,nounits'],
  text=True,capture_output=True,timeout=15,env=env,check=False)
 if r.returncode: fail('guest nvidia-smi failed')
 rows=[[x.strip() for x in line.split(',')] for line in r.stdout.splitlines() if line.strip()]
 if len(rows)!=1 or len(rows[0])!=4: fail('guest does not expose exactly one NVIDIA GPU')
 name,uuid,pci,driver=rows[0]
 if (os.uname().nodename!='pc3-v100' or uuid!='GPU-42d06a85-027a-75ea-7857-a8de27ad465e' or
     not name.startswith('Tesla V100') or pci not in ('0000:00:05.0','00000000:00:05.0') or driver!='580.178.04'):
  fail('guest identity, PCI or R580 version mismatch')
 node=Path('/dev/nvidiactl'); st=node.lstat()
 if not stat.S_ISCHR(st.st_mode) or not os.access(node,os.R_OK|os.W_OK): fail('guest control device unavailable')
 return {'name':name,'uuid':uuid,'pci':'0000:00:05.0','driver_version':driver,
  'control_path':str(node),'control_is_character_device':True,'control_rw_access':True}
try:
 if os.geteuid()==0: fail('guest helper must run as the pinned unprivileged user')
 if payload.get('gpu_uuid')!='GPU-42d06a85-027a-75ea-7857-a8de27ad465e': fail('unexpected target UUID')
 raw=base64.b64decode(payload['binary_base64'],validate=True); digest=hashlib.sha256(raw).hexdigest()
 if digest!=payload.get('binary_sha256'): fail('probe binary hash mismatch')
 report['device_before']=inventory()
 fd,name_path=tempfile.mkstemp(prefix='codex-v100-live-root-',dir='/tmp'); path=Path(name_path)
 with os.fdopen(fd,'wb') as f: f.write(raw)
 path.chmod(0o700); data=path.read_bytes()
 report['helper_before']={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
 if report['helper_before']!={'bytes':len(raw),'sha256':digest}: fail('staged helper identity mismatch')
 holder=subprocess.Popen([str(path),'--hold-root'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
  stderr=subprocess.PIPE,text=True,bufsize=1,env=env)
 ready_set,_,_=select.select([holder.stdout],[],[],20)
 if not ready_set: fail('V100 ROOT holder did not report within 20 seconds')
 line=holder.stdout.readline()
 try: event=json.loads(line)
 except (ValueError,TypeError): event=None
 report['holder_ready']=event
 if not isinstance(event,dict) or event.get('event')!='root-held' or type(event.get('allocated_id')) is not int or not (0<event['allocated_id']<=0xffffffff):
  fail('V100 did not confirm a held ROOT allocation')
 sys.stdout.write(json.dumps({'schema':'nvidia-hybrid-live-root-id-ready-v1','phase':'root-held',
  'device':report['device_before'],'helper_sha256':digest,'holder_ready':event},sort_keys=True)+'\n'); sys.stdout.flush()
 command=sys.stdin.readline()
 if command=='release\n':
  holder.stdin.write(command); holder.stdin.flush()
 else:
  if holder.stdin: holder.stdin.close()
 ready_set,_,_=select.select([holder.stdout],[],[],32)
 if not ready_set: fail('V100 ROOT holder cleanup did not report within 32 seconds')
 line=holder.stdout.readline()
 try: report['holder_final']=json.loads(line)
 except (ValueError,TypeError): report['holder_final']=None
 holder.wait(timeout=5)
 stderr=holder.stderr.read()
 if stderr: report['holder_stderr']=stderr[-1000:]
 if holder.returncode!=0: fail('V100 ROOT holder returned failure')
 final=report['holder_final']
 if (not isinstance(final,dict) or final.get('action')!='hold-root' or
     final.get('release_received') is not True or final.get('free',{}).get('passed') is not True or
     final.get('control_close_succeeded') is not True): fail('V100 ROOT release or cleanup failed')
 report['qualification']='V100-root-held-and-freed'
except Exception as e:
 report['error']=str(e)[:500]
finally:
 if holder is not None and holder.poll() is None:
  try:
   if holder.stdin and not holder.stdin.closed:
    try: holder.stdin.write('release\n'); holder.stdin.flush()
    except (BrokenPipeError,OSError): pass
    holder.stdin.close()
   holder.wait(timeout=32)
  except Exception:
   try: holder.kill(); holder.wait(timeout=5)
   except Exception: pass
 if path is not None:
  try:
   data=path.read_bytes(); report['helper_after']={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
   if report['helper_after']!=report.get('helper_before'):
    report['qualification']='failed'; report['error']='staged helper changed during execution'
   path.unlink(); report['helper_removed']=not path.exists()
   if not report['helper_removed']: report['qualification']='failed'; report['error']='helper cleanup failed'
  except OSError:
   report['qualification']='failed'; report['error']='helper cleanup could not be verified'
 try:
  report['device_after']=inventory()
  before=report.get('device_before')
  if isinstance(before,dict) and any(before.get(k)!=report['device_after'].get(k) for k in ('name','uuid','pci','driver_version')):
   report['qualification']='failed'; report['error']='V100 identity changed during test'
 except Exception as e:
  report['qualification']='failed'; report['postflight_error']=str(e)
 sys.stdout.write(json.dumps(report,sort_keys=True)+'\n'); sys.stdout.flush()
'''

ROOT_REMOTE = r'''import base64,hashlib,json,os,re,select,shlex,stat,subprocess,sys,tempfile
from pathlib import Path

GUEST_KEY='/var/lib/pc3-v100-vm/id_ed25519'
GUEST_KNOWN='/tmp/codex-pc3-vm-known_hosts'
GUEST_FINGERPRINT='###GUEST_FINGERPRINT###'
stage='input'; payload_path=None; probe_path=None; guest=None; target=None
env={k:v for k,v in os.environ.items() if not k.startswith(('LD_','CUDA_','NVIDIA_','PYTHON'))}
env.update({'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
report={'schema':'nvidia-hybrid-pc3-live-root-id-transport-v1','host':os.uname().nodename,
 'host_kernel_release':os.uname().release,'qualification':'failed','source':None,'target':None,
 'payload_file_cleanup_passed':False,'probe_cleanup_passed':False,'guest_hostkey_fingerprint':None,
 'execution_scope':{'driver_changed':False,'module_loaded':False,'vm_management_issued':False,
  'pci_binding_changed':False,'cuda_context_opened':False}}
def fail(message): raise ValueError(message)
def call(argv,input_data=None,timeout=30):
 return subprocess.run(argv,input=input_data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False,env=env)
def canonical_pci(value):
 m=re.fullmatch(r'([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])',value)
 if not m or int(m.group(3),16)>31: fail('invalid PCI identity')
 return f'{int(m.group(1),16)&0xffff:04x}:{int(m.group(2),16):02x}:{int(m.group(3),16):02x}.{int(m.group(4),16)}'
def inventory(uuid):
 r=call(['nvidia-smi','-i',uuid,'--query-gpu=name,uuid,pci.bus_id,driver_version','--format=csv,noheader,nounits'],timeout=15)
 if r.returncode: fail('targeted nvidia-smi failed')
 rows=[[x.strip() for x in line.split(',')] for line in r.stdout.decode().splitlines() if line.strip()]
 if len(rows)!=1 or len(rows[0])!=4: fail('unexpected selected GPU inventory')
 name,u,pci,driver=rows[0]
 if u!=uuid or 'RTX 5080' not in name or canonical_pci(pci)!='0000:02:00.0' or driver!='595.99.02':
  fail('RTX5080 identity or installed R595 version mismatch')
 node=Path('/dev/nvidiactl'); st=node.lstat()
 if not stat.S_ISCHR(st.st_mode) or not os.access(node,os.R_OK|os.W_OK): fail('host control device unavailable')
 return {'name':name,'uuid':u,'pci':'0000:02:00.0','driver_version':driver,
  'control_path':str(node),'control_is_character_device':True,'control_rw_access':True}
def remote_command(argv): return ' '.join(shlex.quote(str(x)) for x in argv)
def guest_base():
 return ['ssh','-F','/dev/null','-T','-oBatchMode=yes','-oIdentitiesOnly=yes',
  '-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+GUEST_KNOWN,'-oConnectTimeout=8',
  '-oConnectionAttempts=1','-i',GUEST_KEY,'-p','22223','ubuntu@127.0.0.1']
def read_line(stream,seconds):
 ready,_,_=select.select([stream],[],[],seconds)
 if not ready: fail('remote V100 did not respond before the bounded deadline')
 line=stream.readline()
 if not line: fail('remote V100 closed its control stream early')
 return json.loads(line)
###GUEST_HOSTKEY_VERIFIER###
try:
 if os.uname().nodename!='pc3': fail('unexpected host identity')
 if len(sys.argv)!=3: fail('payload arguments missing')
 payload_path=Path(sys.argv[1]); payload_digest=sys.argv[2]
 if not re.fullmatch(r'/tmp/codex-v100-payload-[0-9a-f]{32}\.json',str(payload_path)) or not re.fullmatch(r'[0-9a-f]{64}',payload_digest): fail('payload path or digest invalid')
 st=payload_path.lstat()
 if not stat.S_ISREG(st.st_mode) or st.st_uid==0 or stat.S_IMODE(st.st_mode)!=0o600: fail('payload owner or mode invalid')
 raw=payload_path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=payload_digest: fail('payload hash mismatch')
 payload=json.loads(raw.decode('utf-8'))
 payload_path.unlink(); report['payload_file_cleanup_passed']=not payload_path.exists()
 if payload.get('target_uuid')!='GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77' or payload.get('target_pci')!='0000:02:00.0': fail('payload target identity mismatch')
 binary=base64.b64decode(payload['binary_base64'],validate=True); digest=hashlib.sha256(binary).hexdigest()
 if digest!=payload.get('binary_sha256'): fail('probe helper digest mismatch')
 report['target_device_before']=inventory(payload['target_uuid'])
 fd,name=tempfile.mkstemp(prefix='codex-pc3-live-root-',dir='/tmp'); probe_path=Path(name)
 with os.fdopen(fd,'wb') as f: f.write(binary)
 probe_path.chmod(0o700)
 if hashlib.sha256(probe_path.read_bytes()).hexdigest()!=digest: fail('staged host helper mismatch')
 report['probe_helper']={'bytes':len(binary),'sha256':digest}
 key=Path(GUEST_KEY); ks=key.lstat()
 if not stat.S_ISREG(ks.st_mode) or ks.st_uid!=0 or stat.S_IMODE(ks.st_mode)!=0o600: fail('pinned V100 key ownership or mode invalid')
 known=Path(GUEST_KNOWN)
 verify_guest_host_key(known,GUEST_FINGERPRINT,0,call)
 report['guest_hostkey_fingerprint']=GUEST_FINGERPRINT
 guest_payload={'binary_base64':payload['binary_base64'],'binary_sha256':digest,'gpu_uuid':'GPU-42d06a85-027a-75ea-7857-a8de27ad465e'}
 guest_command=remote_command(['python3','-c',###GUEST_SCRIPT_REPR###])
 guest=subprocess.Popen(guest_base()+[guest_command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
  stderr=subprocess.PIPE,text=True,bufsize=1,env=env)
 guest.stdin.write(json.dumps(guest_payload,separators=(',',':'))+'\n'); guest.stdin.flush()
 ready=read_line(guest.stdout,25)
 if ready.get('schema')!='nvidia-hybrid-live-root-id-ready-v1' or ready.get('phase')!='root-held': fail('V100 did not hold a verified ROOT object')
 root_id=ready.get('holder_ready',{}).get('allocated_id')
 if type(root_id) is not int or not (0<root_id<=0xffffffff): fail('V100 holder ROOT ID invalid')
 report['source']={'device':ready.get('device'),'root_id':root_id,'holder_ready':ready.get('holder_ready'),
  'binary_sha256':ready.get('helper_sha256')}
 stage='rtx_mirror_while_v100_live'
 run=call([str(probe_path),'--mirror-root-id',str(root_id)],timeout=20)
 try: target=json.loads(run.stdout.decode('utf-8','strict'))
 except (UnicodeDecodeError,ValueError): target=None
 report['target']={'exit_code':run.returncode,'report':target,'stderr':run.stderr.decode('utf-8','replace')[-1500:]}
 if run.returncode!=0 or not isinstance(target,dict) or target.get('action')!='mirror-root-id' or target.get('allocated_id')!=root_id or target.get('returned_requested_id') is not True or target.get('free',{}).get('passed') is not True:
  fail('RTX5080 did not accept, return and free the V100 ID while V100 source was live')
 report['qualification']='RTX5080-accepted-and-freed-V100-root-ID-while-V100-root-was-live'
except Exception as e:
 report['error']=str(e)[:700]; report['failure_stage']=stage
finally:
 if guest is not None:
  try:
   if guest.stdin and not guest.stdin.closed:
    try: guest.stdin.write('release\n'); guest.stdin.flush()
    except (BrokenPipeError,OSError): pass
    guest.stdin.close()
   try: source_final=read_line(guest.stdout,40)
   except Exception as e: source_final={'error':str(e)}
   report.setdefault('source',{})['final']=source_final
   guest.wait(timeout=5)
   guest_error=guest.stderr.read()
   if guest_error: report['guest_stderr']=guest_error[-1500:]
   report['source']['exit_code']=guest.returncode
   if (guest.returncode!=0 or source_final.get('qualification')!='V100-root-held-and-freed' or
       source_final.get('helper_removed') is not True or
       source_final.get('holder_final',{}).get('release_received') is not True or
       source_final.get('holder_final',{}).get('free',{}).get('passed') is not True):
    report['qualification']='failed'; report['error']='V100 source cleanup did not pass'
  except Exception as e:
   report['qualification']='failed'; report['source_cleanup_error']=str(e)[:400]
 if probe_path is not None:
  try:
   report['probe_helper_removed']=probe_path.unlink(missing_ok=False) is None
  except OSError as e:
   report['probe_cleanup_error']=str(e); report['qualification']='failed'
 try:
  report['target_device_after']=inventory('GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77')
  before=report.get('target_device_before')
  if isinstance(before,dict) and any(before.get(k)!=report['target_device_after'].get(k) for k in ('name','uuid','pci','driver_version')):
   report['qualification']='failed'; report['error']='RTX5080 identity changed during test'
 except Exception as e:
  report['qualification']='failed'; report['postflight_error']=str(e)
report['probe_cleanup_passed']=bool(probe_path is None or not probe_path.exists())
print(json.dumps(report,sort_keys=True))
'''
ROOT_REMOTE = ROOT_REMOTE.replace('###GUEST_FINGERPRINT###', GUEST_FINGERPRINT)
ROOT_REMOTE = ROOT_REMOTE.replace('###GUEST_HOSTKEY_VERIFIER###', inspect.getsource(verify_guest_host_key))
ROOT_REMOTE = ROOT_REMOTE.replace('###GUEST_SCRIPT_REPR###', repr(GUEST_SCRIPT))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_live_result(remote: object, exit_code: int) -> bool:
    if not isinstance(remote, dict) or exit_code != 0:
        return False
    if (remote.get('schema') != 'nvidia-hybrid-pc3-live-root-id-transport-v1' or
            remote.get('qualification') != 'RTX5080-accepted-and-freed-V100-root-ID-while-V100-root-was-live' or
            remote.get('host') != 'pc3' or remote.get('failure_stage') or
            remote.get('guest_hostkey_fingerprint') != GUEST_FINGERPRINT or
            remote.get('payload_file_cleanup_passed') is not True or
            remote.get('probe_cleanup_passed') is not True or
            remote.get('probe_helper_removed') is not True):
        return False
    scope = remote.get('execution_scope')
    if not isinstance(scope, dict) or any(scope.get(key) is not False for key in
            ('driver_changed', 'module_loaded', 'vm_management_issued',
             'pci_binding_changed', 'cuda_context_opened')):
        return False
    before, after = remote.get('target_device_before'), remote.get('target_device_after')
    expected_target = {'uuid': RTX_UUID, 'pci': RTX_PCI, 'driver_version': RTX_DRIVER}
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    if any(before.get(key) != value or after.get(key) != value
           for key, value in expected_target.items()):
        return False
    source = remote.get('source')
    target = remote.get('target')
    if not isinstance(source, dict) or not isinstance(target, dict):
        return False
    source_device = source.get('device')
    source_ready = source.get('holder_ready')
    source_final = source.get('final')
    target_report = target.get('report')
    root_id = source.get('root_id')
    expected_source = {'uuid': V100_UUID, 'pci': V100_PCI, 'driver_version': V100_DRIVER}
    return (
        type(root_id) is int and 0 < root_id <= 0xffffffff and
        isinstance(source_device, dict) and
        all(source_device.get(key) == value for key, value in expected_source.items()) and
        isinstance(source_ready, dict) and source_ready.get('event') == 'root-held' and
        source_ready.get('allocated_id') == root_id and
        source_ready.get('gpu_context_opened') is False and
        isinstance(source_final, dict) and source_final.get('qualification') == 'V100-root-held-and-freed' and
        source_final.get('helper_removed') is True and source_final.get('device_after') == source_device and
        source_final.get('holder_final', {}).get('action') == 'hold-root' and
        source_final.get('holder_final', {}).get('release_received') is True and
        source_final.get('holder_final', {}).get('allocated_id') == root_id and
        source_final.get('holder_final', {}).get('free', {}).get('passed') is True and
        source_final.get('holder_final', {}).get('control_close_succeeded') is True and
        source_final.get('holder_final', {}).get('success') is True and
        source.get('exit_code') == 0 and
        target.get('exit_code') == 0 and isinstance(target_report, dict) and
        target_report.get('action') == 'mirror-root-id' and target_report.get('requested_id') == root_id and
        target_report.get('allocated_id') == root_id and target_report.get('returned_requested_id') is True and
        target_report.get('allocation', {}).get('passed') is True and
        target_report.get('free', {}).get('passed') is True and
        target_report.get('control_close_succeeded') is True and
        target_report.get('gpu_context_opened') is False and target_report.get('success') is True
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
    runner_path = Path(__file__).resolve()
    report: dict[str, object] = {
        'schema': 'nvidia-hybrid-pc3-live-root-id-run-v1',
        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        'qualification': 'failed', 'target': args.target,
        'credential_host': args.credential_host,
        'credential_value_logged': False, 'credential_value_persisted': False,
        'runner_path': str(runner_path), 'runner_sha256': sha256_bytes(runner_path.read_bytes()),
        'root_remote_sha256': sha256_bytes(ROOT_REMOTE.encode()),
        'guest_script_sha256': sha256_bytes(GUEST_SCRIPT.encode()),
        'probe': None, 'remote': None, 'payload_staging': None,
        'payload_cleanup_passed': False, 'pc3_ssh_exit_code': None,
        'pc3_stderr': '',
    }
    secret = None
    payload_path = payload_digest = None
    cleanup_done = False
    try:
        if args.target != DEFAULT_PC3_TARGET or args.host_key_alias != DEFAULT_HOST_KEY_ALIAS:
            raise ValueError('hardware test is restricted to the pinned PC3 SSH target')
        probe_path = args.probe.resolve(strict=True)
        binary = probe_path.read_bytes()
        digest = sha256_bytes(binary)
        report['probe'] = {'path': str(probe_path), 'bytes': len(binary), 'sha256': digest}
        payload = {'binary_base64': base64.b64encode(binary).decode('ascii'),
                   'binary_sha256': digest, 'target_uuid': RTX_UUID, 'target_pci': RTX_PCI}
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode()
        payload_digest = sha256_bytes(payload_bytes)
        payload_path = payload_staging_path(uuid.uuid4().hex)
        report['payload_staging'] = {'path': payload_path, 'bytes': len(payload_bytes),
                                     'sha256': payload_digest, 'uploaded': False}
        secret = fetch_pc3_sudo_secret(args.credential_host, args.credential_file)
        writer_command = ' '.join(shlex.quote(item) for item in
                                  ['python3', '-c', payload_writer_code(), payload_path, payload_digest])
        uploaded = subprocess.run(pc3_ssh_base(args.target, args.host_key_alias) + [writer_command],
                                  input=payload_bytes, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=30, check=False)
        if uploaded.returncode != 0:
            report['payload_staging']['exit_code'] = uploaded.returncode
            report['payload_staging']['stderr'] = uploaded.stderr.decode('utf-8', 'replace')[-1500:]
            raise RuntimeError('PC3 payload staging failed')
        receipt = json.loads(uploaded.stdout.decode('utf-8', 'strict'))
        if receipt != {'bytes': len(payload_bytes), 'sha256': payload_digest}:
            raise RuntimeError('PC3 payload staging receipt mismatch')
        report['payload_staging']['uploaded'] = True
        command = ('sudo -S -p \'\' python3 -c ' + shlex.quote(ROOT_REMOTE) + ' ' +
                   shlex.quote(payload_path) + ' ' + shlex.quote(payload_digest))
        result = subprocess.run(pc3_ssh_base(args.target, args.host_key_alias) + [command],
                                input=sudo_auth_stdin(secret), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=120, check=False)
        report['pc3_ssh_exit_code'] = result.returncode
        stderr = result.stderr.decode('utf-8', 'replace')
        report['pc3_stderr'] = stderr.replace(secret, '[REDACTED]')[-2000:]
        try:
            remote = json.loads(result.stdout.decode('utf-8', 'strict'))
        except (UnicodeDecodeError, ValueError):
            remote = None
        report['remote'] = remote
        if not validate_live_result(remote, result.returncode):
            raise RuntimeError('PC3 did not confirm simultaneous V100-root lifetime, RTX mirror and cleanup')
        report['payload_cleanup_passed'] = True
        cleanup_done = True
        report['qualification'] = 'live-V100-to-RTX5080-root-ID-co-lifecycle-passed'
    except Exception as error:
        report['error'] = str(error)[:700]
    finally:
        if payload_path and payload_digest and not cleanup_done:
            report['payload_cleanup_passed'] = cleanup_pc3_payload(
                args.target, args.host_key_alias, payload_path, payload_digest)
        secret = None
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        print(json.dumps({'error': 'refusing to overwrite existing report', 'path': str(output)}), file=sys.stderr)
        return 2
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, sort_keys=True); stream.write('\n')
    print(json.dumps({'evidence': str(output), 'qualification': report['qualification'],
                      'source_root_id': (report.get('remote') or {}).get('source', {}).get('root_id'),
                      'target_root_id': (((report.get('remote') or {}).get('target') or {}).get('report') or {}).get('allocated_id'),
                      'payload_cleanup_passed': report['payload_cleanup_passed']}))
    return 0 if report['qualification'] != 'failed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
