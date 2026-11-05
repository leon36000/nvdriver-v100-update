#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Request an RTX5080-observed root ID on PC3's isolated V100/R580 guest."""
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
        cleanup_pc3_payload, fetch_pc3_sudo_secret, payload_staging_path,
        payload_writer_code, pc3_ssh_base, sudo_auth_stdin, verify_guest_host_key,
    )
else:
    from run_pc3_v100_guest_reference import (
        DEFAULT_CREDENTIAL_FILE, DEFAULT_CREDENTIAL_HOST,
        DEFAULT_HOST_KEY_ALIAS, DEFAULT_PC3_TARGET,
        cleanup_pc3_payload, fetch_pc3_sudo_secret, payload_staging_path,
        payload_writer_code, pc3_ssh_base, sudo_auth_stdin, verify_guest_host_key,
    )

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROBE = ROOT / 'build/experiments/rm-root-id-probe-v1/rm_root_id_probe'
DEFAULT_RTX_REPORT = ROOT / 'evidence/pc3-rtx5080-postcanary-reference-v1-20261020.json'
RTX_UUID = 'GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77'
RTX_PCI = '0000:02:00.0'
RTX_DRIVER = '595.99.02'
V100_UUID = 'GPU-42d06a85-027a-75ea-7857-a8de27ad465e'
V100_PCI = '0000:00:05.0'
V100_DRIVER = '580.178.04'

GUEST_SCRIPT = r'''import base64,hashlib,json,os,stat,subprocess,sys,tempfile
from pathlib import Path

def fail(message): raise ValueError(message)
payload=json.load(sys.stdin)
report={'schema':'nvidia-hybrid-v100-rm-root-id-probe-v1','host':os.uname().nodename,
        'kernel_release':os.uname().release,'euid':os.geteuid(),'qualification':'failed',
        'device_before':None,'device_after':None,'helper_before':None,'helper_after':None,
        'helper_result':None,'helper_removed':False,'error':''}
path=None
env={k:v for k,v in os.environ.items() if not k.startswith(('LD_','CUDA_','NVIDIA_','PYTHON'))}
env.update({'PATH':'/usr/bin:/bin','LC_ALL':'C'})
def inventory():
 r=subprocess.run(['nvidia-smi','--query-gpu=name,uuid,pci.bus_id,driver_version',
   '--format=csv,noheader,nounits'],text=True,capture_output=True,timeout=15,env=env,check=False)
 if r.returncode: fail('guest nvidia-smi failed')
 rows=[[x.strip() for x in line.split(',')] for line in r.stdout.splitlines() if line.strip()]
 if len(rows)!=1 or len(rows[0])!=4: fail('guest does not expose exactly one NVIDIA GPU')
 name,uuid,pci,driver=rows[0]
 if (os.uname().nodename!='pc3-v100' or uuid!='GPU-42d06a85-027a-75ea-7857-a8de27ad465e' or
     not name.startswith('Tesla V100') or pci not in ('0000:00:05.0','00000000:00:05.0') or
     driver!='580.178.04'):
  fail('guest identity, BDF or R580 version mismatch')
 node=Path('/dev/nvidiactl'); st=node.lstat()
 if not stat.S_ISCHR(st.st_mode) or not os.access(node,os.R_OK|os.W_OK): fail('guest control device is not accessible')
 return {'name':name,'uuid':uuid,'pci':'0000:00:05.0','driver_version':driver,
         'control_path':str(node),'control_is_character_device':True,'control_rw_access':True}
try:
 if os.geteuid()==0: fail('guest probe must run under the pinned unprivileged guest account')
 if payload.get('root_id',0)<=0 or payload.get('root_id',0)>0xffffffff: fail('invalid RTX source root ID')
 if payload.get('gpu_uuid')!='GPU-42d06a85-027a-75ea-7857-a8de27ad465e': fail('unexpected V100 target UUID')
 raw=base64.b64decode(payload['binary_base64'],validate=True)
 digest=hashlib.sha256(raw).hexdigest()
 if digest!=payload.get('binary_sha256'): fail('helper input hash mismatch')
 report['device_before']=inventory()
 fd,name_path=tempfile.mkstemp(prefix='codex-v100-rm-rootid-',dir='/tmp'); path=Path(name_path)
 with os.fdopen(fd,'wb') as f: f.write(raw)
 path.chmod(0o700)
 data=path.read_bytes(); report['helper_before']={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
 if report['helper_before']!={'bytes':len(raw),'sha256':digest}: fail('staged helper identity mismatch')
 run=subprocess.run([str(path),'--mirror-root-id',str(payload['root_id'])],text=True,
                    capture_output=True,timeout=15,env=env,check=False)
 try: child=json.loads(run.stdout)
 except (ValueError,TypeError): child=None
 report['helper_result']={'exit_code':run.returncode,'report':child,'stderr':run.stderr[-2000:]}
 if (run.returncode!=0 or not isinstance(child,dict) or
     child.get('schema')!='nvidia-hybrid-rm-root-id-probe-v1' or
     child.get('qualification')!='root-allocation-and-free-passed' or
     child.get('action')!='mirror-root-id' or child.get('requested_id')!=payload['root_id'] or
     child.get('allocated_id')!=payload['root_id'] or child.get('returned_requested_id') is not True or
     child.get('cleanup_passed') is not True or child.get('gpu_context_opened') is not False):
  fail('R580 did not confirm the requested root ID and cleanup')
 report['qualification']='installed-R580-root-ID-mirror-request-and-free-passed'
except Exception as e:
 report['error']=str(e)
finally:
 if path is not None:
  try:
   data=path.read_bytes(); report['helper_after']={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
   if report['helper_after']!=report.get('helper_before'):
    report['qualification']='failed'; report['error']='staged helper changed during execution'
   path.unlink(); report['helper_removed']=not path.exists()
   if not report['helper_removed']:
    report['qualification']='failed'; report['error']='staged helper cleanup failed'
  except OSError:
   report['qualification']='failed'; report['error']='staged helper cleanup could not be verified'
 try:
  report['device_after']=inventory()
  before=report.get('device_before')
  if isinstance(before,dict) and any(before.get(k)!=report['device_after'].get(k) for k in ('name','uuid','pci','driver_version')):
   report['qualification']='failed'; report['error']='selected V100 identity changed during the probe'
 except Exception as e:
  report['qualification']='failed'; report['postflight_error']=str(e)
print(json.dumps(report,sort_keys=True))
'''

ROOT_REMOTE = r'''import base64,hashlib,json,os,re,shlex,stat,subprocess,sys,tempfile
from pathlib import Path
GUEST_KEY='/var/lib/pc3-v100-vm/id_ed25519'
GUEST_KNOWN='/tmp/codex-pc3-vm-known_hosts'
FINGERPRINT='SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts'
stage='input'
report={'schema':'nvidia-hybrid-pc3-v100-rm-root-id-transport-v1','host':os.uname().nodename,
 'host_kernel_release':os.uname().release,'qualification':'failed','guest':None,'probe':None,
 'execution_scope':{'guest_driver_changed':False,'module_loaded':False,'vm_management_issued':False,
                    'pci_binding_changed':False}}
payload_path=None; payload_digest=''; payload_cleanup_passed=False
env={k:v for k,v in os.environ.items() if not k.startswith(('LD_','CUDA_','NVIDIA_','PYTHON'))}
env.update({'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
def call(argv,input_data=None,timeout=30):
 return subprocess.run(argv,input=input_data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
  timeout=timeout,check=False,env=env)
def guest_base():
 return ['ssh','-F','/dev/null','-T','-oBatchMode=yes','-oIdentitiesOnly=yes',
  '-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+GUEST_KNOWN,'-oConnectTimeout=8',
  '-oConnectionAttempts=1','-i',GUEST_KEY,'-p','22223','ubuntu@127.0.0.1']
def remote_command(argv): return ' '.join(shlex.quote(str(x)) for x in argv)
def guest_json(code,input_data=None,timeout=45):
 cmd=remote_command(['python3','-c',code])
 result=call(guest_base()+[cmd],input_data=input_data,timeout=timeout)
 if result.returncode: raise RuntimeError('pinned V100 guest command failed')
 return json.loads(result.stdout.decode('utf-8','strict'))
###GUEST_HOSTKEY_HELPER###
try:
 if len(sys.argv)!=3: raise ValueError('payload arguments missing')
 payload_path=Path(sys.argv[1]); payload_digest=sys.argv[2]
 if (not re.fullmatch(r'/tmp/codex-v100-payload-[0-9a-f]{32}\.json',str(payload_path)) or
     not re.fullmatch(r'[0-9a-f]{64}',payload_digest)): raise ValueError('payload identity invalid')
 st=payload_path.lstat()
 if not stat.S_ISREG(st.st_mode) or st.st_uid==0 or stat.S_IMODE(st.st_mode)!=0o600: raise ValueError('payload owner or mode invalid')
 raw=payload_path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=payload_digest: raise ValueError('payload hash mismatch')
 payload=json.loads(raw.decode('utf-8'))
 payload_path.unlink(); payload_cleanup_passed=not payload_path.exists()
 if os.uname().nodename!='pc3': raise ValueError('unexpected PC3 host identity')
 if payload.get('root_id',0)<=0 or payload.get('root_id',0)>0xffffffff: raise ValueError('invalid source ROOT ID')
 key=Path(GUEST_KEY); ks=key.lstat()
 if not stat.S_ISREG(ks.st_mode) or ks.st_uid!=0 or stat.S_IMODE(ks.st_mode)!=0o600: raise ValueError('guest SSH key ownership or mode invalid')
 known=Path(GUEST_KNOWN)
 verify_guest_host_key(known,FINGERPRINT,0,call)
 report['guest_hostkey_fingerprint']=FINGERPRINT
 stage='guest_probe'
 payload_guest={'binary_base64':payload['binary_base64'],'binary_sha256':payload['binary_sha256'],
                'root_id':payload['root_id'],'gpu_uuid':'GPU-42d06a85-027a-75ea-7857-a8de27ad465e'}
 import_code=###GUEST_SCRIPT_REPR###
 guest=guest_json(import_code,json.dumps(payload_guest,separators=(',',':')).encode(),timeout=60)
 report['guest']= {'host':guest.get('host'),'kernel_release':guest.get('kernel_release'),
                   'euid':guest.get('euid'),'device_before':guest.get('device_before'),
                   'device_after':guest.get('device_after'),'helper_removed':guest.get('helper_removed')}
 report['probe']=guest.get('helper_result')
 if guest.get('schema')!='nvidia-hybrid-v100-rm-root-id-probe-v1' or guest.get('qualification')!='installed-R580-root-ID-mirror-request-and-free-passed' or guest.get('helper_removed') is not True:
  raise ValueError('V100 guest did not confirm RM allocation, requested ID and cleanup')
 report['qualification']='R595-observed-ID-accepted-and-freed-by-installed-PC3-V100-R580'
except Exception as e:
 report['error']=str(e)[:600]; report['failure_stage']=stage
finally:
 if payload_path is not None and payload_path.exists():
  try:
   st=payload_path.lstat()
   if stat.S_ISREG(st.st_mode) and st.st_uid!=0 and stat.S_IMODE(st.st_mode)==0o600 and hashlib.sha256(payload_path.read_bytes()).hexdigest()==payload_digest:
    payload_path.unlink(); payload_cleanup_passed=not payload_path.exists()
  except OSError: pass
 report['payload_file_cleanup_passed']=payload_cleanup_passed
print(json.dumps(report,sort_keys=True))
'''
ROOT_REMOTE = ROOT_REMOTE.replace('###GUEST_HOSTKEY_HELPER###', inspect.getsource(verify_guest_host_key))
ROOT_REMOTE = ROOT_REMOTE.replace('###GUEST_SCRIPT_REPR###', repr(GUEST_SCRIPT))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_rtx_root_id(report: object) -> tuple[int, dict[str, object]]:
    if not isinstance(report, dict) or report.get('schema') != 'nvidia-hybrid-remote-selected-gpu-transport-v1':
        raise ValueError('unsupported RTX transport report')
    remote = report.get('remote')
    if not isinstance(remote, dict) or remote.get('schema') != 'nvidia-hybrid-remote-selected-gpu-v1':
        raise ValueError('RTX host report is missing')
    selected = remote.get('selected_nvidia_smi')
    if (not isinstance(selected, dict) or selected.get('uuid') != RTX_UUID or
            selected.get('pci') not in (RTX_PCI, '00000000:02:00.0') or
            selected.get('driver') != RTX_DRIVER or 'RTX 5080' not in selected.get('name', '')):
        raise ValueError('RTX source identity does not match installed PC3 hardware')
    acceptance = remote.get('hardware_acceptance')
    observation = (acceptance.get('ioctl_observation') if isinstance(acceptance, dict) else None)
    trace = observation.get('report') if isinstance(observation, dict) else None
    if (not isinstance(trace, dict) or trace.get('trace_complete') is not True or
            trace.get('errors') != [] or trace.get('control_path') != '/dev/nvidiactl'):
        raise ValueError('RTX source trace is incomplete')
    for index, record in enumerate(trace.get('records', [])):
        if not isinstance(record, dict) or record.get('operation') != 'alloc' or record.get('syscall_return') != 0:
            continue
        entry, exit = record.get('entry'), record.get('exit')
        if (isinstance(entry, dict) and isinstance(exit, dict) and
                entry.get('layout') == 'NVOS64' and entry.get('hClass') == 0 and
                entry.get('hRoot') == 0 and entry.get('hObjectParent') == 0 and
                entry.get('pAllocParms') == 0 and entry.get('pRightsRequested') == 0 and
                entry.get('paramsSize') == 0 and entry.get('flags') == 0 and
                exit.get('status') == 0 and exit.get('hClass') == 0x41 and
                type(exit.get('hObjectNew')) is int and 0 < exit['hObjectNew'] <= 0xffffffff):
            return exit['hObjectNew'], {'record_index': index, 'record': record, 'device': selected}
    raise ValueError('no successful ordinary RTX NVOS64 ROOT ID in the typed trace')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, default=DEFAULT_PROBE)
    parser.add_argument('--rtx-report', type=Path, default=DEFAULT_RTX_REPORT)
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
    report: dict[str, object] = {
        'schema': 'nvidia-hybrid-pc3-v100-rm-root-id-host-run-v1',
        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        'qualification': 'failed', 'target': args.target, 'credential_host': args.credential_host,
        'credential_value_logged': False, 'credential_value_persisted': False,
        'runner_path': str(Path(__file__).resolve()),
        'runner_sha256': sha256_bytes(Path(__file__).resolve().read_bytes()),
        'root_remote_sha256': sha256_bytes(ROOT_REMOTE.encode()),
        'guest_script_sha256': sha256_bytes(GUEST_SCRIPT.encode()),
        'rtx_source': None, 'probe': None, 'remote': None,
        'payload_staging': None, 'payload_cleanup_passed': False,
        'pc3_ssh_exit_code': None, 'pc3_stderr': '',
    }
    secret = None; payload_path = None; payload_digest = None
    payload_cleanup_done = False
    try:
        if args.target != DEFAULT_PC3_TARGET or args.host_key_alias != DEFAULT_HOST_KEY_ALIAS:
            raise ValueError('this hardware probe is restricted to the pinned PC3 SSH target')
        probe_path = args.probe.resolve(strict=True)
        source_path = args.rtx_report.resolve(strict=True)
        binary = probe_path.read_bytes(); source_bytes = source_path.read_bytes()
        rtx_report = json.loads(source_bytes)
        root_id, source = extract_rtx_root_id(rtx_report)
        report['rtx_source'] = {'path': str(source_path), 'sha256': sha256_bytes(source_bytes),
                                'observed_at_utc': rtx_report.get('observed_at_utc'),
                                'record_index': source['record_index'], 'root_id': root_id,
                                'device': source['device']}
        report['probe'] = {'path': str(probe_path), 'bytes': len(binary), 'sha256': sha256_bytes(binary)}
        payload = {'binary_base64': base64.b64encode(binary).decode('ascii'),
                   'binary_sha256': sha256_bytes(binary), 'root_id': root_id}
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        payload_digest = sha256_bytes(payload_bytes)
        payload_path = payload_staging_path(uuid.uuid4().hex)
        report['payload_staging'] = {'path': payload_path, 'bytes': len(payload_bytes),
                                     'sha256': payload_digest, 'uploaded': False}
        secret = fetch_pc3_sudo_secret(args.credential_host, args.credential_file)
        writer_command = ' '.join(shlex.quote(item) for item in
                                  ['python3', '-c', payload_writer_code(), payload_path, payload_digest])
        uploaded = subprocess.run(pc3_ssh_base(args.target, args.host_key_alias) + [writer_command],
                                  input=payload_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=30, check=False)
        if uploaded.returncode != 0:
            raise RuntimeError('PC3 payload staging failed')
        receipt = json.loads(uploaded.stdout.decode('utf-8', 'strict'))
        if receipt != {'bytes': len(payload_bytes), 'sha256': payload_digest}:
            raise RuntimeError('PC3 payload receipt mismatch')
        report['payload_staging']['uploaded'] = True
        command = ('sudo -S -p \'\' python3 -c ' + shlex.quote(ROOT_REMOTE) + ' ' +
                   shlex.quote(payload_path) + ' ' + shlex.quote(payload_digest))
        result = subprocess.run(pc3_ssh_base(args.target, args.host_key_alias) + [command],
                                input=sudo_auth_stdin(secret), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=120, check=False)
        report['pc3_ssh_exit_code'] = result.returncode
        report['pc3_stderr'] = result.stderr.decode('utf-8', 'replace')[-2000:]
        try:
            remote = json.loads(result.stdout.decode('utf-8', 'strict'))
        except (UnicodeDecodeError, ValueError):
            remote = None
        report['remote'] = remote
        if (result.returncode != 0 or not isinstance(remote, dict) or
                remote.get('schema') != 'nvidia-hybrid-pc3-v100-rm-root-id-transport-v1' or
                remote.get('qualification') != 'R595-observed-ID-accepted-and-freed-by-installed-PC3-V100-R580' or
                remote.get('payload_file_cleanup_passed') is not True):
            raise RuntimeError('PC3 did not confirm the bounded V100 RM request and cleanup')
        report['payload_cleanup_passed'] = True
        payload_cleanup_done = True
        report['qualification'] = 'RTX5080-observed-ID-accepted-and-freed-by-installed-V100-R580'
    except Exception as error:
        report['error'] = str(error)[:700]
    finally:
        if payload_path and payload_digest and not payload_cleanup_done:
            report['payload_cleanup_passed'] = cleanup_pc3_payload(
                args.target, args.host_key_alias, payload_path, payload_digest)
            payload_cleanup_done = report['payload_cleanup_passed'] is True
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
                      'source_root_id': report['rtx_source']['root_id'] if report['rtx_source'] else None,
                      'pc3_ssh_exit_code': report['pc3_ssh_exit_code'],
                      'payload_cleanup_passed': report['payload_cleanup_passed']}))
    return 0 if report['qualification'] != 'failed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
