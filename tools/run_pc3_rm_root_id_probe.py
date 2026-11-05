#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Test a V100-observed RM root ID against PC3's installed RTX5080 driver.

The remote helper issues one NVOS64 ROOT_CLIENT allocation with that hRoot and
frees it only after a confirmed successful allocation. It opens no CUDA
context, launches no kernel, and does not change any installed driver state.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROBE = ROOT / 'build/experiments/rm-root-id-probe-v1/rm_root_id_probe'
DEFAULT_V100_REPORT = ROOT / 'evidence/pc3-v100-rm-ioctl-reference-v1-20261020.json'
EXPECTED_UUID = 'GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77'
EXPECTED_PCI = '0000:02:00.0'
EXPECTED_HOST = 'pc3'
EXPECTED_DRIVER = '595.99.02'

REMOTE = r'''import base64,hashlib,json,os,re,stat,subprocess,sys,tempfile
from pathlib import Path

def fail(message): raise ValueError(message)
def canonical_pci(value):
 m=re.fullmatch(r'([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])',value)
 if not m or int(m.group(3),16)>31: fail('invalid PCI identity')
 return f'{int(m.group(1),16)&0xffff:04x}:{int(m.group(2),16):02x}:{int(m.group(3),16):02x}.{int(m.group(4),16)}'

payload=json.load(sys.stdin)
report={'schema':'nvidia-hybrid-pc3-rm-root-id-probe-v1','host':os.uname().nodename,
        'kernel_release':os.uname().release,'qualification':'failed','device':None,
        'device_after':None,'helper_before':None,'helper_after':None,'helper_result':None,'error':''}
path=None
env={k:v for k,v in os.environ.items() if not k.startswith(('LD_','CUDA_','NVIDIA_','PYTHON'))}
env.update({'PATH':'/usr/bin:/bin','LC_ALL':'C'})
def inventory(uuid):
 r=subprocess.run(['nvidia-smi','-i',uuid,'--query-gpu=name,uuid,pci.bus_id,driver_version',
    '--format=csv,noheader,nounits'],text=True,capture_output=True,timeout=15,env=env,check=False)
 if r.returncode: fail('targeted nvidia-smi failed')
 rows=[line.strip().split(',') for line in r.stdout.splitlines() if line.strip()]
 if len(rows)!=1 or len(rows[0])!=4: fail('unexpected selected GPU inventory')
 name,observed_uuid,pci,driver=[v.strip() for v in rows[0]]
 if (observed_uuid!=uuid or 'RTX 5080' not in name or canonical_pci(pci)!='0000:02:00.0' or
     driver!='595.99.02'): fail('installed target GPU identity or driver version mismatch')
 return {'name':name,'uuid':observed_uuid,'pci':canonical_pci(pci),'driver_version':driver}
try:
 if report['host']!='pc3': fail('unexpected host identity')
 if payload.get('root_id',0)<=0 or payload.get('root_id',0)>0xffffffff: fail('invalid source root ID')
 if payload.get('gpu_uuid')!='GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77': fail('unexpected target UUID')
 if canonical_pci(payload.get('pci',''))!='0000:02:00.0': fail('unexpected target PCI identity')
 raw=base64.b64decode(payload['binary_base64'],validate=True)
 digest=hashlib.sha256(raw).hexdigest()
 if digest!=payload.get('binary_sha256'): fail('local helper hash mismatch')
 identity=inventory(payload['gpu_uuid'])
 node=Path('/dev/nvidiactl'); st=node.lstat()
 if not stat.S_ISCHR(st.st_mode) or not os.access(node,os.R_OK|os.W_OK): fail('control device is not an accessible character device')
 report['device']={**identity,
                   'control_path':str(node),'control_is_character_device':True,'control_rw_access':True}
 fd,name_path=tempfile.mkstemp(prefix='codex-rm-root-id-',dir='/tmp'); path=Path(name_path)
 with os.fdopen(fd,'wb') as f: f.write(raw)
 path.chmod(0o700)
 report['helper_before']={'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':len(raw)}
 if report['helper_before']!={'sha256':digest,'bytes':len(raw)}: fail('staged helper identity mismatch')
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
  fail('target RM did not confirm the requested root ID and cleanup')
 report['qualification']='installed-R595-root-ID-mirror-request-and-free-passed'
except Exception as e:
 report['error']=str(e)
finally:
 if path is not None:
  try:
   data=path.read_bytes()
   report['helper_after']={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
   if report['helper_after']!=report.get('helper_before'):
    report['qualification']='failed'; report['error']='staged helper changed during execution'
   path.unlink()
   report['helper_removed']=not path.exists()
   if not report['helper_removed']:
    report['qualification']='failed'; report['error']='staged helper cleanup failed'
  except OSError as e:
   report['helper_cleanup_error']=str(e); report['qualification']='failed'; report['error']='staged helper cleanup could not be verified'
 try:
  after=inventory('GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77')
  report['device_after']=after
  before=report.get('device')
  if isinstance(before,dict) and any(before.get(key)!=after.get(key) for key in ('name','uuid','pci','driver_version')):
   report['qualification']='failed'; report['error']='selected GPU identity changed during the probe'
 except Exception as e:
  report['qualification']='failed'; report['postflight_error']=str(e)
print(json.dumps(report,sort_keys=True))
'''


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_v100_root_id(report: object) -> tuple[int, dict[str, object]]:
    if not isinstance(report, dict) or report.get('schema') != 'nvidia-hybrid-pc3-v100-reference-transport-v1':
        raise ValueError('unsupported V100 transport report')
    remote = report.get('remote')
    if not isinstance(remote, dict) or remote.get('schema') != 'nvidia-hybrid-pc3-v100-guest-reference-v1':
        raise ValueError('V100 guest reference is unavailable')
    guest = remote.get('guest')
    if (not isinstance(guest, dict) or not str(guest.get('name', '')).startswith('Tesla V100') or
            guest.get('driver_version') != '580.178.04' or guest.get('pci') != '0000:00:05.0'):
        raise ValueError('V100 source identity does not match the pinned guest')
    observation = remote.get('ioctl_observation')
    if (not isinstance(observation, dict) or observation.get('trace_complete') is not True or
            observation.get('errors') != [] or observation.get('control_path') != '/dev/nvidiactl'):
        raise ValueError('V100 source trace is incomplete')
    matches = []
    for index, record in enumerate(observation.get('records', [])):
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
            matches.append((exit['hObjectNew'], index, record))
    if not matches:
        raise ValueError('no successful ordinary V100 NVOS64 ROOT ID in the typed trace')
    root_id, index, record = matches[0]
    return root_id, {'record_index': index, 'record': record, 'guest': guest}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, default=DEFAULT_PROBE)
    parser.add_argument('--v100-report', type=Path, default=DEFAULT_V100_REPORT)
    parser.add_argument('--output', type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output = args.output.resolve()
    report: dict[str, object] = {
        'schema': 'nvidia-hybrid-pc3-rm-root-id-host-run-v1',
        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        'qualification': 'failed', 'target': 'pc3@pc3', 'ssh_exit_code': None,
        'ssh_stderr': '', 'ssh_stdout': '', 'v100_source': None, 'remote': None,
        'runner_path': str(Path(__file__).resolve()),
        'runner_sha256': sha256_bytes(Path(__file__).resolve().read_bytes()),
        'remote_script_sha256': sha256_bytes(REMOTE.encode()),
    }
    if output.exists():
        print(json.dumps({'error': 'refusing to overwrite existing report', 'path': str(output)}), file=sys.stderr)
        return 2
    try:
        probe = args.probe.resolve(strict=True)
        source_path = args.v100_report.resolve(strict=True)
        binary = probe.read_bytes()
        source_bytes = source_path.read_bytes()
        source_report = json.loads(source_bytes)
        root_id, source_info = extract_v100_root_id(source_report)
        report['v100_source'] = {
            'path': str(source_path), 'sha256': sha256_bytes(source_bytes),
            'observed_at_utc': source_report.get('observed_at_utc'),
            'guest': source_info['guest'], 'record_index': source_info['record_index'],
            'root_id': root_id,
        }
        report['probe'] = {'path': str(probe), 'bytes': len(binary), 'sha256': sha256_bytes(binary)}
        payload = {
            'binary_base64': base64.b64encode(binary).decode('ascii'),
            'binary_sha256': sha256_bytes(binary), 'root_id': root_id,
            'gpu_uuid': EXPECTED_UUID, 'pci': EXPECTED_PCI,
        }
        remote_command = 'python3 -c ' + shlex.quote(REMOTE)
        command = ['ssh', '-T', '-oBatchMode=yes', '-oConnectTimeout=8',
                   '-oConnectionAttempts=1', 'pc3@pc3', remote_command]
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('LD_', 'CUDA_', 'NVIDIA_', 'PYTHON'))}
        environment.update({'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        try:
            result = subprocess.run(command, input=json.dumps(payload).encode(),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=55, check=False, env=environment)
        except subprocess.TimeoutExpired as error:
            report['ssh_exit_code'] = 124
            report['ssh_stderr'] = (error.stderr or b'').decode('utf-8', 'replace')[-2000:]
            raise ValueError('PC3 root-ID probe timed out') from None
        report['ssh_exit_code'] = result.returncode
        report['ssh_stderr'] = result.stderr.decode('utf-8', 'replace')[-2000:]
        report['ssh_stdout'] = result.stdout.decode('utf-8', 'replace')[-16000:]
        try:
            remote = json.loads(result.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError('PC3 returned no valid JSON result') from None
        report['remote'] = remote
        if (result.returncode != 0 or not isinstance(remote, dict) or
                remote.get('schema') != 'nvidia-hybrid-pc3-rm-root-id-probe-v1' or
                remote.get('qualification') != 'installed-R595-root-ID-mirror-request-and-free-passed' or
                remote.get('helper_removed') is not True or
                not isinstance(remote.get('device_after'), dict) or
                remote['device_after'].get('uuid') != EXPECTED_UUID or
                remote['device_after'].get('pci') != EXPECTED_PCI or
                remote['device_after'].get('driver_version') != EXPECTED_DRIVER):
            raise ValueError('PC3 did not confirm the bounded root-ID test and cleanup')
        report['qualification'] = 'V100-observed-ID-accepted-and-freed-by-installed-PC3-RTX5080-R595'
    except Exception as error:
        report['error'] = str(error)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        print(json.dumps({'error': 'refusing to overwrite existing report', 'path': str(output)}), file=sys.stderr)
        return 2
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'evidence': str(output), 'qualification': report['qualification'],
                      'source_root_id': root_id if 'root_id' in locals() else None,
                      'ssh_exit_code': report['ssh_exit_code']}))
    return 0 if report['qualification'] != 'failed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
