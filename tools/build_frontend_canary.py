#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the ROOT-only userspace canary and run syscall-double CPU tests.

The production executable is never executed, including its preflight. No module
is loaded, installed or inspected through a device. The negative fortify witness
is compiled and inspected statically only, never run.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04'


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, log, timeout=60):
    with log.open('x') as stream:
        code = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                              timeout=timeout, check=False).returncode
    return {'argv': command, 'exit_code': code, 'log': str(log), 'log_sha256': sha256(log)}


def build(work, expected_kernel=None):
    expected_kernel = expected_kernel or os.uname().release
    if not expected_kernel or len(expected_kernel) > 127 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-' for c in expected_kernel):
        raise ValueError('invalid expected kernel release')
    compiler = shutil.which('cc')
    if compiler is None:
        raise ValueError('C compiler is unavailable')
    work = work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    includes = [SOURCE / part for part in ('kernel-open/common/inc', 'src/common/sdk/nvidia/inc',
                                           'src/common/inc', 'src/common/inc/swref',
                                           'src/nvidia/arch/nvalloc/unix/include')]
    sdk_headers = [SOURCE / part for part in ('src/common/inc/nvtypes.h', 'src/common/sdk/nvidia/inc/nvos.h',
                                             'src/nvidia/arch/nvalloc/unix/include/nv_escape.h',
                                             'src/nvidia/arch/nvalloc/unix/include/nv-ioctl-numbers.h')]
    if not sdk_headers[0].exists():
        sdk_headers[0] = SOURCE / 'src/common/sdk/nvidia/inc/nvtypes.h'
    inputs = [ROOT / 'src/hybrid_frontend_canary.c', ROOT / 'tests/test_frontend_canary.py',
              Path(__file__).resolve(), ROOT / 'tests/test_rm_root_client.py',
              Path(compiler).resolve(), *sdk_headers]
    report = {'schema': 'nvidia-hybrid-frontend-canary-build-v1',
              'observed_at_utc': datetime.now(timezone.utc).isoformat(),
              'qualification': 'failed', 'expected_kernel_release': expected_kernel,
              'inputs_sha256': {str(p): sha256(p) for p in inputs},
              'production_executable_run': False, 'production_preflight_run': False,
              'module_loaded_or_installed': False, 'gpu_device_opened': False,
              'cuda_validated': False, 'steps': []}
    flags = ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-fstack-protector-strong',
             '-fPIE', '-pie', '-Wl,-z,relro,-z,now', '-DNVRM=1',
             '-DHYBRID_EXPECTED_KERNEL_RELEASE=' + json.dumps(expected_kernel)]
    flags += ['-I' + str(path) for path in includes]
    executable = work / 'hybrid_frontend_canary'
    dependencies = work / 'canary.d'
    command = [compiler, *flags, '-MMD', '-MF', str(dependencies), str(inputs[0]), '-o', str(executable)]
    step = run(command, work / 'compile.log')
    report['steps'].append(step)
    if step['exit_code']:
        report['error'] = 'canary compilation failed'
    else:
        report['executable'] = {'path': str(executable), 'sha256': sha256(executable), 'bytes': executable.stat().st_size}
        compiler_version = subprocess.run([compiler, '--version'], capture_output=True, text=True, check=True).stdout
        report['compiler_version'] = compiler_version
        dependency_paths = [Path(p) for p in shlex.split(dependencies.read_text().replace('\\\n', ' '))[1:]]
        report['compiled_dependency_sha256'] = {str(p): sha256(p) for p in dependency_paths}
        for flags_, name in ((['-h'], 'elf-header.log'), (['-d'], 'elf-dynamic.log'), (['-Ws'], 'elf-symbols.log')):
            report['steps'].append(run(['readelf', *flags_, str(executable)], work / name))
        # All executions below use a separately compiled syscall-double binary.
        test_code = ("import json,sys,unittest;sys.path.insert(0," + repr(str(ROOT / 'tests')) + ");"
                     "import test_frontend_canary as m;"
                     "r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(m));"
                     "print(json.dumps({'tests_run':r.testsRun,'scenario_processes':m.FrontendCanaryTests.counter,'success':r.wasSuccessful()}));"
                     "sys.exit(0 if r.wasSuccessful() else 1)")
        step = run([sys.executable, '-B', '-c', test_code], work / 'cpu-tests.log')
        report['steps'].append(step)
        try:
            report['cpu_tests'] = json.loads((work / 'cpu-tests.log').read_text().splitlines()[-1])
        except (ValueError, IndexError):
            report['cpu_tests'] = {'success': False}
        # Reproduce the initial missing-fortify-wrapper mistake WITHOUT running
        # it: GNU libc redirects readlink to __readlink_chk under fortification.
        spec = importlib.util.spec_from_file_location('canary_fixture', inputs[1])
        fixture_module = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(ROOT / 'tests'))
        spec.loader.exec_module(fixture_module)
        negative_source = work / 'negative-missing-fortify-wrapper.c'
        negative_source.write_text(fixture_module.WRAPPERS)
        negative = work / 'negative-missing-fortify-wrapper'
        command = [compiler, *flags, '-O1', '-fsanitize=undefined', '-fno-sanitize-recover=all', '-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=3', str(inputs[0]), str(negative_source), '-o', str(negative)]
        command += ['-Wl,--wrap=' + name for name in ('open', 'read', 'close', 'readlink', 'uname', 'fstat', 'lstat', 'ioctl')]
        step = run(command, work / 'negative-compile.log')
        report['steps'].append(step)
        negative_found = False
        if not step['exit_code']:
            step = run(['nm', '-u', str(negative)], work / 'negative-undefined.log')
            report['steps'].append(step)
            negative_found = '__readlink_chk@' in (work / 'negative-undefined.log').read_text()
        report['negative_fortify_witness'] = {
            'compiled_only_never_executed': True, 'unwrapped_fortified_readlink_detected': negative_found,
            'historical_initial_fixture_failure': 'Initial fixture wrapped readlink but omitted __readlink_chk; preflight therefore read local binding symlinks and all four binding checks returned false. No control device was opened. The final fixture wraps both symbols and rejects any remaining unwrapped OS entry point via nm before running.',
            'historical_local_symlink_paths': ['/sys/bus/pci/devices/0000:03:00.0/driver',
                                               '/sys/bus/pci/devices/0000:03:00.0/driver/module',
                                               '/sys/bus/pci/devices/0000:02:00.0/driver',
                                               '/sys/bus/pci/devices/0000:02:00.0/driver/module'],
            'historical_failure_does_not_establish_pci_device_absence': True,
            'source': str(negative_source), 'source_sha256': sha256(negative_source),
            'binary': str(negative), 'binary_sha256': sha256(negative) if negative.exists() else None,
        }
        if report['cpu_tests'].get('success') and report['cpu_tests'].get('tests_run') == 6 and negative_found and all(step['exit_code']==0 for step in report['steps']):
            report['qualification'] = 'compiled-canary-with-syscall-double-tests-only'
        else:
            report['error'] = 'CPU contract or static negative witness failed'
    report['inputs_unchanged'] = all(sha256(Path(p))==h for p,h in report['inputs_sha256'].items())
    if not report['inputs_unchanged']:
        report.update(qualification='failed', error='source input changed during build')
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--kernel-release')
    args = parser.parse_args()
    if args.report.exists():
        parser.error('report already exists')
    report = build(args.work, args.kernel_release)
    with args.report.open('x') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report.get(key) for key in ('qualification', 'error', 'cpu_tests')}))
    return 0 if report['qualification'] == 'compiled-canary-with-syscall-double-tests-only' else 1


if __name__ == '__main__':
    raise SystemExit(main())
