# SPDX-License-Identifier: MIT
"""Userspace ROOT canary with syscall spies; no actual sysfs/device/GPU access."""
from pathlib import Path
import json
import subprocess
import tempfile
import unittest

from test_rm_root_client import include_flags

ROOT = Path(__file__).resolve().parents[1]

WRAPPERS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include "nvtypes.h"
#include "nvos.h"
#include "nv_escape.h"
#include "nv-ioctl-numbers.h"
#undef assert
#define assert(value) do { if (!(value)) { fprintf(stderr,"spy assertion line %d: %s\n",__LINE__,#value); _exit(200); } } while(0)
static int control_opens, control_closes, ioctls, link_checks, parameter_reads, enable_reads;
static size_t offsets[4];
static const char *scenario(void) { const char *s=getenv("CANARY_SCENARIO"); assert(s); return s; }
static bool is(const char *s) { return !strcmp(scenario(),s); }
int __real_open(const char *,int,...);
int __wrap_open(const char *path,int flags,...) {
 if(!strcmp(path,"/sys/module/hybrid580_legacy/parameters/hybrid_gpu_pci")) { offsets[0]=0; return 400; }
 if(!strcmp(path,"/sys/module/hybrid580_open/parameters/hybrid_gpu_pci")) { offsets[1]=0; return 401; }
 if(!strcmp(path,"/sys/module/hybrid580_frontend/parameters/enable_control")) { offsets[2]=0; return 402; }
 if(!strcmp(path,"/sys/class/misc/hybrid580ctl/dev")) { offsets[3]=0; return 403; }
 if(!strcmp(path,"/dev/hybrid580ctl")) {
  assert((flags&(O_RDWR|O_CLOEXEC|O_NOFOLLOW))==(O_RDWR|O_CLOEXEC|O_NOFOLLOW));
  assert(link_checks==4 && parameter_reads>=2 && enable_reads>=1); ++control_opens;
  if(is("open-failure")) { errno=EACCES; return -1; }
  return 500;
 }
 assert(!strcmp(path,getenv("CANARY_REPORT")));
 assert((flags&(O_CREAT|O_EXCL|O_NOFOLLOW))==(O_CREAT|O_EXCL|O_NOFOLLOW));
 va_list ap; va_start(ap,flags); int mode=va_arg(ap,int); va_end(ap); assert(mode==0600);
 return __real_open(path,flags,mode);
}
ssize_t __wrap_read(int fd,void *buffer,size_t capacity) {
 assert(fd>=400 && fd<=403);
 const char *value=fd==400?"0000:03:00.0\n":fd==401?"0000:02:00.0\n":fd==402?"Y\n":"10:123\n";
 if(fd<=401) ++parameter_reads;
 if(fd==402) ++enable_reads;
 if(is("parameter-mismatch") && fd==400) value="0000:04:00.0\n";
 if(is("parameter-missing") && fd==401) { errno=ENOENT; return -1; }
 if(is("parameter-prefix") && fd==400) value="0000:03:00.0\nextra\n";
 if(is("disabled") && fd==402) value="N\n";
 if(is("misc-mismatch") && fd==403) value="195:0\n";
 if(is("misc-trailing") && fd==403) value="10:123 garbage\n";
 size_t len=strlen(value), offset=offsets[fd-400];
 if(offset>=len) return 0;
 size_t amount=len-offset; if(amount>capacity) amount=capacity;
 memcpy(buffer,value+offset,amount); offsets[fd-400]+=amount; return (ssize_t)amount;
}
int __wrap_close(int fd) {
 if(fd>=400 && fd<=403) return 0;
 assert(fd==500); assert(++control_closes==1);
 if(is("close-failure")) { errno=EIO; return -1; }
 return 0;
}
ssize_t __wrap_readlink(const char *path,char *buffer,size_t capacity) {
 const char *target;
 if(!strcmp(path,"/sys/bus/pci/devices/0000:03:00.0/driver")) target="../../../bus/pci/drivers/hybrid580_legacy";
 else if(!strcmp(path,"/sys/bus/pci/devices/0000:02:00.0/driver")) target="../../../bus/pci/drivers/hybrid580_open";
 else if(!strcmp(path,"/sys/bus/pci/devices/0000:03:00.0/driver/module")) target="../../../../module/hybrid580_legacy";
 else { assert(!strcmp(path,"/sys/bus/pci/devices/0000:02:00.0/driver/module")); target="../../../../module/hybrid580_open"; }
 ++link_checks;
 if(is("driver-mismatch") && strstr(path,"03:00.0/driver") && !strstr(path,"module")) target="../../../bus/pci/drivers/nvidia";
 if(is("module-mismatch") && strstr(path,"02:00.0/driver/module")) target="../../../../module/nvidia";
 if(is("binding-missing")) { errno=ENOENT; return -1; }
 if(is("link-truncated")) { memset(buffer,'x',capacity); return (ssize_t)capacity; }
 size_t len=strlen(target); assert(len<capacity); memcpy(buffer,target,len); return (ssize_t)len;
}
ssize_t __wrap___readlink_chk(const char *p,char *b,size_t n,size_t cap) { assert(n<=cap); return __wrap_readlink(p,b,n); }
int __wrap_uname(struct utsname *u) { memset(u,0,sizeof(*u)); strcpy(u->release,is("kernel-mismatch")?"wrong-kernel":"7.0.0-38-generic"); return 0; }
int __wrap_lstat(const char *path,struct stat *st) {
 assert(!strcmp(path,"/dev/hybrid580ctl")); memset(st,0,sizeof(*st));
 if(is("node-stat-failure")) { errno=ENOENT; return -1; }
 st->st_mode=is("node-regular-file")?S_IFREG|0600:(is("node-symlink")?S_IFLNK|0777:S_IFCHR|0600);
 st->st_rdev=makedev(10,is("node-device-mismatch")?124:123); return 0;
}
int __wrap_fstat(int fd,struct stat *st) {
 assert(fd==500); memset(st,0,sizeof(*st));
 if(is("stat-failure")) { errno=EIO; return -1; }
 st->st_mode=is("regular-file")?S_IFREG|0600:S_IFCHR|0600;
 st->st_rdev=makedev(10,is("device-mismatch")?124:123); return 0;
}
int __wrap_ioctl(int fd,unsigned long command,...) {
 assert(fd==500); ++ioctls;
 va_list ap; va_start(ap,command); void *payload=va_arg(ap,void *); va_end(ap);
 if(ioctls<=2) {
  assert(_IOC_NR(command)==NV_ESC_RM_ALLOC && _IOC_TYPE(command)==NV_IOCTL_MAGIC && _IOC_DIR(command)==(_IOC_READ|_IOC_WRITE));
  if(ioctls==1) {
   assert(_IOC_SIZE(command)==sizeof(NVOS21_PARAMETERS)); NVOS21_PARAMETERS *p=payload;
   assert(p->hClass==NV01_ROOT && p->hRoot==0 && p->hObjectParent==0 && p->hObjectNew==0 && p->pAllocParms==0 && p->paramsSize==0 && p->status==(NvV32)0xffffffffU);
   if(is("first-transport")) { errno=EINTR; return -1; }
   p->hClass=is("class-not-canonical")?NV01_ROOT:NV01_ROOT_CLIENT; p->hObjectNew=is("zero-handle")?0:987;
   if(!is("missing-status")) p->status=is("first-status")?NV_ERR_INVALID_STATE:NV_OK;
  } else {
   assert(_IOC_SIZE(command)==sizeof(NVOS64_PARAMETERS)); NVOS64_PARAMETERS *p=payload;
   assert(p->hClass==NV01_ROOT && p->hRoot==0 && p->hObjectParent==0 && p->hObjectNew==0 && p->pAllocParms==0 && p->paramsSize==0 && p->pRightsRequested==0 && p->flags==0 && p->status==(NvV32)0xffffffffU);
   if(is("second-transport")) { errno=EFAULT; return -1; }
   p->hClass=NV01_ROOT_CLIENT; p->hObjectNew=is("duplicate-ids")?987:988; p->status=is("second-status")?NV_ERR_INVALID_STATE:NV_OK;
   if(is("mutated-output")) p->pRightsRequested=(NvP64)1;
  }
 } else {
  assert(ioctls<=4 && _IOC_TYPE(command)==NV_IOCTL_MAGIC && _IOC_NR(command)==NV_ESC_RM_FREE && _IOC_SIZE(command)==sizeof(NVOS00_PARAMETERS));
  NVOS00_PARAMETERS *p=payload;
  assert(p->status==(NvV32)0xffffffffU && p->hRoot==p->hObjectOld);
  assert(p->hRoot==(ioctls==3?988:987) && p->hObjectParent==(ioctls==3?988:0));
  if((is("first-free-transport") && ioctls==3) || (is("second-free-transport") && ioctls==4)) { errno=EINTR; return -1; }
  p->status=((is("first-free-status") && ioctls==3) || (is("second-free-status") && ioctls==4))?NV_ERR_INVALID_STATE:NV_OK;
 }
 return 0;
}
__attribute__((destructor)) static void assert_no_retry_or_forbidden_device(void) {
 if(is("success") || is("close-failure")) assert(control_opens==1 && control_closes==1 && ioctls==4);
 else if(is("open-failure")) assert(control_opens==1 && control_closes==0 && ioctls==0);
 else if(is("regular-file") || is("device-mismatch") || is("stat-failure")) assert(control_opens==1 && control_closes==1 && ioctls==0);
 else if(is("first-transport") || is("first-status") || is("class-not-canonical") || is("zero-handle") || is("missing-status")) assert(control_opens==1 && control_closes==1 && ioctls==1);
 else if(is("second-transport") || is("second-status") || is("duplicate-ids") || is("mutated-output")) assert(control_opens==1 && control_closes==1 && ioctls==2);
 else if(is("first-free-transport") || is("first-free-status")) assert(control_opens==1 && control_closes==1 && ioctls==3);
 else if(is("second-free-transport") || is("second-free-status")) assert(control_opens==1 && control_closes==1 && ioctls==4);
 else assert(!control_opens && !control_closes && !ioctls);
}
'''


class FrontendCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.work = Path(cls.tmp.name)
        wrapper = cls.work / 'syscall-spies.c'
        wrapper.write_text(WRAPPERS)
        cls.executable = cls.work / 'canary'
        command = ['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1',
                   '-fsanitize=undefined', '-fno-sanitize-recover=all',
                   '-DHYBRID_EXPECTED_KERNEL_RELEASE="7.0.0-38-generic"', *include_flags(),
                   str(ROOT / 'src/hybrid_frontend_canary.c'), str(wrapper), '-o', str(cls.executable)]
        command += ['-Wl,--wrap=' + name for name in ('open', 'read', 'close', 'readlink', '__readlink_chk', 'uname', 'fstat', 'lstat', 'ioctl')]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            cls.tmp.cleanup()
            raise AssertionError(result.stderr)
        undefined = subprocess.run(['nm', '-u', str(cls.executable)], capture_output=True, text=True, check=True).stdout
        forbidden = {'readlink', '__readlink_chk', 'read', '__read_chk', 'close', 'fstat', 'fstat64', 'lstat', 'lstat64', 'uname', 'ioctl'}
        remaining = {line.split()[-1].split('@')[0] for line in undefined.splitlines() if line.split()}
        if remaining & forbidden:
            cls.tmp.cleanup()
            raise AssertionError('unwrapped OS call in CPU fixture: ' + str(remaining & forbidden))
        cls.counter = 0

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_case(self, scenario, *, execute=True, arguments=None, existing=False, extra=None):
        import os
        type(self).counter += 1
        report = self.work / ('report-' + str(self.counter) + '.json')
        if existing:
            if existing == 'symlink':
                target = self.work / ('preserved-' + str(self.counter))
                target.write_text('preserve-me')
                report.symlink_to(target)
            else:
                report.write_text('preserve-me')
        args = arguments if arguments is not None else ['--legacy-pci', '0000:03:00.0', '--open-pci', '0000:02:00.0', '--output', str(report)]
        if extra:
            args += extra
        if execute and arguments is None:
            args += ['--execute']
        result = subprocess.run([str(self.executable), *args], capture_output=True, text=True, timeout=10,
                                env={**os.environ, 'CANARY_SCENARIO': scenario, 'CANARY_REPORT': str(report)})
        data = json.loads(report.read_text()) if report.exists() and not existing else None
        return result, data, report

    def test_default_and_explicit_dry_run_never_open_control(self):
        for extra in ([], ['--dry-run']):
            result, data, _ = self.run_case('dry-run', execute=False, extra=extra)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(data['qualification'], 'preflight-passed-not-executed')
            self.assertFalse(data['control_opened'])
            self.assertFalse(data['execution_attempted'])
            self.assertFalse(any(op['attempted'] for op in data['operations']))

    def test_success_two_root_layouts_out_of_order_free_and_truthful_report(self):
        result, data, _ = self.run_case('success')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(data['qualification'], 'ROOT-only-control-transactions-passed')
        self.assertEqual([op['object'] for op in data['operations']], [987, 988, 988, 987])
        self.assertEqual([op['parent'] for op in data['operations']], [0, 0, 988, 0])
        self.assertTrue(all(op['success'] for op in data['operations']))
        self.assertTrue(data['control_close_succeeded'])
        for key in ('cuda_validated', 'gpu_kernels_executed', 'uvm_validated', 'backend_cleanup_synchronous'):
            self.assertFalse(data[key])

    def test_preflight_failures_refuse_before_device_open(self):
        for scenario in ('kernel-mismatch', 'parameter-mismatch', 'parameter-missing', 'parameter-prefix',
                         'driver-mismatch', 'module-mismatch', 'binding-missing', 'link-truncated',
                         'disabled', 'misc-mismatch', 'misc-trailing'):
            with self.subTest(scenario=scenario):
                result, data, _ = self.run_case(scenario)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertFalse(data['preflight']['passed'])
                self.assertFalse(data['control_opened'])
                self.assertTrue(data['error'])

    def test_ambiguous_execution_aborts_closes_and_never_retries(self):
        for scenario in ('open-failure', 'node-stat-failure', 'node-regular-file', 'node-symlink', 'node-device-mismatch',
                         'stat-failure', 'regular-file', 'device-mismatch',
                         'first-transport', 'first-status', 'class-not-canonical', 'zero-handle', 'missing-status',
                         'second-transport', 'second-status', 'duplicate-ids', 'mutated-output',
                         'first-free-transport', 'first-free-status', 'second-free-transport', 'second-free-status', 'close-failure'):
            with self.subTest(scenario=scenario):
                result, data, _ = self.run_case(scenario)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse(data['root_transactions_passed'])
                self.assertTrue(data['error'])
                self.assertEqual(data['control_close_succeeded'], scenario not in ('open-failure', 'close-failure', 'node-stat-failure', 'node-regular-file', 'node-symlink', 'node-device-mismatch'))

    def test_existing_report_preserved_before_preflight_and_device_access(self):
        for existing in (True, 'symlink'):
            result, _, report = self.run_case('report-existing', existing=existing)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(report.read_text(), 'preserve-me')

    def test_invalid_arguments_reject_without_files_or_device_access(self):
        cases = [[], ['--execute'], ['--help'], ['--legacy-pci', '0000:03:20.0'],
                 ['--legacy-pci', '0000:03:00.8', '--open-pci', '0000:02:00.0', '--output', 'x'],
                 ['--legacy-pci', '0000:AB:00.0', '--open-pci', '0000:02:00.0', '--output', 'x'],
                 ['--legacy-pci', '0000:03:20.0', '--open-pci', '0000:02:00.0', '--output', 'x'],
                 ['--legacy-pci', '0000:03:00.0', '--open-pci', '0000:02:00.0', '--output', 'x', '--kernel-release', 'a', '--kernel-release', 'b'],
                 ['--legacy-pci', '0000:03:00.0', '--open-pci', '0000:03:00.0', '--output', 'x'],
                 ['--execute', '--dry-run'], ['--execute', '--execute'],
                 ['--kernel-release', 'a', '--kernel-release', 'b'], ['--unknown']]
        for args in cases:
            with self.subTest(arguments=args):
                result, data, report = self.run_case('invalid-arguments', arguments=args)
                self.assertEqual(result.returncode, 0 if args == ['--help'] else 2, result.stderr)
                self.assertIsNone(data)
                self.assertFalse(report.exists())


if __name__ == '__main__':
    unittest.main()
