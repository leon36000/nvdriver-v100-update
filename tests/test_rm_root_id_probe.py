# SPDX-License-Identifier: MIT
"""Exercise the bounded root-ID protocol probe against fake syscalls."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest

from test_rm_root_client import include_flags

ROOT = Path(__file__).resolve().parents[1]

WRAPPERS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include "nvtypes.h"
#include "nvos.h"
#include "nv_escape.h"
#include "nv-ioctl-numbers.h"

static const char *scenario(void) { const char *s=getenv("SCENARIO"); return s?s:"success"; }
static unsigned int allocs, frees, closes;
int __wrap_open(const char *path, int flags, ...) {
 assert(!strcmp(path,"/dev/nvidiactl"));
 assert((flags & O_RDWR) && (flags & O_CLOEXEC) && (flags & O_NOFOLLOW));
 return 401;
}
int __wrap_fstat(int fd, struct stat *st) {
 assert(fd==401); memset(st,0,sizeof(*st)); st->st_mode=S_IFCHR|0600;
 st->st_rdev=makedev(195,255); return 0;
}
int __wrap_ioctl(int fd, unsigned long request, ...) {
 assert(fd==401); va_list ap; va_start(ap,request); void *data=va_arg(ap,void *); va_end(ap);
 if (_IOC_NR(request)==NV_ESC_RM_ALLOC) {
  ++allocs; assert(_IOC_TYPE(request)==NV_IOCTL_MAGIC && _IOC_SIZE(request)==sizeof(NVOS64_PARAMETERS));
  NVOS64_PARAMETERS *p=data; assert(p->pAllocParms==0 && p->paramsSize==0 && p->pRightsRequested==0 && p->flags==NVOS64_FLAGS_NONE);
  assert(p->status==0xffffffffU && p->hObjectParent==0 && p->hObjectNew==0);
  if (!strcmp(scenario(),"mirror") || !strcmp(scenario(),"alloc-mismatch")) assert(p->hClass==NV01_ROOT_CLIENT && p->hRoot==0x1234);
  else assert(p->hClass==NV01_ROOT && p->hRoot==0);
  if (!strcmp(scenario(),"alloc-transport")) { errno=EIO; return -1; }
  p->hClass=NV01_ROOT_CLIENT;
  p->hObjectNew=!strcmp(scenario(),"alloc-zero")?0:
      !strcmp(scenario(),"alloc-mismatch")?0x2222:
      !strcmp(scenario(),"mirror")?0x1234:0x7777;
  p->status=!strcmp(scenario(),"alloc-status")?NV_ERR_INVALID_ARGUMENT:NV_OK;
  return 0;
 }
 assert(_IOC_NR(request)==NV_ESC_RM_FREE && _IOC_TYPE(request)==NV_IOCTL_MAGIC && _IOC_SIZE(request)==sizeof(NVOS00_PARAMETERS));
 ++frees; NVOS00_PARAMETERS *p=data;
 assert(p->status==0xffffffffU && p->hRoot==p->hObjectOld && p->hObjectParent==p->hRoot);
 assert(p->hRoot==(!strcmp(scenario(),"alloc-mismatch")?0x2222:
                  !strcmp(scenario(),"mirror")?0x1234:0x7777));
 if (!strcmp(scenario(),"free-transport")) { errno=EIO; return -1; }
 p->status=!strcmp(scenario(),"free-status")?NV_ERR_INVALID_STATE:NV_OK;
 return 0;
}
int __wrap_close(int fd) { assert(fd==401); ++closes; if (!strcmp(scenario(),"close-failure")) { errno=EIO; return -1; } return 0; }
__attribute__((destructor)) static void check_calls(void) {
 if (!strcmp(scenario(),"bad-cli")) assert(!allocs && !frees && !closes);
 else if (!strcmp(scenario(),"alloc-transport") || !strcmp(scenario(),"alloc-status") || !strcmp(scenario(),"alloc-zero")) assert(allocs==1 && !frees && closes==1);
 else if (!strcmp(scenario(),"free-transport") || !strcmp(scenario(),"free-status") || !strcmp(scenario(),"close-failure")) assert(allocs==1 && frees==1 && closes==1);
 else if (!strcmp(scenario(),"alloc-mismatch")) assert(allocs==1 && frees==1 && closes==1);
 else assert(allocs==1 && frees==1 && closes==1);
}
'''


class RootIdProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        work = Path(cls.temp.name)
        wrappers = work / 'wrappers.c'
        wrappers.write_text(WRAPPERS)
        cls.program = work / 'root-id-probe'
        command = ['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1',
                   '-fsanitize=undefined', '-fno-sanitize-recover=all', *include_flags(),
                   str(ROOT / 'src/rm_root_id_probe.c'), str(wrappers),
                   '-Wl,--wrap=open', '-Wl,--wrap=fstat', '-Wl,--wrap=ioctl',
                   '-Wl,--wrap=close', '-o', str(cls.program)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if built.returncode:
            cls.temp.cleanup()
            raise AssertionError(built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_probe(self, scenario, *args):
        env = os.environ.copy()
        env['SCENARIO'] = scenario
        result = subprocess.run([str(self.program), *args], env=env, capture_output=True,
                                text=True, timeout=10)
        report = json.loads(result.stdout) if result.stdout.strip() else None
        return result, report

    def run_hold_probe(self, scenario, input_data):
        env = os.environ.copy()
        env['SCENARIO'] = scenario
        result = subprocess.run([str(self.program), '--hold-root'], env=env,
                                input=input_data, capture_output=True, text=True, timeout=10)
        events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        return result, events

    def test_hold_root_announces_confirmed_id_then_frees_after_release(self):
        result, events = self.run_hold_probe('success', 'release\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(events), 2)
        ready, finished = events
        self.assertEqual(ready['event'], 'root-held')
        self.assertEqual(ready['allocated_id'], 0x7777)
        self.assertFalse(ready['gpu_context_opened'])
        self.assertEqual(finished['action'], 'hold-root')
        self.assertTrue(finished['release_received'])
        self.assertTrue(finished['allocation']['passed'])
        self.assertTrue(finished['free']['passed'])
        self.assertTrue(finished['control_close_succeeded'])

    def test_hold_root_frees_confirmed_handle_on_eof(self):
        result, events = self.run_hold_probe('success', '')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]['event'], 'root-held')
        self.assertFalse(events[1]['release_received'])
        self.assertTrue(events[1]['free']['passed'])
        self.assertTrue(events[1]['control_close_succeeded'])

    def test_hold_root_frees_confirmed_handle_on_invalid_release(self):
        result, events = self.run_hold_probe('success', 'anything\n')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(events), 2)
        self.assertFalse(events[1]['release_received'])
        self.assertTrue(events[1]['free']['passed'])

    def test_automatic_root_allocates_then_frees_one_confirmed_handle(self):
        result, report = self.run_probe('success', '--allocate-root')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report['qualification'], 'root-allocation-and-free-passed')
        self.assertEqual(report['request']['hRoot'], 0)
        self.assertEqual(report['request']['hClass'], 0)
        self.assertEqual(report['allocated_id'], 0x7777)
        self.assertTrue(report['free']['passed'])
        self.assertFalse(report['gpu_context_opened'])

    def test_mirror_request_uses_the_supplied_root_id_and_returns_same_id(self):
        result, report = self.run_probe('mirror', '--mirror-root-id', '4660')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report['request'], {'layout': 'NVOS64', 'hRoot': 0x1234, 'hClass': 0x41})
        self.assertEqual(report['allocated_id'], 0x1234)
        self.assertTrue(report['returned_requested_id'])
        self.assertTrue(report['free']['passed'])

    def test_malformed_or_zero_mirror_id_is_rejected_before_open(self):
        for value in ('0', '-1', '0x1234', '4294967296', '12x'):
            with self.subTest(value=value):
                result, report = self.run_probe('bad-cli', '--mirror-root-id', value)
                self.assertEqual(result.returncode, 2)
                self.assertIsNone(report)

    def test_failed_allocations_are_not_blindly_freed(self):
        for scenario in ('alloc-transport', 'alloc-status', 'alloc-zero'):
            with self.subTest(scenario=scenario):
                result, report = self.run_probe(scenario, '--allocate-root')
                self.assertEqual(result.returncode, 2)
                self.assertFalse(report['free']['attempted'])

    def test_confirmed_but_mismatched_mirror_id_is_freed_once(self):
        result, report = self.run_probe('alloc-mismatch', '--mirror-root-id', '4660')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report['allocated_id'], 0x2222)
        self.assertFalse(report['returned_requested_id'])
        self.assertTrue(report['free']['attempted'])

    def test_free_or_close_failure_is_reported_without_retry(self):
        for scenario in ('free-transport', 'free-status', 'close-failure'):
            with self.subTest(scenario=scenario):
                result, report = self.run_probe(scenario, '--allocate-root')
                self.assertEqual(result.returncode, 2)
                self.assertFalse(report['cleanup_passed'])


if __name__ == '__main__':
    unittest.main()
