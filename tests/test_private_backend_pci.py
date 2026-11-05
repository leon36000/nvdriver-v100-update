# SPDX-License-Identifier: MIT
"""Pinned-source CPU contracts: deny unselected PCI probes before effects."""
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
ARCHIVE=ROOT/'.cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz'
SHA='060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8'
SOURCE='NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia/nv-pci.c'
PATCH=ROOT/'patches/r580.178.04/0003-private-open-pci-guard.patch'

class PrivatePciTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        digest=hashlib.sha256()
        with ARCHIVE.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''): digest.update(chunk)
        if digest.hexdigest()!=SHA: raise AssertionError('pinned archive mismatch')
        cls.temp=tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name)
        with tarfile.open(ARCHIVE,'r:xz') as archive:
            cls.original=archive.extractfile(SOURCE).read().decode()
        path=cls.root/'kernel-open/nvidia/nv-pci.c'; path.parent.mkdir(parents=True)
        path.write_text(cls.original)
        subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(PATCH)],cwd=cls.root,check=True,capture_output=True)
        cls.text=path.read_text()

    def test_actual_source_guard_and_probe_prefix_before_effect(self):
        start=self.text.index('static int hybrid_pci_bdf_selected(')
        end=self.text.index('\nstatic void\nnv_check_and_exclude_gpu',start)
        helper=self.text[start:end]
        begin=self.text.index('static int\nnv_pci_probe\n')
        finish=self.text.index('    nv_printf(NV_DBG_SETUP',begin)
        prefix=self.text[begin:finish]
        prelude=r'''
#include <assert.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
typedef void nv_state_t; typedef void nv_linux_state_t; typedef void nvidia_stack_t;
typedef unsigned char NvU8; typedef int NvBool; typedef int NV_STATUS;
#define NV_FALSE 0
#define NV_GPU_BAR_INDEX_REGS 0
static NvBool nv_ats_supported;
static char *hybrid_gpu_pci;
static unsigned effects;
struct pci_dev { const char *name; };
struct pci_device_id { int unused; };
static const char *pci_name(struct pci_dev *p) { return p->name; }
static NvU8 nv_bar_index_to_os_bar_index(struct pci_dev *p, int i) { (void)p;(void)i; ++effects; return 0; }
'''
        checks=r'''
static void check(const char *request,const char *actual,int selected) {
    struct pci_dev dev={actual}; hybrid_gpu_pci=(char*)request; effects=0;
    assert(hybrid_pci_bdf_selected(request,actual)==selected);
    assert(nv_pci_probe(&dev,NULL)==(selected?0:-ENODEV));
    assert(effects==(unsigned)selected);
}
int main(void) {
    const char *bad[]={NULL,"","01:00.0","0000:01:00","0000:01:00.00","00000:01:00.0",
      "0000:01:20.0","0000:01:00.8","0000:gg:00.0","0000:0A:00.0","0000:01:00.0 ",
      " 0000:01:00.0","0000:01:00.0\n","0000:01:00.*","0000:01:00.0,0000:02:00.0"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);++i) check(bad[i],"0000:01:00.0",0);
    check("0000:02:00.0","0000:01:00.0",0);
    check("0000:01:00.0","0000:01:00.0",1);
    check("abcd:ff:1f.7","abcd:ff:1f.7",1);
    check("0000:01:00.0",NULL,0);
    return 0;
}
'''
        src=self.root/'guard.c'; exe=self.root/'guard'
        src.write_text(prelude+helper+prefix+'    (void)regs_bar_index;\n    return 0;\n}\n'+checks)
        result=subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-variable','-Wno-unused-parameter','-fsanitize=undefined',str(src),'-o',str(exe)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(subprocess.run([str(exe)],capture_output=True).returncode,0)

    def test_source_count_prefilter_and_readonly_default(self):
        self.assertIn('static char *hybrid_gpu_pci;',self.text)
        self.assertIn('module_param_named(hybrid_gpu_pci, hybrid_gpu_pci, charp, 0400);',self.text)
        count=self.text.split('nv_pci_count_devices(void)',1)[1].split('/*\n * On coherent',1)[0]
        self.assertEqual(count.count('hybrid_pci_bdf_selected(hybrid_gpu_pci, pci_name(pci_dev)) &&'),2)
        self.assertEqual(count.count('rm_is_supported_pci_device('),2)
        self.assertNotIn('hybrid_pci_bdf_selected',self.original)

if __name__=='__main__': unittest.main()
