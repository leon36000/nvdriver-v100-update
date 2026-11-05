# SPDX-License-Identifier: MIT
"""Source-executed lifecycle contract: the private prototype registers PCI GPUs only."""
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / '.cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz'
PATCHES = [ROOT / ('patches/r580.178.04/' + name) for name in (
    '0004-private-open-chardev.patch', '0007-private-open-pci-only-lifecycle.patch')]


class PrivatePciScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with ARCHIVE.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != '060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8':
                raise AssertionError('pinned archive mismatch')
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        with tarfile.open(ARCHIVE, 'r:xz') as archive:
            original = archive.extractfile('NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia/nv.c').read().decode()
        source = cls.root / 'kernel-open/nvidia/nv.c'
        source.parent.mkdir(parents=True)
        source.write_text(original)
        with tarfile.open(ARCHIVE, 'r:xz') as archive:
            for name in ('nv-pci-table.c', 'nv-platform.c'):
                (source.parent / name).write_bytes(archive.extractfile(
                    'NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia/' + name).read())
        for patch in PATCHES:
            result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                                    cwd=cls.root, capture_output=True, text=True)
            if result.returncode or 'offset' in result.stdout:
                raise AssertionError(result.stdout + result.stderr)
        cls.text = source.read_text()

    def test_source_lifecycle_success_failure_and_count(self):
        def fragment(start, end):
            return self.text.split(start, 1)[1].split(end, 1)[0]
        link = 'static void\nnvlink_drivers_exit' + fragment('static void\nnvlink_drivers_exit', 'static void\nnv_module_state_exit')
        drivers = 'static void\nnv_drivers_exit' + fragment('static void\nnv_drivers_exit', 'static void\nnv_module_exit')
        count = 'static int __init\nnvos_count_devices' + fragment('static int __init\nnvos_count_devices', '#if NVCPU_IS_AARCH64')
        prelude = r'''
#include <assert.h>
#include <stddef.h>
#include <errno.h>
#define __init
#define NV_DBG_INFO 0
#define NV_DBG_ERRORS 1
#define nv_printf(...) ((void)0)
#define NVCPU_IS_64_BITS 1
#define NV_SUPPORTS_PLATFORM_DEVICE 1
static unsigned links, link_exits, pci, pci_exits;
static int link_rc, pci_rc, gpu_count;
static int nvlink_core_init(void) { ++links; return link_rc; }
static void nvlink_core_exit(void) { ++link_exits; }
static int nv_pci_register_driver(void) { ++pci; return pci_rc; }
static void nv_pci_unregister_driver(void) { ++pci_exits; }
static int nv_pci_count_devices(void) { return gpu_count; }
/* Forbidden platform/NVSwitch operations intentionally have no declarations:
 * compiling actual helpers with -Werror rejects even an unexecuted reference.
 */
'''
        main = r'''
int main(void) {
    link_rc=-ENOMEM; assert(nvlink_drivers_init()==-ENOMEM);
    assert(links==1 && link_exits==0);
    link_rc=0; assert(nvlink_drivers_init()==0);
    nvlink_drivers_exit(); assert(links==2 && link_exits==1);
    pci_rc=-EBUSY; assert(nv_drivers_init()==-ENODEV);
    assert(pci==1 && pci_exits==0);
    pci_rc=0; assert(nv_drivers_init()==0);
    nv_drivers_exit(); assert(pci==2 && pci_exits==1);
    for(gpu_count=0;gpu_count<=2;++gpu_count) {
        int npci=-1,nplatform=-1;
        assert(nvos_count_devices(&npci,&nplatform)==gpu_count);
        assert(npci==gpu_count && nplatform==0);
        assert(nvos_count_devices(NULL,NULL)==gpu_count);
    }
    return 0;
}
'''
        source = self.root / 'scope.c'
        binary = self.root / 'scope'
        source.write_text(prelude + link + drivers + count + main)
        result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                 '-fsanitize=undefined', str(source), '-o', str(binary)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_switch_presence_cannot_override_selected_gpu_requirement(self):
        init = self.text.split('static int __init nvidia_init_module(void)', 1)[1].split('static void __exit', 1)[0]
        self.assertIn('const NvBool is_nvswitch_present = NV_FALSE;', init)
        self.assertNotIn('os_is_nvswitch_present()', init)
        self.assertIn('if ((count == 0) && (!is_nvswitch_present))', init)
        self.assertIn('if ((num_nv_devices == 0) && (!is_nvswitch_present))', init)

    def test_private_prototype_has_no_public_hardware_autoload_tables(self):
        for name in ('nv-pci-table.c', 'nv-platform.c'):
            text = (self.root / 'kernel-open/nvidia' / name).read_text()
            self.assertNotIn('MODULE_DEVICE_TABLE(', text)


if __name__ == '__main__':
    unittest.main()
