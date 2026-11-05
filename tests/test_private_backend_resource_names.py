# SPDX-License-Identifier: MIT
"""CPU contracts for actual wrapper capability tables and resource literals."""
import hashlib
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / '.cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz'
SHA = '060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8'
PREFIX = 'NVIDIA-kernel-module-source-580.178.04/kernel-open/'
PATCH = ROOT / 'patches/r580.178.04/0006-private-open-resource-names.patch'
FILES = ('nv-caps.c', 'nvlink_linux.c', 'nvlink_linux.h',
         'procfs_nvswitch.c', 'export_nvswitch.h', 'nv-caps-imex.c')


class PrivateResourceNamesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        digest = hashlib.sha256()
        with ARCHIVE.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        if digest.hexdigest() != SHA:
            raise AssertionError('pinned archive mismatch')
        targets = re.findall(r'^\+\+\+ b/([^\n]+)$', PATCH.read_text(), re.M)
        if set(targets) != {'kernel-open/nvidia/' + name for name in FILES}:
            raise AssertionError('resource patch must touch only the six wrapper files')
        if len(targets) != len(FILES):
            raise AssertionError('duplicate or unexpected resource patch target')
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.original = {}
        with tarfile.open(ARCHIVE, 'r:xz') as archive:
            for name in FILES + ('linux_nvswitch.h',):
                text = archive.extractfile(PREFIX + 'nvidia/' + name).read().decode()
                cls.original[name] = text
                path = cls.root / 'kernel-open/nvidia' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
        applied = subprocess.run(
            ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCH)],
            cwd=cls.root, capture_output=True, text=True)
        if applied.returncode != 0:
            raise AssertionError(applied.stdout + applied.stderr)
        if re.search(r'\b(?:fuzz|offset)\b', applied.stdout + applied.stderr):
            raise AssertionError('patch did not apply at its exact pinned location')
        cls.patched = {name: (cls.root / 'kernel-open/nvidia' / name).read_text()
                       for name in FILES}

    def execute_actual_fragments(self, sources, module_name, label):
        caps = sources['nv-caps.c']
        tables = caps[caps.index('#define NV_CAP_NUM_ENTRIES'):caps.index('\nstruct nv_cap\n')]
        readers = caps[caps.index('static int nv_procfs_read_nvlink_minors'):
                       caps.index('\nNV_DEFINE_SINGLE_PROCFS_FILE_READ_ONLY(nvlink_minors')]
        macros = []
        for name, macro in (('nv-caps.c', 'NV_CAP_PROCFS_DIR'),
                            ('nv-caps.c', 'NV_CAP_NAME_BUF_SIZE'),
                            ('nvlink_linux.c', 'NVLINK_PROCFS_DIR'),
                            ('nvlink_linux.h', 'NVLINK_DEVICE_NAME'),
                            ('procfs_nvswitch.c', 'NVSWITCH_PROCFS_DIR'),
                            ('export_nvswitch.h', 'NVSWITCH_DRIVER_NAME')):
            matches = re.findall(r'^#define ' + macro + r'\s+[^\n]+$', sources[name], re.M)
            self.assertEqual(len(matches), 1, macro)
            macros.append(matches[0])
        imex = re.findall(r'MODULE_NAME "-caps-imex-channels(?:!channel%d)?"',
                          sources['nv-caps-imex.c'])
        self.assertEqual(len(imex), 4, 'both class branches, devnode and chrdev name')
        registration = re.search(
            r'alloc_chrdev_region\(&g_nv_cap_drv.devno,\s*0,\s*'
            r'NV_CAP_DRV_MINOR_COUNT,\s*([^;]+)\);', caps)
        self.assertIsNotNone(registration)
        code = r'''
#include <stdio.h>
#include <stdarg.h>
#define NV_ARRAY_ELEMENTS(a) (sizeof(a) / sizeof((a)[0]))
typedef struct { const char *name; int minor; } nv_cap_table_entry_t;
struct seq_file { const char *tag; };
static int seq_printf(struct seq_file *s, const char *fmt, ...) {
    va_list args; va_start(args,fmt); printf("%s:",s->tag);
    int rc=vprintf(fmt,args); va_end(args); return rc;
}
'''
        code += '#define MODULE_NAME "' + module_name + '"\n'
        code += '\n'.join(macros) + '\n' + tables + '\n' + readers
        code += '\nint main(void) {\n'
        for macro in ('NV_CAP_PROCFS_DIR', 'NVLINK_PROCFS_DIR', 'NVLINK_DEVICE_NAME',
                      'NVSWITCH_PROCFS_DIR', 'NVSWITCH_DRIVER_NAME'):
            code += 'printf("resource:%s\\n", ' + macro + ');\n'
        code += 'printf("resource:%s\\n", ' + registration.group(1).strip() + ');\n'
        for literal in imex:
            code += 'printf("resource:%s\\n", ' + literal + ');\n'
        for table, reader in (('nvlink', 'nvlink'), ('sys', 'sys'), ('mig', 'mig'),
                              ('mig_gpu', None)):
            name = 'g_nv_cap_' + table + '_table'
            code += ('for (unsigned i=0; i<NV_ARRAY_ELEMENTS(' + name + '); ++i) '
                     'printf("table:%s\\n", ' + name + '[i].name);\n')
            if reader:
                code += ('{ struct seq_file s={"' + table + '"}; '
                         'nv_procfs_read_' + reader + '_minors(&s,NULL); }\n')
        code += 'return 0;\n}\n'
        path = self.root / (label + '.c')
        binary = self.root / label
        path.write_text(code)
        result = subprocess.run(
            ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
             '-Wno-unused-parameter', '-Wno-missing-field-initializers',
             '-fsanitize=undefined', str(path), '-o', str(binary)],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        ran = subprocess.run([str(binary)], capture_output=True, text=True)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertEqual(ran.stderr, '')
        return ran.stdout.splitlines()

    def assert_complete_contract(self, module_name, label):
        lines = self.execute_actual_fragments(self.patched, module_name, label)
        prefix = '/driver/' + module_name
        expected = {prefix + '-nvlink/capabilities/fabric-mgmt',
                    prefix + '/capabilities/fabric-imex-mgmt',
                    prefix + '/capabilities/mig/config',
                    prefix + '/capabilities/mig/monitor'}
        gpu_names = {f'gpu{gpu}/gi{gi}/access'
                     for gpu in range(32) for gi in range(15)}
        gpu_names |= {f'gpu{gpu}/gi{gi}/ci{ci}/access'
                      for gpu in range(32) for gi in range(15) for ci in range(8)}
        for name in gpu_names:
            gpu, tail = name.split('/', 1)
            expected.add(f'{prefix}/capabilities/{gpu}/mig/{tail}')
        actual = [line.removeprefix('table:') for line in lines if line.startswith('table:')]
        self.assertEqual(len(actual), 4324)
        self.assertEqual(len(set(actual)), len(actual), 'capability paths must be unique')
        self.assertEqual(set(actual), expected)
        resources = [line.removeprefix('resource:') for line in lines
                     if line.startswith('resource:')]
        self.assertEqual(resources, [
            f'driver/{module_name}-caps', f'driver/{module_name}-nvlink',
            f'{module_name}-nvlink', f'driver/{module_name}-nvswitch',
            f'{module_name}-nvswitch', f'{module_name}-caps',
            f'{module_name}-caps-imex-channels', f'{module_name}-caps-imex-channels',
            f'{module_name}-caps-imex-channels!channel%d', f'{module_name}-caps-imex-channels'])
        self.assertEqual([line for line in lines if line.startswith('nvlink:')],
                         ['nvlink:fabric-mgmt 0'])
        self.assertEqual([line for line in lines if line.startswith('sys:')],
                         ['sys:fabric-imex-mgmt 0'])
        mig_rows = [line.removeprefix('mig:').removesuffix(' 0') for line in lines
                    if line.startswith('mig:')]
        self.assertEqual(len(mig_rows), 4322)
        self.assertEqual(set(mig_rows), {'config', 'monitor'} | gpu_names)

    def test_private_names_and_all_capability_readers(self):
        self.assert_complete_contract('hybrid580_open', 'private')

    def test_default_name_preserves_official_resource_paths(self):
        self.assert_complete_contract('nvidia', 'default')

    def test_module_name_available_before_resource_macro_use(self):
        switch = self.original['linux_nvswitch.h']
        self.assertLess(switch.index('#include "nv-linux.h"'),
                        switch.index('#include "export_nvswitch.h"'))
        nvlink = self.patched['nvlink_linux.c']
        self.assertLess(nvlink.index('#include "nv-linux.h"'),
                        nvlink.index('NVLINK_DEVICE_NAME);'))
        self.assertNotIn('MODULE_NAME', self.original['export_nvswitch.h'])


if __name__ == '__main__':
    unittest.main()
