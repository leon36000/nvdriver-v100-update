# SPDX-License-Identifier: MIT
"""Compile and execute the pinned wrapper's actual procfs path construction."""
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
SOURCE = 'NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia/nv-procfs.c'
PATCH = ROOT / 'patches/r580.178.04/0005-private-open-procfs-path.patch'


class PrivateProcfsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        digest = hashlib.sha256()
        with ARCHIVE.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        if digest.hexdigest() != SHA:
            raise AssertionError('pinned archive mismatch')
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        with tarfile.open(ARCHIVE, 'r:xz') as archive:
            cls.original = archive.extractfile(SOURCE).read().decode()
        path = cls.root / 'kernel-open/nvidia/nv-procfs.c'
        path.parent.mkdir(parents=True)
        path.write_text(cls.original)
        result = subprocess.run(
            ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCH)],
            cwd=cls.root, capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError(result.stdout + result.stderr)
        if re.search(r'\b(?:fuzz|offset)\b', result.stdout + result.stderr):
            raise AssertionError('patch did not apply at its exact pinned location')
        cls.patched = path.read_text()

    def run_actual_construction(self, text, module_name, label):
        function = text.split('int nv_procfs_init(void)', 1)[1]
        declaration = re.search(r'^    char nv_dir_name\[[^\n]+;$', function, re.M)
        construction = re.search(
            r'^    snprintf\(nv_dir_name,[^\n]+\);\n\n'
            r"    nv_dir_name\[sizeof\(nv_dir_name\) - 1\] = '\\0';$",
            function, re.M)
        self.assertIsNotNone(declaration, 'actual path buffer declaration missing')
        self.assertIsNotNone(construction, 'actual path construction missing')
        source = self.root / (label + '.c')
        binary = self.root / label
        source.write_text(
            '#include <stdio.h>\n'
            '#define MODULE_NAME "' + module_name + '"\n'
            'static const char *nv_device_name = MODULE_NAME;\n'
            'int main(void) {\n' + declaration.group() + '\n' +
            construction.group() + '\n'
            '    printf("%zu\\n%s\\n", sizeof(nv_dir_name), nv_dir_name);\n'
            '    return 0;\n}\n')
        compiled = subprocess.run(
            ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
             '-fsanitize=undefined', str(source), '-o', str(binary)],
            capture_output=True, text=True)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        ran = subprocess.run([str(binary)], capture_output=True, text=True)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertEqual(ran.stderr, '')
        capacity, path = ran.stdout.splitlines()
        return int(capacity), path

    def test_original_private_name_reproduces_truncation(self):
        capacity, path = self.run_actual_construction(
            self.original, 'hybrid580_open', 'original-private')
        self.assertEqual(capacity, 20)
        self.assertEqual(path, 'driver/hybrid580_op')
        self.assertNotEqual(path, 'driver/hybrid580_open')

    def test_default_module_name_has_exact_capacity_and_path(self):
        capacity, path = self.run_actual_construction(
            self.patched, 'nvidia', 'patched-default')
        self.assertEqual(path, 'driver/nvidia')
        self.assertEqual(capacity, len('driver/nvidia') + 1)

    def test_private_module_name_has_exact_capacity_and_path(self):
        capacity, path = self.run_actual_construction(
            self.patched, 'hybrid580_open', 'patched-private')
        self.assertEqual(path, 'driver/hybrid580_open')
        self.assertEqual(capacity, len('driver/hybrid580_open') + 1)


if __name__ == '__main__':
    unittest.main()
