# SPDX-License-Identifier: MIT
"""CPU contracts for private Open backend source/export isolation; no GPU access."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class PrivateBackendTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('private_backend', ROOT/'tools/probe_private_backend_module.py')
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)

    def test_export_parser_preserves_flavor_and_rejects_duplicate(self):
        rows = self.m.parse_exports('0x123 a nvidia EXPORT_SYMBOL_GPL\n0x456 b nvidia EXPORT_SYMBOL\n')
        self.assertEqual(rows, {'a':'EXPORT_SYMBOL_GPL', 'b':'EXPORT_SYMBOL'})
        with self.assertRaises(ValueError):
            self.m.parse_exports('0x123 a nvidia EXPORT_SYMBOL\n0x456 a nvidia EXPORT_SYMBOL\n')

    def test_destination_collision_refused(self):
        with self.assertRaisesRegex(ValueError, 'collision'):
            self.m.private_header({'entry':'EXPORT_SYMBOL'}, {'hybrid580_open_entry'})
        with self.assertRaisesRegex(ValueError, 'collision'):
            self.m.private_header({}, {
                'hybrid580_open_nvUvmInterfaceDupMemoryWithControlFd'})

    def test_export_strings_and_internal_calls_are_renamed_by_source_macro(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'private.h').write_text(self.m.private_header({'entry':'EXPORT_SYMBOL'}, set()))
            source = root/'contract.c'
            source.write_text('''#include <string.h>
#include "private.h"
#define EXPORT_INNER(sym) const char exported_name[] = #sym
#define EXPORT_SYMBOL(sym) EXPORT_INNER(sym)
int entry(void) { return 37; }
EXPORT_SYMBOL(entry);
int dispatch(void) { return entry(); }
int main(void) { return strcmp(exported_name,"hybrid580_open_entry") || dispatch()!=37; }
''')
            exe = root/'contract'
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(source),'-o',str(exe)],check=True,capture_output=True)
            self.assertEqual(subprocess.run([str(exe)]).returncode,0)
            symbols = subprocess.check_output(['nm','-g',str(exe)],text=True)
            self.assertIn(' T hybrid580_open_entry',symbols)
            self.assertNotIn(' T entry\n',symbols)

    def test_control_fd_export_is_supplementally_namespaced(self):
        header = self.m.private_header({'nvUvmInterfaceDupMemory':'EXPORT_SYMBOL'}, set())
        self.assertIn('#define nvUvmInterfaceDupMemoryWithControlFd '
                      'hybrid580_open_nvUvmInterfaceDupMemoryWithControlFd', header)
        self.assertEqual(header.count(
            '#define nvUvmInterfaceDupMemoryWithControlFd '
            'hybrid580_open_nvUvmInterfaceDupMemoryWithControlFd'), 1)

    def test_private_export_set_must_match_all_original_exports_and_flavors(self):
        original={'a':'EXPORT_SYMBOL','b':'EXPORT_SYMBOL_GPL'}
        self.m.validate_exports(original, {'hybrid580_open_a':'EXPORT_SYMBOL','hybrid580_open_b':'EXPORT_SYMBOL_GPL'})
        for bad in ({'hybrid580_open_a':'EXPORT_SYMBOL'}, {'hybrid580_open_a':'EXPORT_SYMBOL','b':'EXPORT_SYMBOL_GPL'}, {'hybrid580_open_a':'EXPORT_SYMBOL_GPL','hybrid580_open_b':'EXPORT_SYMBOL_GPL'}):
            with self.assertRaises(ValueError): self.m.validate_exports(original,bad)

if __name__ == '__main__': unittest.main()
