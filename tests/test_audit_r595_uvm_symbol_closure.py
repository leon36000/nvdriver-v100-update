import importlib.util
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'audit_r595_uvm_symbol_closure', ROOT / 'tools/audit_r595_uvm_symbol_closure.py')
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class R595UvmSymbolClosureTests(unittest.TestCase):
    def test_provider_name_mapping_accounts_for_r580_renames_and_open_only(self):
        self.assertEqual(AUDIT.private_provider_names(
            'nvUvmInterfaceRegisterUvmEvents'),
            ('hybrid580_open_nvUvmInterfaceRegisterUvmEvents',
             'hybrid580_legacy_nvUvmInterfaceRegisterUvmCallbacks'))
        self.assertEqual(AUDIT.private_provider_names(
            'nvUvmInterfaceAccessBitsDump'),
            ('hybrid580_open_nvUvmInterfaceAccessBitsDump', None))
        self.assertEqual(AUDIT.private_provider_names(
            'nvUvmInterfacePagingChannelAllocate'), (None, None))

    def test_static_closure_accepts_exact_frontend_and_provider_crcs(self):
        apis = (
            'nvUvmInterfaceRegisterUvmEvents',
            'nvUvmInterfaceAccessBitsDump',
            'nvUvmInterfacePagingChannelAllocate',
        )
        stock = {api: '0x00000001' for api in apis}
        frontend_imports = dict(stock)
        frontend_imports.update({
            'hybrid580_open_nvUvmInterfaceRegisterUvmEvents': '0x00000011',
            'hybrid580_legacy_nvUvmInterfaceRegisterUvmCallbacks': '0x00000012',
            'hybrid580_open_nvUvmInterfaceAccessBitsDump': '0x00000013',
        })
        frontend_symvers = {api: {'crc': '0x00000001'} for api in apis}
        reference_symvers = {api: {'crc': '0x00000001'} for api in apis}
        open_symvers = {
            'hybrid580_open_nvUvmInterfaceRegisterUvmEvents': {'crc': '0x00000011'},
            'hybrid580_open_nvUvmInterfaceAccessBitsDump': {'crc': '0x00000013'},
        }
        legacy_symvers = {
            'hybrid580_legacy_nvUvmInterfaceRegisterUvmCallbacks': {'crc': '0x00000012'},
        }

        result = AUDIT.audit_closure(
            apis, stock, frontend_imports, frontend_symvers, reference_symvers,
            open_symvers, legacy_symvers)

        self.assertEqual(result['issues'], [])
        self.assertEqual(result['installed_uvm_interface_import_count'], 3)
        self.assertEqual(result['expected_private_interface_import_count'], 3)

    def test_static_closure_detects_provider_crc_drift(self):
        api = 'nvUvmInterfaceAccessBitsDump'
        result = AUDIT.audit_closure(
            (api,), {api: '0x00000001'},
            {api: '0x00000001',
             'hybrid580_open_' + api: '0x00000014'},
            {api: {'crc': '0x00000001'}},
            {api: {'crc': '0x00000001'}},
            {'hybrid580_open_' + api: {'crc': '0x00000013'}},
            {})

        self.assertIn('private-import-vs-provider-export',
                      {issue['check'] for issue in result['issues']})

    def test_hybrid_extensions_replace_fd_ambiguous_api_and_match_frontend_crcs(self):
        address_space = 'nvUvmInterfaceDupAddressSpace'
        query = 'nvUvmInterfaceQueryCaps'
        extensions = (
            'nvUvmInterfaceDupAddressSpaceWithControlFd',
            'nvUvmInterfaceDupMemoryWithControlFd',
            'nvUvmInterfaceGetGpuProvider',
        )
        stock = {
            query: '0x00000002',
            extensions[0]: '0x00000031',
            extensions[1]: '0x00000032',
            extensions[2]: '0x00000033',
        }
        frontend_imports = dict(stock)
        frontend_symvers = {
            address_space: {'crc': '0x00000001'},
            query: {'crc': '0x00000002'},
            extensions[0]: {'crc': '0x00000031'},
            extensions[1]: {'crc': '0x00000032'},
            extensions[2]: {'crc': '0x00000033'},
        }
        reference = {
            address_space: {'crc': '0x00000001'},
            query: {'crc': '0x00000002'},
        }
        open_imports = {}
        legacy_imports = {}
        open_exports = {}
        legacy_exports = {}
        for api, crc in ((address_space, '0x00000011'), (query, '0x00000012')):
            open_name, legacy_name = AUDIT.private_provider_names(api)
            frontend_imports[open_name] = crc
            frontend_imports[legacy_name] = crc
            open_exports[open_name] = {'crc': crc}
            legacy_exports[legacy_name] = {'crc': crc}

        result = AUDIT.audit_closure(
            (address_space, query), stock, frontend_imports, frontend_symvers,
            reference, open_exports, legacy_exports)

        self.assertEqual(result['issues'], [])
        self.assertEqual(result['installed_uvm_interface_import_count'], 4)
        self.assertEqual(result['installed_r595_api_import_count'], 1)
        self.assertEqual(result['hybrid_extension_import_count'], 3)

    def test_hybrid_extension_crc_drift_is_rejected(self):
        extension = 'nvUvmInterfaceDupMemoryWithControlFd'
        result = AUDIT.audit_closure(
            (), {extension: '0x00000031'}, {},
            {extension: {'crc': '0x00000032'}}, {}, {}, {})

        self.assertIn('hybrid-extension-import-vs-frontend-export',
                      {issue['check'] for issue in result['issues']})

    def test_modversion_parser_rejects_conflicting_duplicate_names(self):
        with self.assertRaisesRegex(ValueError, 'conflicting module import CRCs'):
            AUDIT.parse_modversions(
                '0x00000001 nvUvmInterfaceAccessBitsDump\n'
                '0x00000002 nvUvmInterfaceAccessBitsDump\n')

    @unittest.skipUnless(shutil.which('cc') and shutil.which('objcopy') and
                         shutil.which('readelf'),
                         'ELF fixture tools are unavailable')
    def test_dump_modversions_falls_back_to_linux_variable_size_elf_section(self):
        name = b'hybrid580_open_test_import'
        record_size = 8 + ((len(name) + 1 + 3) & ~3)
        section = (struct.pack('<II', record_size, 0x1234abcd) +
                   (name + b'\0').ljust(record_size - 8, b'\0'))
        values = ','.join(str(value) for value in section)
        source = (f'__attribute__((used,section("__versions"))) '
                  f'const unsigned char versions[] = {{{values}}};\n')
        with tempfile.TemporaryDirectory(prefix='r580-modversions-elf-fallback-') as temp:
            root = Path(temp)
            source_path = root / 'module.c'
            module_path = root / 'module.o'
            source_path.write_text(source)
            subprocess.run(['cc', '-c', str(source_path), '-o', str(module_path)],
                           check=True, capture_output=True, text=True)

            try:
                versions = AUDIT.dump_modversions(
                    module_path, modprobe='/bin/false', include_extended=True)
            except ValueError as error:
                self.fail(f'ELF fallback was not used after kmod rejected the module: {error}')

        self.assertEqual(versions, {'hybrid580_open_test_import': '0x1234abcd'})

    @unittest.skipUnless(shutil.which('cc'), 'ELF fixture compiler is unavailable')
    def test_dump_modversions_never_exposes_captured_module_to_external_tool(self):
        with tempfile.TemporaryDirectory(prefix='r580-modversions-readonly-') as temp:
            root = Path(temp)
            source = root / 'module.c'
            module = root / 'module.ko'
            source.write_text('int module_probe(void) { return 1; }\n')
            subprocess.run(['cc', '-c', str(source), '-o', str(module)],
                           check=True, capture_output=True, text=True)
            original = module.read_bytes()
            mutating_tool = root / 'mutating-modprobe'
            mutating_tool.write_text('#!/bin/sh\nprintf x >> "$2"\nexit 0\n')
            mutating_tool.chmod(0o700)

            AUDIT.dump_modversions(module, modprobe=str(mutating_tool))

            self.assertEqual(module.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
