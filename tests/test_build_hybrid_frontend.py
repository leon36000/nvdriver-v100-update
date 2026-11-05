import importlib.util
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'build_hybrid_frontend', ROOT / 'tools/build_hybrid_frontend.py')
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class BuildHybridFrontendContracts(unittest.TestCase):
    def test_resolve_kernel_build_accepts_exact_detached_header_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            kernel = Path(directory)
            (kernel / 'include/config').mkdir(parents=True)
            (kernel / '.config').write_text('CONFIG_MODVERSIONS=y\n')
            (kernel / 'Module.symvers').write_text('0x00000000 symbol vmlinux EXPORT_SYMBOL\n')
            (kernel / 'Makefile').write_text('VERSION = 6\nPATCHLEVEL = 8\n')
            (kernel / 'include/config/kernel.release').write_text('6.8.0-147-generic\n')

            resolved = BUILDER.resolve_kernel_build(
                '6.8.0-147-generic', kernel_build=kernel)

        self.assertEqual(kernel.resolve(), resolved)

    def test_resolve_kernel_build_rejects_release_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            kernel = Path(directory)
            (kernel / 'include/config').mkdir(parents=True)
            (kernel / '.config').write_text('CONFIG_MODVERSIONS=y\n')
            (kernel / 'Module.symvers').write_text('')
            (kernel / 'Makefile').write_text('VERSION = 6\nPATCHLEVEL = 8\n')
            (kernel / 'include/config/kernel.release').write_text('6.8.0-146-generic\n')

            with self.assertRaisesRegex(ValueError, 'kernel.release'):
                BUILDER.resolve_kernel_build(
                    '6.8.0-147-generic', kernel_build=kernel)

    def test_resolve_kernel_build_rejects_incomplete_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            kernel = Path(directory)
            (kernel / 'include/config').mkdir(parents=True)
            (kernel / '.config').write_text('CONFIG_MODVERSIONS=y\n')
            (kernel / 'Makefile').write_text('VERSION = 6\nPATCHLEVEL = 8\n')
            (kernel / 'include/config/kernel.release').write_text('6.8.0-147-generic\n')

            with self.assertRaisesRegex(ValueError, 'Module.symvers'):
                BUILDER.resolve_kernel_build(
                    '6.8.0-147-generic', kernel_build=kernel)

    def test_frontend_compiler_honors_explicit_compiler_override(self):
        with tempfile.TemporaryDirectory() as directory:
            compiler = Path(directory) / 'target-gcc'
            compiler.write_text('#!/bin/sh\nexit 0\n')
            compiler.chmod(0o755)

            selected = BUILDER.frontend_compiler({'CC': str(compiler)})

        self.assertEqual(str(compiler), selected)

    def test_frontend_compiler_fails_closed_on_missing_explicit_override(self):
        with self.assertRaisesRegex(ValueError, 'CC override'):
            BUILDER.frontend_compiler({'CC': '/missing/target-gcc'})

    def test_frontend_compiler_falls_back_to_x86_64_gcc(self):
        with mock.patch.object(BUILDER.shutil, 'which', return_value='/usr/bin/x86_64-linux-gnu-gcc') as which:
            selected = BUILDER.frontend_compiler({})

        self.assertEqual('/usr/bin/x86_64-linux-gnu-gcc', selected)
        which.assert_called_once_with('x86_64-linux-gnu-gcc')

    def test_objtool_evidence_accepts_delayed_validation_of_exact_module_objects(self):
        delayed_command = ('ld -r -o nvidia.o @nvidia.mod; '
                           './tools/objtool/objtool --retpoline --rethunk --sls '
                           '--stackval --static-call --uaccess --link --module nvidia.o')
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for obj in BUILDER.FRONTEND_LINK_OBJECTS:
                (work / f'.{obj}.cmd').write_text(f'savedcmd_{obj} := gcc -c {obj}\n')
            (work / '.nvidia.o.cmd').write_text(
                f'savedcmd_nvidia.o := {delayed_command}\n')
            (work / 'nvidia.mod').write_text(
                ''.join(f'./{obj}\n' for obj in BUILDER.FRONTEND_LINK_OBJECTS))

            evidence = BUILDER.validate_objtool_build_commands(work, 'nvidia')

        self.assertTrue(evidence['active'])
        self.assertEqual('delayed-module-link', evidence['validation_scope'])
        self.assertEqual(7, evidence['checked_object_count'])

    def test_objtool_delayed_validation_rejects_missing_flags_or_wrong_module(self):
        complete = ('ld -r -o nvidia.o @nvidia.mod; '
                    './tools/objtool/objtool --retpoline --rethunk --sls '
                    '--stackval --link --module nvidia.o')
        for mutation in (
                complete.replace('--stackval ', ''),
                complete.replace('--module nvidia.o', '--module other.o'),
                complete.replace('@nvidia.mod', '@other.mod'),
                complete.replace('@nvidia.mod', ''),
                complete.replace('@nvidia.mod;', '@nvidia.mod extra.o;'),
                complete.replace('@nvidia.mod;', '@nvidia.mod @nvidia.mod;'),
                complete.replace('-o nvidia.o', '-o other.o'),
                complete.replace('-o nvidia.o', ''),
                complete.replace('-o nvidia.o', '-o nvidia.o -o nvidia.o'),
                complete.replace('-o nvidia.o',
                                 '-o nvidia.o --output=other.o'),
                complete.replace('-o nvidia.o', '-o nvidia.o -oother.o'),
                complete.replace('ld -r -o nvidia.o',
                                 'ld -r -- -o nvidia.o'),
                '; ' + complete,
                complete.replace('; ./tools/objtool', ';; ./tools/objtool'),
                complete.replace('./tools/objtool/objtool', '/bin/echo objtool'),
                complete.replace('ld -r', '/bin/echo -r'),
                complete.replace('./tools/objtool/objtool',
                                 'false && ./tools/objtool/objtool'),
                ('ld -r -o nvidia.o @nvidia.mod; '
                 './tools/objtool/objtool --link --module nvidia.o '
                 '> --retpoline --rethunk --sls --stackval'),
                ('ld -r -o nvidia.o @nvidia.mod; '
                 './tools/objtool/objtool --link --module nvidia.o '
                 '# --retpoline --rethunk --sls --stackval')):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                for obj in BUILDER.FRONTEND_LINK_OBJECTS:
                    (work / f'.{obj}.cmd').write_text(f'savedcmd_{obj} := gcc -c {obj}\n')
                (work / '.nvidia.o.cmd').write_text(f'savedcmd_nvidia.o := {mutation}\n')
                (work / 'nvidia.mod').write_text(
                    ''.join(f'./{obj}\n' for obj in BUILDER.FRONTEND_LINK_OBJECTS))

                evidence = BUILDER.validate_objtool_build_commands(work, 'nvidia')

                self.assertFalse(evidence['active'])

    def test_objtool_delayed_validation_rejects_hash_mid_token_and_options_after_terminator(self):
        commands = (
            ('ld -r -o nvidia.o @nvidia.mod; '
             './tools/objtool/objtool --rethunk --sls --stackval '
             '--retpoline#suffix --link --module nvidia.o'),
            ('ld -r -o nvidia.o @nvidia.mod; '
             './tools/objtool/objtool -- --retpoline --rethunk --sls '
             '--stackval --link --module nvidia.o'),
        )
        for command in commands:
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                (work / '.nvidia.o.cmd').write_text(
                    f'savedcmd_nvidia.o := {command}\n')
                (work / 'nvidia.mod').write_text(
                    ''.join(f'./{obj}\n' for obj in BUILDER.FRONTEND_LINK_OBJECTS))

                evidence = BUILDER.validate_objtool_build_commands(work, 'nvidia')

                self.assertFalse(evidence['active'])

    def test_objtool_delayed_validation_rejects_quoted_or_escaped_semicolon(self):
        commands = (
            "ld -r -o nvidia.o @nvidia.mod ';' "
            './tools/objtool/objtool --retpoline --rethunk --sls '
            '--stackval --link --module nvidia.o',
            'ld -r -o nvidia.o @nvidia.mod \\; '
            './tools/objtool/objtool --retpoline --rethunk --sls '
            '--stackval --link --module nvidia.o',
        )
        for command in commands:
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                (work / '.nvidia.o.cmd').write_text(
                    f'savedcmd_nvidia.o := {command}\n')
                (work / 'nvidia.mod').write_text(
                    ''.join(f'./{obj}\n' for obj in BUILDER.FRONTEND_LINK_OBJECTS))

                evidence = BUILDER.validate_objtool_build_commands(work, 'nvidia')

                self.assertFalse(evidence['active'])

    def test_objtool_delayed_validation_rejects_command_substitution(self):
        commands = (
            'ld -r -o nvidia.o @nvidia.mod '
            '$(true; ./tools/objtool/objtool --retpoline --rethunk --sls '
            '--stackval --link --module nvidia.o )',
            'ld -r -o nvidia.o @nvidia.mod '
            '`true; ./tools/objtool/objtool --retpoline --rethunk --sls '
            '--stackval --link --module nvidia.o `',
            'ld -r -o nvidia.o @nvidia.mod; '
            './tools/objtool/objtool ${OTFLAGS} --retpoline --rethunk --sls '
            '--stackval --link --module nvidia.o',
            'ld -r -o nvidia.o @nvidia.mod; '
            './tools/objtool/objtool * --retpoline --rethunk --sls '
            '--stackval --link --module nvidia.o',
            'ld -r -o nvidia.o @nvidia.mod; '
            './tools/objtool/objtool {--,noop} --retpoline --rethunk --sls '
            '--stackval --link --module nvidia.o',
        )
        for command in commands:
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                (work / '.nvidia.o.cmd').write_text(
                    f'savedcmd_nvidia.o := {command}\n')
                (work / 'nvidia.mod').write_text(
                    ''.join(f'./{obj}\n' for obj in BUILDER.FRONTEND_LINK_OBJECTS))

                evidence = BUILDER.validate_objtool_build_commands(work, 'nvidia')

                self.assertFalse(evidence['active'])

    def test_objtool_delayed_validation_rejects_incomplete_or_duplicate_manifest(self):
        delayed_command = ('ld -r -o nvidia.o @nvidia.mod; '
                           './tools/objtool/objtool --retpoline --rethunk --sls '
                           '--stackval --link --module nvidia.o')
        expected = [f'./{obj}' for obj in BUILDER.FRONTEND_LINK_OBJECTS]
        for manifest in (expected[:-1], expected + [expected[0]]):
            with self.subTest(manifest=manifest), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                (work / '.nvidia.o.cmd').write_text(
                    f'savedcmd_nvidia.o := {delayed_command}\n')
                (work / 'nvidia.mod').write_text(''.join(f'{obj}\n' for obj in manifest))

                evidence = BUILDER.validate_objtool_build_commands(work, 'nvidia')

                self.assertFalse(evidence['active'])

    def test_objtool_evidence_uses_each_link_object_command_not_composite_link(self):
        command = ('gcc -c object.c -o object.o; '
                   './tools/objtool/objtool --retpoline --rethunk --sls '
                   '--stackval --module object.o')
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for obj in BUILDER.FRONTEND_LINK_OBJECTS:
                (work / f'.{obj}.cmd').write_text(
                    f'savedcmd_{obj} := {command}\n')
            # The composite .nvidia.o command intentionally only links objects.
            (work / '.nvidia.o.cmd').write_text(
                'savedcmd_nvidia.o := ld -r -o nvidia.o @nvidia.mod\n')

            evidence = BUILDER.validate_objtool_build_commands(work)

        self.assertTrue(evidence['active'])
        self.assertEqual(evidence['checked_object_count'], 7)
        self.assertEqual(evidence['missing_object_commands'], [])
        self.assertEqual(evidence['missing_objtool_objects'], [])
        self.assertEqual(evidence['missing_required_flags'], {})
        self.assertEqual(evidence['required_flags'], [
            '--retpoline', '--rethunk', '--sls', '--stackval', '--module'])

    def test_objtool_evidence_fails_if_any_frontend_object_skips_configured_checks(self):
        command = ('gcc -c object.c -o object.o; '
                   './tools/objtool/objtool --retpoline --rethunk --sls '
                   '--stackval --module object.o')
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for obj in BUILDER.FRONTEND_LINK_OBJECTS:
                (work / f'.{obj}.cmd').write_text(
                    f'savedcmd_{obj} := {command}\n')
            (work / '.hybrid580-standard-node-devices.o.cmd').write_text(
                'savedcmd_hybrid580-standard-node-devices.o := '
                'gcc -c object.c -o object.o; '
                './tools/objtool/objtool --module object.o\n')

            evidence = BUILDER.validate_objtool_build_commands(work)

        self.assertFalse(evidence['active'])
        self.assertEqual(evidence['missing_objtool_objects'], [])
        self.assertEqual(evidence['missing_required_flags'], {
            'hybrid580-standard-node-devices.o': [
                '--retpoline', '--rethunk', '--sls', '--stackval']})

    def test_objtool_evidence_is_inactive_when_no_objtool_run_was_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = BUILDER.validate_objtool_build_commands(Path(directory))
        self.assertFalse(evidence['active'])
        self.assertEqual(evidence['reason'],
                         'one or more frontend object commands lack configured objtool checks')

    def test_frontend_module_name_accepts_only_private_or_stock_identity(self):
        self.assertEqual(BUILDER.validate_frontend_module_name(
            'hybrid580_frontend'), 'hybrid580_frontend')
        self.assertEqual(BUILDER.validate_frontend_module_name('nvidia'), 'nvidia')
        for invalid in ('nvidia_uvm', 'nvidia-uvm', '../nvidia', ''):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, 'unsupported frontend module name'):
                    BUILDER.validate_frontend_module_name(invalid)

    def test_frontend_kbuild_preserves_private_default_and_can_emit_stock_identity(self):
        include_dirs = (Path('/kernel/include'), Path('/project/src'))
        private = BUILDER.render_frontend_kbuild(
            'hybrid580_frontend', include_dirs, Path('/open/Module.symvers'),
            Path('/legacy/Module.symvers'), 'r595')
        stock = BUILDER.render_frontend_kbuild(
            'nvidia', include_dirs, Path('/open/Module.symvers'),
            Path('/legacy/Module.symvers'), 'r595')

        objects = ('hybrid_frontend.o hybrid580_uvm_callback_bridge.o '
                   'rm_root_client.o hybrid580-gpu-catalog.o '
                   'hybrid580-device-instance-map.o hybrid580-standard-node-map.o '
                   'hybrid580-standard-node-devices.o')
        self.assertIn('obj-m += hybrid580_frontend.o\n'
                      'hybrid580_frontend-y := ' + objects + '\n', private)
        self.assertIn('obj-m += nvidia.o\n'
                      'nvidia-y := ' + objects + '\n', stock)
        self.assertIn('KBUILD_EXTRA_SYMBOLS := /open/Module.symvers /legacy/Module.symvers\n', stock)
        self.assertNotIn('HYBRID580_UVM_ABI_R580', stock)

    def test_frontend_symvers_exports_must_belong_to_the_selected_module(self):
        exports = {
            'nvUvmInterfaceRegisterUvmEvents': {
                'module': 'nvidia', 'crc': '0x12345678', 'export': 'EXPORT_SYMBOL'},
            'nvUvmInterfaceDupMemoryWithControlFd': {
                'module': 'nvidia', 'crc': '0x87654321', 'export': 'EXPORT_SYMBOL'},
        }
        report = BUILDER.validate_frontend_export_owners(exports, 'nvidia')
        self.assertTrue(report['matches'])
        self.assertEqual(report['export_count'], 2)
        self.assertEqual(report['mismatches'], {})
        with self.assertRaisesRegex(ValueError, 'Module.symvers owner mismatch'):
            BUILDER.validate_frontend_export_owners(exports, 'hybrid580_frontend')

    def test_frontend_symvers_accepts_only_the_exact_external_module_output_path(self):
        exports = {
            'nvUvmInterfaceExample': {
                'module': '/tmp/kbuild-work/nvidia', 'crc': '0x12345678',
                'export': 'EXPORT_SYMBOL'},
        }
        accepted = BUILDER.validate_frontend_export_owners(
            exports, 'nvidia', Path('/tmp/kbuild-work/nvidia'))
        self.assertEqual(accepted['accepted_symvers_owners'], [
            '/tmp/kbuild-work/nvidia', 'nvidia'])
        with self.assertRaisesRegex(ValueError, 'Module.symvers owner mismatch'):
            BUILDER.validate_frontend_export_owners(
                {'nvUvmInterfaceExample': {'module': '/tmp/other/nvidia'}},
                'nvidia', Path('/tmp/kbuild-work/nvidia'))

    def test_r580_frontend_kbuild_keeps_explicit_abi_define(self):
        rendered = BUILDER.render_frontend_kbuild(
            'nvidia', (), Path('/open/symvers'), Path('/legacy/symvers'), 'r580')
        self.assertIn('-DHYBRID580_UVM_ABI_R580', rendered)
        with self.assertRaisesRegex(ValueError, 'unsupported UVM API ABI'):
            BUILDER.render_frontend_kbuild(
                'nvidia', (), Path('/open/symvers'), Path('/legacy/symvers'), 'r610')

    def test_control_fd_dispatch_has_one_hybrid_frontend_symbol_owner(self):
        apis = (
            'nvUvmInterfaceDupMemoryWithControlFd',
            'nvUvmInterfaceDupAddressSpaceWithControlFd',
            'nvUvmInterfaceAreGpuProvidersSame',
            'nvUvmInterfaceGetGpuProvider',
        )
        ownership = BUILDER.validate_hybrid_dispatch_export_ownership(
            {api: {'export': 'EXPORT_SYMBOL'} for api in apis},
            {'hybrid580_open_nvUvmInterfaceDupMemory': {}},
            {'hybrid580_legacy_nvUvmInterfaceDupMemory': {}},
        )
        for api in apis:
            with self.subTest(api=api):
                self.assertEqual(ownership[api]['frontend_owner'], 'hybrid580_frontend')
                self.assertEqual(ownership[api]['private_provider_exports'], [])
        with self.assertRaisesRegex(ValueError, 'also exported'):
            BUILDER.validate_hybrid_dispatch_export_ownership(
                {apis[0]: {}, apis[1]: {}}, {apis[1]: {}}, {})
        with self.assertRaisesRegex(ValueError, 'missing'):
            BUILDER.validate_hybrid_dispatch_export_ownership({}, {}, {})

    def test_default_provider_trees_match_the_current_r595_r580_abi(self):
        self.assertEqual(
            BUILDER.OPEN,
            ROOT / 'build/experiments/r595-debugger-bridge-provider-build-v4-20261101/source')
        self.assertEqual(
            BUILDER.LEGACY,
            ROOT / 'build/experiments/r58019607-debugger-bridge-provider-build-v3-20261101/source')
        uvm_header = BUILDER.OPEN / 'kernel-open/common/inc/nv_uvm_interface.h'
        symbols = BUILDER.standard_uvm_symbols_from_header(uvm_header)
        self.assertEqual(len(symbols), 79)
        self.assertTrue(BUILDER.R595_OPEN_ONLY_UVM_APIS <= set(symbols))
        imports = BUILDER.expected_backend_imports(uvm_abi='r595',
                                                    standard_uvm_symbols=symbols)
        self.assertTrue({
            f'hybrid580_{provider}_control_session_debugger_alloc_v1'
            for provider in ('open', 'legacy')
        } <= imports)
        self.assertTrue({
            f'hybrid580_{provider}_control_session_debugger_exception_mask_v1'
            for provider in ('open', 'legacy')
        } <= imports)

    def test_backend_specific_control_and_gpu_headers_may_diverge(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            open_headers = root / 'open'
            legacy_headers = root / 'legacy'
            open_headers.mkdir()
            legacy_headers.mkdir()
            for name in BUILDER.SHARED_BACKEND_API_HEADERS:
                (open_headers / name).write_text('shared hybrid580_open API\n')
                (legacy_headers / name).write_text('shared hybrid580_legacy API\n')
            for name in BUILDER.BACKEND_SPECIFIC_API_HEADERS:
                (open_headers / name).write_text('open-only API\n')
                (legacy_headers / name).write_text('legacy-only API\n')

            self.assertTrue(BUILDER.validate_backend_api_headers(
                open_headers, legacy_headers))

    def test_shared_api_header_mismatch_still_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            open_headers = root / 'open'
            legacy_headers = root / 'legacy'
            open_headers.mkdir()
            legacy_headers.mkdir()
            for name in (BUILDER.SHARED_BACKEND_API_HEADERS +
                         BUILDER.BACKEND_SPECIFIC_API_HEADERS):
                (open_headers / name).write_text('hybrid580_open shared API\n')
                (legacy_headers / name).write_text('hybrid580_legacy shared API\n')
            (legacy_headers / BUILDER.SHARED_BACKEND_API_HEADERS[0]).write_text(
                'different API contract\n')

            with self.assertRaisesRegex(ValueError, 'shared backend API mismatch'):
                BUILDER.validate_backend_api_headers(open_headers, legacy_headers)

    def test_module_version_dump_parser_and_provider_crc_check(self):
        module_versions = BUILDER.parse_module_modversions(
            '0x1234abcd\thybrid580_open_control_session_create_v1\n'
            '0xABCD1234 hybrid580_legacy_control_session_create_v1\n')
        imports = {
            'hybrid580_open_control_session_create_v1': {
                'provider': 'Open private module', 'crc': '0x1234ABCD'},
            'hybrid580_legacy_control_session_create_v1': {
                'provider': 'legacy private module', 'crc': '0xabcd1234'},
        }

        checks, mismatches = BUILDER.check_backend_import_crcs(module_versions, imports)

        self.assertEqual(mismatches, [])
        self.assertTrue(all(item['matches_provider'] for item in checks.values()))
        _, missing = BUILDER.check_backend_import_crcs(
            {}, imports)
        self.assertEqual(set(missing), set(imports))
        checks, mismatches = BUILDER.check_backend_import_crcs(
            {'hybrid580_open_control_session_create_v1': '0x00000001'}, imports)
        self.assertEqual(mismatches, sorted(imports))
        self.assertFalse(checks['hybrid580_open_control_session_create_v1'][
            'matches_provider'])

    def test_extended_module_versions_restore_long_imports_and_cross_check_short(self):
        extended = BUILDER.parse_extended_modversions(
            b'compact_symbol\0hybrid580_legacy_nvUvmInterfaceLongSymbol\0\0',
            struct.pack('<II', 0x1234abcd, 0x76543210),
            byte_order='little')
        merged = BUILDER.merge_module_modversions(
            {'compact_symbol': '0x1234abcd'}, extended)
        self.assertEqual(merged, {
            'compact_symbol': '0x1234abcd',
            'hybrid580_legacy_nvUvmInterfaceLongSymbol': '0x76543210',
        })
        with self.assertRaisesRegex(ValueError, 'conflicting modversion'):
            BUILDER.merge_module_modversions(
                {'compact_symbol': '0x00000001'}, extended)
        with self.assertRaisesRegex(ValueError, 'not NUL terminated'):
            BUILDER.parse_extended_modversions(
                b'compact_symbol', struct.pack('<I', 1), byte_order='little')
        with self.assertRaisesRegex(ValueError, 'count mismatch'):
            BUILDER.parse_extended_modversions(
                b'compact_symbol\0', struct.pack('<II', 1, 2),
                byte_order='little')
        with self.assertRaisesRegex(ValueError, 'empty symbol'):
            BUILDER.parse_extended_modversions(
                b'first\0\0second\0', struct.pack('<II', 1, 2),
                byte_order='little')

    def test_linux_compact_module_versions_fallback_parses_records_and_trailing_padding(self):
        def record(name, crc):
            raw_name = name.encode() + b'\0'
            size = 8 + ((len(raw_name) + 3) & ~3)
            return struct.pack('<II', size, crc) + raw_name.ljust(size - 8, b'\0')

        blob = (record('hybrid580_open_api', 0x1234abcd) +
                record('nvUvmInterfaceExample', 0x76543210) + b'\0' * 8)
        self.assertEqual(BUILDER.parse_kernel_modversions_section(blob, 'little'), {
            'hybrid580_open_api': '0x1234abcd',
            'nvUvmInterfaceExample': '0x76543210',
        })
        with self.assertRaisesRegex(ValueError, 'invalid size'):
            BUILDER.parse_kernel_modversions_section(struct.pack('<II', 7, 1), 'little')
        with self.assertRaisesRegex(ValueError, 'malformed name padding'):
            BUILDER.parse_kernel_modversions_section(
                struct.pack('<II', 12, 1) + b'bad!', 'little')

    @unittest.skipUnless(shutil.which('cc') and shutil.which('objcopy'),
                         'ELF fixture tools are unavailable')
    def test_kernel_modversion_elf_extraction_preserves_input_module(self):
        name = b'hybrid580_open_kernel_test_import'
        record_size = 8 + ((len(name) + 1 + 3) & ~3)
        record = (struct.pack('<II', record_size, 0x1234abcd) +
                  (name + b'\0').ljust(record_size - 8, b'\0'))
        values = ','.join(str(value) for value in record)
        with tempfile.TemporaryDirectory(prefix='hybrid-modversions-readonly-') as temp:
            root = Path(temp)
            source = root / 'module.c'
            module = root / 'module.ko'
            source.write_text(
                f'__attribute__((used,section("__versions"))) '
                f'const unsigned char versions[] = {{{values}}};\n')
            subprocess.run(['cc', '-c', str(source), '-o', str(module)],
                           check=True, capture_output=True, text=True)
            original = module.read_bytes()

            with mock.patch.object(BUILDER.subprocess, 'run', wraps=subprocess.run) as run:
                versions = BUILDER.extract_kernel_modversions_section(module, root)

            self.assertEqual(versions, {'hybrid580_open_kernel_test_import': '0x1234abcd'})
            self.assertEqual(module.read_bytes(), original)
            objcopy_calls = [call.args[0] for call in run.call_args_list
                             if Path(call.args[0][0]).name == 'objcopy']
            self.assertTrue(objcopy_calls)
            self.assertTrue(all(Path(command[-2]) == module and
                                Path(command[-1]) != module for command in objcopy_calls))

    @unittest.skipUnless(shutil.which('cc') and shutil.which('objcopy') and
                         shutil.which('zstd'),
                         'ELF or zstd fixture tools are unavailable')
    def test_kernel_modversion_extraction_accepts_zstd_compressed_basic_module(self):
        name = b'hybrid580_open_zstd_consumer_import'
        record = struct.pack('<Q', 0x89abcdef) + name.ljust(56, b'\0')
        values = ','.join(str(value) for value in record)
        with tempfile.TemporaryDirectory(prefix='hybrid-modversions-zstd-') as temp:
            root = Path(temp)
            source = root / 'module.c'
            module = root / 'module.ko'
            compressed = root / 'module.ko.zst'
            source.write_text(
                f'__attribute__((used,section("__versions"))) '
                f'const unsigned char versions[] = {{{values}}};\n')
            subprocess.run(['cc', '-c', str(source), '-o', str(module)],
                           check=True, capture_output=True, text=True)
            with compressed.open('wb') as stream:
                subprocess.run(['zstd', '-q', '-c', str(module)], stdout=stream,
                               check=True, stderr=subprocess.PIPE)
            original = compressed.read_bytes()

            versions = BUILDER.extract_kernel_modversions_section(compressed, root)

            self.assertEqual(versions, {
                'hybrid580_open_zstd_consumer_import': '0x89abcdef'})
            self.assertEqual(compressed.read_bytes(), original)

    @unittest.skipUnless(shutil.which('cc') and shutil.which('objcopy'),
                         'ELF fixture tools are unavailable')
    def test_extended_modversion_elf_extraction_preserves_input_module(self):
        with tempfile.TemporaryDirectory(prefix='hybrid-extended-modversions-readonly-') as temp:
            root = Path(temp)
            source = root / 'module.c'
            object_file = root / 'module.o'
            names = root / 'names.bin'
            crcs = root / 'crcs.bin'
            module = root / 'module.ko'
            source.write_text('int module_probe(void) { return 1; }\n')
            subprocess.run(['cc', '-c', str(source), '-o', str(object_file)],
                           check=True, capture_output=True, text=True)
            names.write_bytes(b'hybrid580_open_extended_test_import\0')
            crcs.write_bytes(struct.pack('<I', 0x76543210))
            subprocess.run([
                'objcopy', '--add-section', f'__version_ext_names={names}',
                '--add-section', f'__version_ext_crcs={crcs}', str(object_file), str(module),
            ], check=True, capture_output=True, text=True)
            original = module.read_bytes()

            with mock.patch.object(BUILDER.subprocess, 'run', wraps=subprocess.run) as run:
                versions = BUILDER.extract_extended_modversions(module, root)

            self.assertEqual(versions, {'hybrid580_open_extended_test_import': '0x76543210'})
            self.assertEqual(module.read_bytes(), original)
            objcopy_calls = [call.args[0] for call in run.call_args_list
                             if Path(call.args[0][0]).name == 'objcopy']
            self.assertEqual(len(objcopy_calls), 2)
            self.assertTrue(all(Path(command[-2]) == module and
                                Path(command[-1]) != module for command in objcopy_calls))

    @unittest.skipUnless(shutil.which('cc') and shutil.which('objcopy') and
                         shutil.which('zstd'),
                         'ELF or zstd fixture tools are unavailable')
    def test_extended_modversion_extraction_accepts_zstd_compressed_module(self):
        with tempfile.TemporaryDirectory(prefix='hybrid-extended-modversions-zstd-') as temp:
            root = Path(temp)
            source = root / 'module.c'
            object_file = root / 'module.o'
            names = root / 'names.bin'
            crcs = root / 'crcs.bin'
            module = root / 'module.ko'
            compressed = root / 'module.ko.zst'
            source.write_text('int module_probe(void) { return 1; }\n')
            subprocess.run(['cc', '-c', str(source), '-o', str(object_file)],
                           check=True, capture_output=True, text=True)
            names.write_bytes(b'hybrid580_open_extended_zstd_import\0')
            crcs.write_bytes(struct.pack('<I', 0x76543210))
            subprocess.run([
                'objcopy', '--add-section', f'__version_ext_names={names}',
                '--add-section', f'__version_ext_crcs={crcs}', str(object_file), str(module),
            ], check=True, capture_output=True, text=True)
            with compressed.open('wb') as stream:
                subprocess.run(['zstd', '-q', '-c', str(module)], stdout=stream,
                               check=True, stderr=subprocess.PIPE)
            original = compressed.read_bytes()

            versions = BUILDER.extract_extended_modversions(compressed, root)

            self.assertEqual(versions, {
                'hybrid580_open_extended_zstd_import': '0x76543210'})
            self.assertEqual(compressed.read_bytes(), original)

    def test_r595_public_and_private_uvm_abi_edges_are_checked_separately(self):
        matched_import = {'matches_provider': True}
        frontend = {'crc': '0x1234', 'export': 'EXPORT_SYMBOL'}
        # Private exports use different symbol names, so their modversion CRCs
        # are expected to differ from the public nvUvmInterface* export.
        open_private = {'crc': '0x5678', 'export': 'EXPORT_SYMBOL'}
        legacy_private = {'crc': '0x9abc', 'export': 'EXPORT_SYMBOL'}
        result = BUILDER.standard_api_r595_contract(
            frontend, open_private, legacy_private,
            matched_import, matched_import)
        self.assertTrue(result['matches_expected_contract'])
        self.assertIsNone(result['matches_frontend_and_open'])
        self.assertIsNone(result['matches_both_providers'])
        self.assertTrue(result['open_private_import_matches_provider'])
        self.assertTrue(result['legacy_private_import_matches_provider'])
        self.assertIn('differently named', result['crc_scope'])
        self.assertFalse(BUILDER.standard_api_r595_contract(
            frontend, open_private, legacy_private,
            matched_import, {'matches_provider': False})[
                'matches_expected_contract'])
        self.assertFalse(BUILDER.standard_api_r595_contract(
            None, open_private, legacy_private,
            matched_import, matched_import)['matches_expected_contract'])
        fail_closed = BUILDER.standard_api_r595_contract(
            frontend, None, None, None, None,
            no_backend_implementation=True)
        self.assertTrue(fail_closed['matches_expected_contract'])
        self.assertFalse(BUILDER.standard_api_r595_contract(
            frontend, None, None, matched_import, None,
            no_backend_implementation=True)['matches_expected_contract'])

    def test_standard_uvm_payload_boundaries_have_explicit_assessments(self):
        self.assertEqual(
            set(BUILDER.UVM_EXPLICIT_PAYLOAD_ABI_ADAPTERS),
            {
                'nvUvmInterfaceRegisterUvmEvents',
                'nvUvmInterfaceDeRegisterUvmEvents',
                'nvUvmInterfaceQueryCopyEnginesCaps',
                'nvUvmInterfaceGetP2PCaps',
                'nvUvmInterfaceGetPmaObject',
                'nvUvmInterfaceRetainChannel',
            })
        for name in BUILDER.UVM_EXPLICIT_PAYLOAD_ABI_ADAPTERS:
            assessment = BUILDER.standard_api_payload_abi_assessment(name)
            self.assertEqual(assessment['classification'], 'explicitly-adapted')
        for name in BUILDER.FAIL_CLOSED_UVM_APIS:
            assessment = BUILDER.standard_api_payload_abi_assessment(name)
            self.assertEqual(assessment['classification'],
                             'fail-closed-no-backend-call')
        self.assertEqual(
            BUILDER.standard_api_payload_abi_assessment(
                'nvUvmInterfaceRegisterGpu')['classification'],
            'unverified-payload-semantics')

    def test_r595_standard_uvm_api_inventory_includes_open_only_access_bits(self):
        header = (ROOT / 'build/experiments/r595-r580-patch-replay-v39-20261023'
                  / 'source/kernel-open/common/inc/nv_uvm_interface.h')
        symbols = BUILDER.standard_uvm_symbols_from_header(header)
        self.assertEqual(len(symbols), 79)
        self.assertEqual(len(symbols), len(set(symbols)))
        self.assertTrue(BUILDER.R595_OPEN_ONLY_UVM_APIS <= set(symbols))
        for name in BUILDER.R595_OPEN_ONLY_UVM_APIS:
            self.assertEqual(
                BUILDER.standard_api_payload_abi_assessment(name)['classification'],
                'open-only-r595-native-payload')

    def test_r580_same_version_surface_uses_76_symbols_and_old_event_names(self):
        header = (BUILDER.OPEN_R580 / 'kernel-open/common/inc'
                  / 'nv_uvm_interface.h')
        symbols = BUILDER.standard_uvm_symbols_from_header(header)
        self.assertEqual(len(symbols), 76)
        self.assertIn('nvUvmInterfaceRegisterUvmCallbacks', symbols)
        self.assertIn('nvUvmInterfaceDeRegisterUvmOps', symbols)
        self.assertNotIn('nvUvmInterfaceRegisterUvmEvents', symbols)
        self.assertNotIn('nvUvmInterfaceAccessBitsDump', symbols)

        imports = BUILDER.expected_backend_imports(
            uvm_abi='r580', standard_uvm_symbols=symbols)
        self.assertIn('hybrid580_legacy_control_session_debugger_alloc_v1', imports)
        self.assertIn('hybrid580_legacy_control_session_debugger_exception_mask_v1', imports)
        self.assertNotIn('hybrid580_open_control_session_debugger_alloc_v1', imports)
        self.assertNotIn('hybrid580_open_control_session_debugger_exception_mask_v1', imports)
        self.assertIn('hybrid580_open_control_session_gpu_name_string_v1', imports)
        self.assertIn('hybrid580_legacy_control_session_gpu_name_string_v1', imports)
        uvm_imports = {name for name in imports if 'nvUvmInterface' in name}
        self.assertEqual(len(uvm_imports), 142)
        self.assertIn('hybrid580_open_nvUvmInterfaceRegisterUvmCallbacks', imports)
        self.assertIn('hybrid580_legacy_nvUvmInterfaceDeRegisterUvmOps', imports)
        self.assertFalse(any('AccessBits' in name for name in uvm_imports))
        self.assertFalse(any('PagingChannel' in name for name in uvm_imports))
        self.assertIn('hybrid580_open_control_session_check_version_v1', imports)
        self.assertIn('hybrid580_legacy_control_session_check_version_v1', imports)

    def test_r580_default_pair_routes_debugger_bridge_to_legacy_only(self):
        open_tree, legacy_tree = BUILDER.default_provider_trees('r580')
        symbols = BUILDER.standard_uvm_symbols_from_header(
            open_tree / 'kernel-open/common/inc/nv_uvm_interface.h')
        imports = BUILDER.expected_backend_imports(
            uvm_abi='r580', standard_uvm_symbols=symbols)
        self.assertIn('hybrid580_legacy_control_session_debugger_alloc_v1', imports)
        self.assertIn('hybrid580_legacy_control_session_debugger_exception_mask_v1', imports)
        self.assertNotIn('hybrid580_open_control_session_debugger_alloc_v1', imports)
        self.assertNotIn('hybrid580_open_control_session_debugger_exception_mask_v1', imports)
        for provider, symvers in (
                ('open', open_tree / 'kernel-open/Module.symvers'),
                ('legacy', legacy_tree / 'Module.symvers')):
            with self.subTest(provider=provider):
                required = {name for name in imports
                            if name.startswith(f'hybrid580_{provider}_')}
                available = set(BUILDER.symbols(symvers))
                self.assertEqual(required - available, set())

    def test_r580_mode_selects_same_branch_provider_pair(self):
        open_tree, legacy_tree = BUILDER.default_provider_trees('r580')
        self.assertEqual(open_tree, BUILDER.OPEN_R580)
        self.assertEqual(legacy_tree, BUILDER.LEGACY_R580)
        self.assertEqual(BUILDER.default_provider_trees('r595'),
                         (BUILDER.OPEN, BUILDER.LEGACY))
        with self.assertRaisesRegex(ValueError, 'unsupported UVM API ABI'):
            BUILDER.default_provider_trees('r610')

    def test_r580_provider_headers_are_identical(self):
        open_header = (BUILDER.OPEN_R580 / 'kernel-open/common/inc'
                       / 'nv_uvm_interface.h')
        legacy_header = (BUILDER.LEGACY_R580 / 'common/inc'
                         / 'nv_uvm_interface.h')
        self.assertEqual(open_header.read_bytes(), legacy_header.read_bytes())

    def test_r580_callback_wrapper_uses_provider_parameter_name_for_dwarf_crc(self):
        header = (BUILDER.OPEN_R580 / 'kernel-open/common/inc'
                  / 'nv_uvm_interface.h').read_text()
        bridge = (ROOT / 'src/hybrid580_uvm_callback_bridge.c').read_text()
        prototype = (
            'NV_STATUS nvUvmInterfaceRegisterUvmCallbacks('
            'struct UvmOpsUvmEvents *importedUvmOps);')
        start = bridge.index('NV_STATUS nvUvmInterfaceRegisterUvmCallbacks(')
        end = bridge.index(
            'EXPORT_SYMBOL(nvUvmInterfaceRegisterUvmCallbacks);', start)
        definition = bridge[start:end]
        self.assertIn(prototype, header)
        self.assertIn('struct UvmOpsUvmEvents *importedUvmOps', definition)
        self.assertIn(
            'hybrid580_uvm_register_callbacks(importedUvmOps, importedUvmOps)',
            definition)

    def test_r580_only_registration_lock_helper_is_guarded_from_r595(self):
        bridge = (ROOT / 'src/hybrid580_uvm_callback_bridge.c').read_text()
        start = bridge.index('static NV_STATUS hybrid580_uvm_register_callbacks(')
        preceding_lines = bridge[:start].rstrip().splitlines()
        self.assertEqual(preceding_lines[-1], '#ifdef HYBRID580_UVM_ABI_R580')

    def test_r580_uvm_contract_checks_each_public_and_private_link_edge_separately(self):
        matched = {'matches_provider': True}
        frontend = {'crc': '0x580', 'export': 'EXPORT_SYMBOL'}
        open_private = {'crc': '0xopen', 'export': 'EXPORT_SYMBOL'}
        legacy_private = {'crc': '0xlegacy', 'export': 'EXPORT_SYMBOL'}
        result = BUILDER.standard_api_r580_contract(
            frontend, open_private, legacy_private, matched, matched)
        self.assertTrue(result['matches_expected_contract'])
        self.assertIsNone(result['matches_frontend_and_open'])
        self.assertIsNone(result['matches_both_providers'])
        self.assertTrue(result['public_consumer_binding_required'])
        self.assertFalse(result['public_consumer_binding_in_this_build'])
        self.assertIn('not compared', result['crc_scope'])
        self.assertFalse(BUILDER.standard_api_r580_contract(
            frontend, open_private, legacy_private, matched,
            {'matches_provider': False})['matches_expected_contract'])
        self.assertFalse(BUILDER.standard_api_r580_contract(
            None, open_private, legacy_private, matched, matched)['matches_expected_contract'])
        fail_closed = BUILDER.standard_api_r580_contract(
            frontend, None, None, None, None, no_backend_implementation=True)
        self.assertTrue(fail_closed['matches_expected_contract'])
        self.assertFalse(BUILDER.standard_api_r580_contract(
            frontend, None, None, matched, None,
            no_backend_implementation=True)['matches_expected_contract'])

    def test_open_only_api_contract_checks_exports_and_private_import_not_cross_name_crc(self):
        matched = {'matches_provider': True}
        frontend = {'crc': '0x1234', 'export': 'EXPORT_SYMBOL'}
        open_private = {'crc': '0x5678', 'export': 'EXPORT_SYMBOL'}
        result = BUILDER.standard_api_r595_open_only_contract(
            frontend, open_private, matched)
        self.assertTrue(result['matches_expected_contract'])
        self.assertFalse(result['legacy_provider_required'])
        self.assertIsNone(result['matches_frontend_and_open'])
        self.assertFalse(BUILDER.standard_api_r595_open_only_contract(
            frontend, None, matched)['matches_expected_contract'])
        self.assertFalse(BUILDER.standard_api_r595_open_only_contract(
            frontend, open_private, {'matches_provider': False})[
                'matches_expected_contract'])

    def test_public_uvm_consumer_imports_are_checked_against_frontend_exports(self):
        frontend = {
            'nvUvmInterfaceRegisterGpu': {
                'crc': '0x1234', 'export': 'EXPORT_SYMBOL'},
            'nvUvmInterfaceGetGpuInfo': {
                'crc': '0x5678', 'export': 'EXPORT_SYMBOL'},
        }
        consumer = {
            'nvUvmInterfaceRegisterGpu': '0x1234',
            'nvUvmInterfaceGetGpuInfo': '0x5678',
        }
        result = BUILDER.check_public_uvm_consumer_bindings(
            frontend, consumer, tuple(frontend))
        self.assertTrue(result['verified'])
        self.assertEqual(2, result['matched_count'])
        self.assertEqual([], result['missing'])
        self.assertEqual([], result['mismatches'])

        consumer['nvUvmInterfaceGetGpuInfo'] = '0xabcd'
        result = BUILDER.check_public_uvm_consumer_bindings(
            frontend, consumer, tuple(frontend))
        self.assertFalse(result['verified'])
        self.assertEqual(['nvUvmInterfaceGetGpuInfo'], result['mismatches'])

        result = BUILDER.check_public_uvm_consumer_bindings(
            frontend, {'nvUvmInterfaceRegisterGpu': '0x1234'}, tuple(frontend))
        self.assertFalse(result['verified'])
        self.assertEqual(['nvUvmInterfaceGetGpuInfo'], result['missing'])


if __name__ == '__main__':
    unittest.main()
