# SPDX-License-Identifier: MIT
import struct
import unittest

from tools.inspect_pc3_v100_loaded_module_identity import (
    GUEST_PROBE,
    compare_build_id_notes,
    compare_function_code_hashes,
    elf_function_hashes,
    parse_gnu_build_id_note,
    validate_guest_report,
)


def note(name=b"GNU\0", build_id=bytes.fromhex("0123456789abcdef"), note_type=3):
    name_field = name + b"\0" * ((-len(name)) % 4)
    desc_field = build_id + b"\0" * ((-len(build_id)) % 4)
    return struct.pack("<III", len(name), len(build_id), note_type) + name_field + desc_field


def elf_with_function(name="_nv031364rm", code=b"\x90\x90\xc3"):
    shstr = b"\0.text\0.strtab\0.symtab\0.shstrtab\0"
    strtab = b"\0" + name.encode() + b"\0"
    text_offset = 64
    strtab_offset = text_offset + len(code)
    symtab_offset = strtab_offset + len(strtab)
    shstr_offset = symtab_offset + 48
    section_offset = shstr_offset + len(shstr)
    data = bytearray(section_offset + 5 * 64)
    data[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", data, 16,
                     1, 62, 1, 0, 0, section_offset, 0,
                     64, 0, 0, 64, 5, 4)
    data[text_offset:text_offset + len(code)] = code
    data[strtab_offset:strtab_offset + len(strtab)] = strtab
    data[symtab_offset + 24:symtab_offset + 48] = struct.pack(
        "<IBBHQQ", 1, 2, 0, 1, 0, len(code)
    )
    data[shstr_offset:shstr_offset + len(shstr)] = shstr
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 6, 0, text_offset, len(code), 0, 0, 16, 0),
        (7, 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0),
        (15, 2, 0, 0, symtab_offset, 48, 2, 1, 8, 24),
        (23, 3, 0, 0, shstr_offset, len(shstr), 0, 0, 1, 0),
    ]
    for index, section in enumerate(sections):
        struct.pack_into("<IIQQQQIIQQ", data, section_offset + index * 64, *section)
    return bytes(data)


class LoadedModuleIdentityTests(unittest.TestCase):
    def test_remote_probe_is_valid_python(self):
        compile(GUEST_PROBE, "<pc3-read-only-module-identity-probe>", "exec")

    def test_remote_probe_does_not_load_or_unload_modules(self):
        for operation in ("insmod", "rmmod", "modprobe", "depmod"):
            self.assertNotIn(operation, GUEST_PROBE)

    def test_remote_probe_collects_only_fixed_rm_function_hashes(self):
        self.assertIn("_nv031364rm", GUEST_PROBE)
        self.assertIn("_nv031399rm", GUEST_PROBE)
        self.assertIn("_nv049612rm", GUEST_PROBE)
        self.assertIn("rm_function_hashes", GUEST_PROBE)

    def test_remote_probe_captures_module_holders_and_nvidia_device_users_read_only(self):
        for marker in ("/sys/module", "/proc/modules", "/proc", "module_usage",
                       "nvidia_device_fds", "proc_scan_complete", "quiescent_observed"):
            self.assertIn(marker, GUEST_PROBE)
        for operation in ("insmod", "rmmod", "modprobe", "depmod", "reboot", "systemctl"):
            self.assertNotIn(operation, GUEST_PROBE)

    def test_reads_gnu_build_id_from_loaded_note(self):
        self.assertEqual(parse_gnu_build_id_note(note()), "0123456789abcdef")

    def test_compares_loaded_note_to_installed_elf_note(self):
        result = compare_build_id_notes(note(), note())
        self.assertTrue(result["build_id_match"])
        self.assertEqual(result["loaded_build_id"], "0123456789abcdef")

    def test_extracts_exact_function_bytes_from_elf_symbol_table(self):
        result = elf_function_hashes(elf_with_function(), ["_nv031364rm"])
        self.assertEqual(result["_nv031364rm"]["size"], 3)
        self.assertEqual(result["_nv031364rm"]["section"], ".text")
        self.assertEqual(result["_nv031364rm"]["sha256"],
                         "39be667df5c9e6069f69c26d1d7923c4939ad24c9fe2a1b10037b322be4421b3")

    def test_rejects_wrong_elf_class_and_non_executable_symbol(self):
        wrong_class = bytearray(elf_with_function())
        wrong_class[4] = 1
        with self.assertRaisesRegex(ValueError, "ELF64"):
            elf_function_hashes(bytes(wrong_class), ["_nv031364rm"])

        non_executable = bytearray(elf_with_function())
        shoff = struct.unpack_from("<HHIQQQIHHHHHH", non_executable, 16)[5]
        struct.pack_into("<Q", non_executable, shoff + 1 * 64 + 8, 0)
        with self.assertRaisesRegex(ValueError, "not in executable"):
            elf_function_hashes(bytes(non_executable), ["_nv031364rm"])

    def test_rejects_function_extent_past_its_section(self):
        malformed = bytearray(elf_with_function())
        shoff = struct.unpack_from("<HHIQQQIHHHHHH", malformed, 16)[5]
        symtab = struct.unpack_from("<IIQQQQIIQQ", malformed, shoff + 3 * 64)
        symbol_offset = symtab[4] + 24
        struct.pack_into("<IBBHQQ", malformed, symbol_offset,
                         1, 2, 0, 1, 0, 100)
        with self.assertRaisesRegex(ValueError, "exceeds its executable section"):
            elf_function_hashes(bytes(malformed), ["_nv031364rm"])

    def test_function_comparison_reports_exact_hash_matches(self):
        function = {"_nv031364rm": {"size": 3, "sha256": "a" * 64}}
        result = compare_function_code_hashes(function, function)
        self.assertTrue(result["all_match"])
        mismatch = compare_function_code_hashes(
            function, {"_nv031364rm": {"size": 3, "sha256": "b" * 64}}
        )
        self.assertFalse(mismatch["all_match"])
        size_mismatch = compare_function_code_hashes(
            function, {"_nv031364rm": {"size": 4, "sha256": "a" * 64}}
        )
        self.assertFalse(size_mismatch["all_match"])

    def test_reports_mismatch_without_equating_version(self):
        result = compare_build_id_notes(note(), note(build_id=b"different-id"))
        self.assertFalse(result["build_id_match"])

    def test_accepts_exact_pinned_read_only_guest_report(self):
        ident = "0123456789abcdef"
        report = {
            "schema": "nvidia-hybrid-pc3-v100-loaded-module-identity-v1",
            "status": "observed", "hostname": "pc3-v100", "kernel_release": "6.8.0-147-generic",
            "effective_uid": 0,
            "execution_scope": {"read_only": True, "experimental_module_loaded": False,
                "stock_driver_changed": False, "pci_binding_changed": False,
                "vm_management_issued": False},
            "gpu": {"name": "Tesla V100-SXM2-16GB", "pci": "00000000:00:05.0",
                "driver_version": "580.178.04"},
            "module": {"version": "580.178.04", "loaded": True},
            "loaded_module": {"gnu_build_id": ident},
            "on_disk_module": {"gnu_build_id": ident, "decompressed_sha256": "a" * 64},
            "build_id_match": True,
        }
        self.assertIs(validate_guest_report(report), report)

    def test_v2_report_requires_all_fixed_function_hashes(self):
        ident = "0123456789abcdef"
        report = {
            "schema": "nvidia-hybrid-pc3-v100-loaded-module-identity-v2",
            "status": "observed", "hostname": "pc3-v100", "kernel_release": "6.8.0-147-generic",
            "effective_uid": 0,
            "execution_scope": {"read_only": True, "experimental_module_loaded": False,
                "stock_driver_changed": False, "pci_binding_changed": False,
                "vm_management_issued": False},
            "gpu": {"name": "Tesla V100-SXM2-16GB", "pci": "00000000:00:05.0",
                "driver_version": "580.178.04"},
            "module": {"version": "580.178.04", "loaded": True},
            "loaded_module": {"gnu_build_id": ident},
            "on_disk_module": {"gnu_build_id": ident, "decompressed_sha256": "a" * 64},
            "build_id_match": True,
            "rm_function_hashes": {name: {"size": 1, "sha256": "b" * 64} for name in
                ("_nv031364rm", "_nv031399rm", "_nv049612rm")},
        }
        self.assertIs(validate_guest_report(report), report)
        del report["rm_function_hashes"]["_nv031364rm"]
        with self.assertRaisesRegex(ValueError, "function hash"):
            validate_guest_report(report)

    def test_v3_report_requires_complete_module_and_device_use_inventory(self):
        ident = "0123456789abcdef"
        report = {
            "schema": "nvidia-hybrid-pc3-v100-loaded-module-identity-v3",
            "status": "observed", "hostname": "pc3-v100", "kernel_release": "6.8.0-147-generic",
            "effective_uid": 0,
            "execution_scope": {"read_only": True, "experimental_module_loaded": False,
                "stock_driver_changed": False, "pci_binding_changed": False,
                "vm_management_issued": False},
            "gpu": {"name": "Tesla V100-SXM2-16GB", "pci": "00000000:00:05.0",
                "driver_version": "580.178.04"},
            "module": {"version": "580.178.04", "loaded": True},
            "loaded_module": {"gnu_build_id": ident},
            "on_disk_module": {"gnu_build_id": ident, "decompressed_sha256": "a" * 64},
            "build_id_match": True,
            "rm_function_hashes": {name: {"size": 1, "sha256": "b" * 64} for name in
                ("_nv031364rm", "_nv031399rm", "_nv049612rm")},
            "module_usage": {"modules": [
                {"name": name, "loaded": True, "proc_refcount": 1, "sysfs_refcount": 1,
                 "sysfs_holders": []} for name in
                ("nvidia", "nvidia_uvm", "nvidia_modeset", "nvidia_drm")],
                "all_expected_loaded": True},
            "nvidia_device_fds": {"proc_scan_complete": True, "proc_processes_scanned": 12,
                "owner_process_count": 0,
                "fd_count": 0, "owners": []},
            "compute_processes": {"query_complete": True, "pids": []},
            "quiescent_observed": True,
        }
        self.assertIs(validate_guest_report(report), report)
        report["nvidia_device_fds"]["proc_scan_complete"] = False
        with self.assertRaisesRegex(ValueError, "quiescence"):
            validate_guest_report(report)

    def test_v3_rejects_inconsistent_quiescence_summary(self):
        ident = "0123456789abcdef"
        report = {
            "schema": "nvidia-hybrid-pc3-v100-loaded-module-identity-v3",
            "status": "observed", "hostname": "pc3-v100", "kernel_release": "6.8.0-147-generic",
            "effective_uid": 0,
            "execution_scope": {"read_only": True, "experimental_module_loaded": False,
                "stock_driver_changed": False, "pci_binding_changed": False,
                "vm_management_issued": False},
            "gpu": {"name": "Tesla V100-SXM2-16GB", "pci": "00000000:00:05.0",
                "driver_version": "580.178.04"},
            "module": {"version": "580.178.04", "loaded": True},
            "loaded_module": {"gnu_build_id": ident},
            "on_disk_module": {"gnu_build_id": ident, "decompressed_sha256": "a" * 64},
            "build_id_match": True,
            "rm_function_hashes": {name: {"size": 1, "sha256": "b" * 64} for name in
                ("_nv031364rm", "_nv031399rm", "_nv049612rm")},
            "module_usage": {"modules": [
                {"name": name, "loaded": True, "proc_refcount": 1, "sysfs_refcount": 1,
                 "sysfs_holders": []} for name in
                ("nvidia", "nvidia_uvm", "nvidia_modeset", "nvidia_drm")],
                "all_expected_loaded": True},
            "nvidia_device_fds": {"proc_scan_complete": True, "proc_processes_scanned": 12,
                "owner_process_count": 1,
                "fd_count": 1, "owners": [{"pid": 42, "comm": "python", "fd_count": 1,
                                               "nodes": ["nvidia0"]}]},
            "compute_processes": {"query_complete": True, "pids": [42]},
            "quiescent_observed": True,
        }
        with self.assertRaisesRegex(ValueError, "quiescence"):
            validate_guest_report(report)

    def test_rejects_build_id_claim_that_contradicts_observation(self):
        ident = "0123456789abcdef"
        report = {
            "schema": "nvidia-hybrid-pc3-v100-loaded-module-identity-v1",
            "status": "observed", "hostname": "pc3-v100", "kernel_release": "6.8.0-147-generic",
            "effective_uid": 0,
            "execution_scope": {"read_only": True, "experimental_module_loaded": False,
                "stock_driver_changed": False, "pci_binding_changed": False,
                "vm_management_issued": False},
            "gpu": {"name": "Tesla V100-SXM2-16GB", "pci": "00000000:00:05.0",
                "driver_version": "580.178.04"},
            "module": {"version": "580.178.04", "loaded": True},
            "loaded_module": {"gnu_build_id": "fedcba9876543210"},
            "on_disk_module": {"gnu_build_id": ident, "decompressed_sha256": "a" * 64},
            "build_id_match": True,
        }
        with self.assertRaisesRegex(ValueError, "contradicts"):
            validate_guest_report(report)

    def test_rejects_truncated_note(self):
        with self.assertRaisesRegex(ValueError, "truncated"):
            parse_gnu_build_id_note(note()[:-2])

    def test_rejects_non_gnu_build_id_note(self):
        with self.assertRaisesRegex(ValueError, "GNU build-id"):
            parse_gnu_build_id_note(note(name=b"ABC\0"))


if __name__ == "__main__":
    unittest.main()
