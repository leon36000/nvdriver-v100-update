import importlib.util
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "system_features_vmm_fabric_probe",
    ROOT / "src/system_features_vmm_fabric_probe.py",
)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class VmmFabricAbiTests(unittest.TestCase):
    def test_cuda_13_abi_struct_sizes_and_offsets(self):
        self.assertEqual(probe.ctypes.sizeof(probe.CUmemFabricHandle), 64)
        self.assertEqual(probe.ctypes.sizeof(probe.CUmemLocation), 8)
        self.assertEqual(probe.ctypes.sizeof(probe.CUmemAccessDesc), 12)
        self.assertEqual(probe.ctypes.sizeof(probe.CUmemAllocationProp), 32)
        self.assertEqual(probe.CUmemAllocationProp.location.offset, 8)
        self.assertEqual(probe.CUmemAllocationProp.win32HandleMetaData.offset, 16)
        self.assertEqual(probe.CUmemAllocationProp.allocFlags.offset, 24)

    def test_device_allocation_properties_match_vmm_contract(self):
        prop = probe.build_allocation_prop(device_ordinal=0)
        self.assertEqual(prop.type, probe.CU_MEM_ALLOCATION_TYPE_PINNED)
        self.assertEqual(prop.requestedHandleTypes, probe.CU_MEM_HANDLE_TYPE_FABRIC)
        self.assertEqual(prop.location.type, probe.CU_MEM_LOCATION_TYPE_DEVICE)
        self.assertEqual(prop.location.id, 0)
        self.assertIsNone(prop.win32HandleMetaData)
        self.assertEqual(prop.allocFlags.compressionType, 0)
        self.assertEqual(prop.allocFlags.gpuDirectRDMACapable, 0)
        self.assertEqual(prop.allocFlags.usage, 0)
        self.assertEqual(bytes(prop.allocFlags.reserved), bytes(4))

    def test_device_allocation_properties_can_request_posix_fd_export(self):
        prop = probe.build_allocation_prop(
            device_ordinal=0,
            handle_type=probe.CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR,
        )
        self.assertEqual(
            prop.requestedHandleTypes,
            probe.CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR,
        )

    def test_expected_device_contract_defaults_to_pinned_v100(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(probe.expected_device_contract(), {
                "pci": "0000:00:05.0", "device_name_prefix": "Tesla V100",
                "sm": 70, "driver_api": 13000,
            })

    def test_expected_device_contract_supports_an_explicit_blackwell_pin(self):
        values = {
            "NVIDIA_HYBRID_VMM_EXPECTED_PCI": "0000:02:00.0",
            "NVIDIA_HYBRID_VMM_EXPECTED_DEVICE_NAME_PREFIX": "NVIDIA GeForce RTX 5080",
            "NVIDIA_HYBRID_VMM_EXPECTED_SM": "120",
            "NVIDIA_HYBRID_VMM_EXPECTED_DRIVER_API": "13020",
        }
        with patch.dict(os.environ, values, clear=True):
            self.assertEqual(probe.expected_device_contract(), {
                "pci": "0000:02:00.0", "device_name_prefix": "NVIDIA GeForce RTX 5080",
                "sm": 120, "driver_api": 13020,
            })

    def test_expected_device_contract_rejects_malformed_identity_or_numbers(self):
        for key, value in (
            ("NVIDIA_HYBRID_VMM_EXPECTED_PCI", "0000:02:00.0; reboot"),
            ("NVIDIA_HYBRID_VMM_EXPECTED_SM", "120.0"),
            ("NVIDIA_HYBRID_VMM_EXPECTED_DRIVER_API", "-1"),
        ):
            with self.subTest(key=key), patch.dict(os.environ, {key: value}, clear=True):
                with self.assertRaisesRegex(ValueError, "expected_device_contract"):
                    probe.expected_device_contract()

    def test_access_descriptor_requests_only_device_read_write(self):
        desc = probe.build_access_desc(device_ordinal=0)
        self.assertEqual(desc.location.type, probe.CU_MEM_LOCATION_TYPE_DEVICE)
        self.assertEqual(desc.location.id, 0)
        self.assertEqual(desc.flags, probe.CU_MEM_ACCESS_FLAGS_PROT_READWRITE)

    def test_fabric_message_round_trip_is_bounded_and_exact(self):
        handle = bytes(range(probe.FABRIC_HANDLE_BYTES))
        size = probe.MAX_ALLOCATION_BYTES
        encoded = probe.encode_fabric_message(size, handle)
        self.assertEqual(len(encoded), probe.FABRIC_MESSAGE_BYTES)
        self.assertEqual(probe.decode_fabric_message(encoded), (size, handle))
        with self.assertRaises(ValueError):
            probe.decode_fabric_message(encoded[:-1])
        with self.assertRaises(ValueError):
            probe.decode_fabric_message(encoded + b"x")
        with self.assertRaises(ValueError):
            probe.encode_fabric_message(0, handle)
        with self.assertRaises(ValueError):
            probe.encode_fabric_message(size + 1, handle)
        with self.assertRaises(ValueError):
            probe.encode_fabric_message(size, handle[:-1])

    def test_numeric_payload_is_deterministic_and_bounded(self):
        initial = probe.pack_words(probe.EXPECTED_WORDS)
        updated = probe.pack_words(probe.transform_words(probe.EXPECTED_WORDS))
        self.assertEqual(len(initial), probe.PAYLOAD_BYTES)
        self.assertEqual(len(updated), probe.PAYLOAD_BYTES)
        self.assertNotEqual(initial, updated)
        self.assertEqual(probe.transform_words(probe.transform_words(probe.EXPECTED_WORDS)),
                         probe.EXPECTED_WORDS)

    def test_posix_fd_child_launch_inherits_only_the_exported_descriptor(self):
        read_fd, write_fd = os.pipe()
        try:
            argv, env, kwargs = probe.build_child_invocation(
                "import os; os.fstat(int(os.environ['NVIDIA_HYBRID_VMM_POSIX_FD']))",
                kind="posix_fd", allocation_size=probe.MAX_ALLOCATION_BYTES,
                shareable_fd=read_fd,
                fabric_handle=None,
            )
            self.assertEqual(kwargs["pass_fds"], (read_fd,))
            self.assertNotIn("input", kwargs)
            self.assertEqual(env[probe.SHARE_KIND_ENV], "posix_fd")
            self.assertEqual(env[probe.POSIX_SIZE_ENV], str(probe.MAX_ALLOCATION_BYTES))
            child = subprocess.run(argv, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, check=False, **kwargs)
            self.assertEqual(child.returncode, 0, child.stderr.decode("utf-8", "replace"))
            self.assertGreater(os.fstat(read_fd).st_ino, 0)
        finally:
            os.close(read_fd)
            os.close(write_fd)


if __name__ == "__main__":
    unittest.main()
