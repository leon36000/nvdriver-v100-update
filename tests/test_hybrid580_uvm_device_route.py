# SPDX-License-Identifier: MIT
"""Compile and execute the physical-device UVM provider route contract."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

from tools.audit_volta_uvm_candidate_paths import (  # noqa: E402
    _extract_function,
    _normalized_function,
)


class Hybrid580UvmDeviceRouteTests(unittest.TestCase):
    def test_device_create_and_destroy_follow_uuid_owner_without_cross_rm_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "hybrid580_uvm_device_route_test"
            build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                 str(ROOT / "tests/fixtures/hybrid580_uvm_device_route_test.c"),
                 "-o", str(binary)],
                capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("passed", run.stdout)

    def test_public_device_create_executes_exact_bridge_and_backend_adapters(self):
        bridge = ROOT / "src/hybrid580_uvm_callback_bridge.c"
        bridge_lines = bridge.read_text(encoding="utf-8").splitlines(keepends=True)
        source = (ROOT / "tests/fixtures/hybrid580_uvm_device_create_wrapper_test.c").read_text()
        functions = (
            ("static uint32_t hybrid580_open_device_create(",
             "/* INSERT_EXACT_DEVICE_ADAPTERS */"),
            ("static uint32_t hybrid580_legacy_device_create(",
             "/* INSERT_EXACT_DEVICE_ADAPTERS */"),
            ("static void hybrid580_open_device_destroy(",
             "/* INSERT_EXACT_DEVICE_ADAPTERS */"),
            ("static void hybrid580_legacy_device_destroy(",
             "/* INSERT_EXACT_DEVICE_ADAPTERS */"),
            ("NV_STATUS nvUvmInterfaceDeviceCreate(",
             "/* INSERT_EXACT_PUBLIC_DEVICE_CREATE */"),
        )
        for signature, _ in functions:
            self.assertEqual(bridge.read_text().count(signature), 1, signature)
        def exact_source(signature):
            extracted = _extract_function(bridge, signature)
            return "".join(bridge_lines[
                extracted["start_line"] - 1:extracted["end_line"]])

        adapters = "\n\n".join(
            exact_source(signature)
            for signature, marker in functions
            if marker == "/* INSERT_EXACT_DEVICE_ADAPTERS */")
        public_wrapper = exact_source(functions[-1][0])
        adapter_marker = "/* INSERT_EXACT_DEVICE_ADAPTERS */"
        wrapper_marker = "/* INSERT_EXACT_PUBLIC_DEVICE_CREATE */"
        self.assertEqual(source.count(adapter_marker), 1)
        self.assertEqual(source.count(wrapper_marker), 1)
        generated = source.replace(adapter_marker, adapters).replace(
            wrapper_marker, public_wrapper)

        with tempfile.TemporaryDirectory(prefix="hybrid580-device-create-public-") as directory:
            source_path = Path(directory) / "device_create_public_test.c"
            binary = Path(directory) / "device_create_public_test"
            source_path.write_text(generated)
            build = subprocess.run(
                ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined", "-fno-sanitize-recover=all",
                 "-I", str(ROOT),
                 str(source_path), "-o", str(binary)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("exact public DeviceCreate wrapper", run.stdout)

    def test_r595_consumer_and_hybrid_bridge_share_pinned_directional_route_contract(self):
        consumer = ROOT / "tests/fixtures/upstream/nvidia-r595-uvm-p2p/595.112.07/uvm_gpu_p2p_consumer_excerpt.c"
        bridge = ROOT / "src/hybrid580_uvm_callback_bridge.c"
        compat = ROOT / "src/hybrid580_uvm_abi_compat.h"
        route = ROOT / "src/hybrid580_uvm_device_route.h"
        builder = (ROOT / "tools/build_hybrid_frontend.py").read_text(encoding="utf-8")

        self.assertEqual(
            hashlib.sha256(consumer.read_bytes()).hexdigest(),
            "33913c7fffc5c5307969a1fd15ebdb735259705edc0e4923c3ae9897099a2af2",
        )
        excerpt_text = consumer.read_text(encoding="utf-8")
        self.assertIn("d8257d95ae5fed364163e4df51db66df8b1ee0d2", excerpt_text)
        self.assertIn("66881c4ae46461314d41342b2a27df9119d68d68f90d181e3a32670dcc19f590",
                      excerpt_text)
        query = "".join(_normalized_function(_extract_function(
            consumer, "static NV_STATUS get_parent_p2p_caps(")).split())
        peer_init = "".join(_normalized_function(_extract_function(
            consumer, "static NV_STATUS parent_peers_init(")).split())
        aperture = "".join(_normalized_function(_extract_function(
            consumer, "static uvm_aperture_t parent_gpu_peer_aperture(")).split())
        dma_range = "".join(_normalized_function(_extract_function(
            consumer, "static bool gpu_phys_address_is_bar1p2p_peer(")).split())
        open_backend = "".join(_normalized_function(_extract_function(
            bridge, "static uint32_t hybrid580_open_get_p2p_caps(")).split())
        legacy_backend = "".join(_normalized_function(_extract_function(
            bridge, "static uint32_t hybrid580_legacy_get_p2p_caps(")).split())
        dispatch = "".join(_normalized_function(_extract_function(
            bridge, "NV_STATUS nvUvmInterfaceGetP2PCaps(")).split())
        pair_router = "".join(_normalized_function(_extract_function(
            route, "hybrid580_uvm_device_route_pair_call(")).split())
        r580_conversion = "".join(_normalized_function(_extract_function(
            compat, "static inline int hybrid580_uvm_p2p_caps_from_r580(")).split())

        self.assertIn(
            "uvm_parent_id_value(parent_gpu0->id)<uvm_parent_id_value(parent_gpu1->id)",
            query,
        )
        self.assertIn(
            "nvUvmInterfaceGetP2PCaps(rm_device0,rm_device1,p2p_caps_params)",
            query,
        )
        for index in (0, 1):
            self.assertIn(
                f"bar1_p2p_pcie_atomics_enabled[{index}]=p2p_caps_params.bar1PcieAtomics[{index}]",
                peer_init,
            )
        self.assertIn("peer_index=0", aperture)
        self.assertIn("peer_index=1", aperture)
        self.assertIn("bar1_p2p_pcie_atomics_enabled[peer_index]", aperture)
        self.assertIn("uvm_parent_id_cmp(gpu->parent->id,peer_parent_gpu->id)<0", dma_range)
        self.assertIn("bar1_p2p_dma_base_address[peer_index]", dma_range)
        self.assertIn("bar1_p2p_dma_size[peer_index]", dma_range)
        self.assertIn(
            "hybrid580_open_nvUvmInterfaceGetP2PCaps((uvmGpuDeviceHandle)device1,"
            "(uvmGpuDeviceHandle)device2,(UvmGpuP2PCapsParams*)params)",
            open_backend,
        )
        self.assertIn("hybrid580_legacy_nvUvmInterfaceGetP2PCaps(", legacy_backend)
        self.assertIn("&legacy_caps", legacy_backend)
        self.assertIn("hybrid580_uvm_p2p_caps_from_r580(", legacy_backend)
        self.assertIn(
            "hybrid580_uvm_device_route_pair_call(&hybrid580_uvm_devices,"
            "(uintptr_t)device1,(uintptr_t)device2,p2pCapsParams,"
            "hybrid580_open_p2p_caps_ops,hybrid580_legacy_p2p_caps_ops,"
            "&backend_status)",
            dispatch,
        )
        self.assertIn("provider1!=provider2", pair_router)
        self.assertIn("HYBRID580_UVM_DEVICE_PAIR_ROUTE_CROSS_PROVIDER", pair_router)
        self.assertIn("selected->call(selected->context,native_device1,native_device2,params)",
                      pair_router)
        self.assertIn("UVM_LINK_TYPE_NONE", dispatch)
        self.assertIn("r595->bar1PcieAtomics[0]=NV_FALSE", r580_conversion)
        self.assertIn("r595->bar1PcieAtomics[1]=NV_FALSE", r580_conversion)
        self.assertIn("uvm_abi='r595'", builder)
        self.assertIn("ifuvm_abi=='r580'else''", "".join(builder.split()))


if __name__ == "__main__":
    unittest.main()
