# SPDX-License-Identifier: MIT
"""Execute the production mixed-provider P2P bridge and R595 skip predicate."""
from pathlib import Path
import hashlib
import subprocess
import tempfile
import unittest

from tools.audit_hybrid_uvm_abi import c_function_definition


ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "src/hybrid580_uvm_callback_bridge.c"
R595_GPU = ROOT / (
    "build/research/open-gpu-kernel-modules-595.99.02/source/"
    "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia-uvm/uvm_gpu.c"
)
R595_GPU_SHA256 = "66881c4ae46461314d41342b2a27df9119d68d68f90d181e3a32670dcc19f590"
FIXTURE = ROOT / "tests/fixtures/hybrid580_uvm_p2p_bridge_contract_test.c"
MARKER = "/* INSERT_EXTRACTED_PRODUCTION_FUNCTIONS */"


def production_functions(bridge_mutation=None, discovery_mutation=None):
    """Assemble exact pinned production function definitions for the host fixture."""
    if (R595_GPU.is_symlink() or
            hashlib.sha256(R595_GPU.read_bytes()).hexdigest() != R595_GPU_SHA256):
        raise AssertionError("pinned R595 UVM reference source changed")
    definitions = [
        "NV_STATUS " + c_function_definition(
            BRIDGE, "nvUvmInterfaceGetP2PCaps"),
        "NV_STATUS " + c_function_definition(
            BRIDGE, "nvUvmInterfaceP2pObjectCreate"),
        "static NV_STATUS " + c_function_definition(
            R595_GPU, "get_parent_p2p_caps"),
        "static NV_STATUS " + c_function_definition(
            R595_GPU, "parent_peers_discover_static_link"),
    ]

    # The bridge must precede the R595 adapter that calls it.
    if bridge_mutation is not None:
        index, old, new = bridge_mutation
        if old not in definitions[index]:
            raise AssertionError(f"bridge mutation anchor missing: {old}")
        definitions[index] = definitions[index].replace(old, new, 1)
    if discovery_mutation is not None:
        index, old, new = discovery_mutation
        if old not in definitions[index]:
            raise AssertionError(f"discovery mutation anchor missing: {old}")
        definitions[index] = definitions[index].replace(old, new, 1)
    return "\n\n".join(definitions)


def compile_and_run(bridge_mutation=None, discovery_mutation=None):
    template = FIXTURE.read_text(encoding="utf-8")
    if template.count(MARKER) != 1:
        raise AssertionError("fixture must contain exactly one extraction marker")
    source = template.replace(
        MARKER,
        production_functions(bridge_mutation, discovery_mutation),
        1,
    )
    with tempfile.TemporaryDirectory(prefix="hybrid-p2p-bridge-contract-") as temp:
        c_path = Path(temp) / "p2p_bridge_contract.c"
        binary = Path(temp) / "p2p_bridge_contract"
        c_path.write_text(source, encoding="utf-8")
        build = subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=undefined", "-I", str(ROOT / "src"),
             str(c_path), "-o", str(binary)],
            capture_output=True, text=True, timeout=20, check=False)
        if build.returncode != 0:
            return build, None
        run = subprocess.run([str(binary)], capture_output=True, text=True,
                             timeout=5, check=False)
        return build, run


class Hybrid580UvmP2pBridgeContractTests(unittest.TestCase):
    def test_reference_function_source_matches_pinned_r595_release_file(self):
        self.assertFalse(R595_GPU.is_symlink())
        self.assertEqual(hashlib.sha256(R595_GPU.read_bytes()).hexdigest(),
                         R595_GPU_SHA256)

    def test_production_bridge_and_r595_discovery_skip_mixed_pair(self):
        build, run = compile_and_run()
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        self.assertIsNotNone(run)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("production bridge and R595 discovery contract passed",
                      run.stdout)

    def test_regression_rejects_nonzero_peer_link_for_mixed_pair(self):
        mutation = (
            0,
            "p2pCapsParams->p2pLink = UVM_LINK_TYPE_NONE;",
            "p2pCapsParams->p2pLink = UVM_LINK_TYPE_NVLINK_1;",
        )
        build, run = compile_and_run(bridge_mutation=mutation)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        self.assertIsNotNone(run)
        self.assertNotEqual(run.returncode, 0,
                            "mixed-provider NVLink mutation escaped the assertions")

    def test_regression_rejects_missing_capability_zeroing(self):
        mutation = (
            0,
            "memset(p2pCapsParams, 0, sizeof(*p2pCapsParams));",
            "(void)0;",
        )
        build, run = compile_and_run(bridge_mutation=mutation)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        self.assertIsNotNone(run)
        self.assertNotEqual(run.returncode, 0,
                            "nonzero mixed-provider capability fields escaped")

    def test_regression_rejects_mixed_provider_object_success(self):
        mutation = (
            1,
            "NV_ERR_NOT_SUPPORTED, &public_handle",
            "NV_OK, &public_handle",
        )
        build, run = compile_and_run(bridge_mutation=mutation)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        self.assertIsNotNone(run)
        self.assertNotEqual(run.returncode, 0,
                            "mixed-provider object-success mutation escaped")

    def test_regression_rejects_discovery_predicate_that_does_not_skip_none(self):
        mutation = (
            3,
            "p2p_caps_params.p2pLink == UVM_LINK_TYPE_NONE",
            "p2p_caps_params.p2pLink != UVM_LINK_TYPE_NONE",
        )
        build, run = compile_and_run(discovery_mutation=mutation)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        self.assertIsNotNone(run)
        self.assertNotEqual(run.returncode, 0,
                            "automatic peer-setup mutation escaped")


if __name__ == "__main__":
    unittest.main()
