# SPDX-License-Identifier: MIT
"""Execute the production R580 P2P ABI adapter through the real route API."""
from pathlib import Path
import hashlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.audit_hybrid_uvm_abi import c_function_definition

BRIDGE = ROOT / "src/hybrid580_uvm_callback_bridge.c"
R595_FIXTURE = ROOT / "tests/fixtures/upstream/nvidia-r595-p2p/595.112.07"
R595_INCLUDE = R595_FIXTURE / "include"
FIXTURE = ROOT / "tests/fixtures/hybrid580_r580_p2p_route_test.c"
MARKER = "/* INSERT_EXTRACTED_PRODUCTION_FUNCTIONS */"
R595_INPUT_SHA256 = {
    "nv_uvm_link_type_enum_excerpt.h":
        "cc5606011d716126df95192e9a317ec0ff763b4e518d08c832fdfd4c3b8c38b7",
    "nv_uvm_p2p_caps_struct_excerpt.h":
        "5a5574d7b316e03e87fe8efe7783cd1c59911d1a5045d538ee7338eee8fbe250",
}


def verify_pinned_r595_inputs():
    for relative, expected in R595_INPUT_SHA256.items():
        path = R595_FIXTURE / relative
        if path.is_symlink() or not path.is_file():
            raise AssertionError(f"pinned R595 input is missing or a symlink: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise AssertionError(f"pinned R595 input hash mismatch: {relative}")
    shim = (R595_INCLUDE / "nv_uvm_types.h").read_text(encoding="utf-8")
    for excerpt in R595_INPUT_SHA256:
        if f'"../{excerpt}"' not in shim:
            raise AssertionError(f"test ABI shim does not compile pinned excerpt: {excerpt}")


def production_definitions(adapter_mutation=None, table_mutation=None):
    """Extract the shipping R595-build adapter, dispatch table, and API."""
    source = BRIDGE.read_text(encoding="utf-8")
    adapter_match = re.search(
        r"static uint32_t\s+hybrid580_legacy_get_p2p_caps\s*\(", source)
    if adapter_match is None:
        raise AssertionError("production R580 P2P adapter is missing")
    adapter_start = adapter_match.start()
    adapter_open = source.find("{", adapter_match.end())
    depth = 0
    adapter_end = None
    for offset in range(adapter_open, len(source)):
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if depth == 0:
                adapter_end = offset + 1
                break
    if adapter_end is None:
        raise AssertionError("production R580 P2P adapter is unterminated")
    legacy_ops = re.search(
        r"static const struct hybrid580_uvm_device_pair_backend_ops\s+"
        r"hybrid580_legacy_p2p_caps_ops\s*=\s*\{.*?\n\};",
        source,
        re.S,
    )
    if legacy_ops is None:
        raise AssertionError("production R580 P2P dispatch table is missing")
    adapter = source[adapter_start:adapter_end]
    table = legacy_ops.group(0)
    if adapter_mutation is not None:
        if adapter_mutation[0] not in adapter:
            raise AssertionError(
                f"production adapter mutation anchor missing: {adapter_mutation[0]}")
        adapter = adapter.replace(adapter_mutation[0], adapter_mutation[1], 1)
    if table_mutation is not None:
        if table_mutation[0] not in table:
            raise AssertionError(
                f"production table mutation anchor missing: {table_mutation[0]}")
        table = table.replace(table_mutation[0], table_mutation[1], 1)
    return "\n\n".join((
        adapter,
        table,
        "NV_STATUS " + c_function_definition(
            BRIDGE, "nvUvmInterfaceGetP2PCaps"),
    ))


def compile_and_run(adapter_mutation=None, table_mutation=None):
    verify_pinned_r595_inputs()
    source = FIXTURE.read_text(encoding="utf-8")
    if source.count(MARKER) != 1:
        raise AssertionError("fixture needs exactly one extraction marker")
    source = source.replace(
        MARKER,
        production_definitions(adapter_mutation, table_mutation),
        1,
    )
    with tempfile.TemporaryDirectory(prefix="hybrid580-r580-p2p-route-") as temp:
        c_path = Path(temp) / "r580_p2p_route.c"
        binary = Path(temp) / "r580_p2p_route"
        c_path.write_text(source, encoding="utf-8")
        build = subprocess.run(
            ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=undefined", "-fno-sanitize-recover=all",
             "-I", str(R595_INCLUDE), "-I", str(ROOT / "src"),
             str(c_path), "-o", str(binary)],
            capture_output=True, text=True, timeout=30, check=False)
        if build.returncode != 0:
            return build, None
        run = subprocess.run([str(binary)], capture_output=True, text=True,
                             timeout=5, check=False)
        return build, run


class Hybrid580R580P2pRouteTests(unittest.TestCase):
    def _run_mutation(self, **mutations):
        build, run = compile_and_run(**mutations)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        self.assertIsNotNone(run)
        self.assertNotEqual(run.returncode, 0,
                            "production P2P mutation escaped the assertions")

    def test_r595_112_07_abi_excerpts_are_pinned(self):
        verify_pinned_r595_inputs()

    def test_production_r580_adapter_and_route(self):
        build, run = compile_and_run()
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        self.assertIsNotNone(run)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("production route contract passed", run.stdout)

    def test_mutation_direct_legacy_payload_forwarding_is_rejected(self):
        self._run_mutation(adapter_mutation=(
            "&legacy_caps);",
            "(struct hybrid580_r580_UvmGpuP2PCapsParams *)params);",
        ))

    def test_mutation_suppressing_unrepresentable_link_error_is_rejected(self):
        self._run_mutation(adapter_mutation=(
            "status = NV_ERR_INVALID_STATE;",
            "status = NV_OK;",
        ))

    def test_mutation_relabeling_legacy_dispatch_as_open_is_rejected(self):
        self._run_mutation(table_mutation=(
            ".provider = HYBRID580_UVM_PROVIDER_LEGACY,",
            ".provider = HYBRID580_UVM_PROVIDER_OPEN,",
        ))


if __name__ == "__main__":
    unittest.main()
