# SPDX-License-Identifier: MIT
"""Compose exact R595 UVM duplicate/free callsites with bridge wrappers."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "src/hybrid580_uvm_callback_bridge.c"
FIXTURE = ROOT / "tests/fixtures/hybrid580_uvm_duplicate_memory_bridge_test.c"
R595_SOURCE = ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/open-gpu-kernel-modules-595.99.02/kernel-open/nvidia-uvm/uvm_map_external.c"
R595_FIXTURE = ROOT / "tests/fixtures/r595_uvm_external_map_callsite.c"
R595_PATCH = ROOT / "patches/r595.99.02/0003-uvm-external-allocation-control-fd.patch"
R595_SOURCE_SHA256 = "90de5bb57f41ce3f4c7d1316b8c8541e87dd3f23457aef81f9241273c86ad409"
R595_FIXTURE_SHA256 = "87bad135f952132b865fe275c6482cd3c63e76a7757cc820ced8da156a076825"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _patched_r595_callsite(directory: Path) -> str:
    force_fixture = os.environ.get("NVIDIA_HYBRID_TEST_USE_R595_FIXTURE") == "1"
    if R595_SOURCE.is_file() and not force_fixture:
        source_bytes = R595_SOURCE.read_bytes()
        if _sha256(source_bytes) != R595_SOURCE_SHA256:
            raise AssertionError("local R595 UVM source differs from the pinned input")
        is_full_source = True
    else:
        source_bytes = R595_FIXTURE.read_bytes()
        if _sha256(source_bytes) != R595_FIXTURE_SHA256:
            raise AssertionError("R595 UVM callsite fixture differs from its pinned input")
        is_full_source = False

    target_dir = directory / "nvidia-uvm"
    target_dir.mkdir()
    target = target_dir / "uvm_map_external.c"
    target.write_bytes(source_bytes)
    patched = subprocess.run(
        ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(R595_PATCH)],
        cwd=directory, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=20, check=False)
    if patched.returncode != 0:
        raise AssertionError("R595 control-fd patch failed: " + patched.stdout)
    if "fuzz" in patched.stdout.lower():
        raise AssertionError("R595 control-fd patch applied with fuzz")
    if is_full_source and "offset" in patched.stdout.lower():
        raise AssertionError("R595 control-fd patch offset the pinned full source")

    source = target.read_text()
    if source.count("status = uvm_rm_locked_call(nvUvmInterfaceDupMemoryWithControlFd(") != 1:
        raise AssertionError("patched R595 external-map callsite is absent or ambiguous")
    return source


def _extract_source_statement(source: str, marker: str) -> str:
    if source.count(marker) != 1:
        raise AssertionError("source statement is absent or ambiguous: " + marker)
    start = source.index(marker)
    opening = source.index("(", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "(":
            depth += 1
        elif source[index] == ")":
            depth -= 1
            if depth == 0:
                end = index + 1
                if source[end:end + 1] != ";":
                    raise AssertionError("patched UVM call is not a complete statement")
                return source[start:end + 1]
    raise AssertionError("patched UVM call has unbalanced parentheses")


class Hybrid580UvmDuplicateMemoryBridgeHostTests(unittest.TestCase):
    def test_exact_r595_external_map_duplicate_and_free_compose_with_bridge(self):
        bridge = BRIDGE.read_text()
        wrappers = (
            ("NV_STATUS nvUvmInterfaceDupMemoryWithControlFd(",
             "EXPORT_SYMBOL(nvUvmInterfaceDupMemoryWithControlFd);",
             "/* INSERT_EXACT_PRODUCTION_WRAPPER */"),
            ("NV_STATUS nvUvmInterfaceFreeDupedHandle(",
             "EXPORT_SYMBOL(nvUvmInterfaceFreeDupedHandle);",
             "/* INSERT_EXACT_PRODUCTION_FREE_WRAPPER */"),
        )

        fixture = FIXTURE.read_text()
        generated = fixture
        for start_marker, end_marker, insertion in wrappers:
            self.assertEqual(bridge.count(start_marker), 1)
            wrapper = bridge.split(start_marker, 1)[1].split(end_marker, 1)[0]
            wrapper = start_marker + wrapper
            self.assertEqual(generated.count(insertion), 1)
            generated = generated.replace(insertion, wrapper)

        with tempfile.TemporaryDirectory(prefix="r595-external-map-source-") as patch_dir:
            callsite = _patched_r595_callsite(Path(patch_dir))
            source_statements = (
                ("status = uvm_rm_locked_call(nvUvmInterfaceDupMemoryWithControlFd(",
                 "/* INSERT_EXACT_R595_EXTERNAL_MAP_CALL */"),
                ("status = uvm_rm_locked_call(nvUvmInterfaceFreeDupedHandle(",
                 "/* INSERT_EXACT_R595_FREE_DUPED_HANDLE_CALL */"),
            )
            for marker, insertion in source_statements:
                self.assertEqual(generated.count(insertion), 1)
                generated = generated.replace(
                    insertion, _extract_source_statement(callsite, marker))

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "duplicate_memory_bridge_test.c"
            binary = Path(directory) / "duplicate_memory_bridge_test"
            source.write_text(generated)
            build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined", "-fno-sanitize-recover=all",
                 "-I", str(ROOT / "src"), str(source), "-o", str(binary)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("R595 external-map duplicate/free composition passed", run.stdout)


if __name__ == "__main__":
    unittest.main()
