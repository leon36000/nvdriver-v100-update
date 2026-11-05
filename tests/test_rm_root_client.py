# SPDX-License-Identifier: MIT
"""Execute only project-owned fake RM callbacks against real R580 headers."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04"


def include_flags():
    return ["-DNVRM=1", "-I" + str(ROOT / "src")] + [
        "-I" + str(SOURCE / part) for part in (
            "kernel-open/common/inc", "src/common/sdk/nvidia/inc",
            "src/common/inc", "src/common/inc/swref",
            "src/nvidia/arch/nvalloc/unix/include")]


class RootClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.executables = {}
        for session in (0, 1):
            for alloc64 in (0, 1):
                cls.compile_variant(alloc64, session)

    @classmethod
    def compile_variant(cls, alloc64, session):
        executable = Path(cls.tmp.name) / ("root-contract-" + str(alloc64) + "-" + str(session))
        cls.executables[alloc64, session] = executable
        command = ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-parameter", "-fsanitize=undefined", "-fno-sanitize-recover=all",
                   "-DFIXTURE_ALLOC64=" + str(alloc64), "-DFIXTURE_SESSION=" + str(session), *include_flags(), str(ROOT / "src/rm_root_client.c"),
                   str(ROOT / "tests/fixtures/rm_root_client_contract.c"),
                   "-o", str(executable)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            cls.tmp.cleanup()
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_session_endpoint_header_is_self_contained(self):
        source = Path(self.tmp.name) / 'standalone-session-header.c'
        source.write_text('#include "rm_session_endpoint.h"\n'
                          '_Static_assert(HYBRID_RM_SESSION_ABI_V1 == 1, "version");\n'
                          'struct hybrid_rm_session_endpoint_v1 standalone;\n')
        result = subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                 *include_flags(), '-c', str(source), '-o',
                                 str(source.with_suffix('.o'))], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_protocol_and_failure_scenarios(self):
        scenarios = (
            "success", "root-alias", "invalid-input", "alias", "first-reject", "second-reject",
            "mismatched-id", "transport-error", "ambiguous-output", "missing-status",
            "zero-id", "rollback-failure", "close-failure", "free-transport-error",
            "free-missing-status", "reentrant", "reuse")
        for (alloc64, session), executable in self.executables.items():
            variant_scenarios = scenarios + (("unsupported64",) if alloc64 else ())
            if session:
                variant_scenarios += tuple("session-invalid-" + field for field in (
                    "version", "size", "invoke", "context", "backend", "file", "alias-context", "alias-backend"))
            for scenario in variant_scenarios:
                with self.subTest(alloc64=alloc64, session=session, scenario=scenario):
                    result = subprocess.run([str(executable), scenario],
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
