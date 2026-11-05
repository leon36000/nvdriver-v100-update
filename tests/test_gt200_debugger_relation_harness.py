"""Exercise the observer's actual debugger relation helper without a GPU."""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
R580_SOURCE = ROOT / (
    "build/experiments/openrm580-baseline-v1/"
    "NVIDIA-kernel-module-source-580.178.04")
INCLUDE_DIRS = (
    "src/common/sdk/nvidia/inc",
    "src/common/inc",
    "src/nvidia/arch/nvalloc/unix/include",
    "kernel-open/common/inc",
    "kernel-open/nvidia-uvm",
)


class GT200DebuggerRelationHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="gt200-debugger-relation-")
        cls.binary = Path(cls.tmp.name) / "relation-harness"
        fixture = ROOT / "tests/fixtures/gt200_debugger_relation_test.c"
        command = [
            "cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DNVRM=1",
            *["-I" + str(R580_SOURCE / path) for path in INCLUDE_DIRS],
            str(fixture), "-pthread", "-o", str(cls.binary),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            cls.tmp.cleanup()
            raise AssertionError(result.stderr or result.stdout)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_relation_uses_root_and_preserves_historical_equality_semantics(self):
        result = subprocess.run([str(self.binary)], capture_output=True, text=True,
                                timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertEqual(result.stdout.strip(),
                         "root-scoped-live-allocation-handle-relation-and-exception-mask-pass")


if __name__ == "__main__":
    unittest.main()
