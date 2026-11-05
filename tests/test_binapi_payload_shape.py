import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BinapiPayloadShapeTests(unittest.TestCase):
    def test_masks_only_nonzero_slots_and_changed_byte_positions(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binapi-payload-shape-test"
            result = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 str(ROOT / "tests/fixtures/binapi_payload_shape_test.c"),
                 "-o", str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True,
                                    timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
