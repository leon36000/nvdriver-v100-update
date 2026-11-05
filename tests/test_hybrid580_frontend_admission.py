import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class FrontendAdmissionTest(unittest.TestCase):
    def test_shared_admission_contract_compiles_and_drains(self):
        with tempfile.TemporaryDirectory(prefix="hybrid580-admission-") as directory:
            binary = Path(directory) / "admission-test"
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
                str(ROOT / "tests/fixtures/hybrid580_frontend_admission_test.c"),
                "-o", str(binary),
            ], check=True, cwd=ROOT)
            result = subprocess.run([str(binary)], check=True, capture_output=True,
                                    text=True, cwd=ROOT)
            self.assertEqual(result.stdout.strip(), "frontend admission contract passed")

    def test_frontend_routes_sleepable_and_nonblocking_entries_differently(self):
        source = (ROOT / "src/hybrid_frontend.c").read_text()
        required = (
            "wait_event_freezable(hybrid_front_admission_wait",
            "hybrid_front_admission_enter_release",
            "TASK_UNINTERRUPTIBLE | TASK_FREEZABLE",
            "hybrid_front_admission_try_enter()",
            "poll_wait(front, &hybrid_front_admission_wait, wait)",
            "hybrid_front_admission_drain",
            "hybrid_front_gpu_mmap_inner(front, vma)",
        )
        for marker in required:
            self.assertTrue(marker in source, f"missing frontend gate path: {marker}")

        fops = source.split("static const struct file_operations hybrid_front_fops = {", 1)[1]
        self.assertTrue(".open = hybrid_front_open," in fops)
        self.assertTrue(".release = hybrid_front_release," in fops)
        self.assertTrue(".unlocked_ioctl = hybrid_front_ioctl," in fops)
        self.assertTrue(".mmap = hybrid_front_gpu_mmap," in fops)
        self.assertTrue(".poll = hybrid_front_gpu_poll," in fops)


if __name__ == "__main__":
    unittest.main()
