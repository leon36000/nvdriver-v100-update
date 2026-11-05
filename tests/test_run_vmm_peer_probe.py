# SPDX-License-Identifier: MIT
"""CPU-only safety tests for the VMM peer hardware-runner preflight."""

from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch
import subprocess
import json
import sys

from tools.run_vmm_peer_probe import (clean_probe_environment, decode_captured_output,
                                      load_build_manifest, normalize_pci, parse_expected,
                                      query_idle_pair, sha256, write_exclusive)


class VmmPeerRunnerTests(unittest.TestCase):
    def setUp(self):
        self.expected = {70: "0000:01:00.0", 120: "0000:02:00.0"}

    def test_normalizes_nvidia_smi_domain_and_short_pci_forms(self):
        self.assertEqual(normalize_pci("00000000:01:00.0"), "0000:01:00.0")
        self.assertEqual(normalize_pci("02:00.0"), "0000:02:00.0")

    def test_probe_environment_removes_dynamic_loader_overrides(self):
        env = clean_probe_environment({"PATH": "/bin", "CUDA_VISIBLE_DEVICES": "0,1",
                                       "LD_PRELOAD": "/tmp/inject.so",
                                       "LD_LIBRARY_PATH": "/tmp/cuda",
                                       "LD_AUDIT": "/tmp/audit.so"})
        self.assertEqual(env, {"PATH": "/bin", "CUDA_VISIBLE_DEVICES": "0,1"})

    def test_timeout_capture_decoder_accepts_text_and_bytes(self):
        self.assertEqual(decode_captured_output("timeout text"), "timeout text")
        self.assertEqual(decode_captured_output(b"timeout bytes"), "timeout bytes")
        self.assertEqual(decode_captured_output(None), "")

    def test_parses_exact_pair_and_rejects_duplicate_architecture(self):
        self.assertEqual(parse_expected(["70=01:00.0", "120=02:00.0"]), self.expected)
        with self.assertRaisesRegex(ValueError, "one exact PCI identity"):
            parse_expected(["70=01:00.0", "70=02:00.0"])

    @patch("tools.run_vmm_peer_probe.subprocess.run")
    def test_allows_idle_exact_devices(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0,
                "00000000:01:00.0, GPU-aa, NVIDIA Tesla V100, 16, 32768\n"
                "00000000:02:00.0, GPU-bb, NVIDIA RTX 5080, 0, 16384\n", ""),
            subprocess.CompletedProcess([], 0, "No running processes found\n", ""),
        ]
        inventory, active = query_idle_pair(self.expected)
        self.assertEqual(active, [])
        self.assertEqual([row["pci_bus_id"] for row in inventory], list(self.expected.values()))
        self.assertEqual([row["name"] for row in inventory],
                         ["NVIDIA Tesla V100", "NVIDIA RTX 5080"])

    @patch("tools.run_vmm_peer_probe.subprocess.run")
    def test_refuses_active_compute_process_on_target(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0,
                "00000000:01:00.0, GPU-aa, NVIDIA Tesla V100, 16, 32768\n"
                "00000000:02:00.0, GPU-bb, NVIDIA RTX 5080, 0, 16384\n", ""),
            subprocess.CompletedProcess([], 0, "GPU-bb, 4242\n", ""),
        ]
        with self.assertRaisesRegex(RuntimeError, "compute process is active"):
            query_idle_pair(self.expected)

    @patch("tools.run_vmm_peer_probe.subprocess.run")
    def test_refuses_wrong_gpu_model_at_expected_pci_identity(self, run):
        run.return_value = subprocess.CompletedProcess([], 0,
            "00000000:01:00.0, GPU-aa, NVIDIA Tesla V100, 16, 32768\n"
            "00000000:02:00.0, GPU-bb, NVIDIA RTX 5090, 0, 16384\n", "")
        with self.assertRaisesRegex(RuntimeError, "expected RTX 5080"):
            query_idle_pair(self.expected)
        run.assert_called_once()

    def test_build_manifest_and_binary_must_match_independent_hash_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = root / "hybrid_cuda_vmm_peer_probe"
            module = root / "hybrid_probe.sm70-sm120.fatbin"
            manifest_path = root / "build-manifest.json"
            probe.write_bytes(b"pinned-probe")
            module.write_bytes(b"pinned-sm70-sm120-fatbin")
            manifest = {
                "schema": "nvidia-hybrid-vmm-peer-probe-build-v1",
                "mode": "explicit-vmm-access-no-cuCtxEnablePeerAccess",
                "binary": {"path": str(probe), "sha256": sha256(probe)},
                "fatbin": {"path": str(module), "sha256": sha256(module)},
                "links_libcuda_directly": False,
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with patch("tools.run_vmm_peer_probe.PROBE_SHA256", sha256(probe)), \
                    patch("tools.run_vmm_peer_probe.BUILD_MANIFEST_SHA256",
                          sha256(manifest_path)), \
                    patch("tools.run_vmm_peer_probe.FATBIN_SHA256", sha256(module)):
                self.assertEqual(load_build_manifest(probe, module), manifest)

    def test_rejects_replaced_probe_even_if_adjacent_manifest_is_edited(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = root / "hybrid_cuda_vmm_peer_probe"
            module = root / "hybrid_probe.sm70-sm120.fatbin"
            manifest_path = root / "build-manifest.json"
            probe.write_bytes(b"replacement-probe")
            module.write_bytes(b"pinned-sm70-sm120-fatbin")
            manifest_path.write_text("{}", encoding="utf-8")
            with patch("tools.run_vmm_peer_probe.PROBE_SHA256", "a" * 64), \
                    patch("tools.run_vmm_peer_probe.BUILD_MANIFEST_SHA256",
                          sha256(manifest_path)):
                with self.assertRaisesRegex(RuntimeError, "binary differs from its pinned"):
                    load_build_manifest(probe, module)

    def test_rejects_altered_build_manifest_before_parsing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = root / "hybrid_cuda_vmm_peer_probe"
            module = root / "hybrid_probe.sm70-sm120.fatbin"
            manifest_path = root / "build-manifest.json"
            probe.write_bytes(b"pinned-probe")
            module.write_bytes(b"pinned-sm70-sm120-fatbin")
            manifest_path.write_text("not-json", encoding="utf-8")
            with patch("tools.run_vmm_peer_probe.PROBE_SHA256", sha256(probe)), \
                    patch("tools.run_vmm_peer_probe.BUILD_MANIFEST_SHA256", "b" * 64):
                with self.assertRaisesRegex(RuntimeError, "manifest differs from its pinned"):
                    load_build_manifest(probe, module)

    def test_evidence_creation_never_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            write_exclusive(path, {"state": "first"})
            with self.assertRaises(FileExistsError):
                write_exclusive(path, {"state": "second"})
            self.assertEqual(json.loads(path.read_text()), {"state": "first"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW is required")
    def test_evidence_creation_refuses_symlink_leaf(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            target = Path(directory) / "target.json"
            target.write_text("preserve")
            path.symlink_to(target)
            with self.assertRaises(OSError):
                write_exclusive(path, {"state": "replacement"})
            self.assertTrue(path.is_symlink())
            self.assertEqual(target.read_text(), "preserve")

    def test_hash_refuses_symlink_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "regular.bin"
            link = root / "linked.bin"
            target.write_bytes(b"pinned data")
            link.symlink_to(target)
            with self.assertRaises(OSError):
                sha256(link)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is required")
    def test_hash_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "probe"
            os.mkfifo(fifo)
            completed = subprocess.run(
                [sys.executable, "-B", "-c",
                 "from pathlib import Path; from tools.run_vmm_peer_probe import sha256; sha256(Path(__import__('sys').argv[1]))",
                 str(fifo)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, check=False, timeout=2,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("expected a regular file while hashing", completed.stderr)


if __name__ == "__main__":
    unittest.main()
