# SPDX-License-Identifier: MIT
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import run_software_test_suite as suite
from run_hybrid_acceptance import (PINNED_MODULE_SHA256 as ACCEPTANCE_MODULE_SHA256,
                                   PINNED_PROBE_SHA256 as ACCEPTANCE_PROBE_SHA256)


class SoftwareSuiteBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="software-suite-bundle-")
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name) / "bundle"
        self.bundle.mkdir()
        self.probe = self.bundle / "hybrid_cuda_probe"
        self.probe.write_bytes(b"pinned probe fixture")
        self.probe_sha256 = hashlib.sha256(self.probe.read_bytes()).hexdigest()
        self.module = self.bundle / suite.PROBE_FATBIN.name
        self.module.write_bytes(b"pinned fatbin fixture")
        self.module_sha256 = hashlib.sha256(self.module.read_bytes()).hexdigest()
        self.manifest_path = self.bundle / "build-manifest.json"
        self.host_source = (suite.ROOT / "src/hybrid_cuda_probe.cpp").resolve()
        self.kernel_source = (suite.ROOT / "kernels/hybrid_probe.cu").resolve()
        self.builder = suite.ROOT / "tools/build_probe_cuda129.py"
        self.source_hashes = {
            str(self.host_source): hashlib.sha256(self.host_source.read_bytes()).hexdigest(),
            str(self.kernel_source): hashlib.sha256(self.kernel_source.read_bytes()).hexdigest(),
        }
        self.manifest = {
            "schema": "nvidia-hybrid-probe-build-v2",
            "probe": {"path": str(self.probe.resolve()), "sha256": self.probe_sha256},
            "fatbin": {"path": str(self.module.resolve()), "sha256": self.module_sha256},
            "source_inputs_sha256": self.source_hashes,
            "build_tool_sha256": hashlib.sha256(self.builder.read_bytes()).hexdigest(),
            "fatbin_images": ["sm_70", "sm_120a"],
            "fatbin_image_kinds": {"sm_70": "ptx", "sm_120a": "cubin"},
        }
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def _verify_with_pinned_fixture(self, bundle):
        with patch.multiple(
            suite,
            PINNED_PROBE_SHA256=self.probe_sha256,
            PINNED_PROBE_FATBIN_SHA256=self.module_sha256,
            PINNED_HOST_SOURCE_SHA256=self.source_hashes[str(self.host_source)],
            PINNED_KERNEL_SOURCE_SHA256=self.source_hashes[str(self.kernel_source)],
        ):
            return suite._verify_probe_build(bundle)

    def test_custom_bundle_directory_selects_its_pinned_probe_and_manifest(self):
        probe_sha256, manifest_sha256, probe, manifest = self._verify_with_pinned_fixture(self.bundle)
        self.assertEqual(probe_sha256, self.probe_sha256)
        self.assertEqual(manifest_sha256, hashlib.sha256(self.manifest_path.read_bytes()).hexdigest())
        self.assertEqual(probe, self.probe)
        self.assertEqual(manifest, self.manifest_path)

    def test_custom_bundle_rejects_manifest_that_names_another_probe_path(self):
        self.manifest["probe"]["path"] = str(self.bundle / "other-probe")
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not identify the pinned probe"):
            self._verify_with_pinned_fixture(self.bundle)

    def test_custom_bundle_rejects_unpinned_fatbin_even_if_manifest_matches_it(self):
        self.module.write_bytes(b"substituted fatbin")
        self.manifest["fatbin"] = {"path": str(self.module.resolve()),
                                   "sha256": hashlib.sha256(self.module.read_bytes()).hexdigest()}
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "fatbin differs from the pinned test input"):
            self._verify_with_pinned_fixture(self.bundle)

    def test_custom_bundle_rejects_manifest_that_names_another_fatbin(self):
        self.manifest["fatbin"]["path"] = str(self.bundle / "other.fatbin")
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not identify the pinned fatbin"):
            self._verify_with_pinned_fixture(self.bundle)

    def test_private_log_writer_accepts_explicit_evidence_root(self):
        evidence = Path(self.temp.name) / "workspace" / "evidence"
        logs = evidence / "logs"
        logs.mkdir(parents=True)
        output = logs / "run.log"
        suite._write_private_raw_log(output, b"private evidence", evidence_root=evidence)
        self.assertEqual(output.read_bytes(), b"private evidence")
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)

    def test_private_log_writer_rejects_path_outside_explicit_evidence_root(self):
        evidence = Path(self.temp.name) / "workspace" / "evidence"
        evidence.mkdir(parents=True)
        outside = Path(self.temp.name) / "outside.log"
        with self.assertRaisesRegex(ValueError, "inside evidence"):
            suite._write_private_raw_log(outside, b"private evidence", evidence_root=evidence)

    def test_acceptance_and_software_suite_share_probe_and_fatbin_pins(self):
        self.assertEqual(ACCEPTANCE_PROBE_SHA256, suite.PINNED_PROBE_SHA256)
        self.assertEqual(ACCEPTANCE_MODULE_SHA256, suite.PINNED_PROBE_FATBIN_SHA256)


if __name__ == "__main__":
    unittest.main()
