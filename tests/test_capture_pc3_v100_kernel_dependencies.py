#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU-only contracts for the read-only PC3 kernel support-module capture."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/capture_pc3_v100_kernel_dependencies.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("pc3_kernel_dependencies", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(kind, name, path, payload, depends=None):
    result = {
        "kind": kind,
        "name": name,
        "path": path,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "data_base64": base64.b64encode(payload).decode("ascii"),
    }
    if kind == "module":
        result["depends"] = depends or []
    return result


def valid_capture():
    release = "6.8.0-147-generic"
    module_root = f"/lib/modules/{release}"
    files = [
        record("module", "ecc", "kernel/crypto/ecc.ko.zst", b"ecc-zst"),
        record("module", "ecdh_generic", "kernel/crypto/ecdh_generic.ko.zst",
               b"ecdh-zst", ["ecc"]),
        record("module", "ecdsa_generic", "kernel/crypto/ecdsa_generic.ko.zst",
               b"ecdsa-zst", ["ecc"]),
    ]
    files.extend(record("metadata", name, name, f"{name}\n".encode()) for name in (
        "modules.builtin", "modules.builtin.modinfo", "modules.dep",
        "modules.order", "modules.softdep"))
    return {
        "schema": "pc3-v100-kernel-dependency-payload-v1",
        "hostname": "pc3-v100",
        "kernel_release": release,
        "module_root": module_root,
        "roots": ["ecc", "ecdh_generic", "ecdsa_generic"],
        "missing": [],
        "files": files,
    }


class GuestPayloadValidation(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool()

    def validate(self, payload):
        return self.tool.validate_guest_capture(
            json.dumps(payload, separators=(",", ":")).encode())

    def test_accepts_exact_guest_modules_and_kernel_metadata(self):
        result = self.validate(valid_capture())

        self.assertEqual(result["hostname"], "pc3-v100")
        self.assertEqual(result["kernel_release"], "6.8.0-147-generic")
        self.assertEqual([item["name"] for item in result["modules"]],
                         ["ecc", "ecdh_generic", "ecdsa_generic"])
        self.assertEqual(result["modules"][1]["depends"], ["ecc"])
        self.assertEqual(set(result["metadata"]), {
            "modules.builtin", "modules.builtin.modinfo", "modules.dep",
            "modules.order", "modules.softdep"})
        self.assertEqual(result["modules"][0]["data"], b"ecc-zst")

    def test_rejects_wrong_guest_or_kernel(self):
        payload = valid_capture()
        payload["hostname"] = "pc3-host"
        with self.assertRaisesRegex(ValueError, "guest identity"):
            self.validate(payload)

        payload = valid_capture()
        payload["kernel_release"] = "7.0.0-38-generic"
        with self.assertRaisesRegex(ValueError, "kernel release"):
            self.validate(payload)

    def test_rejects_missing_or_unexpected_module_and_metadata(self):
        payload = valid_capture()
        payload["files"] = [x for x in payload["files"] if x.get("name") != "ecc"]
        with self.assertRaisesRegex(ValueError, "module set"):
            self.validate(payload)

        payload = valid_capture()
        payload["files"].append(record(
            "module", "other", "kernel/crypto/other.ko", b"other"))
        with self.assertRaisesRegex(ValueError, "module set"):
            self.validate(payload)

        payload = valid_capture()
        payload["files"] = [x for x in payload["files"] if x.get("name") != "modules.softdep"]
        with self.assertRaisesRegex(ValueError, "metadata set"):
            self.validate(payload)

    def test_rejects_path_escape_and_wrong_tree_location(self):
        payload = valid_capture()
        payload["files"][0]["path"] = "../../tmp/ecc.ko"
        with self.assertRaisesRegex(ValueError, "module path"):
            self.validate(payload)

        payload = valid_capture()
        payload["files"][0]["path"] = "updates/ecc.ko"
        with self.assertRaisesRegex(ValueError, "module path"):
            self.validate(payload)

    def test_rejects_corrupt_file_bytes_and_hashes(self):
        payload = valid_capture()
        payload["files"][0]["data_base64"] = base64.b64encode(b"tampered").decode()
        with self.assertRaisesRegex(ValueError, "module file identity"):
            self.validate(payload)

        payload = valid_capture()
        payload["files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "module file identity"):
            self.validate(payload)

    def test_rejects_unexpected_hard_dependency_edges(self):
        payload = valid_capture()
        payload["files"][1]["depends"] = []
        with self.assertRaisesRegex(ValueError, "dependency graph"):
            self.validate(payload)

    def test_rejects_malformed_or_duplicate_capture_records(self):
        payload = valid_capture()
        payload["files"][0]["bytes"] += 1
        with self.assertRaisesRegex(ValueError, "module file identity"):
            self.validate(payload)

        payload = valid_capture()
        payload["files"].append(payload["files"][0].copy())
        with self.assertRaisesRegex(ValueError, "duplicate capture path"):
            self.validate(payload)


if __name__ == "__main__":
    unittest.main()
