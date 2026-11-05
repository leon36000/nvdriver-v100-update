#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the exact GitLab transfer tree receipt."""

from __future__ import annotations

import json
import gzip
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.verify_transfer_manifest import (
    create_manifest,
    verify_manifest,
    write_manifest,
)


class TransferManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hybrid-transfer-manifest-")
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "core.filemode", "true"],
                       check=True)
        (self.root / "src").mkdir()
        (self.root / "src" / "module.c").write_text("int driver_probe(void) { return 0; }\n")
        executable = self.root / "tools" / "probe.sh"
        executable.parent.mkdir()
        executable.write_text("#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        subprocess.run(["git", "-C", str(self.root), "add", "src/module.c", "tools/probe.sh"],
                       check=True)
        self.manifest = "evidence/transfer-tree.json.gz"

    def tearDown(self):
        self.temp.cleanup()

    def test_manifest_round_trip_binds_paths_hashes_and_executable_mode(self):
        document = write_manifest(self.root, self.manifest)
        subprocess.run(["git", "-C", str(self.root), "add", self.manifest], check=True)

        result = verify_manifest(self.root, self.manifest)
        self.assertEqual(document["file_count"], 2)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["files_verified"], 2)
        with gzip.open(self.root / self.manifest, "rt", encoding="utf-8") as stream:
            document_on_disk = json.load(stream)
        self.assertEqual(document_on_disk["schema"],
                         "nvidia-hybrid-git-transfer-manifest-v1")
        records = {entry["path"]: entry for entry in document["files"]}
        self.assertEqual(records["tools/probe.sh"]["mode"], "100755")

    def test_content_mutation_fails_hash_verification(self):
        write_manifest(self.root, self.manifest)
        subprocess.run(["git", "-C", str(self.root), "add", self.manifest], check=True)
        (self.root / "src" / "module.c").write_text("int driver_probe(void) { return 1; }\n")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            verify_manifest(self.root, self.manifest)

    def test_new_index_path_fails_exact_path_set_check(self):
        write_manifest(self.root, self.manifest)
        subprocess.run(["git", "-C", str(self.root), "add", self.manifest], check=True)
        (self.root / "unexpected.txt").write_text("extra\n")
        subprocess.run(["git", "-C", str(self.root), "add", "unexpected.txt"], check=True)
        with self.assertRaisesRegex(ValueError, "path set differs"):
            verify_manifest(self.root, self.manifest)

    def test_working_tree_verification_does_not_need_index_access(self):
        write_manifest(self.root, self.manifest)
        os.chmod(self.root / "tools" / "probe.sh", 0o755)
        result = verify_manifest(self.root, self.manifest, working_tree=True)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["files_verified"], 2)


if __name__ == "__main__":
    unittest.main()
