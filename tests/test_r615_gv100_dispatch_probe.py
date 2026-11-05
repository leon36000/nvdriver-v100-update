# SPDX-License-Identifier: MIT
"""Tests for the pinned, source-only R615 GV100 dispatch compile probe."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import tools.probe_r615_gv100_dispatch as report_writer  # noqa: E402
from tools.probe_r615_gv100_dispatch import (  # noqa: E402
    R615_KERNEL_OPEN_PREFIX,
    create_verified_r615_snapshot,
    make_probe_report,
    summarize_build_output,
    validate_report_path,
    validate_r615_source,
    validate_scratch_path,
    write_private_evidence_report,
    write_private_report,
)


def _tree_manifest(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        name = path.relative_to(directory).as_posix()
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _make_r615_fixture(tmp: Path) -> tuple[Path, Path, str, str]:
    archive = tmp / "615-source.tar"
    kernel_open = tmp / "kernel-open"
    (kernel_open / "nvidia-uvm").mkdir(parents=True)
    (kernel_open / "Kbuild").write_text("fixture build manifest\n")
    (kernel_open / "nvidia-uvm" / "uvm_hal.c").write_text("fixture HAL\n")
    with tarfile.open(archive, "w") as output:
        output.add(kernel_open, arcname=R615_KERNEL_OPEN_PREFIX)
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    return archive, kernel_open, archive_hash, _tree_manifest(kernel_open)


class R615DispatchProbeTests(unittest.TestCase):
    def test_summarizes_compiler_warnings_separately_from_errors(self):
        result = summarize_build_output(
            "nvidia-uvm/x.c:1: warning: first\n"
            "objtool: warning: second\n"
            "nvidia-uvm/y.c:2: error: stop\n"
        )

        self.assertEqual(result["warning_line_count"], 2)
        self.assertEqual(result["compiler_error_line_count"], 1)

    def test_accepts_exact_archive_subtree_and_returns_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, kernel_open, archive_hash, manifest = _make_r615_fixture(
                Path(directory)
            )

            result = validate_r615_source(
                archive,
                kernel_open,
                expected_archive_sha256=archive_hash,
                expected_manifest_sha256=manifest,
                expected_file_count=2,
            )

        self.assertTrue(result["provenance_valid"])
        self.assertEqual(result["archive_sha256"], archive_hash)
        self.assertEqual(result["archive_manifest_sha256"], manifest)
        self.assertEqual(result["archive_subtree_prefix"], R615_KERNEL_OPEN_PREFIX)

    def test_rejects_archive_not_matching_the_pinned_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, kernel_open, _, manifest = _make_r615_fixture(Path(directory))

            with self.assertRaisesRegex(ValueError, "archive SHA-256 mismatch"):
                validate_r615_source(
                    archive,
                    kernel_open,
                    expected_archive_sha256="0" * 64,
                    expected_manifest_sha256=manifest,
                    expected_file_count=2,
                )

    def test_rejects_extracted_tree_with_changed_or_extra_source(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, kernel_open, archive_hash, manifest = _make_r615_fixture(
                Path(directory)
            )
            (kernel_open / "nvidia-uvm" / "uvm_hal.c").write_text("altered\n")

            with self.assertRaisesRegex(ValueError, "provenance"):
                validate_r615_source(
                    archive,
                    kernel_open,
                    expected_archive_sha256=archive_hash,
                    expected_manifest_sha256=manifest,
                    expected_file_count=2,
                )

    def test_scratch_must_be_fresh_and_inside_experiment_root(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            experiment_root = repository / "build" / "experiments"
            experiment_root.mkdir(parents=True)
            candidate = experiment_root / "r615-probe"

            self.assertEqual(
                validate_scratch_path(candidate, repository), candidate.resolve()
            )
            with self.assertRaisesRegex(ValueError, "inside"):
                validate_scratch_path(repository / "outside", repository)
            candidate.mkdir()
            with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
                validate_scratch_path(candidate, repository)

    def test_scratch_rejects_symlinked_experiment_root_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo"
            experiment_root = repository / "build" / "experiments"
            experiment_root.mkdir(parents=True)
            outside = Path(directory) / "outside"
            outside.mkdir()
            experiment_root.rmdir()
            experiment_root.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "symlink"):
                validate_scratch_path(experiment_root / "probe", repository)

    def test_scratch_rejects_symlinked_build_parent_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repo"
            repository.mkdir()
            outside = root / "outside-build"
            (outside / "experiments").mkdir(parents=True)
            (repository / "build").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "symlink"):
                validate_scratch_path(
                    repository / "build" / "experiments" / "probe", repository
                )

    def test_report_uses_exact_r615_label_and_does_not_retain_legacy_source_key(self):
        report = make_probe_report(
            source_provenance={
                "provenance_valid": True,
                "archive_sha256": "1" * 64,
                "archive_manifest_sha256": "2" * 64,
                "extracted_manifest_sha256": "2" * 64,
                "extracted_file_count": 457,
                "archive_file_count": 457,
            },
            scratch=Path("/tmp/scratch"),
            overlay={
                "r580_archive_sha256": "3" * 64,
                "r595_source": "/exact/r615/kernel-open",
                "compile_probe_only": True,
            },
            dispatch_audit={"modern_static_dispatch_candidate": True},
            build={"module_linked_this_run": True},
            prepared_source_manifest={"manifest_sha256": "4" * 64, "file_count": 461},
            implementation_sha256={"tools/probe_r615_gv100_dispatch.py": "5" * 64},
        )

        self.assertEqual(report["base_release"], "NVIDIA Open R615.71.10")
        self.assertEqual(report["schema"], "r615-r580-gv100-dispatch-compile-probe-v2")
        self.assertEqual(report["modern_source_root"], "/exact/r615/kernel-open")
        self.assertEqual(report["r615_verified_snapshot_manifest_sha256"], "2" * 64)
        self.assertEqual(report["prepared_source_tree"]["manifest_sha256"], "4" * 64)
        self.assertEqual(report["implementation_sha256"]["tools/probe_r615_gv100_dispatch.py"], "5" * 64)
        self.assertNotIn("r595_source", report)
        self.assertFalse(report["runtime_or_hardware_validated"])
        self.assertFalse(report["loaded_or_installed"])

    def test_snapshot_is_copied_then_validated_against_the_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, source, archive_hash, manifest = _make_r615_fixture(root)
            destination = root / "private-snapshot" / "kernel-open"
            destination.parent.mkdir()

            provenance = create_verified_r615_snapshot(
                archive,
                source,
                destination,
                expected_archive_sha256=archive_hash,
                expected_manifest_sha256=manifest,
                expected_file_count=2,
            )

            self.assertEqual(provenance["archive_manifest_sha256"], manifest)
            self.assertEqual(provenance["extracted_manifest_sha256"], manifest)
            self.assertEqual(provenance["archive_file_count"], 2)

    def test_snapshot_rejects_changed_source_and_removes_unverified_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, source, archive_hash, manifest = _make_r615_fixture(root)
            (source / "Kbuild").write_text("changed after initial inspection\n")
            destination = root / "private-snapshot" / "kernel-open"
            destination.parent.mkdir()

            with self.assertRaisesRegex(ValueError, "provenance"):
                create_verified_r615_snapshot(
                    archive,
                    source,
                    destination,
                    expected_archive_sha256=archive_hash,
                    expected_manifest_sha256=manifest,
                    expected_file_count=2,
                )

            self.assertFalse(destination.exists())

    def test_report_path_is_confined_to_repository_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repo"
            evidence = repository / "evidence"
            evidence.mkdir(parents=True)

            self.assertEqual(
                validate_report_path(Path("evidence/result.json"), repository),
                evidence / "result.json",
            )
            with self.assertRaisesRegex(ValueError, "inside repository evidence"):
                validate_report_path(Path("/tmp/outside.json"), repository)

    def test_private_report_rejects_symlink_without_truncating_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text("preserve me\n")
            link = root / "report.json"
            link.symlink_to(target)

            with self.assertRaises(OSError):
                write_private_report(link, {"ok": True})

            self.assertEqual(target.read_text(), "preserve me\n")

    def test_private_report_rejects_parent_symlink_without_external_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = root / "external"
            external.mkdir()
            alias = root / "alias"
            alias.symlink_to(external, target_is_directory=True)

            with self.assertRaises(OSError):
                write_private_report(alias / "report.json", {"ok": True})

            self.assertFalse((external / "report.json").exists())

    def test_private_report_collision_is_refused_without_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            report_path.write_text("preserve existing evidence\n")

            with self.assertRaises(FileExistsError):
                write_private_report(report_path, {"ok": True})

            self.assertEqual(report_path.read_text(), "preserve existing evidence\n")

    def test_private_report_is_mode_six_hundred_and_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            write_private_report(report_path, {"status": "compile-only"})

            self.assertEqual(os.stat(report_path).st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(report_path.read_text()), {"status": "compile-only"})

    def test_confined_writer_keeps_the_validated_parent_directory_fd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            evidence = root / "evidence"
            nested = evidence / "nested"
            nested.mkdir(parents=True)
            external = Path(directory) / "external"
            external.mkdir()
            report_path = Path("evidence/nested/report.json")
            original_write = report_writer._write_private_report_at

            def replace_named_parent_after_open(parent_fd, name, report):
                nested.rename(evidence / "nested-held")
                nested.symlink_to(external, target_is_directory=True)
                return original_write(parent_fd, name, report)

            with mock.patch.object(
                report_writer,
                "_write_private_report_at",
                side_effect=replace_named_parent_after_open,
            ):
                written_path = write_private_evidence_report(
                    report_path, {"status": "anchored"}, root
                )

            self.assertEqual(written_path, evidence / "nested" / "report.json")
            self.assertTrue((evidence / "nested-held" / "report.json").is_file())
            self.assertFalse((external / "report.json").exists())
            self.assertEqual(
                json.loads((evidence / "nested-held" / "report.json").read_text()),
                {"status": "anchored"},
            )

    def test_confined_writer_rejects_paths_outside_evidence_and_symlink_parents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            evidence = root / "evidence"
            evidence.mkdir(parents=True)
            external = Path(directory) / "external"
            external.mkdir()

            with self.assertRaisesRegex(ValueError, "inside repository evidence"):
                write_private_evidence_report(
                    Path("../outside/report.json"), {"ok": True}, root
                )

            alias = evidence / "alias"
            alias.symlink_to(external, target_is_directory=True)
            with self.assertRaises(OSError):
                write_private_evidence_report(
                    Path("evidence/alias/report.json"), {"ok": True}, root
                )
            self.assertFalse((external / "report.json").exists())


if __name__ == "__main__":
    unittest.main()
