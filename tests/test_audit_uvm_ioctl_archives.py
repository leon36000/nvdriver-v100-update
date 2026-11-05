#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for archive-pinned UVM route comparisons."""

from io import BytesIO
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_uvm_ioctl_archives import (  # noqa: E402
    DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
    RELEASES,
    audit_legacy_system_wide_atomics_api,
    compare_pinned_archives,
    extract_uvm_archive_sources,
)
from tools.audit_r595_uvm_hal_table_closure import (  # noqa: E402
    REQUIRED_GV100_TABLE_TARGETS,
)


def _archive(path: Path, members: list[tuple[str, bytes, bytes | None]]) -> None:
    with tarfile.open(path, "w:gz") as output:
        for name, data, linkname in members:
            info = tarfile.TarInfo(name)
            if linkname is None:
                info.size = len(data)
                output.addfile(info, BytesIO(data))
            else:
                info.type = tarfile.SYMTYPE
                info.linkname = linkname
                output.addfile(info)


class AuditUvmIoctlArchivesTests(unittest.TestCase):
    def _complete_members(self):
        prefix = "open-gpu-kernel-modules/kernel-open/nvidia-uvm/"
        return [
            (prefix + "uvm.c",
             b"UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_ONE, handler_one);\n", None),
            (prefix + "uvm_hal.c", b"static const char fixture[] = \"u\";\n", None),
            (prefix + "uvm_ioctl.h", b"#define UVM_ONE UVM_IOCTL_BASE(1)\n", None),
            (prefix + "uvm_linux_ioctl.h", b"", None),
            (prefix + "uvm_api.h", b"", None),
            (prefix + "uvm_policy.c", b"", None),
        ]

    def test_reads_only_required_regular_members_without_archive_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.tar.gz"
            members = self._complete_members()
            _archive(path, members)
            sources, provenance = extract_uvm_archive_sources(path)
        self.assertEqual(set(sources), {
            "uvm.c", "uvm_hal.c", "uvm_ioctl.h", "uvm_linux_ioctl.h",
            "uvm_api.h", "uvm_policy.c",
        })
        self.assertEqual(sources["uvm.c"], members[0][1])
        self.assertTrue(provenance["archive_sha256"])
        self.assertEqual(provenance["uvm.c_member"], members[0][0])

    def test_checks_expected_archive_digest_before_parsing_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "wrong-digest.tar.gz"
            path.write_bytes(b"not a compressed tar archive")
            with self.assertRaisesRegex(ValueError, "does not match its pin"):
                extract_uvm_archive_sources(path, expected_sha256="0" * 64)

    def test_rejects_path_traversal_even_when_target_suffix_matches(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "unsafe.tar.gz"
            members = self._complete_members()
            members[0] = ("../" + members[0][0], members[0][1], None)
            _archive(path, members)
            with self.assertRaisesRegex(ValueError, "unsafe path"):
                extract_uvm_archive_sources(path)

    def test_rejects_duplicate_target_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.tar.gz"
            members = self._complete_members()
            members.append(members[0])
            _archive(path, members)
            with self.assertRaisesRegex(ValueError, "duplicate uvm.c"):
                extract_uvm_archive_sources(path)

    def test_rejects_target_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "symlink.tar.gz"
            members = self._complete_members()
            members[0] = (members[0][0], b"", "elsewhere")
            _archive(path, members)
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                extract_uvm_archive_sources(path)

    def test_legacy_atomic_policy_audit_requires_old_api_and_rejects_modern_route(self):
        from tools.audit_uvm_ioctl_archives import LEGACY_SYSTEM_WIDE_ATOMICS

        old_sources = {
            "uvm_api.h": b"uvm_api_enable_system_wide_atomics uvm_api_disable_system_wide_atomics",
            "uvm_policy.c": b"uvm_api_enable_system_wide_atomics uvm_api_disable_system_wide_atomics system_wide_atomics_set scoped_atomics_supported",
        }
        old_surface = {
            "ioctl_definitions": {name: "defined" for name in LEGACY_SYSTEM_WIDE_ATOMICS},
            "routes": dict(LEGACY_SYSTEM_WIDE_ATOMICS),
        }
        modern_sources = {
            "R595.112.07": {"uvm.c": b"", "uvm_ioctl.h": b""},
            "R615.78.08": {"uvm.c": b"", "uvm_ioctl.h": b""},
        }
        modern_surfaces = {
            release: {"ioctl_definitions": {}, "routes": {}}
            for release in modern_sources
        }

        report = audit_legacy_system_wide_atomics_api(
            old_sources, old_surface, modern_sources, modern_surfaces
        )
        self.assertEqual(report["disposition"], "legacy-system-wide-atomics-uapi-removed")
        self.assertTrue(report["baseline"]["scoped_atomics_guard_present"])

        modern_surfaces["R595.112.07"]["routes"]["UVM_ENABLE_SYSTEM_WIDE_ATOMICS"] = "handler"
        with self.assertRaisesRegex(ValueError, "survived in R595.112.07"):
            audit_legacy_system_wide_atomics_api(
                old_sources, old_surface, modern_sources, modern_surfaces
            )

    def test_current_pinned_archives_have_closed_full_source_route_diff(self):
        self.assertEqual(set(RELEASES), {"R595.112.07", "R615.78.08"})
        report = compare_pinned_archives()
        comparison = report["comparison"]
        self.assertEqual(report["schema"], "nvidia-uvm-archive-compatibility-audit-v2")
        self.assertEqual(comparison["baseline"]["route_count"], 39)
        self.assertEqual(comparison["candidate"]["route_count"], 38)
        self.assertEqual(comparison["baseline"]["all_route_count"], 43)
        self.assertEqual(comparison["candidate"]["all_route_count"], 42)
        self.assertEqual(comparison["baseline"]["ioctl_definition_count"], 68)
        self.assertEqual(comparison["candidate"]["ioctl_definition_count"], 67)
        self.assertEqual(comparison["baseline"]["all_ioctl_definition_count"], 70)
        self.assertEqual(comparison["candidate"]["all_ioctl_definition_count"], 69)
        self.assertEqual(comparison["baseline"]["route_definition_closure"], "closed")
        self.assertEqual(comparison["candidate"]["route_definition_closure"], "closed")
        self.assertEqual(len(comparison["removed_dispatch_routes"]), 6)
        self.assertEqual(len(comparison["added_dispatch_routes"]), 5)
        self.assertFalse(report["runtime_compatibility_proven"])
        self.assertFalse(report["hardware_tested"])
        atomic_api = report["legacy_system_wide_atomics_api"]
        self.assertEqual(atomic_api["disposition"], "legacy-system-wide-atomics-uapi-removed")
        self.assertTrue(atomic_api["baseline"]["scoped_atomics_guard_present"])
        for release in ("R595.112.07", "R615.78.08"):
            for operation in atomic_api["baseline"]["operations"].values():
                self.assertFalse(operation["modern_branches"][release]["ioctl_definition_present"])
                self.assertFalse(operation["modern_branches"][release]["dispatch_route_present"])
        self.assertEqual(
            report["r580_volta_reference"]["archive_sha256"],
            DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
        )
        for branch in ("R595.112.07", "R615.78.08"):
            hal = report["volta_hal_dispatch_comparisons"][branch]
            self.assertTrue(hal["r580_all_required_targets_present"])
            self.assertEqual(hal["modern_missing_targets"], REQUIRED_GV100_TABLE_TARGETS)
            self.assertFalse(hal["modern_static_dispatch_candidate"])
            for selector in hal["modern_selector_contract"].values():
                self.assertEqual(selector["missing_class_status"], "NV_ERR_INVALID_CLASS")
                self.assertTrue(selector["null_checked_before_install"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
