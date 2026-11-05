# SPDX-License-Identifier: MIT
"""Version-pinned R580 UVM source archive root tests."""
import io
import hashlib
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.audit_r595_uvm_hal_table_closure import (  # noqa: E402
    checked_source_archive_root,
    extract_r580_uvm_c_sources,
)
from tools.probe_r595_gv100_complete_hal import read_member_from_archive  # noqa: E402
from tools.probe_r595_gv100_fault_hal import extract_archived_r580_uvm  # noqa: E402
from tools.probe_volta_uvm_port import (  # noqa: E402
    source_archive_root,
)
from tools import probe_volta_uvm_port  # noqa: E402


class R580ArchiveRootVersionTests(unittest.TestCase):
    ROOT_196 = "NVIDIA-kernel-module-source-580.196.07"
    REQUIRED_FAULT_INPUTS = (
        "kernel-open/nvidia-uvm/uvm_hal.c",
        "kernel-open/nvidia-uvm/uvm_hal.h",
        "kernel-open/nvidia-uvm/uvm_volta_fault_buffer.c",
        "kernel-open/nvidia-uvm/uvm_pascal_fault_buffer.c",
        "kernel-open/nvidia-uvm/uvm_pascal_fault_buffer.h",
        "kernel-open/nvidia-uvm/hwref/pascal/gp100/dev_fault.h",
        "kernel-open/nvidia-uvm/clb069.h",
    )

    def _archive(self, roots):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for root in roots:
                data = b"/* pinned fixture */\n"
                member = tarfile.TarInfo(
                    f"{root}/kernel-open/nvidia-uvm/uvm_volta.c")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        output.seek(0)
        return tarfile.open(fileobj=output, mode="r:")

    def test_accepts_exactly_pinned_r580_196_source_root(self):
        archive = self._archive(["NVIDIA-kernel-module-source-580.196.07"])
        try:
            self.assertEqual(
                checked_source_archive_root(
                    archive, "NVIDIA-kernel-module-source-580.196.07"),
                "NVIDIA-kernel-module-source-580.196.07")
        finally:
            archive.close()

    def test_rejects_archive_root_not_matching_requested_version(self):
        archive = self._archive(["NVIDIA-kernel-module-source-580.196.07"])
        try:
            with self.assertRaisesRegex(ValueError, "unexpected source root"):
                checked_source_archive_root(
                    archive, "NVIDIA-kernel-module-source-580.178.04")
        finally:
            archive.close()

    def test_rejects_ambiguous_archive_roots(self):
        archive = self._archive([
            "NVIDIA-kernel-module-source-580.196.07",
            "NVIDIA-kernel-module-source-580.178.04",
        ])
        try:
            with self.assertRaisesRegex(ValueError, "exactly one"):
                checked_source_archive_root(
                    archive, "NVIDIA-kernel-module-source-580.196.07")
        finally:
            archive.close()

    def test_complete_hal_source_helpers_propagate_the_exact_196_root(self):
        with tempfile.TemporaryDirectory(prefix="r580-196-root-") as temporary:
            archive_path = Path(temporary) / "r580-196-fixture.tar"
            with tarfile.open(archive_path, mode="w") as archive:
                relatives = (
                    "kernel-open/nvidia-uvm/uvm_volta.c",
                    "kernel-open/nvidia-uvm/uvm_extra.c",
                    *self.REQUIRED_FAULT_INPUTS,
                )
                for relative in relatives:
                    data = f"/* {relative} */\n".encode()
                    member = tarfile.TarInfo(f"{self.ROOT_196}/{relative}")
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))

            with tarfile.open(archive_path, "r:") as archive:
                self.assertEqual(source_archive_root(archive, self.ROOT_196), self.ROOT_196)
            with self.assertRaisesRegex(ValueError, "unexpected source root"):
                with tarfile.open(archive_path, "r:") as archive:
                    source_archive_root(archive)

            c_sources = extract_r580_uvm_c_sources(
                archive_path, Path(temporary) / "c-sources", expected_root=self.ROOT_196)
            self.assertTrue((c_sources / "uvm_volta.c").is_file())
            self.assertTrue((c_sources / "uvm_extra.c").is_file())

            fault_sources = extract_archived_r580_uvm(
                archive_path, Path(temporary) / "fault-sources",
                expected_root=self.ROOT_196)
            self.assertTrue((fault_sources / "uvm_volta_fault_buffer.c").is_file())

            self.assertEqual(
                read_member_from_archive(
                    archive_path,
                    "kernel-open/nvidia-uvm/uvm_volta.c",
                    expected_root=self.ROOT_196),
                "/* kernel-open/nvidia-uvm/uvm_volta.c */\n",
            )

    def test_prepare_overlay_accepts_only_explicitly_selected_196_root(self):
        with tempfile.TemporaryDirectory(prefix="r580-196-overlay-root-") as temporary:
            root = Path(temporary)
            archive_path = root / "r580-196-fixture.tar"
            with tarfile.open(archive_path, mode="w") as archive:
                entries = {
                    f"{self.ROOT_196}/COPYING": b"licensed as MIT\n",
                    f"{self.ROOT_196}/kernel-open/nvidia-uvm/uvm_push_macros.h": b"",
                    f"{self.ROOT_196}/kernel-open/nvidia-uvm/uvm_volta.c": b"",
                }
                for name, data in entries.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))

            r595 = root / "r595"
            uvm = r595 / "nvidia-uvm"
            uvm.mkdir(parents=True)
            (uvm / "nvidia-uvm-sources.Kbuild").write_text(
                "NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_tracker.c\n")
            (uvm / "uvm_push_macros.h").write_text("")

            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            scratch = root / "overlay"
            expected_stop = RuntimeError("stopped after validated archive inputs")
            with patch.object(probe_volta_uvm_port, "VOLTA_FILES", ()), \
                    patch.object(probe_volta_uvm_port, "DEPENDENCY_FILES", ()), \
                    patch.object(probe_volta_uvm_port, "SUBCHANNEL_MAPPINGS", ()), \
                    patch.object(probe_volta_uvm_port.shutil, "copytree",
                                 side_effect=expected_stop):
                with self.assertRaisesRegex(RuntimeError, "validated archive inputs"):
                    probe_volta_uvm_port.prepare_overlay(
                        archive_path, r595, scratch,
                        expected_archive_sha256=digest,
                        expected_source_root=self.ROOT_196,
                    )

                with self.assertRaisesRegex(ValueError, "unexpected source root"):
                    probe_volta_uvm_port.prepare_overlay(
                        archive_path, r595, root / "default-root-overlay",
                        expected_archive_sha256=digest,
                    )


if __name__ == "__main__":
    unittest.main()
