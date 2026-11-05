# SPDX-License-Identifier: MIT
"""Source-text parser tests for the pinned OpenRM GV100 release matrix."""

import unittest
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile

from tools.compare_openrm_gv100 import (
    FILES,
    INPUTS,
    SOURCE_COMMITS,
    inspect_archive,
    parse_generated_sources,
)


def source_fixture(*, gv100_enabled="0", gv10x_enabled="1",
                   volta_classic_enabled="0",
                   arch_row="{ 0x0, 0x0, 0x0 }, // GV100 (disabled)",
                   chip_label=False, legacy_registration=False):
    return {
        "src/nvidia/generated/rmconfig.h": (
            f"#define RMCFG_CHIP_GV10X     {gv10x_enabled}\n"
            f"#define RMCFG_CHIP_GV100     {gv100_enabled}\n"
            f"#define RMCFG_CHIP_VOLTA_CLASSIC_GPUS {volta_classic_enabled}\n"
        ),
        "src/nvidia/generated/g_chips2halspec_nvoc.c": (
            "/* generated chip/HAL mapping */\n"
            + ("// GV100\n" if chip_label else "")
        ),
        "src/nvidia/generated/g_hal_register.h": (
            "/* generated legacy HAL registration */\n"
            + ("void registerHalModule_GV100(void);\n" if legacy_registration else "")
        ),
        "src/nvidia/generated/g_hal_archimpl.h": f"{arch_row}\n",
        "src/nvidia/src/kernel/core/hal_mgr.c": "/* pinned source identity fixture */\n",
    }


class OpenRmGv100SourceMatrixTests(unittest.TestCase):
    def test_matrix_pins_the_current_official_r580_open_source_release(self):
        pinned = {
            version: (filename, prefix, digest)
            for version, filename, prefix, digest in INPUTS
        }
        self.assertEqual(
            pinned["580.196.07"],
            (
                "NVIDIA-kernel-module-source-580.196.07.tar.xz",
                "NVIDIA-kernel-module-source-580.196.07",
                "21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084",
            ),
        )
        self.assertEqual(
            SOURCE_COMMITS["580.196.07"],
            "02e64bf229e77873c9df22ebcfed6a3e0b813206",
        )

    def test_matrix_pins_current_r595_and_r615_source_releases(self):
        pinned = {version: digest for version, _name, _prefix, digest in INPUTS}
        self.assertEqual(pinned["595.112.07"],
                         "567d4ba082a54ef733e7ce87c87401da488a3aabe29837c92feb19011c8250c4")
        self.assertEqual(pinned["615.71.10"],
                         "c01605048cab3d988b1b3028fbee0646ba0937407949dc43514b3e4694f40f6c")
        self.assertIn("615.78.08", pinned)

    def test_matrix_pins_the_official_r610_57_04_source_archive(self):
        pinned = {version: digest for version, _name, _prefix, digest in INPUTS}
        self.assertEqual(
            pinned["610.57.04"],
            "619d7b5ce1f79c3211afdbf87d02b2174d268b10d005c5b8f994be22299be681",
        )
        self.assertEqual(
            SOURCE_COMMITS["610.57.04"],
            "e4a5faa2567f28c8eabe0ebb6422b6d0abcf37eb",
        )

    def test_disabled_gv100_profile_is_reported_as_static_metadata(self):
        result = parse_generated_sources("615.78.08", source_fixture())
        self.assertEqual(result["chip_flags"], {
            "GV10X": 1, "GV100": 0, "VOLTA_CLASSIC_GPUS": 0,
        })
        self.assertEqual(result["gv100_chip_id_row"], "{ 0x0, 0x0, 0x0 }, // GV100 (disabled)")
        self.assertFalse(result["chiphal_gv100_label_present"])
        self.assertFalse(result["gv100_legacy_registration_symbol_present"])
        self.assertEqual(result["source_profile"], "gv100-disabled-in-generated-profile")

    def test_enabled_flag_alone_does_not_claim_gv100_support(self):
        result = parse_generated_sources(
            "fixture", source_fixture(gv100_enabled="1")
        )
        self.assertEqual(result["chip_flags"]["GV100"], 1)
        self.assertEqual(result["source_profile"], "not-proven-disabled-or-enabled")

    def test_ambiguous_config_or_chip_rows_fail_closed(self):
        duplicate_config = source_fixture()
        duplicate_config["src/nvidia/generated/rmconfig.h"] += (
            "#define RMCFG_CHIP_GV100 1\n"
        )
        with self.assertRaisesRegex(ValueError, "ambiguous .*chip flag GV100"):
            parse_generated_sources("fixture", duplicate_config)

        duplicate_row = source_fixture(
            arch_row="{ 0x0, 0x0, 0x0 }, // GV100 (disabled)\n{ 0x1, 0x2, 0x3 }, // GV100 duplicate"
        )
        with self.assertRaisesRegex(ValueError, "ambiguous .*GV100 chipID row"):
            parse_generated_sources("fixture", duplicate_row)

    def test_all_generated_source_inputs_are_required(self):
        incomplete = source_fixture()
        del incomplete["src/nvidia/generated/g_hal_register.h"]
        with self.assertRaisesRegex(ValueError, "missing generated source"):
            parse_generated_sources("fixture", incomplete)

    def test_generated_sources_must_use_exact_repository_paths(self):
        misplaced = source_fixture()
        misplaced["elsewhere/rmconfig.h"] = misplaced.pop(
            "src/nvidia/generated/rmconfig.h"
        )
        with self.assertRaisesRegex(ValueError, "missing generated source"):
            parse_generated_sources("fixture", misplaced)

    def test_archive_reader_hashes_one_snapshot_and_requires_regular_members(self):
        fixture = source_fixture()
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            archive_path = cache / "fixture.tar.gz"
            prefix = "fixture-root"
            with tarfile.open(archive_path, "w:gz") as archive:
                for relative in FILES:
                    payload = fixture[relative].encode("utf-8")
                    member = tarfile.TarInfo(f"{prefix}/{relative}")
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            result = inspect_archive(
                cache, "fixture", archive_path.name, prefix, digest
            )
            self.assertEqual(result["archive_sha256"], digest)
            self.assertEqual(result["source_profile"], "gv100-disabled-in-generated-profile")
            self.assertEqual(set(result["files"]), set(FILES))

    def test_archive_reader_rejects_digest_mismatch_and_duplicate_members(self):
        fixture = source_fixture()
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            archive_path = cache / "fixture.tar.gz"
            prefix = "fixture-root"
            with tarfile.open(archive_path, "w:gz") as archive:
                for relative in FILES:
                    payload = fixture[relative].encode("utf-8")
                    member = tarfile.TarInfo(f"{prefix}/{relative}")
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
                duplicate = tarfile.TarInfo(f"{prefix}/{FILES[0]}")
                duplicate.size = 0
                archive.addfile(duplicate, io.BytesIO(b""))
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "digest differs"):
                inspect_archive(cache, "fixture", archive_path.name, prefix, "0" * 64)
            with self.assertRaisesRegex(ValueError, "expected one source member"):
                inspect_archive(cache, "fixture", archive_path.name, prefix, digest)

    def test_archive_leaf_symlink_is_rejected(self):
        fixture = source_fixture()
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            archive_path = cache / "fixture.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                for relative in FILES:
                    payload = fixture[relative].encode("utf-8")
                    member = tarfile.TarInfo(f"fixture-root/{relative}")
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
            link = cache / "alias.tar.gz"
            link.symlink_to(archive_path.name)
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            with self.assertRaises(OSError):
                inspect_archive(cache, "fixture", link.name, "fixture-root", digest)


if __name__ == "__main__":
    unittest.main()
