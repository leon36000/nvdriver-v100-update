#!/usr/bin/env python3
"""Contracts for exact R580 Open patch replay against a pinned R595 tree."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "r580_open_replay_r595", ROOT / "tools/replay_r580_open_patches_on_r595.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ReplayR580OpenPatchesOnR595Tests(unittest.TestCase):
    def test_patch_order_matches_gpu_backend_builder_sequence(self):
        self.assertEqual(len(MODULE.PATCH_ORDER), 40)
        self.assertEqual(MODULE.PATCH_COUNT, 45)
        self.assertEqual(MODULE.PATCH_ORDER[0], "0006-private-open-resource-names.patch")
        self.assertEqual(MODULE.ADAPTED_PATCHES[-1],
                         "0007-private-open-pci-only-lifecycle.patch")
        self.assertEqual(MODULE.PATCH_ORDER[-7:-1], (
            "0001-private-open-pm-channel-depth-enum.patch",
            "0031-private-open-pm-channel-depth.patch",
            "0033-private-open-pm-vma-access-guard.patch",
            "0034-private-open-vma-free-list-lock.patch",
            "0035-private-open-pm-recovery-provider.patch",
            "0036-private-open-pm-channel-dpm-modeset.patch"))
        self.assertLess(
            MODULE.PATCH_ORDER.index("0038-private-open-build-version-v1.patch"),
            MODULE.PATCH_ORDER.index("0044-private-open-system-features.patch"))
        self.assertEqual(
            MODULE.PATCH_ORDER[MODULE.PATCH_ORDER.index(
                "0044-private-open-system-features.patch") + 1],
            "0045-private-open-fabric-status.patch")
        self.assertEqual(
            MODULE.PATCH_ORDER[MODULE.PATCH_ORDER.index(
                "0045-private-open-fabric-status.patch") + 1],
            "0047-private-open-client-share-policy.patch")
        self.assertEqual(
            MODULE.PATCH_ORDER[MODULE.PATCH_ORDER.index(
                "0047-private-open-client-share-policy.patch") + 1],
            "0048-private-open-sync-boost-groups.patch")
        self.assertEqual(
            MODULE.PATCH_ORDER[MODULE.PATCH_ORDER.index(
                "0048-private-open-sync-boost-groups.patch") + 1],
            "0049-private-open-control-export-prototypes.patch")
        self.assertEqual(MODULE.PATCH_ORDER[-1],
                         "0050-private-open-debugger-bridge.patch")
        self.assertTrue(all((ROOT / "patches/r580.178.04" / name).is_file()
                            for name in (*MODULE.ADAPTED_PATCHES, *MODULE.PATCH_ORDER)))

    def test_control_export_prototypes_match_frontend_contract_exactly(self):
        patch = ROOT / "patches/r580.178.04/0049-private-open-control-export-prototypes.patch"
        replay_header = (ROOT / "build/experiments/r595-syncboost-replay-v3/source/"
                         "kernel-open/nvidia/hybrid580-control-session.h")
        public_header = ROOT / "src/hybrid580-control-session.h"
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            target = tree / "kernel-open/nvidia/hybrid580-control-session.h"
            target.parent.mkdir(parents=True)
            target.write_bytes(replay_header.read_bytes())
            before = target.read_text()
            MODULE.apply_patch_exact(patch, tree)
            after = target.read_text()
        for name in (
            "hybrid580_open_control_session_client_share_policy_v1",
            "hybrid580_open_control_session_sync_boost_groups_v1",
        ):
            pattern = r"NV_STATUS\s+" + re.escape(name) + r"\s*\([^;]*\);"
            old_matches = re.findall(pattern, before, re.S)
            new_matches = re.findall(pattern, after, re.S)
            shared_matches = re.findall(pattern, public_header.read_text(), re.S)
            self.assertEqual(old_matches, [])
            self.assertEqual(len(new_matches), 1)
            self.assertEqual(len(shared_matches), 1)
            self.assertEqual(" ".join(new_matches[0].split()),
                             " ".join(shared_matches[0].split()))

    def test_debugger_bridge_prototypes_match_the_frontend_contract(self):
        replay_source = (ROOT / "build/experiments/r595-debugger-bridge-patch-base-v1/source")
        patch = ROOT / "patches/r580.178.04/0050-private-open-debugger-bridge.patch"
        public_header = ROOT / "src/hybrid580-control-session.h"
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            target_dir = tree / "kernel-open/nvidia"
            target_dir.mkdir(parents=True)
            for filename in ("nv.c", "hybrid580-control-session.h"):
                (target_dir / filename).write_bytes(
                    (replay_source / "kernel-open/nvidia" / filename).read_bytes())
            MODULE.apply_patch_exact(patch, tree)
            patched_header = (target_dir / "hybrid580-control-session.h").read_text()
        for name in (
            "hybrid580_open_control_session_debugger_alloc_v1",
            "hybrid580_open_control_session_debugger_exception_mask_v1",
        ):
            pattern = r"NV_STATUS\s+" + re.escape(name) + r"\s*\([^;]*\);"
            patched = re.findall(pattern, patched_header, re.S)
            public = re.findall(pattern, public_header.read_text(), re.S)
            self.assertEqual(len(patched), 1)
            self.assertEqual(len(public), 1)
            self.assertEqual(" ".join(patched[0].split()),
                             " ".join(public[0].split()))

    def test_debugger_bridge_r595_rebase_preserves_provider_and_uses_unique_anchor(self):
        patch = (ROOT / "patches/r580.178.04/0050-private-open-debugger-bridge.patch").read_text()
        context = (
            "    return status;\n"
            "}\n"
            "EXPORT_SYMBOL(hybrid580_open_control_session_engine_alloc_v1);\n"
            "\n"
            "int hybrid580_open_control_session_sys_params_v1(\n"
            "    struct hybrid580_control_session *session, NvU64 memblock_size)\n")
        source = "before\n" + context + "after\n"
        lines = patch.splitlines(keepends=True)
        header_index = lines.index("@@ -179,15 +181,15 @@\n")
        header_body = lines[header_index + 1:]
        old_header_context = "".join(
            line[1:] for line in header_body
            if line.startswith(" ") or line.startswith("-"))
        header = "before\n" + old_header_context + "after\n"
        rebased = MODULE.rebase_debugger_bridge_patch_r595(patch, source, header)
        self.assertIn("@@ -2,6 +2,181 @@", rebased)
        self.assertIn("@@ -2,15 +4,23 @@", rebased)
        self.assertNotIn("@@ -6563,6 +6563,181 @@", rebased)
        self.assertNotIn("@@ -179,15 +181,15 @@", rebased)
        additions = lambda text: [line for line in text.splitlines()
                                  if line.startswith("+") and not line.startswith("+++")]
        self.assertEqual(additions(rebased), additions(patch))
        self.assertIn("hybrid580_open_control_session_client_share_policy_v1(", header)
        self.assertIn("hybrid580_open_control_session_sync_boost_groups_v1(", header)
        self.assertEqual(
            rebased.count(" hybrid580_open_control_session_client_share_policy_v1(\n"), 1)
        self.assertEqual(
            rebased.count(" hybrid580_open_control_session_sync_boost_groups_v1(\n"), 1)
        self.assertEqual(
            [line for line in rebased.splitlines()
             if line.startswith("-") and not line.startswith("---")], [])
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            MODULE.rebase_debugger_bridge_patch_r595(patch, "before\nafter\n", header)
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            MODULE.rebase_debugger_bridge_patch_r595(
                patch, "before\n" + context + context, header)
        with self.assertRaisesRegex(ValueError, "header anchor"):
            MODULE.rebase_debugger_bridge_patch_r595(patch, source, "before\nafter\n")
        with self.assertRaisesRegex(ValueError, "patch differs"):
            MODULE.rebase_debugger_bridge_patch_r595(
                patch.replace("NV_OK", "NV_ERR"), source, header)

    def test_debugger_bridge_patch_preserves_virtual_memory_allocation(self):
        replay_source = (ROOT / "build/experiments/r595-debugger-bridge-patch-base-v1/source")
        patch = ROOT / "patches/r580.178.04/0050-private-open-debugger-bridge.patch"
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            target_dir = tree / "kernel-open/nvidia"
            target_dir.mkdir(parents=True)
            for filename in ("nv.c", "hybrid580-control-session.h"):
                (target_dir / filename).write_bytes(
                    (replay_source / "kernel-open/nvidia" / filename).read_bytes())
            MODULE.apply_patch_exact(patch, tree)
            patched_source = (target_dir / "nv.c").read_text()
        self.assertIn("0x000050a0U /* NV50_MEMORY_VIRTUAL */", patched_source)
        self.assertRegex(
            patched_source,
            r"class_id != 0x000050a0U /\* NV50_MEMORY_VIRTUAL \*/\)\)")

    def test_sync_boost_groups_r595_rebase_uses_exact_anchor_and_preserves_provider(self):
        patch = (ROOT / "patches/r580.178.04/0048-private-open-sync-boost-groups.patch").read_text()
        source = ("prefix\n"
                  "EXPORT_SYMBOL(hybrid580_open_control_session_client_share_policy_v1);\n"
                  "\n"
                  "suffix\n")
        rebased = MODULE.rebase_sync_boost_groups_patch_r595(patch, source)
        self.assertIn("@@ -2,2 +2,109 @@", rebased)
        self.assertNotIn("@@ -5102,6 +5102,113 @@", rebased)
        self.assertIn(" EXPORT_SYMBOL(hybrid580_open_control_session_client_share_policy_v1);\n",
                      rebased)
        additions = lambda text: [line for line in text.splitlines()
                                  if line.startswith("+") and not line.startswith("+++")]
        self.assertEqual(additions(rebased), additions(patch))
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            MODULE.rebase_sync_boost_groups_patch_r595(
                patch, source.replace("client_share_policy_v1);", "other);"))
        with self.assertRaisesRegex(ValueError, "successor context changed"):
            MODULE.rebase_sync_boost_groups_patch_r595(
                patch, source.replace("\n\nsuffix", "\nsuffix"))

    def test_sync_boost_provider_header_adds_only_the_exact_sdk_include(self):
        original = (
            "#ifndef HYBRID580_CONTROL_SESSION_H\n"
            "#include <ctrl/ctrl0000/ctrl0000gpu.h>\n"
            "struct file;\n")
        adapted = MODULE.add_sync_boost_group_header_r595(original)
        self.assertEqual(adapted, original.replace(
            "#include <ctrl/ctrl0000/ctrl0000gpu.h>\n",
            "#include <ctrl/ctrl0000/ctrl0000gpu.h>\n"
            "#include <ctrl/ctrl0000/ctrl0000syncgpuboost.h>\n"))
        with self.assertRaisesRegex(ValueError, "already present"):
            MODULE.add_sync_boost_group_header_r595(adapted)
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            MODULE.add_sync_boost_group_header_r595("#include <class/cl0080.h>\n")

    def test_patch_applier_rejects_offsets_and_fuzz(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.txt").write_text("before\nanchor\nafter\n")
            patch = root / "sample.patch"
            patch.write_text("""--- a/sample.txt
+++ b/sample.txt
@@ -2,1 +2,1 @@
-anchor
+changed
""")
            MODULE.apply_patch_exact(patch, root)
            self.assertEqual((root / "sample.txt").read_text(), "before\nchanged\nafter\n")

            shifted_root = root / "shifted"
            shifted_root.mkdir()
            (shifted_root / "sample.txt").write_text("extra\nbefore\nanchor\nafter\n")
            with self.assertRaisesRegex(RuntimeError, "offset|fuzz|FAILED"):
                MODULE.apply_patch_exact(patch, shifted_root)

    def test_manifest_hash_rejects_patch_input_drift(self):
        self.assertEqual(len(MODULE.PATCH_ORDER), 40)
        with self.assertRaisesRegex(ValueError, "source snapshot"):
            MODULE.validate_pinned_tree("0" * 64, MODULE.SOURCE_FILE_COUNT)

    def test_pinned_source_profiles_select_exact_595_99_and_595_112_inputs(self):
        r595_99 = MODULE.source_profile("595.99.02")
        r595_112 = MODULE.source_profile("595.112.07")
        self.assertEqual(r595_99.source_sha256,
                         "6d4ae86fb03f3afac63007c3c13422b114c93f5ab6a271ccb3dde5fb2440c066")
        self.assertEqual(r595_112.source_sha256,
                         "8e29bef1a16a00952024fbe0224d90ce115a72b393e89d5cff337fe5f908d2d1")
        self.assertEqual(r595_112.source_file_count, 3810)
        self.assertEqual(r595_112.baseline_symvers_sha256,
                         "1afbdc5d864d0d8f7ae7c57b6def32b82a0d99da73772fafc85f5da07baaa918")
        self.assertNotEqual(r595_99.source_path, r595_112.source_path)
        with self.assertRaisesRegex(ValueError, "unsupported pinned source version"):
            MODULE.source_profile("595.999.99")

    def test_resource_names_r595_rebase_uses_unique_source_context(self):
        patch = (ROOT / "patches/r580.178.04/0006-private-open-resource-names.patch").read_text()
        call = ("    rc = alloc_chrdev_region(&g_nv_cap_drv.devno,\n"
                "                             0,\n"
                "                             NV_CAP_DRV_MINOR_COUNT,\n"
                "                             \"nvidia-caps\");\n")
        source = "\n" * 865 + call
        rebased = MODULE.rebase_resource_names_patch_r595(patch, source)
        self.assertIn("@@ -866,7 +866,7 @@", rebased)
        self.assertNotIn("@@ -823,7 +823,7 @@", rebased)
        target_hunk = re.search(
            r"@@ -(\d+),7 \+\d+,7 @@\n"
            r"     rc = alloc_chrdev_region\(&g_nv_cap_drv\.devno,\n",
            rebased)
        self.assertIsNotNone(target_hunk)
        self.assertEqual(int(target_hunk.group(1)), 866)
        additions = lambda text: [line for line in text.splitlines()
                                  if line.startswith("+") and not line.startswith("+++")]
        self.assertEqual(additions(rebased), additions(patch))
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            MODULE.rebase_resource_names_patch_r595(patch, "prefix\n" + call + call)
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            MODULE.rebase_resource_names_patch_r595(patch, "prefix\n")

    def test_system_features_r595_rebase_changes_only_exact_line_number(self):
        patch = (ROOT / "patches/r580.178.04/0044-private-open-system-features.patch").read_text()
        rebased = MODULE.rebase_system_features_patch_r595(patch)
        self.assertIn("@@ -5957,6 +5957,103 @@", rebased)
        self.assertNotIn("@@ -4723,6 +4723,103 @@", rebased)
        additions = lambda text: [line for line in text.splitlines()
                                  if line.startswith("+") and not line.startswith("+++")]
        self.assertEqual(additions(rebased), additions(patch))
        self.assertIn(" NV_STATUS hybrid580_open_control_session_rusd_alloc_v1(\n", rebased)

    def test_system_features_r595_112_rebase_preserves_provider_body(self):
        patch = (ROOT / "patches/r580.178.04/0044-private-open-system-features.patch").read_text()
        rebased = MODULE.rebase_system_features_patch_r595(patch, "595.112.07")
        self.assertIn("@@ -5969,6 +5969,103 @@", rebased)
        self.assertNotIn("@@ -5957,6 +5957,103 @@", rebased)
        additions = lambda text: [line for line in text.splitlines()
                                  if line.startswith("+") and not line.startswith("+++")]
        self.assertEqual(additions(rebased), additions(patch))

    def test_fabric_status_r595_rebase_preserves_provider_and_uses_exact_anchor(self):
        patch = (ROOT / "patches/r580.178.04/0045-private-open-fabric-status.patch").read_text()
        rebased = MODULE.rebase_fabric_status_patch_r595(patch)
        self.assertIn("@@ -6053,6 +6053,102 @@", rebased)
        self.assertNotIn("@@ -4819,6 +4819,102 @@", rebased)
        additions = lambda text: [line for line in text.splitlines()
                                  if line.startswith("+") and not line.startswith("+++")]
        self.assertEqual(additions(rebased), additions(patch))
        self.assertIn(" NV_STATUS hybrid580_open_control_session_rusd_alloc_v1(\n", rebased)

    def test_fabric_status_r595_112_rebase_preserves_provider_body(self):
        patch = (ROOT / "patches/r580.178.04/0045-private-open-fabric-status.patch").read_text()
        rebased = MODULE.rebase_fabric_status_patch_r595(patch, "595.112.07")
        self.assertIn("@@ -6065,6 +6065,102 @@", rebased)
        self.assertNotIn("@@ -6053,6 +6053,102 @@", rebased)
        additions = lambda text: [line for line in text.splitlines()
                                  if line.startswith("+") and not line.startswith("+++")]
        self.assertEqual(additions(rebased), additions(patch))

    def test_client_share_policy_r595_rebase_changes_only_unique_line_number(self):
        patch = (ROOT / "patches/r580.178.04/0047-private-open-client-share-policy.patch").read_text()
        source = "prefix\nEXPORT_SYMBOL(hybrid580_open_control_session_fabric_status_v1);\nsuffix\n"
        rebased = MODULE.rebase_client_share_policy_patch_r595(patch, source)
        self.assertIn("@@ -2,2 +2,97 @@", rebased)
        self.assertNotIn("@@ -5008,6 +5008,101 @@", rebased)
        additions = lambda text: [line for line in text.splitlines()
                                  if line.startswith("+") and not line.startswith("+++")]
        self.assertEqual(additions(rebased), additions(patch))
        self.assertEqual(source.count("EXPORT_SYMBOL(hybrid580_open_control_session_fabric_status_v1);"), 1)


if __name__ == "__main__":
    unittest.main()
