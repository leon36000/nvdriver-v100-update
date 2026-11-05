# SPDX-License-Identifier: MIT
import hashlib
import json
from pathlib import Path
import unittest

from tools.audit_p2p_branch_delta import (
    R580_FUNCTION,
    R580_STRUCT,
    R595_FUNCTION,
    R595_STRUCT,
    audit_branch_delta_texts,
)


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "evidence/r580-r595-p2p-abi-delta-v1-20261102.json"
EXPECTED_FIXTURE_HASHES = {
    R580_FUNCTION: "e1c5e1ccfd7743abd3faf9c3e392c57289e6ea1177999aef2556faae3bd8dfff",
    R580_STRUCT: "6e41d7fe81278e103c62129ae8ced115b970a9df8370c2bb984d25a9be06f330",
    R595_STRUCT: "5a5574d7b316e03e87fe8efe7783cd1c59911d1a5045d538ee7338eee8fbe250",
}


class AuditP2PBranchDeltaTests(unittest.TestCase):
    def _inputs(self):
        return (
            R580_FUNCTION.read_text(encoding="utf-8"),
            R580_STRUCT.read_text(encoding="utf-8"),
            R595_FUNCTION.read_text(encoding="utf-8"),
            R595_STRUCT.read_text(encoding="utf-8"),
        )

    def test_upstream_excerpt_hashes_and_provenance_are_pinned(self):
        for path, expected in EXPECTED_FIXTURE_HASHES.items():
            payload = path.read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), expected)
            self.assertIn(b"SPDX-License-Identifier: MIT", payload)
            self.assertIn(b"Source archive SHA-256:", payload)
            self.assertIn(b"Source file SHA-256:", payload)
        upstream = json.loads((ROOT / "evidence/r595-p2p-producer-v2-20261102.json").read_text())
        release = upstream["releases"]["595.112.07"]
        self.assertEqual(release["tag_object"], "2e8dd6c0bbd2e08194b96abeb5c319717cd13682")
        self.assertEqual(release["commit"], "d8257d95ae5fed364163e4df51db66df8b1ee0d2")

    def test_branch_delta_and_compiled_x86_64_layout(self):
        report = audit_branch_delta_texts(*self._inputs())
        self.assertTrue(all(report["checks"].values()))
        self.assertEqual(report["abi_layout"]["r580"]["sizeof"], 64)
        self.assertEqual(report["abi_layout"]["r595"]["sizeof"], 72)
        self.assertEqual(report["abi_layout"]["r595"]["bar1PcieAtomics_offset"], 64)
        self.assertFalse(report["runtime_or_hardware_validated"])

    def test_r580_atomic_field_mutation_fails_closed(self):
        old_fn, old_struct, new_fn, new_struct = self._inputs()
        old_fn = old_fn.replace(
            "p2pCapsParams->p2pLink         = UVM_LINK_TYPE_NONE;",
            "p2pCapsParams->bar1PcieAtomics[0] = NV_FALSE;\n"
            "    p2pCapsParams->p2pLink         = UVM_LINK_TYPE_NONE;",
            1,
        )
        with self.assertRaisesRegex(ValueError, "r580_has_no_bar1_atomic_field_or_producer_output"):
            audit_branch_delta_texts(old_fn, old_struct, new_fn, new_struct)

    def test_swapping_r595_atomic_owner_fails_closed(self):
        old_fn, old_struct, new_fn, new_struct = self._inputs()
        new_fn = new_fn.replace(
            "device1->session,\n                                                                                    pLocalGpu,\n"
            "                                                                                    pRemoteGpu);",
            "device1->session,\n                                                                                    pRemoteGpu,\n"
            "                                                                                    pLocalGpu);",
            1,
        )
        with self.assertRaisesRegex(ValueError, "r595_maps_directional_atomic_flags_to_bar1_owners"):
            audit_branch_delta_texts(old_fn, old_struct, new_fn, new_struct)

    def test_r595_bar1_link_classification_mutation_fails_closed(self):
        old_fn, old_struct, new_fn, new_struct = self._inputs()
        new_fn = new_fn.replace("UVM_LINK_TYPE_PCIE_BAR1", "UVM_LINK_TYPE_PCIE", 1)
        with self.assertRaisesRegex(ValueError, "r595_distinguishes_bar1_from_generic_pcie_link"):
            audit_branch_delta_texts(old_fn, old_struct, new_fn, new_struct)

    def test_generated_receipt_contains_only_sanitized_source_results(self):
        payload = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "nvidia-r580-r595-p2p-source-abi-delta-v1")
        self.assertEqual(payload["abi_layout"]["r580"]["sizeof"], 64)
        self.assertEqual(payload["abi_layout"]["r595"]["sizeof"], 72)
        self.assertFalse(payload["runtime_or_hardware_validated"])
        serialized = json.dumps(payload).lower()
        self.assertNotIn("pseudocode", serialized)
        self.assertNotIn("normalized_result", serialized)


if __name__ == "__main__":
    unittest.main()
