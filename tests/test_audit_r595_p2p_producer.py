# SPDX-License-Identifier: MIT
import unittest
import hashlib
import json
from pathlib import Path

from tools.audit_r595_p2p_producer import audit_p2p_source_text


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "evidence/r595-p2p-producer-v2-20261102.json"
EXCERPTS = {
    "595.99.02": (
        ROOT / "tests/fixtures/upstream/nvidia-r595-p2p/595.99.02/nv_gpu_ops_p2p_excerpt.c",
        "3a717aa6032fa1fc2433787b0992bf851817245292d467d932e4c3016e22a87a",
    ),
    "595.112.07": (
        ROOT / "tests/fixtures/upstream/nvidia-r595-p2p/595.112.07/nv_gpu_ops_p2p_excerpt.c",
        "b82c723cef882f053fca6ac7b3837b47aed2be5636ac23c956c46a04668008e4",
    ),
}


SOURCE = r"""
static NV_STATUS getSystemP2PCaps(struct gpuDevice *device1,
                                  struct gpuDevice *device2,
                                  struct systemP2PCaps *p2pCaps)
{
    if (REF_VAL(NV0000_CTRL_SYSTEM_GET_P2P_CAPS_READS_SUPPORTED, p2pCapsParams->p2pCaps) &&
        REF_VAL(NV0000_CTRL_SYSTEM_GET_P2P_CAPS_WRITES_SUPPORTED, p2pCapsParams->p2pCaps)) {
        p2pCaps->accessSupported = NV_TRUE;
    }
    p2pCaps->bar1Supported = !!REF_VAL(NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PCI_BAR1_SUPPORTED,
                                       p2pCapsParams->p2pCaps);
}

// TODO: Bug 3264814: support BAR1 PCIe atomics.
// The logic here should consider bus topology and routing between the two GPUs.
NvBool _nvGpuOpsIsBar1P2pAtomicEnabled(struct gpuSession *session,
                                       OBJGPU *pMappingGpu,
                                       OBJGPU *pOwningGpu)
{
    NvU32 arch;
    NV_STATUS status = _nvGpuOpsGetDeviceArchByGpuId(session, pOwningGpu->gpuId, &arch);
    NV_ASSERT_OR_RETURN(status == NV_OK, 0);
    return arch >= GPU_ARCHITECTURE_BLACKWELL_GB1XX;
}

NV_STATUS nvGpuOpsGetP2PCaps(struct gpuDevice *device1,
                             struct gpuDevice *device2,
                             getP2PCapsParams *p2pCapsParams)
{
    p2pCapsParams->bar1PcieAtomics[0] = NV_FALSE;
    p2pCapsParams->bar1PcieAtomics[1] = NV_FALSE;
    status = getSystemP2PCaps(device1, device2, &p2pCaps, RMAPI_EXTERNAL_KERNEL);
    if (p2pCaps.accessSupported) {
        if (p2pCaps.bar1Supported) {
            kbusGetBar1P2PDmaInfo_HAL(pLocalGpu, pRemoteGpu,
                                      GPU_GET_KERNEL_BUS(pRemoteGpu),
                                      &p2pCapsParams->bar1DmaAddress[0],
                                      &p2pCapsParams->bar1DmaSize[0]);
            p2pCapsParams->bar1PcieAtomics[0] =
                _nvGpuOpsIsBar1P2pAtomicEnabled(device1->session, pLocalGpu, pRemoteGpu);
            kbusGetBar1P2PDmaInfo_HAL(pRemoteGpu, pLocalGpu,
                                      GPU_GET_KERNEL_BUS(pLocalGpu),
                                      &p2pCapsParams->bar1DmaAddress[1],
                                      &p2pCapsParams->bar1DmaSize[1]);
            p2pCapsParams->bar1PcieAtomics[1] =
                _nvGpuOpsIsBar1P2pAtomicEnabled(device2->session, pRemoteGpu, pLocalGpu);
        }
    }
}
"""


class AuditR595P2PProducerTests(unittest.TestCase):
    def test_committed_upstream_excerpts_match_pinned_receipt(self):
        receipt_bytes = RECEIPT.read_bytes()
        self.assertEqual(
            hashlib.sha256(receipt_bytes).hexdigest(),
            "342152cf82b334c141efcdd97d64d87abc3629e8906e65b75ba50dce34f2f19b",
        )
        receipt = json.loads(receipt_bytes)
        normalized_by_release = {}
        for version, (path, expected_sha256) in EXCERPTS.items():
            excerpt_bytes = path.read_bytes()
            excerpt = excerpt_bytes.decode("utf-8")
            self.assertEqual(hashlib.sha256(excerpt_bytes).hexdigest(), expected_sha256)
            release = receipt["releases"][version]
            self.assertIn(release.get("upstream_tag_object", release.get("tag_object")), excerpt)
            self.assertIn(release.get("upstream_commit", release.get("commit")), excerpt)
            self.assertIn(release["source_file_sha256"], excerpt)
            result = audit_p2p_source_text(excerpt)
            normalized_by_release[version] = {
                name: function["normalized_sha256"]
                for name, function in result["functions"].items()
            }
            for name, function in result["functions"].items():
                self.assertEqual(
                    function["normalized_sha256"],
                    release["functions"][name]["normalized_sha256"],
                )
        self.assertEqual(normalized_by_release["595.99.02"],
                         normalized_by_release["595.112.07"])

    def test_reports_two_directional_bar1_owners(self):
        report = audit_p2p_source_text(SOURCE)
        self.assertTrue(all(report["checks"].values()))
        self.assertEqual(
            report["direction_contract"]["bar1PcieAtomics_index_0"]["bar1_owner_gpu"],
            "device2 / pRemoteGpu",
        )
        self.assertEqual(
            report["direction_contract"]["bar1PcieAtomics_index_1"]["bar1_owner_gpu"],
            "device1 / pLocalGpu",
        )
        self.assertFalse(report["runtime_or_hardware_validated"])

    def test_swapped_direction_zero_owner_fails_closed(self):
        mutated = SOURCE.replace(
            "bar1PcieAtomics[0] =\n                _nvGpuOpsIsBar1P2pAtomicEnabled(device1->session, pLocalGpu, pRemoteGpu)",
            "bar1PcieAtomics[0] =\n                _nvGpuOpsIsBar1P2pAtomicEnabled(device1->session, pRemoteGpu, pLocalGpu)",
            1,
        )
        with self.assertRaisesRegex(ValueError, "index_zero_maps_device1_to_device2_bar1"):
            audit_p2p_source_text(mutated)

    def test_swapped_direction_one_owner_fails_closed(self):
        mutated = SOURCE.replace(
            "bar1PcieAtomics[1] =\n                _nvGpuOpsIsBar1P2pAtomicEnabled(device2->session, pRemoteGpu, pLocalGpu)",
            "bar1PcieAtomics[1] =\n                _nvGpuOpsIsBar1P2pAtomicEnabled(device2->session, pLocalGpu, pRemoteGpu)",
            1,
        )
        with self.assertRaisesRegex(ValueError, "index_one_maps_device2_to_device1_bar1"):
            audit_p2p_source_text(mutated)

    def test_using_mapping_gpu_for_architecture_gate_fails_closed(self):
        mutated = SOURCE.replace("pOwningGpu->gpuId", "pMappingGpu->gpuId", 1)
        with self.assertRaisesRegex(ValueError, "atomic_architecture_query_uses_owning_gpu"):
            audit_p2p_source_text(mutated)

    def test_removing_reads_gate_fails_closed(self):
        mutated = SOURCE.replace(
            "REF_VAL(NV0000_CTRL_SYSTEM_GET_P2P_CAPS_READS_SUPPORTED, p2pCapsParams->p2pCaps) &&\n        ",
            "",
            1,
        )
        with self.assertRaisesRegex(ValueError, "rm_access_requires_both_reads_and_writes"):
            audit_p2p_source_text(mutated)

    def test_topology_caveat_must_remain_visible(self):
        mutated = SOURCE.replace("bus topology and routing", "GPU model", 1)
        with self.assertRaisesRegex(ValueError, "source_retains_topology_and_routing_todo"):
            audit_p2p_source_text(mutated)


if __name__ == "__main__":
    unittest.main()
