# SPDX-License-Identifier: MIT
"""Fail-closed validation of cached hybrid UVM provider identities."""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PREIMAGE = ROOT / (
    "build/experiments/r595-tracker-detach-prune-v4-20261028T2100Z/"
    "candidate/nvidia-uvm/uvm_gpu.c"
)
PATCH = ROOT / (
    "patches/r595.99.02/0008-validate-hybrid-provider-id-before-gpu-publication.patch"
)
PREIMAGE_SHA256 = "925ffe7bad8362431e71985c77b76c8a84f16ab3b08e7c32115c503ea81f760d"


def validate_provider_id_before_publication(source: str) -> None:
    start = source.index("static NV_STATUS add_gpu(")
    end = source.index("\n// Increment the refcount for the GPU with the given UUID", start)
    add_gpu = source[start:end]

    query = add_gpu.index(
        "status = nvUvmInterfaceGetGpuProvider(&parent_gpu->uuid, &gpu->hybrid_provider_id);"
    )
    validation = add_gpu.index(
        "if (gpu->hybrid_provider_id != HYBRID580_UVM_PROVIDER_ID_OPEN &&"
    )
    reject = add_gpu.index("status = NV_ERR_NOT_SUPPORTED;", validation)
    unwind = add_gpu.index("goto error;", reject)
    uvm_capability_check = add_gpu.index("if (!gpu_supports_uvm(parent_gpu))")
    init_gpu = add_gpu.index("status = init_gpu(gpu, gpu_info);")
    publication = add_gpu.index("uvm_global_add_parent_gpu(parent_gpu);")

    assert query < validation < reject < unwind < uvm_capability_check < init_gpu < publication
    guard = add_gpu[validation:uvm_capability_check]
    assert "HYBRID580_UVM_PROVIDER_ID_LEGACY" in guard
    assert "status = NV_ERR_NOT_SUPPORTED;" in guard
    assert "goto error;" in guard


class R595ProviderIdValidationTests(unittest.TestCase):
    def _patched_source(self) -> str:
        self.assertTrue(PREIMAGE.is_file(), f"missing pinned R595 UVM preimage: {PREIMAGE}")
        self.assertTrue(PATCH.is_file(), f"missing provider-ID validation patch: {PATCH}")
        original = PREIMAGE.read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), PREIMAGE_SHA256)

        with tempfile.TemporaryDirectory(prefix="r595-provider-id-validation-") as directory:
            root = Path(directory)
            target = root / "nvidia-uvm/uvm_gpu.c"
            target.parent.mkdir(parents=True)
            target.write_bytes(original)
            result = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotRegex(result.stdout, r"\b(?:offset|fuzz)\b")
            return target.read_text()

    def test_exact_patch_rejects_unknown_ids_before_gpu_publication(self):
        self.assertIsNone(validate_provider_id_before_publication(self._patched_source()))

    def test_mutation_accepting_unknown_provider_id_fails_the_contract(self):
        source = self._patched_source()
        source = source.replace(
            "if (gpu->hybrid_provider_id != HYBRID580_UVM_PROVIDER_ID_OPEN &&\n"
            "        gpu->hybrid_provider_id != HYBRID580_UVM_PROVIDER_ID_LEGACY) {",
            "if (false) {",
            1,
        )
        with self.assertRaises((AssertionError, ValueError)):
            validate_provider_id_before_publication(source)


if __name__ == "__main__":
    unittest.main()
