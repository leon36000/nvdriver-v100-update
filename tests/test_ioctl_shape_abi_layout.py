# SPDX-License-Identifier: MIT
"""Compile observed ioctl packet ABIs against exact public R580 and R595 sources."""
import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
R580 = ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04"
R595 = ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/open-gpu-kernel-modules-595.99.02"
R595_ARCHIVE = ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source.tar.gz"
R595_ARCHIVE_SHA256 = "b8891cb617683e28ef1e4c3add8dbc30e648b8cd6429a3d521f20dde44633262"
FIXTURE = ROOT / "tests/fixtures/ioctl_shape_abi_layout_test.c"

PINNED_R580_HEADERS = {
    "src/common/sdk/nvidia/inc/nvos.h": "07f9f453afbf080750663abc9e04e2d3b55500887303ba03bd6855916d2405bd",
    "src/nvidia/arch/nvalloc/unix/include/nv-ioctl-numbers.h": "7f449a019521f2f858a2d485eed1ee0fa4a8ffc82c9aecd484be5d3f6821f87d",
    "src/nvidia/arch/nvalloc/unix/include/nv-ioctl.h": "65778345a796fce81827bbc63bd26fe80c60dbe970007009ae902f0a7f6e730f",
    "src/nvidia/arch/nvalloc/unix/include/nv-unix-nvos-params-wrappers.h": "d3ff263781baae28ade28d5fd7a9f69d2019e8f4ca7bfb5675fa280be77792e5",
    "src/nvidia/arch/nvalloc/unix/include/nv_escape.h": "12850ee7368dbfeba1e2392f9ff7fb44563d88ed12cbf478d0c0f61a03763570",
    "src/nvidia/arch/nvalloc/unix/include/nv.h": "cd3631cac31133639babd711d5101b8ed1d3d953adb5df0b21f888fd0f3eb799",
    "src/nvidia/arch/nvalloc/unix/src/escape.c": "dad7e4a427d6f045d2e11a60837e2f73567321426e24e399cf5b45d0bcf724a7",
    "src/nvidia/arch/nvalloc/unix/src/osapi.c": "bbb08710a4674408530e40146913b2ea328e2ba921c61f2a05bc31f8593416aa",
}

PINNED_R595_FILES = {
    "src/common/sdk/nvidia/inc/nvos.h": "5786e4c046f08dd627f13760474599624d578325938fe269cb4321c2e3502c02",
    "src/nvidia/arch/nvalloc/unix/include/nv-ioctl-numbers.h": "7a9d2670092496aca00b5109b61e41c90c9f66ace404965a728d692b77191352",
    "src/nvidia/arch/nvalloc/unix/include/nv-ioctl.h": "c2aa6dad513c8dd1ae9bd412b649ccf1928c45dccf32adbbce8a3bed28420f48",
    "src/nvidia/arch/nvalloc/unix/include/nv-unix-nvos-params-wrappers.h": "d3ff263781baae28ade28d5fd7a9f69d2019e8f4ca7bfb5675fa280be77792e5",
    "src/nvidia/arch/nvalloc/unix/include/nv_escape.h": "51da358aac86eba22c9ca9db137cd2b41e36f433b9848f99dbc1ce744f5115e7",
    "src/nvidia/arch/nvalloc/unix/include/nv.h": "4ceb693ba3cc209239b24d8365f7a87e954eeebed68b2518e06e0b1571623d16",
    "src/nvidia/arch/nvalloc/unix/src/escape.c": "39f28fe5883582f3447d367834c7272ae2a3374d2b97b1e0bc2b110efb7e5fc9",
    "src/nvidia/arch/nvalloc/unix/src/osapi.c": "e05c1d00b6bc3e8d08ff7b901050dd654051e1ca88ec065acb314c9f977e708a",
}


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class IoctlShapeAbiLayoutTests(unittest.TestCase):
    def test_r580_and_r595_headers_encode_the_observed_packet_layouts(self):
        for relative, expected in PINNED_R580_HEADERS.items():
            with self.subTest(source="R580", path=relative):
                self.assertEqual(_sha256(R580 / relative), expected)

        self.assertEqual(_sha256(R595_ARCHIVE), R595_ARCHIVE_SHA256)
        prefix = "open-gpu-kernel-modules-595.99.02/"
        with tarfile.open(R595_ARCHIVE, "r:gz") as archive:
            for relative, expected in PINNED_R595_FILES.items():
                with self.subTest(source="R595", path=relative):
                    member = archive.extractfile(prefix + relative)
                    self.assertIsNotNone(member)
                    archived = member.read()
                    self.assertEqual(archived, (R595 / relative).read_bytes())
                    self.assertEqual(hashlib.sha256(archived).hexdigest(), expected)

        with tempfile.TemporaryDirectory(prefix="ioctl-shape-abi-") as temporary:
            output = Path(temporary) / "layout"
            for source_name, source_root in (("R580", R580), ("R595", R595)):
                with self.subTest(source=source_name):
                    includes = (
                        source_root / "src/common/sdk/nvidia/inc",
                        source_root / "src/common/inc",
                        source_root / "src/nvidia/arch/nvalloc/unix/include",
                        source_root / "kernel-open/common/inc",
                    )
                    command = [
                        "cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        *("-I" + str(path) for path in includes),
                        str(FIXTURE), "-o", str(output),
                    ]
                    compiled = subprocess.run(
                        command, capture_output=True, text=True, timeout=30
                    )
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    executed = subprocess.run(
                        [str(output)], capture_output=True, text=True, timeout=5
                    )
                    self.assertEqual(executed.returncode, 0, executed.stderr)

    def test_pinned_sources_route_each_request_to_its_declared_operation(self):
        sources = (("R580", R580), ("R595", R595))
        for version, source_root in sources:
            with self.subTest(source=version):
                escape = (source_root / "src/nvidia/arch/nvalloc/unix/src/escape.c").read_text()
                osapi = (source_root / "src/nvidia/arch/nvalloc/unix/src/osapi.c").read_text()
                map_start = escape.index("case NV_ESC_RM_MAP_MEMORY:")
                map_end = escape.index("case NV_ESC_RM_UNMAP_MEMORY:", map_start)
                map_case = escape[map_start:map_end]
                for token in (
                    "dataSize != sizeof(*pApi)", "NV_CTL_DEVICE_ONLY(nv)",
                    "Nv04MapMemoryWithSecInfo(pParms, secInfo)",
                    "rm_create_mmap_context(", "Nv04UnmapMemoryWithSecInfo(&params, secInfo)",
                ):
                    self.assertIn(token, map_case)

                update_start = escape.index("case NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO:")
                update_case = escape[update_start:escape.find("\n        case ", update_start + 1)]
                for token in (
                    "dataSize != sizeof(*pApi)", "NV_CTL_DEVICE_ONLY(nv)",
                    "NvP64_VALUE(pApi->pOldCpuAddress)",
                    "NvP64_VALUE(pApi->pNewCpuAddress)", "rm_update_device_mapping_info(",
                ):
                    self.assertIn(token, update_case)

                event_start = osapi.index("case NV_ESC_ALLOC_OS_EVENT:")
                event_case = osapi[event_start:osapi.index("case NV_ESC_FREE_OS_EVENT:", event_start)]
                for token in (
                    "dataSize != sizeof(nv_ioctl_alloc_os_event_t)",
                    "allocate_os_event(pApi->hClient, nvfp, pApi->fd)",
                ):
                    self.assertIn(token, event_case)

                free_start = osapi.index("case NV_ESC_FREE_OS_EVENT:")
                free_case = osapi[free_start:osapi.index("case NV_ESC_RM_GET_EVENT_DATA:", free_start)]
                for token in (
                    "dataSize != sizeof(nv_ioctl_free_os_event_t)",
                    "free_os_event(pApi->hClient, pApi->fd)",
                ):
                    self.assertIn(token, free_case)


if __name__ == "__main__":
    unittest.main()
