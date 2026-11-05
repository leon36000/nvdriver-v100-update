#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare the R580 and R595 RM P2P producer and UVM capability ABI.

The committed source excerpts are MIT-licensed upstream code. This audit is
static and deliberately makes no device, topology, CUDA, or runtime claim.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_r595_p2p_producer import _extract_function  # noqa: E402
from tools.audit_volta_uvm_capability_map import (  # noqa: E402
    _mask_c_comments_and_literals,
    _splice_c_lines,
)

R580_FUNCTION = ROOT / "tests/fixtures/upstream/nvidia-r580-p2p/580.196.07/nv_gpu_ops_p2p_excerpt.c"
R580_STRUCT = ROOT / "tests/fixtures/upstream/nvidia-r580-p2p/580.196.07/nv_uvm_p2p_caps_struct_excerpt.h"
R595_FUNCTION = ROOT / "tests/fixtures/upstream/nvidia-r595-p2p/595.112.07/nv_gpu_ops_p2p_excerpt.c"
R595_STRUCT = ROOT / "tests/fixtures/upstream/nvidia-r595-p2p/595.112.07/nv_uvm_p2p_caps_struct_excerpt.h"
DEFAULT_REPORT = ROOT / "evidence/r580-r595-p2p-abi-delta-v1-20261102.json"

EXPECTED_FIELDS = [
    {"type": "NvU32", "name": "peerIds", "count": 2},
    {"type": "NvU32", "name": "egmPeerIds", "count": 2},
    {"type": "NvU32", "name": "p2pLink", "count": 1},
    {"type": "NvU32", "name": "optimalNvlinkWriteCEs", "count": 2},
    {"type": "NvU32", "name": "totalLinkLineRateMBps", "count": 1},
    {"type": "NvU64", "name": "bar1DmaAddress", "count": 2},
    {"type": "NvU64", "name": "bar1DmaSize", "count": 2},
]
R595_ATOMIC_FIELD = {"type": "NvBool", "name": "bar1PcieAtomics", "count": 2}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular source excerpt: {path}")
    return path.read_bytes()


def _struct_fields(text: str) -> tuple[list[dict], str]:
    logical, _ = _splice_c_lines(text)
    masked = _mask_c_comments_and_literals(logical)
    match = re.search(r"(?m)^\s*typedef\s+struct\s+UvmGpuP2PCapsParams_tag\b", masked)
    if not match:
        raise ValueError("UvmGpuP2PCapsParams declaration is missing")
    opening = masked.find("{", match.end())
    if opening < 0:
        raise ValueError("UvmGpuP2PCapsParams opening brace is missing")
    depth = 0
    closing = None
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing is None:
        raise ValueError("UvmGpuP2PCapsParams structure is unbalanced")
    fields = []
    for line in masked[opening + 1:closing].splitlines():
        field = re.fullmatch(r"\s*(NvU32|NvU64|NvBool)\s+(\w+)(?:\[(\d+)\])?\s*;\s*", line)
        if field:
            fields.append({
                "type": field.group(1),
                "name": field.group(2),
                "count": int(field.group(3) or "1"),
            })
    return fields, "".join(masked[match.start():closing + 1].split())


def _compile_layout_probe(r580_struct: str, r595_struct: str) -> dict:
    compiler = shlex.split(os.environ.get("CC", "cc"))
    if not compiler or not shutil.which(compiler[0]):
        raise ValueError("a C compiler is required for the pinned x86-64 ABI layout probe")
    if platform.machine().lower() not in ("x86_64", "amd64"):
        raise ValueError("the pinned ABI layout probe is defined for x86-64 only")

    def renamed(source: str, name: str) -> str:
        return (source.replace("UvmGpuP2PCapsParams_tag", f"{name}_tag")
                      .replace("UvmGpuP2PCapsParams", name))

    c_source = f'''#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
typedef uint8_t NvU8;
typedef uint32_t NvU32;
typedef uint64_t NvU64;
typedef NvU8 NvBool;
{renamed(r580_struct, "R580P2PCaps")}
{renamed(r595_struct, "R595P2PCaps")}
int main(void) {{
    printf("%zu %zu %zu\\n", sizeof(R580P2PCaps), _Alignof(R580P2PCaps),
           offsetof(R580P2PCaps, bar1DmaAddress));
    printf("%zu %zu %zu %zu\\n", sizeof(R595P2PCaps), _Alignof(R595P2PCaps),
           offsetof(R595P2PCaps, bar1DmaAddress), offsetof(R595P2PCaps, bar1PcieAtomics));
    return 0;
}}
'''
    with tempfile.TemporaryDirectory(prefix="p2p-abi-audit-") as temp:
        source = Path(temp) / "layout.c"
        binary = Path(temp) / "layout"
        source.write_text(c_source, encoding="utf-8")
        build = subprocess.run(
            [*compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)],
            check=False, capture_output=True, text=True,
        )
        if build.returncode:
            raise ValueError(f"C layout probe failed to compile: {build.stderr.strip()}")
        run = subprocess.run([str(binary)], check=False, capture_output=True, text=True)
        if run.returncode:
            raise ValueError(f"C layout probe failed: {run.stderr.strip()}")
    try:
        old_size, old_align, old_bar1_offset = map(int, run.stdout.splitlines()[0].split())
        new_size, new_align, new_bar1_offset, atomic_offset = map(int, run.stdout.splitlines()[1].split())
    except (IndexError, ValueError) as error:
        raise ValueError("C layout probe returned malformed output") from error
    result = {
        "target": "x86_64-linux-gnu",
        "compiler": compiler,
        "r580": {"sizeof": old_size, "alignof": old_align, "bar1DmaAddress_offset": old_bar1_offset},
        "r595": {
            "sizeof": new_size,
            "alignof": new_align,
            "bar1DmaAddress_offset": new_bar1_offset,
            "bar1PcieAtomics_offset": atomic_offset,
        },
    }
    if (old_size, old_align, old_bar1_offset) != (64, 8, 32):
        raise ValueError(f"R580 layout differs from the pinned ABI expectation: {result['r580']}")
    if (new_size, new_align, new_bar1_offset, atomic_offset) != (72, 8, 32, 64):
        raise ValueError(f"R595 layout differs from the pinned ABI expectation: {result['r595']}")
    return result


def audit_branch_delta_texts(r580_function: str, r580_struct: str,
                             r595_function: str, r595_struct: str) -> dict:
    old_fn = _extract_function(r580_function, "nvGpuOpsGetP2PCaps")
    new_fn = _extract_function(r595_function, "nvGpuOpsGetP2PCaps")
    old_code, new_code = old_fn["_compact"], new_fn["_compact"]
    old_fields, old_struct_code = _struct_fields(r580_struct)
    new_fields, new_struct_code = _struct_fields(r595_struct)

    checks = {
        "r580_p2p_struct_matches_known_base_fields": old_fields == EXPECTED_FIELDS,
        "r595_retains_r580_field_prefix": new_fields[:-1] == EXPECTED_FIELDS,
        "r595_appends_two_nvbool_atomic_flags": new_fields[-1:] == [R595_ATOMIC_FIELD],
        "r580_producer_has_two_directional_bar1_dma_mappings": (
            "kbusGetBar1P2PDmaInfo_HAL(pLocalGpu,pRemoteGpu,GPU_GET_KERNEL_BUS(pRemoteGpu),"
            "&p2pCapsParams->bar1DmaAddress[0],&p2pCapsParams->bar1DmaSize[0])" in old_code
            and "kbusGetBar1P2PDmaInfo_HAL(pRemoteGpu,pLocalGpu,GPU_GET_KERNEL_BUS(pLocalGpu),"
            "&p2pCapsParams->bar1DmaAddress[1],&p2pCapsParams->bar1DmaSize[1])" in old_code
        ),
        "r580_has_no_bar1_atomic_field_or_producer_output": (
            "bar1PcieAtomics" not in old_struct_code and "bar1PcieAtomics" not in old_code
        ),
        "r580_reports_generic_pcie_link_after_bar1_probe": bool(re.search(
            r"if\(p2pCaps\.bar1Supported\)\{.*?p2pCapsParams->p2pLink=UVM_LINK_TYPE_PCIE;",
            old_code,
        )),
        "r595_maps_directional_atomic_flags_to_bar1_owners": (
            "p2pCapsParams->bar1PcieAtomics[0]=_nvGpuOpsIsBar1P2pAtomicEnabled("
            "device1->session,pLocalGpu,pRemoteGpu);" in new_code
            and "p2pCapsParams->bar1PcieAtomics[1]=_nvGpuOpsIsBar1P2pAtomicEnabled("
            "device2->session,pRemoteGpu,pLocalGpu);" in new_code
        ),
        "r595_distinguishes_bar1_from_generic_pcie_link": (
            "p2pCapsParams->p2pLink=UVM_LINK_TYPE_PCIE_BAR1;" in new_code
            and "p2pCapsParams->p2pLink=UVM_LINK_TYPE_PCIE;" in new_code
        ),
    }
    if not all(checks.values()):
        failed = ", ".join(name for name, passed in checks.items() if not passed)
        raise ValueError(f"R580/R595 P2P source contract changed or is incomplete: {failed}")

    return {
        "checks": checks,
        "struct_fields": {"r580": old_fields, "r595": new_fields},
        "source_function_fingerprints": {
            "r580_nvGpuOpsGetP2PCaps": old_fn["normalized_sha256"],
            "r595_nvGpuOpsGetP2PCaps": new_fn["normalized_sha256"],
        },
        "branch_delta": [
            "R580 UvmGpuP2PCapsParams has no bar1PcieAtomics field; R595 appends two NvBool entries.",
            "R580 reports UVM_LINK_TYPE_PCIE for the PCIe path; R595 distinguishes PCIE_BAR1 from PCIE.",
            "R580 and R595 preserve the two directional BAR1 DMA mappings in the inspected source excerpts.",
        ],
        "abi_layout": _compile_layout_probe(r580_struct, r595_struct),
        "runtime_or_hardware_validated": False,
    }


def _build_report() -> dict:
    r580_fn, r580_struct = _read(R580_FUNCTION), _read(R580_STRUCT)
    r595_fn, r595_struct = _read(R595_FUNCTION), _read(R595_STRUCT)
    text_report = audit_branch_delta_texts(
        r580_fn.decode("utf-8"), r580_struct.decode("utf-8"),
        r595_fn.decode("utf-8"), r595_struct.decode("utf-8"),
    )
    return {
        "schema": "nvidia-r580-r595-p2p-source-abi-delta-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "releases": {
            "580.196.07": {
                "source_archive_sha256": "21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084",
                "source_file_sha256": "98e4fcca21a17eb9b52793805f4d3a0f8ab9468a4f7154c0eddc2714b1443722",
                "types_file_sha256": "ee22643e79d6b7dae56ac52da517bae19b6594b1bf9564baeb68df10af6d5922",
                "nvtypes_file_sha256": "57bf6ee0fc9f604e7d6f224a3b861521526bb0b115e99a33e5704d881daca708",
                "nvbool_typedef": "typedef NvU8 NvBool;",
            },
            "595.112.07": {
                "source_archive_sha256": "567d4ba082a54ef733e7ce87c87401da488a3aabe29837c92feb19011c8250c4",
                "upstream_tag_object": "2e8dd6c0bbd2e08194b96abeb5c319717cd13682",
                "upstream_commit": "d8257d95ae5fed364163e4df51db66df8b1ee0d2",
                "source_file_sha256": "e3cd52c0eb84554ad92e8ab6436e949492f45591307ff0b149a239367a837c8f",
                "types_file_sha256": "9bbe94713cfd6215ecb74e4626c19077e386009fe340fe156f94de9693ea635e",
                "nvtypes_file_sha256": "0cadade26afecb4d7994893264467ae2cdac2c90fc1412c4d87a9a4184b25e6e",
                "nvbool_typedef": "typedef NvU8 NvBool;",
            },
        },
        "fixture_sha256": {
            "r580_function": _sha256(r580_fn),
            "r580_struct": _sha256(r580_struct),
            "r595_function": _sha256(r595_fn),
            "r595_struct": _sha256(r595_struct),
        },
        **text_report,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()
    output = args.output
    if output.exists():
        parser.error(f"refusing to overwrite existing report: {output}")
    report = _build_report()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "pass", "report": str(output), "checks": len(report["checks"]),
                      "abi_layout": report["abi_layout"], "runtime_or_hardware_validated": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
