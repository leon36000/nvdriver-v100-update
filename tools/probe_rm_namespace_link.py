#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Test RM object namespace isolation; transform only a copy of the Open object.

Relocatable linking permits unresolved symbols, not classified by this probe.
Success establishes only
symbol isolation, never kernel-module coexistence, ABI, CUDA, or licensing rights
to redistribute a combined artifact. Neither input object is modified.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def symbols(text):
    strong, names, undefined = set(), set(), set()
    for line in text.splitlines():
        fields = line.strip().split(None, 7)
        if len(fields) != 8 or not fields[0].endswith(":"):
            continue
        name, binding, index = fields[7], fields[4], fields[6]
        names.add(name)
        if index == "UND":
            undefined.add(name)
        elif (binding in {"WEAK", "UNIQUE", "GNU_UNIQUE"} or
              (binding == "GLOBAL" and index == "ABS")):
            raise ValueError(f"unsupported external definition: {binding}/{index} {name}")
        elif binding == "GLOBAL" and index != "ABS":
            strong.add(name)
    return strong, names, undefined


def probe(legacy, modern, work, prefix):
    legacy, modern, work = legacy.resolve(strict=True), modern.resolve(strict=True), work.resolve()
    if not legacy.is_file() or not modern.is_file() or legacy == modern:
        raise ValueError("two distinct regular object inputs are required")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", prefix):
        raise ValueError("prefix must be a nonempty C identifier")
    work.mkdir(parents=True, exist_ok=False)
    before = {str(path): sha256(path) for path in (legacy, modern)}
    report = {
        "schema": "nvidia-hybrid-rm-namespace-link-v1",
        "probe_tool_sha256": sha256(Path(__file__).resolve()),
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "relocatable-object-namespace-only", "input_sha256": before,
        "transformed_input": "copy-of-open-object-only", "prefix": prefix,
        "steps": [], "loaded_or_installed": False,
        "undefined_symbol_classification": "not-established",
        "kernel_exports_or_abi_validated": False, "cuda_routing_implemented": False,
        "uvm_ownership_integrated": False, "proprietary_input_modified": False,
        "redistribution_rights_established": False,
    }

    def run(name, command):
        log = work / (name + ".log")
        code = 124
        with log.open("x") as stream:
            try:
                result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                                        check=False, timeout=60)
                code = result.returncode
            except subprocess.TimeoutExpired:
                pass
        report["steps"].append({"name": name, "argv": command, "exit_code": code,
                                "log": str(log), "log_sha256": sha256(log)})
        if code:
            raise RuntimeError(f"{name} exited {code}; see {log}")
        return log.read_text()

    try:
        legacy_strong, legacy_names, legacy_undefined = symbols(run("legacy-symbols", ["readelf", "-Ws", str(legacy)]))
        open_strong, open_names, open_undefined = symbols(run("open-symbols", ["readelf", "-Ws", str(modern)]))
        overlap = sorted(legacy_strong & open_strong)
        cross_references = {
            "legacy_to_open": sorted(legacy_undefined & (open_strong - set(overlap))),
            "open_to_legacy": sorted(open_undefined & (legacy_strong - set(overlap))),
        }
        report["implicit_cross_backend_references"] = cross_references
        if any(cross_references.values()):
            raise ValueError("implicit cross-backend symbol resolution requires an explicit reviewed bridge")
        all_names = legacy_names | open_names
        if any(prefix + name in all_names for name in overlap):
            raise ValueError("a destination symbol already exists in an input")
        if any(re.search(r"\s", name) for name in overlap):
            raise ValueError("symbol-map format cannot represent whitespace in a name")
        symbol_map = work / "open-symbol-renames.txt"
        symbol_map.write_text("".join(f"{name} {prefix}{name}\n" for name in overlap))
        report.update(renamed_symbol_count=len(overlap), symbol_map=str(symbol_map),
                      symbol_map_sha256=sha256(symbol_map))
        isolated = work / "open-namespaced.o"
        run("objcopy", ["objcopy", "--redefine-syms", str(symbol_map), str(modern), str(isolated)])
        renamed_strong, _, _ = symbols(run("namespaced-symbols", ["readelf", "-Ws", str(isolated)]))
        expected_modern = (open_strong - set(overlap)) | {prefix + name for name in overlap}
        if renamed_strong != expected_modern or renamed_strong & legacy_strong:
            raise RuntimeError("namespaced strong-symbol set differs from the requested mapping")
        combined = work / "combined-rm.o"
        run("relocatable-link", ["ld", "-r", "-o", str(combined), str(legacy), str(isolated)])
        combined_strong, _, combined_undefined = symbols(run(
            "combined-symbols", ["readelf", "-Ws", str(combined)]))
        if combined_strong != legacy_strong | expected_modern:
            raise RuntimeError("combined object lost or added unexpected strong symbols")
        report.update(
            qualification="linked-objects-only", combined_strong_symbol_count=len(combined_strong),
            combined_undefined_symbol_count=len(combined_undefined),
            namespaced_open_object={"path": str(isolated), "sha256": sha256(isolated)},
            combined_object={"path": str(combined), "sha256": sha256(combined),
                             "bytes": combined.stat().st_size},
        )
    except (OSError, ValueError, RuntimeError) as error:
        report.update(qualification="failed", error=str(error))
    report["inputs_unchanged"] = before == {str(path): sha256(path) for path in (legacy, modern)}
    if not report["inputs_unchanged"]:
        report.update(qualification="failed", error="an input changed during the experiment")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-object", required=True, type=Path)
    parser.add_argument("--open-object", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path, help="new directory; overwrite refused")
    parser.add_argument("--prefix", default="hybrid595_")
    args = parser.parse_args()
    try:
        report = probe(args.legacy_object, args.open_object, args.work_dir, args.prefix)
        path = args.work_dir / "result.json"
        with path.open("x") as stream:
            stream.write(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"report": str(path.resolve()), **report}, indent=2))
        return 0 if report["qualification"] == "linked-objects-only" else 2
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
