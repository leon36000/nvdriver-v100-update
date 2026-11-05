#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inventory the external dependencies left by the R580 RM relocatable link.

This is a read-only static audit. Existing object definitions are exact symbol
observations, while source matches are explicitly only syntax candidates; neither
kind changes the fact that the recorded ``ld -r`` output leaves these names UND.
No kernel build, module load, installation, or GPU access is performed.
"""

import argparse
from bisect import bisect_right
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LINK_EVIDENCE = REPO_ROOT / "evidence/same-branch-rm-link-v2-20261018.json"
DEFAULT_COMBINED_LOG = REPO_ROOT / "build/experiments/same-branch-rm-link-v2/combined-symbols.log"
DEFAULT_OPEN_ROOT = REPO_ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04"
DEFAULT_PROPRIETARY_ROOT = REPO_ROOT / ".cache/vendor-proprietary/r580.178.04-ubuntu/usr/src/nvidia-580.178.04"
DEFAULT_OUTPUT = REPO_ROOT / "evidence/r580-external-dependencies-20261018.json"
SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".hh", ".hpp", ".s", ".S"}
ARTIFACT_SUFFIXES = {".o", ".ko", ".a"}
STRONG_NM_TYPES = set("TDBRGS")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_undefined_symbols(text):
    """Return exact unique UND names from readelf -Ws output."""
    names = set()
    for line in text.splitlines():
        fields = line.strip().split(None, 7)
        if len(fields) == 8 and fields[0].endswith(":") and fields[6] == "UND":
            names.add(fields[7])
    return names


def classify_symbol(name):
    """Name-family description only; this does not claim a provider exists."""
    if name.startswith("__x86_indirect_thunk_"):
        return "kernel-x86-thunk", "prefix __x86_indirect_thunk_; likely kernel/toolchain retpoline helper"
    if name.startswith("libspdm_"):
        return "libspdm-api", "prefix libspdm_; cryptographic/SPDM API family"
    if name.startswith("nvswitch_os_"):
        return "nvswitch-os-adapter", "prefix nvswitch_os_; NVSwitch OS adaptation API"
    if name.startswith("nvlink_"):
        return "nvlink-os-adapter", "prefix nvlink_; NVLink OS adaptation/API family"
    if name.startswith("nv_"):
        return "nv-os-adapter", "prefix nv_; NVIDIA Linux wrapper/RM integration family"
    if name.startswith("os_"):
        return "os-abstraction", "prefix os_; NVIDIA OS abstraction family"
    if name == "nvidia_caps_root":
        return "wrapper-global-state", "exact name; NVIDIA capability-root global"
    if name == "out_string":
        return "rm-output-callback", "exact name; RM output callback family"
    return "unclassified", "no recognized name-family rule"


def load_link_evidence(evidence_path, combined_log_path):
    """Validate the prior linked-objects-only evidence and its current log."""
    evidence_path, combined_log_path = Path(evidence_path), Path(combined_log_path)
    report = json.loads(evidence_path.read_text())
    if report.get("qualification") != "linked-objects-only":
        raise ValueError("same-branch evidence is not qualified as linked-objects-only")
    if report.get("scope") != "relocatable-object-namespace-only":
        raise ValueError("unexpected same-branch evidence scope")
    actual_log_hash = sha256(combined_log_path)
    step = next((item for item in report.get("steps", [])
                 if item.get("name") == "combined-symbols"), None)
    if not step or step.get("log_sha256") != actual_log_hash:
        raise ValueError("combined-symbols.log hash differs from the linked evidence")
    input_hashes = report.get("input_sha256", {})
    for raw_path, expected in input_hashes.items():
        path = Path(raw_path)
        if not path.is_file():
            raise FileNotFoundError(f"linked evidence input is missing: {path}")
        if sha256(path) != expected:
            raise ValueError(f"linked evidence input hash changed: {path}")
    return report, actual_log_hash


def _source_files(root):
    root = Path(root).resolve(strict=True)
    return root, sorted((path for path in root.rglob("*")
                         if path.is_file() and path.suffix in SOURCE_SUFFIXES),
                        key=lambda path: path.as_posix())


def _mask_comments_and_strings(text):
    """Blank comments/string literals but preserve offsets and newlines."""
    chars = list(text)
    i = 0
    state = "code"
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if state == "code":
            if ch == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                state, i = "block-comment", i + 2
                continue
            if ch == "/" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                state, i = "line-comment", i + 2
                continue
            if ch in ('"', "'"):
                state = "string" if ch == '"' else "char"
                chars[i] = " "
                i += 1
                continue
        elif state == "block-comment":
            if ch == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                state, i = "code", i + 2
                continue
            if ch != "\n":
                chars[i] = " "
        elif state == "line-comment":
            if ch == "\n":
                state = "code"
            else:
                chars[i] = " "
        else:
            quote = '"' if state == "string" else "'"
            if ch == "\\":
                chars[i] = " "
                if i + 1 < len(chars) and chars[i + 1] != "\n":
                    chars[i + 1] = " "
                    i += 2
                    continue
            elif ch == quote:
                chars[i] = " "
                state = "code"
            elif ch != "\n":
                chars[i] = " "
        i += 1
    return "".join(chars)


def _matching_paren(text, opening):
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _definition_kind(masked, start, end, file_scope_depth):
    """Return a conservative syntax candidate, never a link/provenance proof."""
    after = end
    while after < len(masked) and masked[after].isspace():
        after += 1
    if after < len(masked) and masked[after] == "(":
        close = _matching_paren(masked, after)
        if close is None:
            return None
        after = close + 1
        while True:
            while after < len(masked) and masked[after].isspace():
                after += 1
            attribute = re.match(r"(?:__attribute__|__declspec)\s*\(", masked[after:])
            if not attribute:
                break
            opening = after + attribute.end() - 1
            close = _matching_paren(masked, opening)
            if close is None:
                return None
            after = close + 1
        if after < len(masked) and masked[after] == "{":
            return "function-definition-syntax-candidate"
        if after < len(masked) and masked[after] == ";":
            return "declaration"
        return None

    # Object definitions such as `nv_cap_t *nvidia_caps_root = NULL;` or
    # `nv_parm_t nv_parms[] = { ... };`. Ignore assignments in function bodies.
    if file_scope_depth == 0 and after < len(masked) and masked[after] == "[":
        depth = 0
        closing = None
        for index in range(after, len(masked)):
            if masked[index] == "[":
                depth += 1
            elif masked[index] == "]":
                depth -= 1
                if depth == 0:
                    closing = index
                    break
        if closing is not None:
            after = closing + 1
            while after < len(masked) and masked[after].isspace():
                after += 1
    if file_scope_depth == 0 and after < len(masked) and masked[after] in "={":
        line_start = masked.rfind("\n", 0, start) + 1
        prefix = masked[line_start:start]
        if not re.search(r"\bextern\b", prefix) and not re.search(r"#\s*define\s*$", prefix):
            return "global-object-definition-syntax-candidate"
    return None


def _linkage_hint(masked, start, kind):
    statement_start = max(masked.rfind(";", 0, start), masked.rfind("}", 0, start)) + 1
    prefix = masked[statement_start:start]
    if re.search(r"\bstatic\b", prefix):
        return "static-internal-linkage-not-a-global-provider"
    if kind == "function-definition-syntax-candidate" and re.search(r"\binline\b", prefix):
        return "inline-emission-and-linkage-depend-on-language-mode-and-build-flags"
    if re.search(r"\bextern\b", prefix):
        return "extern-linkage-syntax-candidate"
    return "external-linkage-syntax-candidate"


def scan_source_candidates(symbols, roots):
    """Search C-family source roots; candidates are not compiled/link verified."""
    result = {name: [] for name in symbols}
    occurrence_counts = {name: {} for name in symbols}
    inventories = []
    token_pattern = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_])")
    target_names = set(symbols)

    for root_id, raw_root in roots:
        root, files = _source_files(raw_root)
        digest = hashlib.sha256()
        source_file_hashes = {}
        for path in files:
            try:
                raw = path.read_bytes()
            except OSError:
                raise
            file_hash = hashlib.sha256(raw).hexdigest()
            rel = path.relative_to(root).as_posix()
            source_file_hashes[rel] = file_hash
            digest.update(rel.encode("utf-8", "surrogateescape") + b"\0" +
                          file_hash.encode("ascii") + b"\n")
            text = raw.decode("utf-8", errors="replace")
            masked = _mask_comments_and_strings(text)
            lines = text.splitlines()
            line_starts = [0]
            line_starts.extend(index + 1 for index, ch in enumerate(text) if ch == "\n")
            previous_position = 0
            brace_depth = 0
            for match in token_pattern.finditer(masked):
                intervening = masked[previous_position:match.start()]
                brace_depth += intervening.count("{") - intervening.count("}")
                previous_position = match.end()
                name = match.group(0)
                if name not in target_names:
                    continue
                line_no = bisect_right(line_starts, match.start())
                table = occurrence_counts[name]
                table[root_id] = table.get(root_id, 0) + 1
                kind = _definition_kind(masked, match.start(), match.end(), brace_depth)
                if kind is None or kind == "declaration":
                    continue
                original_line = lines[line_no - 1] if line_no <= len(lines) else ""
                candidate = {
                    "root": root_id,
                    "path": rel,
                    "line": line_no,
                    "kind": kind,
                    "linkage_hint": _linkage_hint(masked, match.start(), kind),
                    "sha256": file_hash,
                    "excerpt": original_line.strip()[:240],
                    "link_verified": False,
                }
                if candidate not in result[name]:
                    result[name].append(candidate)
        inventories.append({"root": root_id, "path": str(root),
                            "file_count": len(files), "sha256": digest.hexdigest(),
                            "per_file_sha256": source_file_hashes})
    for name in result:
        result[name].sort(key=lambda item: (item["root"], item["path"], item["line"]))
    for inventory in inventories:
        inventory.pop("per_file_sha256", None)
    return result, inventories, occurrence_counts


def _artifact_files(root):
    root = Path(root).resolve(strict=True)
    return root, sorted((path for path in root.rglob("*")
                         if path.is_file() and path.suffix in ARTIFACT_SUFFIXES),
                        key=lambda path: path.as_posix())


def _source_version(root, root_id):
    readme = Path(root) / "README.md"
    if readme.is_file():
        text = readme.read_text(errors="replace")
        match = re.search(r"(?i)\bversion\s+(\d+\.\d+\.\d+)\b", text)
        if match:
            return {"version": match.group(1),
                    "version_basis": "README.md text",
                    "version_source_sha256": sha256(readme)}
    if root_id == "proprietary-r580-wrapper-source":
        match = re.search(r"nvidia-(\d+\.\d+\.\d+)$", str(root))
        if match:
            return {"version": match.group(1), "version_basis": "source-root directory name only"}
    return {"version": None, "version_basis": "not identified from the scanned root"}


def load_source_build_lists(open_root):
    """Read literal source entries from existing R580 make/Kbuild manifests."""
    root = Path(open_root).resolve(strict=True)
    manifests = []
    entries = {"nvidia-kbuild": set(), "openrm-srcs-mk": set()}
    candidates = [
        ("nvidia-kbuild", root / "kernel-open/nvidia/nvidia-sources.Kbuild",
         re.compile(r"^\s*NVIDIA_SOURCES\s*\+=\s*([^\s#]+)")),
        ("openrm-srcs-mk", root / "src/nvidia/srcs.mk",
         re.compile(r"^\s*SRCS\s*\+=\s*([^\s#]+)")),
    ]
    for key, path, pattern in candidates:
        if not path.is_file():
            manifests.append({"name": key, "path": str(path), "present": False,
                              "entry_count": 0, "sha256": None})
            continue
        count = 0
        for line in path.read_text(errors="replace").splitlines():
            match = pattern.match(line)
            if match:
                entries[key].add(match.group(1))
                count += 1
        manifests.append({"name": key, "path": str(path), "present": True,
                          "literal_entry_count": count,
                          "unique_literal_entry_count": len(entries[key]),
                          "sha256": sha256(path)})
    return entries, manifests


def _build_membership(root_id, relative_path, source_lists):
    if root_id != "open580-source":
        return {"status": "not-evaluated-for-this-source-root"}
    if relative_path.startswith("kernel-open/") and relative_path.endswith(".c"):
        item = relative_path[len("kernel-open/"):]
        included = item in source_lists["nvidia-kbuild"]
        return {"source_list": "kernel-open/nvidia/nvidia-sources.Kbuild",
                "direct_source_entry": included,
                "status": "listed" if included else "not-listed"}
    if relative_path.startswith("src/nvidia/") and relative_path.endswith(".c"):
        item = relative_path[len("src/nvidia/"):]
        included = item in source_lists["openrm-srcs-mk"]
        return {"source_list": "src/nvidia/srcs.mk",
                "direct_source_entry": included,
                "status": "listed" if included else "not-listed"}
    if relative_path.endswith((".h", ".hpp", ".hh")):
        return {"status": "header-not-a-direct-source-entry"}
    return {"status": "not-listed-in-inspected-source-manifests"}


def scan_object_providers(symbols, roots):
    """Find exact global definitions with nm; source objects are not linked here."""
    strong = {name: [] for name in symbols}
    weak = {name: [] for name in symbols}
    common = {name: [] for name in symbols}
    inventories = []
    object_paths = []
    object_meta = {}

    for root_id, raw_root in roots:
        root, files = _artifact_files(raw_root)
        manifest = hashlib.sha256()
        for path in files:
            rel = path.relative_to(root).as_posix()
            file_hash = sha256(path)
            manifest.update(rel.encode("utf-8", "surrogateescape") + b"\0" +
                            file_hash.encode("ascii") + b"\n")
            object_paths.append(path)
            object_meta[str(path)] = (root_id, root, rel, file_hash)
        inventories.append({"root": root_id, "path": str(root),
                            "artifact_count": len(files), "sha256": manifest.hexdigest()})

    if object_paths:
        command = ["nm", "-A", "-g", "--defined-only", "--format=posix"] + [str(p) for p in object_paths]
        try:
            completed = subprocess.run(command, capture_output=True, text=True,
                                       check=False, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError(f"unable to index existing object artifacts with nm: {error}") from error
        if completed.returncode != 0:
            raise RuntimeError(f"nm exited {completed.returncode}: {completed.stderr[-2000:]}")
        for line in completed.stdout.splitlines():
            path_field, separator, record = line.partition(": ")
            fields = record.split()
            if not separator or len(fields) < 2:
                continue
            name, nm_type = fields[0], fields[1]
            if name not in symbols:
                continue
            meta = object_meta.get(str(Path(path_field).resolve()))
            if not meta:
                continue
            root_id, root, rel, file_hash = meta
            provider = {"root": root_id, "path": rel, "sha256": file_hash,
                        "nm_type": nm_type,
                        "value": fields[2] if len(fields) > 2 else None,
                        "size": fields[3] if len(fields) > 3 else None}
            if nm_type in {"W", "V", "w", "v"}:
                weak[name].append(provider)
            elif nm_type in {"C", "c"}:
                common[name].append(provider)
            elif nm_type in STRONG_NM_TYPES:
                strong[name].append(provider)
    return strong, weak, common, inventories


def audit(link_evidence_path=DEFAULT_LINK_EVIDENCE,
          combined_log_path=DEFAULT_COMBINED_LOG,
          open_source_root=DEFAULT_OPEN_ROOT,
          proprietary_source_root=DEFAULT_PROPRIETARY_ROOT):
    link_evidence_path = Path(link_evidence_path).resolve(strict=True)
    combined_log_path = Path(combined_log_path).resolve(strict=True)
    open_source_root = Path(open_source_root).resolve(strict=True)
    proprietary_source_root = Path(proprietary_source_root).resolve(strict=True)
    link, log_hash = load_link_evidence(link_evidence_path, combined_log_path)
    symbols = parse_undefined_symbols(combined_log_path.read_text(errors="replace"))
    expected = link.get("combined_undefined_symbol_count")
    if expected != len(symbols):
        raise ValueError(f"linked report says {expected} UND names; log has {len(symbols)}")

    source_candidates, source_inventories, occurrence_counts = scan_source_candidates(
        symbols, [("open580-source", open_source_root),
                  ("proprietary-r580-wrapper-source", proprietary_source_root)])
    source_lists, source_list_manifests = load_source_build_lists(open_source_root)
    for candidates in source_candidates.values():
        for candidate in candidates:
            candidate["build_list_membership"] = _build_membership(
                candidate["root"], candidate["path"], source_lists)
    for item, (root_id, root) in zip(
            source_inventories,
            [("open580-source", open_source_root),
             ("proprietary-r580-wrapper-source", proprietary_source_root)]):
        item.update(_source_version(root, root_id))
    strong, weak, common, object_inventories = scan_object_providers(
        symbols, [("open580-existing-artifacts", open_source_root),
                  ("proprietary-r580-existing-artifacts", proprietary_source_root)])

    by_category = {}
    records = []
    for name in sorted(symbols):
        category, basis = classify_symbol(name)
        by_category[category] = by_category.get(category, 0) + 1
        providers = strong[name]
        source_defs = source_candidates[name]
        if providers:
            status = "exact-strong-definition-in-scanned-object-not-proven-linked"
        elif source_defs:
            status = "source-definition-syntax-candidate-uncompiled"
        elif weak[name]:
            status = "weak-object-definition-only-no-strong-provider"
        elif common[name]:
            status = "common-object-definition-only-no-strong-provider"
        else:
            status = "no-definition-found-in-scanned-objects-or-source-candidates"
        records.append({
            "name": name,
            "category": category,
            "category_basis": basis,
            "combined_link_state": "undefined-in-recorded-ld-r-output",
            "provider_search_state": status,
            "exact_strong_object_definitions": providers,
            "weak_object_definitions": weak[name],
            "common_object_definitions": common[name],
            "source_definition_candidates": source_defs,
            "source_occurrence_count_by_tree": occurrence_counts[name],
        })

    source_candidates_count = sum(bool(record["source_definition_candidates"]) for record in records)
    exact_provider_count = sum(bool(record["exact_strong_object_definitions"]) for record in records)
    return {
        "schema": "nvidia-r580-rm-external-dependency-audit-v1",
        "audit_tool_sha256": sha256(Path(__file__).resolve()),
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "static-source-and-existing-object-inventory-only",
        "scope": "411-unique-undefined-symbols-from-same-branch-relocatable-link",
        "input_evidence": {
            "link_evidence_path": str(link_evidence_path),
            "link_evidence_sha256": sha256(link_evidence_path),
            "combined_symbols_log_path": str(combined_log_path),
            "combined_symbols_log_sha256": log_hash,
            "linked_object_hashes": link.get("input_sha256", {}),
        },
        "source_roots": source_inventories,
        "source_build_manifests": source_list_manifests,
        "existing_object_artifact_roots": object_inventories,
        "counts": {
            "unique_undefined_names": len(symbols),
            "category_counts": dict(sorted(by_category.items())),
            "symbols_with_exact_strong_object_definitions": exact_provider_count,
            "symbols_with_source_definition_syntax_candidates": source_candidates_count,
            "symbols_with_no_candidate_definition": sum(
                not record["exact_strong_object_definitions"] and
                not record["source_definition_candidates"] for record in records),
            "symbols_retained_undefined_in_combined_object": len(symbols),
        },
        "interpretation_limits": [
            "The same-branch ld -r experiment still leaves every listed name UND.",
            "An nm definition in a scanned constituent object is not proof that it was included in the combined RM pair or a final kernel module.",
            "A source syntax candidate is not compiler-verified, ABI-verified, or link-verified.",
            "Literal Kbuild/source-list membership is recorded, but build conditionals and preprocessor configuration are not evaluated.",
            "Conditional compilation and build configuration are not evaluated; alternate candidates may be mutually exclusive.",
            "No kernel module build, kernel export resolution, module load, GPU test, CUDA test, or redistribution-license conclusion was performed.",
            "Prefix-based categories describe naming families; they do not establish implementation ownership or runtime semantics.",
        ],
        "symbols": records,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--link-evidence", type=Path, default=DEFAULT_LINK_EVIDENCE)
    parser.add_argument("--combined-log", type=Path, default=DEFAULT_COMBINED_LOG)
    parser.add_argument("--open-source-root", type=Path, default=DEFAULT_OPEN_ROOT)
    parser.add_argument("--proprietary-source-root", type=Path, default=DEFAULT_PROPRIETARY_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    report = audit(args.link_evidence, args.combined_log,
                   args.open_source_root, args.proprietary_source_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + ".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(args.output)
    print(json.dumps({"report": str(args.output.resolve()), "counts": report["counts"],
                      "qualification": report["qualification"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
