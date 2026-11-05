#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rebuild unmodified Open580 RM with return thunks; never build/load a module.

This experiment addresses naked returns only. It does not qualify the complete
security properties, ABI, hardware behavior, or performance of the resulting RM.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
ARCHIVE_HASH = "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
TOP = "NVIDIA-kernel-module-source-580.178.04"
BASELINE = ROOT / "build/experiments/openrm580-baseline-v1" / TOP / "src/nvidia/_out/Linux_x86_64/nv-kernel.o"
BASELINE_HASH = "5e9219a4a263315d20757159852b35be61dfd2ce75dcd2ca90b1cd1764d6bb8a"
FLAG = "-mfunction-return=thunk-extern"
WITNESS = "resIsPartialUnmapSupported_d69453"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def build_command(source: Path, jobs: int) -> list[str]:
    if jobs < 1:
        raise ValueError("jobs must be positive")
    return ["make", "-C", str(source / "src/nvidia"), f"-j{jobs}",
            "NV_VERBOSE=1", f"EXTRA_CFLAGS={FLAG}"]


def audit_compile_commands(text: str) -> dict:
    commands = []
    for line in text.splitlines():
        if line.startswith(("$ ", "cwd:")):
            continue
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        if "-c" not in parts:
            continue
        at = parts.index("-c")
        if at + 1 >= len(parts) or not parts[at + 1].endswith(".c"):
            continue
        if FLAG not in parts:
            raise ValueError("C compilation missing the exact return-thunk flag: " + line[:200])
        commands.append(line)
    if not commands:
        raise ValueError("no actual verbose C compilation commands observed")
    digest = hashlib.sha256("\n".join(commands).encode()).hexdigest()
    return {"c_compile_count": len(commands), "all_have_exact_flag": True,
            "commands_sha256": digest, "first_command": commands[0]}


def disassembly_evidence(text: str, symbol: str) -> dict:
    body = re.search(r"^[0-9a-fA-F]+ <" + re.escape(symbol) + r">:\n(.*?)(?=^[0-9a-fA-F]+ <|^Disassembly of section|\Z)",
                     text, re.M | re.S)
    if not body:
        raise ValueError("exact witness function absent from disassembly")
    instructions = []
    relocations = []
    for line in body.group(1).splitlines():
        inst = re.match(r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*([a-z][a-z0-9]*)\b(.*)$", line)
        if inst:
            addr, raw, mnemonic, operand = inst.groups()
            instructions.append((int(addr, 16), raw.split(), mnemonic, operand.strip()))
        rel = re.match(r"^\s*([0-9a-fA-F]+):\s+R_X86_64_PLT32\s+__x86_return_thunk-0x4\s*$", line)
        if rel:
            relocations.append(int(rel.group(1), 16))
    if not instructions:
        raise ValueError("no decoded instructions in witness")
    raw_return = any(x[2] in ("ret", "retq", "retl", "retw") for x in instructions)
    jumps = [addr for addr, raw, mnemonic, operand in instructions
             if mnemonic in ("jmp", "jmpq") and raw[0] == "e9" and len(raw) == 5
             and addr + 1 in relocations]
    return {"symbol": symbol, "instruction_count": len(instructions),
            "raw_return": raw_return, "return_thunk_jump": bool(jumps),
            "thunk_jump_offsets": jumps, "disassembly": body.group(0)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / "build/experiments/openrm580-return-thunk-v1")
    parser.add_argument("--report", type=Path, default=ROOT / "evidence/r580-open-return-thunk-20261019.json")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    work, report_path = args.work_dir.resolve(), args.report.resolve()
    if work.exists() or report_path.exists():
        parser.error("scratch and report must both be new; refusing overwrite")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    logs = ROOT / "evidence/logs"
    logs.mkdir(exist_ok=True, parents=True)
    report = {"schema": "nvidia-open580-return-thunk-v1", "source_tag": "580.178.04",
              "observed_at_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "open-rm-return-thunk-compiler-experiment-only",
              "loaded_or_installed": False, "module_built": False,
              "hardware_validated": False, "full_security_qualified": False,
              "extra_cflags": [FLAG], "steps": [], "qualification": "not-started"}
    env = os.environ.copy()
    removed = []
    for name in ("CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "EXTRA_CFLAGS", "MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES", "CC", "CXX", "LD", "OBJCOPY", "TARGET_ARCH", "NV_VERBOSE", "NV_SPECTRE_V2"):
        if name in env:
            removed.append(name)
            del env[name]
    env["LC_ALL"] = "C"
    report["removed_environment_variable_names"] = removed

    def run(name: str, command: list[str], timeout: int = 900) -> str:
        path = logs / f"open580-return-thunk-{name}-{stamp}.log"
        start = time.monotonic()
        with path.open("x") as stream:
            stream.write("$ " + shlex.join(command) + f"\ncwd: {ROOT}\n\n")
            stream.flush()
            try:
                result = subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
                                        stderr=subprocess.STDOUT, timeout=timeout, check=False)
                code = result.returncode
            except subprocess.TimeoutExpired:
                stream.write(f"\nTIMEOUT after {timeout}s\n")
                code = 124
        report["steps"].append({"name": name, "argv": command, "cwd": str(ROOT),
                                "exit_code": code, "duration_seconds": round(time.monotonic() - start, 3),
                                "log": str(path), "log_sha256": sha256(path)})
        if code:
            raise RuntimeError(f"{name} failed ({code}); preserved log {path}")
        return path.read_text(errors="replace")

    try:
        if sha256(ARCHIVE) != ARCHIVE_HASH or sha256(BASELINE) != BASELINE_HASH:
            raise ValueError("source archive or reference core differs from pinned SHA-256")
        report.update(source_archive=str(ARCHIVE), archive_sha256=ARCHIVE_HASH,
                      baseline_core={"path": str(BASELINE), "sha256": BASELINE_HASH}, work_dir=str(work))
        with tarfile.open(ARCHIVE, "r:xz") as archive:
            members = archive.getmembers()
            if {m.name.split("/", 1)[0] for m in members if m.name} != {TOP}:
                raise ValueError("unexpected archive root")
            work.mkdir(parents=True)
            archive.extractall(work, members=members, filter="data")
        source = work / TOP
        original = {str(p.relative_to(source)): sha256(p) for p in source.rglob("*")
                    if p.is_file() and not p.is_symlink()}
        report["original_file_count"] = len(original)
        report["original_files_manifest_sha256"] = hashlib.sha256(
            json.dumps(original, sort_keys=True).encode()).hexdigest()
        report["compiler_version"] = run("compiler", ["cc", "--version"]).splitlines()[3:5]
        build_log = run("rm-build", build_command(source, args.jobs))
        report["compile_commands"] = audit_compile_commands(build_log)
        core = source / "src/nvidia/_out/Linux_x86_64/nv-kernel.o"
        report["artifact"] = {"path": str(core), "sha256": sha256(core), "bytes": core.stat().st_size}
        nm = run("core-undefined", ["nm", "-u", str(core)])
        und = {line.split()[-1] for line in nm.splitlines() if re.match(r"^\s+U\s+", line)}
        report["core_undefined_symbols"] = sorted(und)
        if "__x86_return_thunk" not in und:
            raise ValueError("built core does not import return thunk")
        report["witness"] = {}
        for label, path in (("baseline", BASELINE), ("return_thunk", core)):
            text = run(label + "-witness", ["objdump", "-dr", "--disassemble=" + WITNESS, str(path)])
            report["witness"][label] = disassembly_evidence(text, WITNESS)
        before, after = report["witness"]["baseline"], report["witness"]["return_thunk"]
        if not before["raw_return"] or before["return_thunk_jump"] or after["raw_return"] or not after["return_thunk_jump"]:
            raise ValueError("witness disassembly does not demonstrate the expected return transformation")
        changed = [name for name, digest in original.items()
                   if not (source / name).is_file() or sha256(source / name) != digest]
        report["changed_original_files"] = changed
        report["source_files_unchanged"] = not changed
        report["archive_unchanged"] = sha256(ARCHIVE) == ARCHIVE_HASH
        report["baseline_core_unchanged"] = sha256(BASELINE) == BASELINE_HASH
        if changed or not report["archive_unchanged"] or not report["baseline_core_unchanged"]:
            raise ValueError("an immutable input changed")
        report["qualification"] = "compiled-rm-and-witness-verified-only"
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["error"] = f"{type(error).__name__}: {error}"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"report": str(report_path), "status": report["status"],
                      "qualification": report["qualification"], "error": report.get("error")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
