#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Measure selected R580 C declaration layouts without loading a kernel module.

The probe compiles and executes tiny host programs which include the real
headers from the Open 580.178.04 source tree and the proprietary-wrapper
package.  It intentionally does not claim that these host compilation flags
match NVIDIA's kernel-module build flags or that the proprietary RM binary's
internal ABI has been recovered.
"""

import argparse
from datetime import datetime, timezone
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OPEN_ROOT = (PROJECT_ROOT / "build/experiments/openrm580-baseline-v1/"
                     "NVIDIA-kernel-module-source-580.178.04")
DEFAULT_PROP_ROOT = (PROJECT_ROOT / ".cache/vendor-proprietary/"
                     "r580.178.04-ubuntu/usr/src/nvidia-580.178.04")

TYPE_FIELDS = {
    "NvP64": (),
    "NvHandle": (),
    "nvidia_stack_t": ("size", "top", "stack"),
    "nv_state_t": ("priv", "os_state", "flags", "pci_info", "subsystem_id",
                   "gpu_id", "iovaspace_id", "iommus", "client_managed_console",
                   "is_pm_unsupported"),
    "nv_file_private_t": ("handles", "maxHandles", "deviceInstance", "gpuInstanceId",
                          "metadata", "ctl_nvfp", "ctl_nvfp_priv",
                          "register_or_refcount", "event_posting_refcount",
                          "bCleanupRmapi"),
    "NVOS00_PARAMETERS": ("hRoot", "hObjectParent", "hObjectOld", "status"),
    "NVOS21_PARAMETERS": ("hRoot", "hObjectParent", "hObjectNew", "hClass",
                           "pAllocParms", "paramsSize", "status"),
    "NVOS54_PARAMETERS": ("hClient", "hObject", "cmd", "flags", "params",
                           "paramsSize", "status"),
    "NVOS64_PARAMETERS": ("hRoot", "hObjectParent", "hObjectNew", "hClass",
                           "pAllocParms", "pRightsRequested", "paramsSize", "flags",
                           "status"),
}

IOCTL_WRAPPER_FIELDS = {
    "nv_ioctl_nvos02_parameters_with_fd": ("params", "fd"),
    "nv_ioctl_nvos33_parameters_with_fd": ("params", "fd"),
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _version(root):
    path = root / "version.mk"
    if not path.is_file():
        return {"path": str(path), "exists": False, "version": None}
    text = path.read_text(errors="replace")
    found = re.search(r"(?m)^NVIDIA_VERSION\s*=\s*(\S+)\s*$", text)
    return {"path": str(path), "exists": True,
            "sha256": sha256(path), "version": found.group(1) if found else None}


def _file_record(path):
    if not path.is_file():
        return {"path": str(path), "exists": False}
    return {"path": str(path), "exists": True, "bytes": path.stat().st_size,
            "sha256": sha256(path)}


def _header_comparison(open_path, prop_path):
    opened, prop = _file_record(open_path), _file_record(prop_path)
    result = {"open": opened, "proprietary_wrapper": prop}
    if not opened["exists"] or not prop["exists"]:
        result.update(exact_equal=None, comparison="one-or-both-files-absent")
        return result
    equal = opened["sha256"] == prop["sha256"]
    result["exact_equal"] = equal
    if not equal:
        a = open_path.read_text(errors="replace").splitlines()
        b = prop_path.read_text(errors="replace").splitlines()
        diff = list(difflib.unified_diff(a, b, fromfile="open", tofile="proprietary",
                                        n=0, lineterm=""))
        added = [line for line in diff if line.startswith("+") and not line.startswith("+++")]
        removed = [line for line in diff if line.startswith("-") and not line.startswith("---")]
        result["diff_summary"] = {
            "added_line_count": len(added), "removed_line_count": len(removed),
            "changed_line_excerpt": (added + removed)[:12],
        }
    return result


def _include_directories(open_root, prop_root):
    return {
        "open": [
            open_root / "kernel-open/common/inc",
            open_root / "src/common/sdk/nvidia/inc",
            open_root / "src/common/inc",
            open_root / "src/common/inc/swref",
            open_root / "src/nvidia/arch/nvalloc/unix/include",
        ],
        "proprietary_wrapper": [
            prop_root / "common/inc",
            open_root / "src/common/sdk/nvidia/inc",
            open_root / "src/common/inc",
            open_root / "src/common/inc/swref",
            open_root / "src/nvidia/arch/nvalloc/unix/include",
        ],
    }


def _measurement_source(type_name, fields, wrapper=False):
    lines = ["#include <stddef.h>", "#include <stdio.h>", "#include <nv.h>",
             "#include <nvos.h>"]
    if wrapper:
        lines.append("#include <nv-unix-nvos-params-wrappers.h>")
    lines.extend([
        "int main(void) {",
        f'    printf("TYPE\\t%s\\t%zu\\t%zu", "{type_name}", '
        f"sizeof({type_name}), _Alignof({type_name}));",
    ])
    for field in fields:
        lines.append(
            f'    printf("\\tFIELD\\t%s\\t%zu", "{field}", '
            f"offsetof({type_name}, {field}));")
    lines.extend(["    putchar('\\n');", "    return 0;", "}"])
    return "\n".join(lines) + "\n"


def _compile_measurement(compiler, include_dirs, definitions, type_name, fields,
                         temp_root, variant, wrapper=False):
    source = _measurement_source(type_name, fields, wrapper=wrapper)
    label = f"{variant}-{type_name}"
    source_path = temp_root / f"{label}.c"
    executable = temp_root / label
    source_path.write_text(source)
    command = [compiler, "-std=gnu11", "-Wall", "-Werror"]
    command.extend(f"-D{definition}" for definition in definitions)
    command.extend(f"-I{path}" for path in include_dirs)
    command.extend([str(source_path), "-o", str(executable)])
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    result = {
        "type": type_name,
        "field_list": list(fields),
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "compile": {"argv": command, "command_display": shlex.join(command),
                    "exit_code": None, "diagnostic": ""},
        "execution": {"argv": [str(executable)], "exit_code": None, "stdout": "",
                      "diagnostic": ""},
        "layout": None,
        "qualification": "compile-failed",
    }
    try:
        compiled = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, env=env, timeout=60,
                                  check=False)
        result["compile"]["exit_code"] = compiled.returncode
        result["compile"]["diagnostic"] = compiled.stdout.strip()
    except subprocess.TimeoutExpired as error:
        result["compile"]["exit_code"] = 124
        result["compile"]["diagnostic"] = str(error)
    except OSError as error:
        result["compile"]["exit_code"] = 127
        result["compile"]["diagnostic"] = str(error)
    if result["compile"]["exit_code"] != 0:
        return result
    try:
        ran = subprocess.run([str(executable)], text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, timeout=10, check=False)
        result["execution"].update(exit_code=ran.returncode, stdout=ran.stdout.strip(),
                                   diagnostic=ran.stderr.strip())
    except (OSError, subprocess.TimeoutExpired) as error:
        result["execution"].update(exit_code=124, diagnostic=str(error))
        return result
    if result["execution"]["exit_code"] != 0:
        result["qualification"] = "execution-failed"
        return result
    try:
        line = result["execution"]["stdout"].splitlines()[0].split("\t")
        if len(line) < 4 or line[0] != "TYPE" or line[1] != type_name:
            raise ValueError("measurement output has unexpected shape")
        members = {}
        tail = line[4:]
        if len(tail) % 3:
            raise ValueError("field-offset output has unexpected shape")
        for index in range(0, len(tail), 3):
            if tail[index] != "FIELD":
                raise ValueError("field-offset marker is missing")
            members[tail[index + 1]] = int(tail[index + 2])
        result["layout"] = {"size": int(line[2]), "alignment": int(line[3]),
                            "field_offsets": members}
        if set(members) != set(fields):
            raise ValueError("reported member-offset set differs from probe")
        result["qualification"] = "compiled-and-ran-host-layout-probe"
    except (IndexError, ValueError) as error:
        result["qualification"] = "measurement-output-invalid"
        result["execution"]["diagnostic"] = str(error)
    return result


def _tool_version(compiler):
    try:
        result = subprocess.run([compiler, "--version"], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=10, check=False)
        return {"argv": [compiler, "--version"], "exit_code": result.returncode,
                "output": "\n".join(result.stdout.splitlines()[:4])}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"argv": [compiler, "--version"], "exit_code": None,
                "output": str(error)}


def _binary_facts(binary, nm):
    record = _file_record(binary)
    result = {"file": record, "qualification": "opaque-not-established",
              "layout_match_established": False,
              "reason": "ELF bytes and symbols do not expose a complete source-level RM ABI layout; no matching compiler configuration or binary-side type metadata was established."}
    if not record["exists"]:
        result["reason"] = "The proprietary wrapper package has no nv-kernel.o_binary at the expected path."
        return result
    file_cmd = shutil.which("file")
    if file_cmd:
        try:
            fact = subprocess.run([file_cmd, str(binary)], text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  timeout=20, check=False)
            result["file_identification"] = {"argv": [file_cmd, str(binary)],
                                             "exit_code": fact.returncode,
                                             "output": fact.stdout.strip()}
        except (OSError, subprocess.TimeoutExpired) as error:
            result["file_identification"] = {"exit_code": None, "output": str(error)}
    readelf = shutil.which("readelf")
    if readelf:
        try:
            fact = subprocess.run([readelf, "-h", str(binary)], text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  timeout=30, check=False)
            selected = [line.strip() for line in fact.stdout.splitlines()
                        if any(key in line for key in ("Class:", "Data:", "Type:",
                                                       "Machine:", "Number of sections:"))]
            result["elf_header"] = {"argv": [readelf, "-h", str(binary)],
                                    "exit_code": fact.returncode,
                                    "selected_output": selected}
        except (OSError, subprocess.TimeoutExpired) as error:
            result["elf_header"] = {"exit_code": None, "selected_output": [str(error)]}
    if nm:
        matches = []
        command = [nm, "-a", str(binary)]
        try:
            # Keep the full symbol stream off the Python heap and bound the
            # scan even if the binary or tool behaves unexpectedly.
            with tempfile.TemporaryFile() as symbol_stream:
                process = subprocess.Popen(command, stdout=symbol_stream,
                                           stderr=subprocess.PIPE,
                                           env={**os.environ, "LC_ALL": "C"})
                try:
                    _, stderr = process.communicate(timeout=60)
                    exit_code = process.returncode
                    diagnostic = stderr.decode(errors="replace").strip()
                except subprocess.TimeoutExpired:
                    process.kill()
                    _, stderr = process.communicate()
                    exit_code = 124
                    diagnostic = "nm scan exceeded 60 seconds"
                if exit_code == 0:
                    symbol_stream.seek(0)
                    for raw_line in symbol_stream:
                        line = raw_line.decode(errors="replace")
                        if re.search(r"nv_ioctl_nvos|NVOS(00|21|54|64)_PARAMETERS", line):
                            matches.append(line.strip())
            result["symbol_name_scan"] = {"argv": command, "exit_code": exit_code,
                                          "matching_names": matches[:50],
                                          "match_count": len(matches),
                                          "diagnostic": diagnostic}
        except OSError as error:
            result["symbol_name_scan"] = {"argv": command, "exit_code": None,
                                          "matching_names": [], "match_count": 0,
                                          "diagnostic": str(error)}
    return result


def _source_text(open_root, prop_root):
    open_kernel = open_root / "kernel-open/common/inc"
    prop_common = prop_root / "common/inc"
    open_unix = open_root / "src/nvidia/arch/nvalloc/unix/include"
    pairs = {
        "rm_nv_h": (open_kernel / "nv.h", prop_common / "nv.h"),
        "unix_nv_h": (open_unix / "nv.h", prop_common / "nv.h"),
        "kernel_nvtypes_h": (open_kernel / "nvtypes.h", prop_common / "nvtypes.h"),
        "kernel_nvstatus_h": (open_kernel / "nvstatus.h", prop_common / "nvstatus.h"),
        "nv_ioctl_h": (open_kernel / "nv-ioctl.h", prop_common / "nv-ioctl.h"),
        "nv_linux_h": (open_kernel / "nv-linux.h", prop_common / "nv-linux.h"),
        "kernel_interface_api_h": (open_kernel / "nv-kernel-interface-api.h",
                                   prop_common / "nv-kernel-interface-api.h"),
        "sdk_nvtypes_vs_wrapper_nvtypes_h": (
            open_root / "src/common/sdk/nvidia/inc/nvtypes.h",
            prop_common / "nvtypes.h"),
    }
    comparisons = {name: _header_comparison(*paths) for name, paths in pairs.items()}
    open_nvos = open_root / "src/common/sdk/nvidia/inc/nvos.h"
    prop_nvos = prop_common / "nvos.h"
    wrapper = open_unix / "nv-unix-nvos-params-wrappers.h"
    prop_wrapper = prop_root / "common/inc/nv-unix-nvos-params-wrappers.h"
    prop_nvos_paths = sorted(str(path) for path in prop_root.rglob("nvos.h"))
    prop_wrapper_paths = sorted(str(path) for path in
                                prop_root.rglob("nv-unix-nvos-params-wrappers.h"))
    open_escape = open_root / "src/nvidia/arch/nvalloc/unix/src/escape.c"
    prop_escape = prop_root / "nvidia/nv.c"
    def occurrences(path, pattern):
        if not path.is_file():
            return []
        return [{"line": index, "text": line.strip()[:300]}
                for index, line in enumerate(path.read_text(errors="replace").splitlines(), 1)
                if re.search(pattern, line)]
    return {
        "header_comparisons": comparisons,
        "nvos_header": {"open": _file_record(open_nvos),
                        "open_exists": open_nvos.is_file(),
                        "proprietary_wrapper": _file_record(prop_nvos),
                        "proprietary_wrapper_exists": bool(prop_nvos_paths),
                        "proprietary_wrapper_matches": prop_nvos_paths},
        "rm_private_declaration_guard": {
            "macro": "NVRM",
            "open_nv_h": str(open_kernel / "nv.h"),
            "proprietary_nv_h": str(prop_common / "nv.h"),
            "open_guard_line": next((index for index, line in enumerate(
                (open_kernel / "nv.h").read_text(errors="replace").splitlines(), 1)
                if line.strip() == "#ifdef NVRM"), None),
            "proprietary_guard_line": next((index for index, line in enumerate(
                (prop_common / "nv.h").read_text(errors="replace").splitlines(), 1)
                if line.strip() == "#ifdef NVRM"), None),
            "types_inside_guard": ["nvidia_stack_t", "nv_state_t", "nv_file_private_t"],
        },
        "nv_ioctl_nvos_wrappers": {
            "open_header": _file_record(wrapper),
            "proprietary_wrapper_header": _file_record(prop_wrapper),
            "proprietary_wrapper_matches": prop_wrapper_paths,
            "open_type_definitions": occurrences(wrapper, r"}\s*nv_ioctl_nvos\w+"),
            "open_escape_references": occurrences(open_escape, r"nv_ioctl_nvos\w+"),
            "proprietary_source_references": occurrences(prop_escape, r"nv_ioctl_nvos\w+"),
            "interpretation": "The nv_ioctl_nvos* names located here are wrapper structure types in the Open Unix layer, not demonstrated RM function exports. The proprietary wrapper package does not contain that header.",
        },
    }


def probe(open_root=DEFAULT_OPEN_ROOT, prop_root=DEFAULT_PROP_ROOT, compiler="cc"):
    open_root = Path(open_root).resolve(strict=True)
    prop_root = Path(prop_root).resolve(strict=True)
    if not open_root.is_dir() or not prop_root.is_dir():
        raise ValueError("both Open and proprietary source roots must be directories")
    binary = prop_root / "nvidia/nv-kernel.o_binary"
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        compiler_path = compiler
    definitions = ["NVRM=1"]
    include_dirs = _include_directories(open_root, prop_root)
    for variant, paths in include_dirs.items():
        absent = [str(path) for path in paths if not path.is_dir()]
        if absent:
            raise ValueError(f"required include directories absent for {variant}: {absent}")
    report = {
        "schema": "nvidia-r580-abi-layout-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "probe_tool": {"path": str(Path(__file__).resolve()),
                       "sha256": sha256(Path(__file__).resolve())},
        "scope": "host-compiled-declaration-layout-only; no module load or GPU access",
        "inputs": {
            "open_source_root": str(open_root),
            "open_source_version": _version(open_root),
            "proprietary_wrapper_root": str(prop_root),
            "proprietary_wrapper_version_from_path": "580.178.04",
            "binary_rm": str(binary),
        },
        "compiler": {"resolved_path": compiler_path, **_tool_version(compiler_path)},
        "source_text": _source_text(open_root, prop_root),
        "compiled_layout": {
            "language": "GNU C11 host program compiled and executed locally",
            "definitions": definitions,
            "kernel_interface_layer_defined": False,
            "kernel_module_build_flags_verified": False,
            "kernel_module_build_qualification": "not-established",
            "variants": {},
            "layout_comparison": {},
            "limits": [
                "-DNVRM=1 exposes RM declarations guarded by NVRM; it does not reproduce the kernel module build environment.",
                "NV_KERNEL_INTERFACE_LAYER and kernel conftest-generated headers are intentionally not used.",
                "NVOS declarations for the proprietary-wrapper variant are supplied by the Open SDK nvos.h because the proprietary wrapper package does not contain nvos.h; nvtypes.h and the other wrapper headers resolve from the proprietary include directory first.",
            ],
        },
        "binary_rm_abi": _binary_facts(binary, shutil.which("nm")),
        "safety": {"kernel_module_loaded": False, "gpu_accessed": False,
                   "inputs_modified": False, "installation_attempted": False},
    }
    with tempfile.TemporaryDirectory(prefix="r580-abi-layout-") as directory:
        temp_root = Path(directory)
        for variant, paths in include_dirs.items():
            values = {}
            for type_name, fields in TYPE_FIELDS.items():
                values[type_name] = _compile_measurement(
                    compiler_path, paths, definitions, type_name, fields,
                    temp_root, variant)
            report["compiled_layout"]["variants"][variant] = {
                "include_directories": [str(path) for path in paths],
                "nvos_declaration_source": (
                    "open-sdk-header-with-proprietary-wrapper-header-search-order"
                    if variant == "proprietary_wrapper"
                    else "open-sdk-header"),
                "types": values,
            }
        wrapper_header = (open_root / "src/nvidia/arch/nvalloc/unix/include/"
                          "nv-unix-nvos-params-wrappers.h")
        wrapper_values = {}
        for type_name, fields in IOCTL_WRAPPER_FIELDS.items():
            wrapper_values[type_name] = _compile_measurement(
                compiler_path, include_dirs["open"], definitions, type_name, fields,
                temp_root, "open-unix-wrapper", wrapper=True)
    report["compiled_layout"]["ioctl_wrapper_types"] = {
        "open": {"header": str(wrapper_header), "types": wrapper_values},
        "proprietary_wrapper": {
            "qualification": "not-available-in-wrapper-source",
            "header": str(prop_root / "common/inc/nv-unix-nvos-params-wrappers.h"),
            "types": {name: {"qualification": "not-compiled-source-header-absent"}
                      for name in IOCTL_WRAPPER_FIELDS},
        },
    }
    open_types = report["compiled_layout"]["variants"]["open"]["types"]
    prop_types = report["compiled_layout"]["variants"]["proprietary_wrapper"]["types"]
    for name in TYPE_FIELDS:
        left, right = open_types[name], prop_types[name]
        if left["layout"] is None or right["layout"] is None:
            status = "not-comparable"
        else:
            status = "equal" if left["layout"] == right["layout"] else "different"
        report["compiled_layout"]["layout_comparison"][name] = status
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--open-root", type=Path, default=DEFAULT_OPEN_ROOT)
    parser.add_argument("--proprietary-root", type=Path, default=DEFAULT_PROP_ROOT)
    parser.add_argument("--compiler", default="cc")
    parser.add_argument("--output", type=Path,
                        default=PROJECT_ROOT / "evidence/r580-abi-layout-20261018.json")
    args = parser.parse_args()
    try:
        report = probe(args.open_root, args.proprietary_root, args.compiler)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(json.dumps({"report": str(args.output.resolve()),
                          "layout_comparison": report["compiled_layout"]["layout_comparison"],
                          "binary_rm_abi": report["binary_rm_abi"]["qualification"]},
                         indent=2))
        failed = [f"{variant}:{name}={entry['qualification']}"
                  for variant, result in report["compiled_layout"]["variants"].items()
                  for name, entry in result["types"].items()
                  if entry["qualification"] != "compiled-and-ran-host-layout-probe"]
        failed.extend(f"open-wrapper:{name}={entry['qualification']}"
                      for name, entry in report["compiled_layout"]["ioctl_wrapper_types"]["open"]["types"].items()
                      if entry["qualification"] != "compiled-and-ran-host-layout-probe")
        return 0 if not failed else 2
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(2, str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
