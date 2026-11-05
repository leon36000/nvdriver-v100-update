#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture and summarize selected-process ioctl metadata without reading payloads."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import zlib


MAX_TRACE_BYTES = 8 * 1024 * 1024
MAX_TRACE_GZIP_BYTES = 1024 * 1024
MAX_TRACE_LINE_BYTES = 16 * 1024
MAX_CAPTURE_TEXT_BYTES = 64 * 1024
LINE = re.compile(
    r"^(?P<pid>\d+)\s+ioctl\((?P<fd>[^,]+),\s*(?P<request>0x[0-9a-fA-F]+),\s*"
    r"(?P<argument>.*?)\)\s+=\s+(?P<return>-?\d+)(?:\s+.*)?$"
)
NODE = re.compile(r"</dev/nvidia(?:ctl|[0-9]+|-uvm)<char [0-9]+:[0-9]+>>")
DEVICE_PATH = re.compile(r"</dev/nvidia(?:ctl|[0-9]+|-uvm)<char [0-9]+:[0-9]+>>")
NODE_TRACE_SYSCALLS = ("ioctl", "open", "openat", "openat2", "close", "close_range",
                       "dup", "dup2", "dup3", "fcntl")
NODE_TRACE_LINE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<call>ioctl|open|openat|openat2|close|close_range|dup|dup2|dup3|fcntl)\("
    r"(?P<args>.*)\)\s+=\s+(?P<return>-?\d+)(?:<.*>)?(?:\s+.*)?$")
OPEN_PATH = re.compile(r'"(?P<path>(?:\\.|[^"\\])*)"')
FD_PREFIX = re.compile(r"^\s*(?P<fd>\d+)")
FCNTL_RAW_LINE = re.compile(
    r"^(?P<pid>\d+)\s+fcntl\((?P<args>.*)\)\s+=\s+(?P<return>-?\d+|0x[0-9a-fA-F]+)(?:<.*>)?(?:\s+.*)?$")
SELECTED_NODE_PATHS = {
    "/dev/nvidiactl": "nvidiactl",
    "/dev/nvidia-uvm": "nvidia-uvm",
}


def _selected_node(path: str) -> str | None:
    if path in SELECTED_NODE_PATHS:
        return SELECTED_NODE_PATHS[path]
    match = re.fullmatch(r"/dev/(nvidia[0-9]+)", path)
    return match.group(1) if match else None


def summarize_node_open_trace(raw: str | bytes, *, max_bytes: int = MAX_TRACE_BYTES) -> dict[str, object]:
    """Summarize selected NVIDIA node opens and descriptor use without retaining arguments."""
    if isinstance(raw, bytes):
        raw_bytes = raw
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            text = ""
    elif isinstance(raw, str):
        text = raw
        raw_bytes = raw.encode("utf-8")
    else:
        raise TypeError("trace input must be str or bytes")

    digest = hashlib.sha256(raw_bytes).hexdigest()
    empty = {
        "schema": "nvidia-hybrid-node-open-trace-v1",
        "qualification": "invalid-or-empty-node-trace",
        "trace_complete": False,
        "trace_bytes": len(raw_bytes),
        "trace_sha256": digest,
        "events": [],
        "unparsed_lines": [],
        "selected_node_open_count": 0,
        "successful_selected_node_open_count": 0,
        "selected_node_descriptors_open_at_trace_end": 0,
        "selected_node_descriptors_open_at_trace_end_by_node": {},
        "ioctl_counts_by_node": {},
        "other_open_count": 0,
        "relative_path_open_count": 0,
        "negative_syscall_returns": 0,
        "descriptor_lifecycle_scope": "selected node descriptors only; ioctl payloads and syscall arguments omitted",
    }
    if not raw_bytes:
        empty["qualification"] = "empty-node-trace"
        return empty
    if len(raw_bytes) > max_bytes:
        empty["qualification"] = "trace-size-limit-exceeded"
        return empty
    try:
        raw.decode("utf-8", "strict") if isinstance(raw, bytes) else text
    except UnicodeDecodeError:
        empty["qualification"] = "invalid-utf8-node-trace"
        return empty

    events: list[dict[str, object]] = []
    unparsed: list[dict[str, object]] = []
    active: dict[int, tuple[int, str]] = {}
    active_owner: dict[int, int] = {}
    descriptor_task_ambiguity = False
    next_file_id = 1
    selected_opens = successful_opens = other_opens = relative_opens = 0
    negative_returns = 0
    ioctl_counts: dict[str, int] = {}

    for index, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        encoded = line.encode("utf-8", "replace")
        match = NODE_TRACE_LINE.fullmatch(line) if len(encoded) <= MAX_TRACE_LINE_BYTES else None
        if match is None:
            fcntl_match = FCNTL_RAW_LINE.fullmatch(line)
            if fcntl_match is not None:
                args = fcntl_match.group("args")
                fd_text = args.split(",", 1)[0]
                annotated = DEVICE_PATH.search(fd_text)
                if annotated is None:
                    continue
                node = _selected_node(annotated.group(0)[1:].split("<char", 1)[0])
                descriptor = FD_PREFIX.match(fd_text)
                command_parts = args.split(",", 2)
                if node is None or descriptor is None or len(command_parts) < 2:
                    unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
                    continue
                command = command_parts[1].strip()
                try:
                    command_number = int(command, 0)
                except ValueError:
                    command_number = -1
                if command not in ("F_DUPFD", "F_DUPFD_CLOEXEC") and command_number not in (0, 1030):
                    continue
                source_fd, target_fd = int(descriptor.group("fd")), int(fcntl_match.group("return"), 0)
                info = active.get(source_fd)
                if info is None:
                    unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
                    continue
                if active_owner.get(source_fd) != int(fcntl_match.group("pid")):
                    descriptor_task_ambiguity = True
                    unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
                if target_fd in active and active_owner.get(target_fd) != int(fcntl_match.group("pid")):
                    descriptor_task_ambiguity = True
                    unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
                active[target_fd] = info
                active_owner[target_fd] = int(fcntl_match.group("pid"))
                events.append({"line": index, "tid": int(fcntl_match.group("pid")),
                               "operation": "dup", "fd": target_fd, "source_fd": source_fd,
                               "file_id": info[0], "node": info[1], "succeeded": True})
                continue
            if re.match(r"^\d+\s+fcntl\(", line) and "/dev/nvidia" not in line:
                # Ordinary libc descriptor-flag queries are outside this selected
                # device-node trace and their arguments are intentionally discarded.
                continue
            unparsed.append({"line": index, **_line_digest(line), "target_hint": "syscall-or-unknown"})
            continue

        tid, call = int(match.group("pid")), match.group("call")
        args, syscall_return = match.group("args"), int(match.group("return"))
        if syscall_return < 0:
            negative_returns += 1
        if call in ("open", "openat", "openat2"):
            path_match = OPEN_PATH.search(args)
            if path_match is None:
                # The path text is intentionally not retained. A relative path could
                # name an NVIDIA node through a directory descriptor, so it weakens
                # claims that all selected node opens were observed.
                relative_opens += 1
                continue
            path = path_match.group("path")
            node = _selected_node(path)
            if node is None:
                if not path.startswith("/"):
                    relative_opens += 1
                else:
                    other_opens += 1
                continue
            selected_opens += 1
            if syscall_return >= 0:
                successful_opens += 1
                file_id = next_file_id
                next_file_id += 1
                if syscall_return in active:
                    descriptor_task_ambiguity = True
                    unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
                active[syscall_return] = (file_id, node)
                active_owner[syscall_return] = tid
            else:
                file_id = None
            events.append({"line": index, "tid": tid, "operation": "open", "fd": syscall_return,
                           "file_id": file_id, "node": node, "succeeded": syscall_return >= 0})
            continue

        if call == "ioctl":
            ioctl_match = LINE.fullmatch(line)
            descriptor = FD_PREFIX.match(args)
            request_match = None
            annotated = DEVICE_PATH.search(args)
            annotated_node = (_selected_node(annotated.group(0)[1:].split("<char", 1)[0])
                              if annotated else None)
            if ioctl_match is not None:
                fd_text, request_text, argument_text, return_text = ioctl_match.group(
                    "fd", "request", "argument", "return")
                annotated = DEVICE_PATH.search(fd_text)
                if annotated:
                    annotated_node = _selected_node(annotated.group(0)[1:].split("<char", 1)[0])
                request_match = re.fullmatch(
                    r"(?P<request>0x[0-9a-fA-F]+)", request_text)
                argument_ok = re.fullmatch(r"0x[0-9a-fA-F]+", argument_text) is not None
                syscall_return = int(return_text)
                descriptor = FD_PREFIX.match(fd_text)
            else:
                argument_ok = False
            if annotated_node is None:
                continue
            if request_match is None or not argument_ok or descriptor is None:
                unparsed.append({"line": index, **_line_digest(line), "target_hint": "nvidia-node"})
                continue
            fd = int(descriptor.group("fd"))
            info = active.get(fd)
            file_id = (info[0] if info and info[1] == annotated_node and
                       not descriptor_task_ambiguity else None)
            if file_id is None:
                # An strace path annotation alone does not establish that this
                # descriptor came from an open/dup observed in this capture.
                # Keep the ioctl metadata, but fail closed on lifecycle claims.
                unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
            events.append({"line": index, "tid": tid, "operation": "ioctl", "fd": fd,
                           "file_id": file_id, "node": annotated_node,
                           "request": request_match.group("request").lower(),
                           "syscall_return": syscall_return})
            ioctl_counts[annotated_node] = ioctl_counts.get(annotated_node, 0) + 1
            continue

        descriptor = FD_PREFIX.match(args)
        if call == "close":
            if descriptor is None:
                unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
                continue
            fd = int(descriptor.group("fd"))
            info = active.get(fd)
            if info is not None:
                if active_owner.get(fd) != tid:
                    descriptor_task_ambiguity = True
                    unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
                events.append({"line": index, "tid": tid, "operation": "close", "fd": fd,
                               "file_id": info[0], "node": info[1], "succeeded": syscall_return == 0})
                if syscall_return == 0:
                    active.pop(fd, None)
                    active_owner.pop(fd, None)
            continue
        if call in ("dup", "dup2", "dup3", "fcntl"):
            if descriptor is None:
                continue
            source_fd = int(descriptor.group("fd"))
            if call == "fcntl":
                command_parts = args[descriptor.end():].lstrip().split(",", 1)
                command = command_parts[0].strip() if command_parts else ""
                try:
                    command_number = int(command, 0)
                except ValueError:
                    command_number = -1
                if command not in ("F_DUPFD", "F_DUPFD_CLOEXEC") and command_number not in (0, 1030):
                    continue
            info = active.get(source_fd)
            if syscall_return < 0:
                continue
            if info is not None and active_owner.get(source_fd) != tid:
                descriptor_task_ambiguity = True
                unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
            if call in ("dup2", "dup3") and syscall_return != source_fd:
                # A successful dup2/dup3 closes its target before installing
                # the source. Never retain a selected node under a stale FD.
                target_info = active.pop(syscall_return, None)
                target_owner = active_owner.pop(syscall_return, None)
                if target_info is not None:
                    events.append({"line": index, "tid": tid, "operation": "dup_replace",
                                   "fd": syscall_return, "file_id": target_info[0],
                                   "node": target_info[1], "succeeded": True})
                    if info is None or target_owner != tid:
                        # The replacement's origin is not established by this
                        # trace, so it could itself be an inherited selected FD.
                        descriptor_task_ambiguity = True
                        unparsed.append({"line": index, **_line_digest(line),
                                         "target_hint": "descriptor"})
            if info is not None:
                if syscall_return in active and active_owner.get(syscall_return) != tid:
                    descriptor_task_ambiguity = True
                    unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
                active[syscall_return] = info
                active_owner[syscall_return] = tid
                events.append({"line": index, "tid": tid, "operation": "dup", "fd": syscall_return,
                               "source_fd": source_fd, "file_id": info[0], "node": info[1],
                               "succeeded": True})
            elif DEVICE_PATH.search(args.split(",", 1)[0]) is not None:
                # A selected-node source annotation without a tracked identity
                # is inherited, injected, or otherwise outside observed opens.
                unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
            continue
        if call == "close_range":
            bounds = re.fullmatch(r"\s*(\d+)\s*,\s*(\d+|UINT_MAX)\s*,\s*(\S+)\s*", args)
            if bounds is None:
                unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
            elif syscall_return == 0 and bounds.group(3) not in ("0", "0x0"):
                # CLOEXEC and UNSHARE change descriptor state in ways this bounded
                # summary does not model; do not mistake them for close operations.
                unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
            elif syscall_return == 0:
                first = int(bounds.group(1))
                last = 0xFFFFFFFF if bounds.group(2) == "UINT_MAX" else int(bounds.group(2))
                for fd in list(active):
                    if first <= fd <= last:
                        if active_owner.get(fd) != tid:
                            descriptor_task_ambiguity = True
                            unparsed.append({"line": index, **_line_digest(line), "target_hint": "descriptor"})
                        info = active.pop(fd)
                        active_owner.pop(fd, None)
                        events.append({"line": index, "tid": tid, "operation": "close_range",
                                       "fd": fd, "file_id": info[0], "node": info[1], "succeeded": True})

    by_opens = sum(event["operation"] == "open" for event in events)
    from collections import Counter
    active_by_node = Counter(node for _, node in active.values())
    complete = bool(events) and not unparsed and relative_opens == 0
    qualification = ("complete-node-open-trace" if complete else
                     "partial-node-open-trace" if events or unparsed or relative_opens else
                     "no-selected-node-events")
    return {
        "schema": "nvidia-hybrid-node-open-trace-v1",
        "qualification": qualification,
        "trace_complete": complete,
        "trace_bytes": len(raw_bytes),
        "trace_sha256": digest,
        "events": events,
        "unparsed_lines": unparsed,
        "selected_node_open_count": by_opens,
        "successful_selected_node_open_count": successful_opens,
        "selected_node_descriptors_open_at_trace_end": len(active),
        "selected_node_descriptors_open_at_trace_end_by_node": dict(sorted(active_by_node.items())),
        "ioctl_counts_by_node": dict(sorted(ioctl_counts.items())),
        "other_open_count": other_opens,
        "relative_path_open_count": relative_opens,
        "negative_syscall_returns": negative_returns,
        "descriptor_lifecycle_scope": "selected node descriptors only; ioctl payloads and syscall arguments omitted",
    }


def _line_digest(line: str) -> dict[str, object]:
    data = line.encode("utf-8", "replace")
    if data.endswith(b"\n"):
        data = data[:-1]
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _empty_summary(qualification: str, trace_bytes: int) -> dict[str, object]:
    return {
        "schema": "nvidia-hybrid-ioctl-metadata-summary-v2",
        "qualification": qualification,
        "trace_complete": False,
        "trace_bytes": trace_bytes,
        "parsed_calls": 0,
        "calls": [],
        "unparsed_lines": [],
        "other_descriptor_calls": 0,
        "requests": [],
        "rm_alloc_packet_sizes": [],
        "negative_syscall_returns": 0,
        "root_class_or_payload_pointers_observed": False,
        "payload_status_observed": False,
        "uvm_workload_validated": False,
        "scope": "ioctl metadata only; no RM payload or pointed memory decoding",
    }


def summarize(raw: str | bytes, *, max_bytes: int = MAX_TRACE_BYTES) -> dict[str, object]:
    """Summarize complete strace ioctl lines, redacting every argument value."""
    if isinstance(raw, bytes):
        raw_bytes = raw
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            result = _empty_summary("invalid-utf8-trace", len(raw))
            result["trace_sha256"] = hashlib.sha256(raw).hexdigest()
            return result
    elif isinstance(raw, str):
        text = raw
        raw_bytes = raw.encode("utf-8")
    else:
        raise TypeError("trace input must be str or bytes")

    if len(raw_bytes) > max_bytes:
        result = _empty_summary("trace-size-limit-exceeded", len(raw_bytes))
        result["trace_sha256"] = hashlib.sha256(raw_bytes).hexdigest()
        return result
    if not raw_bytes:
        result = _empty_summary("empty-ioctl-trace", 0)
        result["trace_sha256"] = hashlib.sha256(raw_bytes).hexdigest()
        return result

    rows: list[dict[str, object]] = []
    unparsed: list[dict[str, object]] = []
    other = 0
    for index, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        line_bytes = line.encode("utf-8", "replace")
        match = LINE.fullmatch(line) if len(line_bytes) <= MAX_TRACE_LINE_BYTES else None
        if match is None:
            digest = _line_digest(line)
            target_hint = "nvidia-node" if "/dev/nvidia" in line else "other-or-unknown"
            unparsed.append({"line": index, **digest, "target_hint": target_hint})
            continue

        fd_text, request_text, argument_text, transport_text = match.group(
            "fd", "request", "argument", "return"
        )
        request = int(request_text, 16)
        device = DEVICE_PATH.search(fd_text)
        node = device.group(0)[1:].split("<char", 1)[0] if device else None
        # A driver ioctl argument must remain a numeric value. A decoded
        # structure is unexpected and makes the trace partial without retaining it.
        if node is not None and not re.fullmatch(r"0x[0-9a-fA-F]+", argument_text):
            digest = _line_digest(line)
            unparsed.append({"line": index, **digest, "target_hint": "nvidia-node"})
            continue

        transport = int(transport_text)
        if node is None:
            other += 1
            node_label = "other"
        else:
            node_label = node
        row: dict[str, object] = {
            "line": index,
            "pid": int(match.group("pid")),
            "node": node_label,
            "request": request_text.lower(),
            "syscall_return": transport,
        }
        if node is not None and ((request >> 8) & 0xFF) == ord("F"):
            row.update(number=request & 0xFF, bytes=(request >> 16) & 0x3FFF,
                       direction=(request >> 30) & 0x3)
        rows.append(row)

    from collections import Counter
    requests = Counter((row["node"], row["request"]) for row in rows)
    allocations = Counter(row["bytes"] for row in rows if row.get("number") == 0x2B)
    complete = bool(rows) and not unparsed
    qualification = ("complete-ioctl-line-summary" if complete else
                     "partial-ioctl-line-summary" if rows or unparsed else "empty-ioctl-trace")
    return {
        "schema": "nvidia-hybrid-ioctl-metadata-summary-v2",
        "qualification": qualification,
        "trace_complete": complete,
        "trace_bytes": len(raw_bytes),
        "trace_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "parsed_calls": len(rows),
        "calls": rows,
        "unparsed_lines": unparsed,
        "other_descriptor_calls": other,
        "requests": [{"node": node, "request": request, "count": count}
                     for (node, request), count in sorted(requests.items())],
        "rm_alloc_packet_sizes": [{"bytes": size, "count": count}
                                  for size, count in sorted(allocations.items())],
        "negative_syscall_returns": sum(row["syscall_return"] < 0 for row in rows),
        "root_class_or_payload_pointers_observed": False,
        "payload_status_observed": False,
        "uvm_workload_validated": False,
        "scope": "ioctl metadata only; no RM payload or pointed memory decoding",
    }


def _limit_trace_file(max_bytes: int) -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_bytes, max_bytes))
    os.umask(0o077)


def _decode_output(raw: bytes | None) -> str:
    if not raw:
        return ""
    text = raw.decode("utf-8", "replace")
    if len(text.encode("utf-8", "replace")) > MAX_CAPTURE_TEXT_BYTES:
        return text[:MAX_CAPTURE_TEXT_BYTES] + " [truncated]"
    return text


def capture(strace_path: str, trace_path: str, command: list[str], *, timeout: float,
            max_bytes: int = MAX_TRACE_BYTES, env: dict[str, str] | None = None,
            syscalls: tuple[str, ...] = ("ioctl",), summary_fn=None) -> dict[str, object]:
    """Run one command under bounded strace; kill its whole process group on timeout."""
    if os.name != "posix":
        raise OSError("strace capture requires a POSIX host")
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("timeout must be positive")
    if not isinstance(max_bytes, int) or max_bytes < 1 or max_bytes > MAX_TRACE_BYTES:
        raise ValueError("trace limit must be between 1 byte and the 8 MiB hard cap")
    if not command or any(not isinstance(arg, str) or "\0" in arg for arg in command):
        raise ValueError("invalid traced command")
    allowed_syscalls = set(NODE_TRACE_SYSCALLS)
    if (not isinstance(syscalls, tuple) or not syscalls or
            any(not isinstance(name, str) or name not in allowed_syscalls for name in syscalls) or
            len(set(syscalls)) != len(syscalls)):
        raise ValueError("invalid strace syscall selection")
    summarize_trace = summarize if summary_fn is None else summary_fn

    tracer = Path(strace_path).resolve(strict=True)
    if not tracer.is_file() or not os.access(tracer, os.X_OK):
        raise ValueError("strace binary is not executable")
    destination = Path(trace_path).absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("trace path already exists")
    if not destination.parent.is_dir():
        raise FileNotFoundError("private trace directory does not exist")
    parent_stat = destination.parent.stat()
    if parent_stat.st_uid != os.geteuid() or parent_stat.st_mode & 0o077:
        raise PermissionError("trace directory must be owned by the caller and mode 0700 or stricter")

    safe_env = dict(env) if env is not None else {
        key: value for key, value in os.environ.items()
        if not key.startswith(("LD_", "CUDA_", "NVIDIA_", "PYTHON"))
    }
    version_result = subprocess.run([str(tracer), "--version"], text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=safe_env, timeout=5, check=False)
    version = (version_result.stdout or version_result.stderr).strip()[:256]
    if version_result.returncode != 0 or not version.startswith("strace -- version "):
        raise RuntimeError("strace version preflight failed")

    argv = [str(tracer), "-f", "-qq", "-yy", "-X", "raw", "-e", "trace=" + ",".join(syscalls),
            "-o", str(destination), "--", *command]
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=safe_env, start_new_session=True,
                               preexec_fn=lambda: _limit_trace_file(max_bytes))
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()

    trace_bytes = b""
    size_limit_exceeded = False
    if destination.exists():
        trace_stat = destination.lstat()
        if not stat.S_ISREG(trace_stat.st_mode) or trace_stat.st_uid != os.geteuid():
            raise OSError("strace produced an unsafe trace file")
        os.chmod(destination, 0o600)
        size_limit_exceeded = trace_stat.st_size >= max_bytes
        if trace_stat.st_size <= max_bytes:
            trace_bytes = destination.read_bytes()
    trace_summary = summarize_trace(trace_bytes, max_bytes=max_bytes)
    if size_limit_exceeded:
        trace_summary["trace_complete"] = False
        trace_summary["qualification"] = "trace-size-limit-exceeded"
    trace_report = {
        "path": str(destination),
        "bytes": len(trace_bytes) if not size_limit_exceeded else destination.stat().st_size,
        "sha256": hashlib.sha256(trace_bytes).hexdigest() if not size_limit_exceeded else None,
        "trace_complete": trace_summary["trace_complete"] and not timed_out and not size_limit_exceeded,
        "size_limit_exceeded": size_limit_exceeded,
        "summary": trace_summary,
    }
    return {
        "argv": argv,
        "exit_code": process.returncode,
        "stdout": _decode_output(stdout),
        "stderr": _decode_output(stderr),
        "timed_out": timed_out,
        "strace_path": str(tracer),
        "strace_sha256": hashlib.sha256(tracer.read_bytes()).hexdigest(),
        "strace_version": version,
        "trace": trace_report,
        "raw_trace": trace_bytes,
    }


def inflate_gzip_trace(compressed: bytes, *, max_bytes: int = MAX_TRACE_BYTES) -> bytes:
    """Inflate one bounded gzip member and reject trailing or incomplete data."""
    if not isinstance(compressed, bytes) or not compressed:
        raise ValueError("compressed trace is empty")
    if len(compressed) > MAX_TRACE_GZIP_BYTES:
        raise ValueError("compressed trace exceeds the 1 MiB transport cap")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    raw = decoder.decompress(compressed, max_bytes + 1)
    if len(raw) > max_bytes or decoder.unconsumed_tail:
        raise ValueError("inflated trace exceeds the 8 MiB limit")
    tail = decoder.flush()
    raw += tail
    if len(raw) > max_bytes:
        raise ValueError("inflated trace exceeds the 8 MiB limit")
    if not decoder.eof or decoder.unused_data:
        raise ValueError("compressed trace is truncated or has trailing data")
    return raw


def write_trace_sidecar(path: str | Path, compressed: bytes, transport: dict[str, object],
                        expected_summary: dict[str, object], *,
                        require_complete: bool = True, summary_fn=None) -> dict[str, object]:
    """Verify remote trace bytes and summary, then store a private gzip sidecar."""
    if len(compressed) > MAX_TRACE_GZIP_BYTES:
        raise ValueError("compressed trace exceeds the 1 MiB transport cap")
    gzip_sha = hashlib.sha256(compressed).hexdigest()
    if (transport.get("gzip_bytes") != len(compressed) or
            transport.get("gzip_sha256") != gzip_sha):
        raise ValueError("compressed trace size or hash mismatch")
    raw = inflate_gzip_trace(compressed)
    raw_sha = hashlib.sha256(raw).hexdigest()
    if transport.get("raw_bytes") != len(raw) or transport.get("raw_sha256") != raw_sha:
        raise ValueError("raw trace size or hash mismatch")
    summarize_trace = summarize if summary_fn is None else summary_fn
    summary = summarize_trace(raw)
    if (require_complete and not summary["trace_complete"]) or summary != expected_summary:
        raise ValueError("local trace summary differs from remote capture")

    destination = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(compressed)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    return {"path": str(destination.resolve()), "compressed_bytes": len(compressed),
            "compressed_sha256": gzip_sha, "raw_bytes": len(raw), "raw_sha256": raw_sha,
            "mode": "0600", "summary": summary}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        parser.error("report already exists")
    raw = args.trace.read_bytes()
    report = summarize(raw)
    if raw and len(raw) <= MAX_TRACE_BYTES:
        report["trace"] = {"path": str(args.trace.resolve()),
                           "sha256": hashlib.sha256(raw).hexdigest()}
    report["tool_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with args.report.open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in
                      ("qualification", "parsed_calls", "rm_alloc_packet_sizes", "trace_complete")}))
    return 0 if report["trace_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
