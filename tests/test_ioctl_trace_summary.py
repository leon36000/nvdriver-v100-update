# SPDX-License-Identifier: MIT
import importlib.util
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ioctl_summary", ROOT / "tools/summarize_rm_ioctl_trace.py")
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


class IoctlSummaryTests(unittest.TestCase):
    def test_packet_lengths_match_actual_linux_and_nvidia_headers(self):
        source_root = ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "sizes.c").write_text(
                '#include <sys/ioctl.h>\n#include <stdio.h>\n#include <nvos.h>\n'
                '#include <nv_escape.h>\nint main(void) {\n'
                'printf("%lx %lx\\n", (unsigned long)_IOC(_IOC_READ|_IOC_WRITE,\'F\',NV_ESC_RM_ALLOC,sizeof(NVOS21_PARAMETERS)), '
                '(unsigned long)_IOC(_IOC_READ|_IOC_WRITE,\'F\',NV_ESC_RM_ALLOC,sizeof(NVOS64_PARAMETERS))); return 0; }\n')
            includes = [source_root / part for part in
                        ("kernel-open/common/inc", "src/common/sdk/nvidia/inc",
                         "src/common/inc", "src/nvidia/arch/nvalloc/unix/include")]
            subprocess.run(["cc", *["-I" + str(p) for p in includes], str(path / "sizes.c"),
                            "-o", str(path / "sizes")], capture_output=True, check=True)
            numbers = subprocess.check_output([str(path / "sizes")], text=True).split()
        raw = "\n".join(f"7 ioctl(8</dev/nvidiactl<char 195:255>>, 0x{number}, 0x123) = 0" for number in numbers)
        result = SUMMARY.summarize(raw)
        self.assertEqual(result["rm_alloc_packet_sizes"], [{"bytes": 32, "count": 1}, {"bytes": 48, "count": 1}])

    def test_transport_success_is_not_payload_or_uvm_validation(self):
        raw = ('7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0x123) = -1 EINVAL (Invalid argument)\n'
               '7 ioctl(9</dev/nvidia-uvm<char 510:0>>, 0x27, 0x123) = 0\n')
        result = SUMMARY.summarize(raw)
        self.assertEqual(result["parsed_calls"], 2)
        self.assertEqual(result["negative_syscall_returns"], 1)
        for key in ("payload_status_observed", "root_class_or_payload_pointers_observed", "uvm_workload_validated"):
            self.assertFalse(result[key])

    def test_empty_trace_is_never_complete(self):
        result = SUMMARY.summarize("")
        self.assertFalse(result["trace_complete"])
        self.assertEqual(result["qualification"], "empty-ioctl-trace")
        self.assertEqual(result["parsed_calls"], 0)

    def test_other_ioctl_lines_are_counted_without_retaining_arguments(self):
        raw = ("7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0x7ffed00d) = 0\n"
               "7 ioctl(1, 0x802c542a, 0x7ffe12345678) = -1 ENOTTY (Inappropriate ioctl for device)\n"
               "7 ioctl(9</dev/nvidia-uvm<char 510:0>>, 0x27, 0x77) = 0\n")
        result = SUMMARY.summarize(raw)
        self.assertTrue(result["trace_complete"])
        self.assertEqual(result["parsed_calls"], 3)
        self.assertEqual(result["other_descriptor_calls"], 1)
        serialized = json.dumps(result)
        for private_argument in ("0x7ffed00d", "0x7ffe12345678", "0x77", "Inappropriate ioctl"):
            self.assertNotIn(private_argument, serialized)

    def test_unparsed_ioctl_lines_are_hashed_and_redacted(self):
        raw = "7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0xdeadbeef <unfinished ...>\n"
        result = SUMMARY.summarize(raw)
        self.assertFalse(result["trace_complete"])
        self.assertEqual(result["qualification"], "partial-ioctl-line-summary")
        self.assertEqual(result["unparsed_lines"][0]["line"], 1)
        self.assertEqual(len(result["unparsed_lines"][0]["sha256"]), 64)
        self.assertNotIn("text", result["unparsed_lines"][0])
        self.assertNotIn("deadbeef", json.dumps(result))

    def test_oversized_input_is_rejected_before_line_parsing(self):
        result = SUMMARY.summarize("x" * 257, max_bytes=256)
        self.assertFalse(result["trace_complete"])
        self.assertEqual(result["qualification"], "trace-size-limit-exceeded")
        self.assertEqual(result["parsed_calls"], 0)
        self.assertNotIn("text", json.dumps(result))

    def test_gzip_sidecar_is_hash_checked_and_private(self):
        raw = b"7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0x123) = 0\n"
        compressed = gzip.compress(raw, mtime=0)
        transport = {"gzip_bytes": len(compressed),
                     "gzip_sha256": hashlib.sha256(compressed).hexdigest(),
                     "raw_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.strace.gz"
            result = SUMMARY.write_trace_sidecar(path, compressed, transport, SUMMARY.summarize(raw))
            self.assertEqual(path.read_bytes(), compressed)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result["raw_sha256"], transport["raw_sha256"])
            with self.assertRaises(FileExistsError):
                SUMMARY.write_trace_sidecar(path, compressed, transport, SUMMARY.summarize(raw))

    def test_gzip_transport_corruption_mismatch_and_expansion_are_rejected(self):
        raw = b"7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0x123) = 0\n"
        compressed = gzip.compress(raw, mtime=0)
        transport = {"gzip_bytes": len(compressed),
                     "gzip_sha256": hashlib.sha256(compressed).hexdigest(),
                     "raw_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "never-created.gz"
            with self.assertRaises(ValueError):
                SUMMARY.write_trace_sidecar(path, compressed + b"bad", transport, SUMMARY.summarize(raw))
            self.assertFalse(path.exists())
            wrong = dict(transport, raw_sha256="0" * 64)
            with self.assertRaises(ValueError):
                SUMMARY.write_trace_sidecar(path, compressed, wrong, SUMMARY.summarize(raw))
            with self.assertRaises(ValueError):
                SUMMARY.inflate_gzip_trace(gzip.compress(b"x" * 4096), max_bytes=1024)

    def test_unknown_or_split_lines_cannot_claim_complete_coverage(self):
        result = SUMMARY.summarize('7 ioctl(8, 0xc030462b, 0x123 <unfinished ...>\n')
        self.assertEqual(result["qualification"], "partial-ioctl-line-summary")
        self.assertEqual(len(result["unparsed_lines"]), 1)
        self.assertEqual(result["parsed_calls"], 0)

    def test_node_open_trace_tracks_selected_descriptors_without_exposing_paths_or_args(self):
        raw = ("123 openat(AT_FDCWD, \"/dev/nvidiactl\", O_RDWR|O_CLOEXEC) = "
               "3</dev/nvidiactl<char 195:255>>\n"
               "123 ioctl(3</dev/nvidiactl<char 195:255>>, 0xc01046d3, 0x7ffe1234) = 0\n"
               "123 openat(AT_FDCWD, \"/dev/nvidia-uvm\", O_RDWR|O_CLOEXEC) = "
               "4</dev/nvidia-uvm<char 510:0>>\n"
               "123 openat(AT_FDCWD, \"/etc/private-cuda-token\", O_RDONLY) = 5\n"
               "123 dup(3</dev/nvidiactl<char 195:255>>) = 6</dev/nvidiactl<char 195:255>>\n"
               "123 close(6</dev/nvidiactl<char 195:255>>) = 0\n"
               "123 close_range(3, 4, 0) = 0\n")
        result = SUMMARY.summarize_node_open_trace(raw)
        self.assertTrue(result["trace_complete"])
        self.assertEqual(result["successful_selected_node_open_count"], 2)
        self.assertEqual(result["ioctl_counts_by_node"], {"nvidiactl": 1})
        self.assertEqual([row["operation"] for row in result["events"]],
                         ["open", "ioctl", "open", "dup", "close", "close_range", "close_range"])
        serialized = json.dumps(result)
        for private_value in ("private-cuda-token", "O_RDWR", "O_CLOEXEC", "0x7ffe1234", "195:255", "510:0"):
            self.assertNotIn(private_value, serialized)
        self.assertEqual(result["other_open_count"], 1)

    def test_node_open_trace_rejects_ioctl_without_observed_descriptor_identity(self):
        raw = ('123 openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3</dev/nvidiactl<char 195:255>>\n'
               '123 ioctl(9</dev/nvidiactl<char 195:255>>, 0xc020462a, 0x123) = 0\n'
               '123 close(3</dev/nvidiactl<char 195:255>>) = 0\n')
        result = SUMMARY.summarize_node_open_trace(raw)
        self.assertFalse(result["trace_complete"])
        ioctl = next(row for row in result["events"] if row["operation"] == "ioctl")
        self.assertIsNone(ioctl["file_id"])
        self.assertEqual(result["unparsed_lines"][0]["target_hint"], "descriptor")

    def test_node_open_trace_invalidates_selected_target_overwritten_by_dup2(self):
        raw = ('123 openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3</dev/nvidiactl<char 195:255>>\n'
               '123 dup2(4</dev/null>, 3</dev/nvidiactl<char 195:255>>) = 3</dev/null>\n'
               '123 close(3</dev/null>) = 0\n')
        result = SUMMARY.summarize_node_open_trace(raw)
        self.assertFalse(result["trace_complete"])
        self.assertEqual(result["selected_node_descriptors_open_at_trace_end"], 0)
        self.assertTrue(any(row["target_hint"] == "descriptor" for row in result["unparsed_lines"]))

    def test_node_open_trace_fails_closed_on_cross_task_descriptor_reuse(self):
        raw = ('123 openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3</dev/nvidiactl<char 195:255>>\n'
               '456 close(3</dev/nvidiactl<char 195:255>>) = 0\n'
               '456 openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3</dev/nvidiactl<char 195:255>>\n'
               '123 ioctl(3</dev/nvidiactl<char 195:255>>, 0xc020462a, 0x123) = 0\n')
        result = SUMMARY.summarize_node_open_trace(raw)
        self.assertFalse(result["trace_complete"])
        self.assertTrue(any(row["target_hint"] == "descriptor" for row in result["unparsed_lines"]))

    def test_node_open_trace_marks_malformed_selected_ioctl_incomplete(self):
        raw = ('123 openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3</dev/nvidiactl<char 195:255>>\n'
               '123 ioctl(3</dev/nvidiactl<char 195:255>>, INVALID, 0x123) = 0\n')
        result = SUMMARY.summarize_node_open_trace(raw)
        self.assertFalse(result["trace_complete"])
        self.assertTrue(any(row["target_hint"] == "nvidia-node" for row in result["unparsed_lines"]))
        self.assertEqual(result["ioctl_counts_by_node"], {})

    def test_node_open_trace_fails_closed_on_relative_or_unparsed_open_paths(self):
        relative = SUMMARY.summarize_node_open_trace(
            '123 openat(4</dev>, "nvidia0", O_RDWR) = 7</dev/nvidia0<char 195:0>>\n')
        self.assertFalse(relative["trace_complete"])
        self.assertEqual(relative["relative_path_open_count"], 1)
        self.assertNotIn('"nvidia0"', json.dumps(relative))
        split = SUMMARY.summarize_node_open_trace(
            '123 openat(AT_FDCWD, "/dev/nvidia0", O_RDWR <unfinished ...>\n')
        self.assertFalse(split["trace_complete"])
        self.assertEqual(len(split["unparsed_lines"]), 1)
        self.assertNotIn("/dev/nvidia0", json.dumps(split))
        cloexec = SUMMARY.summarize_node_open_trace(
            '123 openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3</dev/nvidiactl<char 195:255>>\n'
            '123 close_range(3, 3, CLOSE_RANGE_CLOEXEC) = 0\n')
        self.assertFalse(cloexec["trace_complete"])
        self.assertEqual(cloexec["selected_node_descriptors_open_at_trace_end"], 1)
        self.assertEqual(len(cloexec["unparsed_lines"]), 1)


class IoctlCaptureTests(unittest.TestCase):
    def fake_strace(self, path, body):
        path.write_text("#!/usr/bin/env python3\n" + body)
        path.chmod(0o700)
        return path

    def test_capture_uses_private_numeric_trace_and_preserves_child_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tracer = self.fake_strace(root / "strace", r'''import subprocess,sys
if sys.argv[1:] == ["--version"]:
 print("strace -- version 6.fixture"); raise SystemExit(0)
args=sys.argv[1:]
out=args[args.index("-o")+1]
cmd=args[args.index("--")+1:]
Path=None
open(out,"w").write("7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0x123) = 0\n")
raise SystemExit(subprocess.run(cmd,check=False).returncode)
''')
            trace = root / "trace.log"
            captured = SUMMARY.capture(str(tracer), str(trace), [sys.executable, "-c", "raise SystemExit(77)"],
                                      timeout=5, max_bytes=4096)
            self.assertEqual(captured["exit_code"], 77)
            self.assertFalse(captured["timed_out"])
            self.assertTrue(captured["trace"]["trace_complete"])
            self.assertEqual(captured["trace"]["summary"]["parsed_calls"], 1)
            self.assertEqual(captured["strace_version"], "strace -- version 6.fixture")
            self.assertEqual(trace.stat().st_mode & 0o777, 0o600)

    def test_capture_rejects_existing_trace_path_without_spawning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tracer = self.fake_strace(root / "strace", "raise SystemExit(90)\n")
            trace = root / "trace.log"
            trace.write_text("preserve me")
            with self.assertRaises(FileExistsError):
                SUMMARY.capture(str(tracer), str(trace), ["/bin/true"], timeout=2, max_bytes=1024)
            self.assertEqual(trace.read_text(), "preserve me")

    def test_capture_stops_at_the_hard_file_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tracer = self.fake_strace(root / "strace", r'''import sys
if sys.argv[1:] == ["--version"]:
 print("strace -- version fixture"); raise SystemExit(0)
args=sys.argv[1:]
out=args[args.index("-o")+1]
open(out,"w").write("x"*10000)
''')
            trace = root / "limited.log"
            captured = SUMMARY.capture(str(tracer), str(trace), [sys.executable, "-c", "pass"],
                                       timeout=5, max_bytes=128)
            self.assertTrue(captured["trace"]["size_limit_exceeded"])
            self.assertFalse(captured["trace"]["trace_complete"])
            self.assertLessEqual(trace.stat().st_size, 128)

    def test_capture_kills_the_process_group_on_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tracer = self.fake_strace(root / "strace", r'''import subprocess,sys,time
if sys.argv[1:] == ["--version"]:
 print("strace -- version fixture"); raise SystemExit(0)
args=sys.argv[1:]
out=args[args.index("-o")+1]
cmd=args[args.index("--")+1:]
open(out,"w").write("7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0x123) = 0\\n")
subprocess.Popen(cmd)
time.sleep(30)
''')
            trace = root / "timeout.log"
            captured = SUMMARY.capture(str(tracer), str(trace), [sys.executable, "-c", "import time; time.sleep(30)"],
                                       timeout=0.2, max_bytes=4096)
            self.assertTrue(captured["timed_out"])
            self.assertFalse(captured["trace"]["trace_complete"])

    def test_capture_supports_a_bounded_node_lifecycle_syscall_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tracer = self.fake_strace(root / "strace", r'''import subprocess,sys
if sys.argv[1:] == ["--version"]:
 print("strace -- version 6.fixture"); raise SystemExit(0)
args=sys.argv[1:]
out=args[args.index("-o")+1]
open(out,"w").write('123 openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3</dev/nvidiactl<char 195:255>>\n')
raise SystemExit(subprocess.run(args[args.index("--")+1:],check=False).returncode)
''')
            trace = root / "node.strace"
            captured = SUMMARY.capture(str(tracer), str(trace), [sys.executable, "-c", "pass"],
                timeout=5, max_bytes=4096, syscalls=SUMMARY.NODE_TRACE_SYSCALLS,
                summary_fn=SUMMARY.summarize_node_open_trace)
            self.assertIn("trace=ioctl,open,openat,openat2,close,close_range,dup,dup2,dup3,fcntl",
                          captured["argv"])
            self.assertTrue(captured["trace"]["trace_complete"])
            self.assertEqual(captured["trace"]["summary"]["successful_selected_node_open_count"], 1)


if __name__ == "__main__":
    unittest.main()
