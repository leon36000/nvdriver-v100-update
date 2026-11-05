from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.verify_llama_cuda_artifacts import (
    VerificationError,
    count_image_entries,
    matching_version_line,
    parse_needed_sonames,
    parse_cmake_cache,
    regular_file_identity,
    _resolve_dir,
    write_new_json,
)


class LlamaCudaArtifactVerifierTests(unittest.TestCase):
    def test_cmake_cache_preserves_architecture_list_and_boolean_values(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp) / "CMakeCache.txt"
            cache.write_text(
                "// generated\nCMAKE_CUDA_ARCHITECTURES:UNINITIALIZED=70-virtual;120a-real\n"
                "GGML_CUDA:BOOL=ON\nGGML_NATIVE:BOOL=OFF\n",
                encoding="utf-8",
            )
            values = parse_cmake_cache(cache)
        self.assertEqual(values["CMAKE_CUDA_ARCHITECTURES"], "70-virtual;120a-real")
        self.assertEqual(values["GGML_CUDA"], "ON")
        self.assertEqual(values["GGML_NATIVE"], "OFF")

    def test_duplicate_cmake_cache_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp) / "CMakeCache.txt"
            cache.write_text("GGML_CUDA:BOOL=ON\nGGML_CUDA:BOOL=OFF\n", encoding="utf-8")
            with self.assertRaisesRegex(VerificationError, "duplicate CMakeCache key"):
                parse_cmake_cache(cache)

    def test_malformed_cmake_cache_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp) / "CMakeCache.txt"
            cache.write_text("this is not a cache entry\n", encoding="utf-8")
            with self.assertRaisesRegex(VerificationError, "malformed CMakeCache"):
                parse_cmake_cache(cache)

    def test_resolve_dir_accepts_directories_within_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            expected = root / "source"
            expected.mkdir()
            self.assertEqual(_resolve_dir(root, "source"), expected.resolve())

    def test_resolve_dir_rejects_paths_outside_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            outside = Path(temp) / "outside"
            outside.mkdir()
            (root / "escape").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(VerificationError, "escapes project root"):
                _resolve_dir(root, "escape")

    def test_image_inventory_counts_only_requested_architecture(self):
        output = (
            "ELF file    1: libggml-cuda.1.sm_120a.cubin\n"
            "ELF file    2: libggml-cuda.2.sm_120a.cubin\n"
            "ELF file    3: libggml-cuda.3.sm_100.cubin\n"
            "PTX file    1: libggml-cuda.1.sm_70.ptx\n"
            "PTX file    2: libggml-cuda.2.sm_70.ptx\n"
        )
        self.assertEqual(count_image_entries(output, "ELF", "sm_120a"), 2)
        self.assertEqual(count_image_entries(output, "ELF", "sm_100"), 1)
        self.assertEqual(count_image_entries(output, "PTX", "sm_70"), 2)
        self.assertEqual(count_image_entries(output, "PTX", "sm_120a"), 0)

    def test_version_line_matches_case_insensitively(self):
        output = "Cuda compilation tools, release 12.9, V12.9.86\n"
        self.assertEqual(
            matching_version_line(output, "v12.9.86"),
            "Cuda compilation tools, release 12.9, V12.9.86",
        )

    def test_dynamic_dependency_parser_requires_and_sorts_sonames(self):
        output = (
            " 0x0000000000000001 (NEEDED) Shared library: [libcudart.so.12]\n"
            " 0x0000000000000001 (NEEDED) Shared library: [libcublas.so.12]\n"
        )
        self.assertEqual(parse_needed_sonames(output), ["libcublas.so.12", "libcudart.so.12"])
        with self.assertRaisesRegex(VerificationError, "no readable DT_NEEDED"):
            parse_needed_sonames("no dynamic section")
        with self.assertRaisesRegex(VerificationError, "duplicate DT_NEEDED"):
            parse_needed_sonames(output + output.splitlines()[0] + "\n")

    def test_runtime_identity_hashes_and_stats_one_open_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "libcudart.so.12"
            payload = b"runtime-library-fixture"
            path.write_bytes(payload)
            identity = regular_file_identity(path)
        self.assertEqual(identity["size_bytes"], len(payload))
        self.assertEqual(identity["sha256"], __import__("hashlib").sha256(payload).hexdigest())
        self.assertGreater(identity["inode"], 0)

    def test_receipt_writer_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "receipt.json"
            write_new_json(path, {"status": "first"})
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                write_new_json(path, {"status": "second"})
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
