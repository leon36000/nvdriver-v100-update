# SPDX-License-Identifier: MIT
"""Static dependency inventory tests; no kernel build, GPU, or module load."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "rm_external_dependencies", ROOT / "tools/audit_rm_external_dependencies.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RmExternalDependencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def compile_object(self, name, source):
        if not shutil.which("cc") or not shutil.which("nm"):
            self.skipTest("cc and nm are required for ELF provider fixture")
        c_path = self.root / f"{name}.c"
        obj_path = self.root / f"{name}.o"
        c_path.write_text(source)
        subprocess.run(["cc", "-c", str(c_path), "-o", str(obj_path)],
                       check=True, capture_output=True)
        return obj_path

    def test_nm_provider_scan_separates_strong_and_weak_definitions(self):
        self.compile_object(
            "providers",
            "int exact_provider(void) { return 5; }\n"
            "__attribute__((weak)) int weak_candidate(void) { return 6; }\n")
        strong, weak, common, manifest = MODULE.scan_object_providers(
            {"exact_provider", "weak_candidate", "missing_provider"},
            [("fixture", self.root)])
        self.assertEqual(len(strong["exact_provider"]), 1)
        self.assertEqual(strong["exact_provider"][0]["nm_type"], "T")
        self.assertEqual(len(weak["weak_candidate"]), 1)
        self.assertEqual(strong["weak_candidate"], [])
        self.assertEqual(strong["missing_provider"], [])
        self.assertEqual(common["missing_provider"], [])
        self.assertEqual(manifest[0]["artifact_count"], 1)
        self.assertEqual(len(manifest[0]["sha256"]), 64)

    def test_source_definition_is_candidate_not_link_resolution(self):
        src = self.root / "kernel-open" / "nvidia"
        src.mkdir(parents=True)
        source = src / "shim.c"
        source.write_text(
            "/* fake_provider() in a comment must not count */\n"
            "int fake_provider(void)\n{ return 7; }\n"
            "static int internal_provider(void) { return 8; }\n"
            "int global_state = 0;\n"
            "int option_table[] = { 1, 2 };\n"
            "extern int declaration_only(void);\n"
            "int caller(void) { global_state = 1; return fake_provider(); }\n")
        result, inventory, occurrence_counts = MODULE.scan_source_candidates(
            {"fake_provider", "internal_provider", "declaration_only", "global_state", "option_table",
             "absent_provider"},
            [("open580", self.root)])
        self.assertEqual(result["fake_provider"][0]["kind"],
                         "function-definition-syntax-candidate")
        self.assertEqual(result["declaration_only"], [])
        self.assertEqual(result["fake_provider"][0]["linkage_hint"],
                         "external-linkage-syntax-candidate")
        self.assertEqual(result["internal_provider"][0]["linkage_hint"],
                         "static-internal-linkage-not-a-global-provider")
        self.assertEqual([item["line"] for item in result["global_state"]], [5])
        self.assertEqual(result["global_state"][0]["kind"],
                         "global-object-definition-syntax-candidate")
        self.assertEqual(result["option_table"][0]["kind"],
                         "global-object-definition-syntax-candidate")
        self.assertEqual(result["absent_provider"], [])
        self.assertFalse(result["fake_provider"][0]["link_verified"])
        self.assertEqual(inventory[0]["file_count"], 1)
        self.assertEqual(len(inventory[0]["sha256"]), 64)
        self.assertGreater(occurrence_counts["fake_provider"]["open580"], 1)

    def test_literal_kbuild_source_membership_is_distinct_from_provider_proof(self):
        (self.root / "kernel-open/nvidia").mkdir(parents=True)
        (self.root / "kernel-open/nvidia/nvidia-sources.Kbuild").write_text(
            "NVIDIA_SOURCES += nvidia/shim.c\n")
        (self.root / "src/nvidia").mkdir(parents=True)
        (self.root / "src/nvidia/srcs.mk").write_text(
            "SRCS += src/crypt.c\n")
        entries, manifests = MODULE.load_source_build_lists(self.root)
        self.assertIn("nvidia/shim.c", entries["nvidia-kbuild"])
        self.assertIn("src/crypt.c", entries["openrm-srcs-mk"])
        self.assertEqual(MODULE._build_membership(
            "open580-source", "kernel-open/nvidia/shim.c", entries)["status"], "listed")
        self.assertEqual(MODULE._build_membership(
            "open580-source", "src/nvidia/src/crypt.c", entries)["status"], "listed")
        self.assertTrue(all(item["sha256"] for item in manifests))

    def test_real_link_evidence_411_names_and_classification_are_reproducible(self):
        evidence_path = ROOT / "evidence/same-branch-rm-link-v2-20261018.json"
        log_path = ROOT / "build/experiments/same-branch-rm-link-v2/combined-symbols.log"
        if not evidence_path.is_file() or not log_path.is_file():
            self.skipTest("canonical R580 link evidence is not present")
        evidence, _ = MODULE.load_link_evidence(evidence_path, log_path)
        names = MODULE.parse_undefined_symbols(log_path.read_text(errors="replace"))
        self.assertEqual(evidence["combined_undefined_symbol_count"], 411)
        self.assertEqual(len(names), 411)
        self.assertEqual(MODULE.classify_symbol("libspdm_sha256_new")[0], "libspdm-api")
        self.assertEqual(MODULE.classify_symbol("__x86_indirect_thunk_r10")[0],
                         "kernel-x86-thunk")
        self.assertEqual(MODULE.classify_symbol("nvswitch_os_malloc_trace")[0],
                         "nvswitch-os-adapter")
        self.assertEqual(MODULE.classify_symbol("nv_alloc_pages")[0], "nv-os-adapter")


if __name__ == "__main__":
    unittest.main()
