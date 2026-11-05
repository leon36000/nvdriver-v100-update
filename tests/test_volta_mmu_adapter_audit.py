#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for fail-closed source parsing in the Volta MMU audit."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_volta_mmu_adapter_contract import (  # noqa: E402
    audit,
    call_sites,
    extract_function,
    normalize_c,
    volta_pte_encoder_profile,
)


class VoltaMmuAdapterAuditTests(unittest.TestCase):
    @staticmethod
    def _write_pte_header(root, relative):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("""#define NV_MMU_VER2_PTE_VALID 0:0
#define NV_MMU_VER2_PTE_VALID_TRUE 0x1
#define NV_MMU_VER2_PTE_VALID_FALSE 0x0
#define NV_MMU_VER2_PTE_VOL 3:3
#define NV_MMU_VER2_PTE_VOL_TRUE 0x1
#define NV_MMU_VER2_PTE_VOL_FALSE 0x0
#define NV_MMU_VER2_PTE_PRIVILEGE 5:5
#define NV_MMU_VER2_PTE_PRIVILEGE_TRUE 0x1
#define NV_MMU_VER2_PTE_PRIVILEGE_FALSE 0x0
""")

    def test_extract_function_ignores_braces_inside_comments_and_strings(self):
        source = '''
static int sample(void)
{
    /* } must not close the function */
    const char *text = "{ still inside the string }";
    return text[0] == '{';
}
'''
        body = extract_function(source, "sample")
        self.assertIn('"{ still inside the string }"', body)
        self.assertIn("return text[0] == '{';", body)

    def test_extract_function_rejects_ambiguous_definitions(self):
        source = "static int sample(void) { return 0; }\nint sample(void) { return 1; }\n"
        with self.assertRaisesRegex(ValueError, "found 2"):
            extract_function(source, "sample")

    def test_callsite_parser_records_arguments_and_skips_definition(self):
        source = """
static NvU64 unmapped_pte(NvU64 page_size) { return 0; }
void test(void) { (void)hal->unmapped_pte(UVM_PAGE_SIZE_64K); }
"""
        rows = call_sites(source, "unmapped_pte")
        self.assertEqual([row["argument"] for row in rows], ["UVM_PAGE_SIZE_64K"])
        self.assertEqual(rows[0]["line"], 3)

    def test_normalizer_ignores_comments_but_preserves_tokens(self):
        self.assertEqual(normalize_c("return 1; /* comment */"), normalize_c("return\n1;"))
        self.assertNotEqual(normalize_c("return 1;"), normalize_c("return 2;"))

    def test_volta_pte_profile_accepts_only_exact_r580_or_two_site_extension(self):
        r580 = """
            if (aperture == UVM_APERTURE_SYS)
                aperture_bits = NV_MMU_VER2_PTE_APERTURE_SYSTEM_COHERENT_MEMORY;
            else if (aperture == UVM_APERTURE_VID)
                aperture_bits = NV_MMU_VER2_PTE_APERTURE_VIDEO_MEMORY;
            if (aperture == UVM_APERTURE_SYS) {
                pte_bits |= HWVALUE64(_MMU_VER2, PTE, ADDRESS_SYS, address);
            }
            else {
                NvU64 addr_lo = address & HWMASK64(_MMU_VER2, PTE, ADDRESS_VID);
                NvU64 addr_hi = address >> HWSIZE(_MMU_VER2, PTE, ADDRESS_VID);
                pte_bits |= HWVALUE64(_MMU_VER2, PTE, ADDRESS_VID, addr_lo);
                pte_bits |= HWVALUE64(_MMU_VER2, PTE, COMPTAGLINE, addr_hi);
            }
        """
        candidate = r580.replace(
            "else if (aperture == UVM_APERTURE_VID)",
            "else if (aperture == UVM_APERTURE_SYS_NON_COHERENT)"
            " aperture_bits = NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY;"
            " else if (aperture == UVM_APERTURE_VID)",
            1,
        ).replace(
            "if (aperture == UVM_APERTURE_SYS) {",
            "if (aperture == UVM_APERTURE_SYS ||"
            " aperture == UVM_APERTURE_SYS_NON_COHERENT) {",
            1,
        )
        self.assertEqual(volta_pte_encoder_profile(r580, r580), "r580-source-exact")
        self.assertEqual(
            volta_pte_encoder_profile(r580, candidate),
            "r595-volta-system-noncoherent-aperture-extension",
        )
        wrong_aperture = candidate.replace(
            "PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY",
            "PTE_APERTURE_SYSTEM_COHERENT_MEMORY",
            1,
        )
        self.assertIsNone(volta_pte_encoder_profile(r580, wrong_aperture))
        wrong_address_branch = candidate.replace(
            "aperture == UVM_APERTURE_SYS || aperture == UVM_APERTURE_SYS_NON_COHERENT",
            "aperture == UVM_APERTURE_SYS",
            1,
        )
        self.assertIsNone(volta_pte_encoder_profile(r580, wrong_address_branch))

    def test_audit_accepts_the_expected_64k_abi_adapter_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            r580 = base / "r580"
            r595 = base / "r595"
            candidate = base / "candidate"
            for root in (r580, r595, candidate):
                root.mkdir()
            self._write_pte_header(r580, "hwref/pascal/gp100/dev_mmu.h")
            self._write_pte_header(r580, "hwref/volta/gv100/dev_mmu.h")
            self._write_pte_header(candidate, "hwref/volta/gv100/dev_mmu.h")
            self._write_pte_header(r595, "hwref/turing/tu102/dev_mmu.h")
            (r580 / "uvm_pascal_mmu.c").write_text('''
static NvU64 unmapped_pte_pascal(NvU64 page_size)
{
    if (page_size != UVM_PAGE_SIZE_64K) return 0;
    return PTE_UNMAPPED_64K;
}
''')
            r580_volta = '''
uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_volta(NvU64 big_page_size)
{
    UVM_ASSERT(big_page_size == UVM_PAGE_SIZE_64K || big_page_size == UVM_PAGE_SIZE_128K);
    if (big_page_size == UVM_PAGE_SIZE_128K)\n        return NULL;
    return uvm_hal_mmu_mode_pascal(big_page_size);
}
static NvU64 make_pte_volta(void) { return VOLTA_PTE; }
'''
            (r580 / "uvm_volta_mmu.c").write_text(r580_volta)
            (r580 / "uvm_va_block.c").write_text('''
void clear(void) {
    hal->unmapped_pte(tree->big_page_size);
    hal->unmapped_pte(big_page_size);
    hal->unmapped_pte(UVM_PAGE_SIZE_64K);
    hal->unmapped_pte(tree->big_page_size);
    hal->unmapped_pte(big_page_size);
    hal->unmapped_pte(UVM_PAGE_SIZE_64K);
    hal->unmapped_pte(tree->big_page_size);
}
''')
            (r595 / "uvm_turing_mmu.c").write_text('''
static NvU64 unmapped_pte_turing(void) { return PTE_UNMAPPED_64K; }
static NvU64 poisoned_pte_turing(uvm_page_tree_t *tree)
{
    return WRITE_HWCONST64(tree->hal->make_pte(), PRIVILEGE, TRUE);
}
''')
            (r595 / "uvm_va_block.c").write_text('''
void clear(void) {
    hal->unmapped_pte(); hal->unmapped_pte(); hal->unmapped_pte();
    hal->unmapped_pte(); hal->unmapped_pte(); hal->unmapped_pte(); hal->unmapped_pte();
}
''')
            (candidate / "uvm_pascal_mmu.c").write_text('''
static NvU64 unmapped_pte_pascal(void) { return PTE_UNMAPPED_64K; }
static NvU64 poisoned_pte_pascal(uvm_page_tree_t *tree)
{
    return WRITE_HWCONST64(tree->hal->make_pte(), PRIVILEGE, TRUE);
}
''')
            (candidate / "uvm_volta_mmu.c").write_text(r580_volta + '''
uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_volta_r595(void)
{
    return uvm_hal_mmu_mode_volta(UVM_PAGE_SIZE_64K);
}
''')

            report = audit(r580, r595, candidate)
            self.assertTrue(all(report["checks"].values()))
            self.assertEqual(len(report["legacy_unmapped_call_sites"]), 7)
            self.assertEqual(len(report["modern_unmapped_call_sites"]), 7)
            self.assertFalse(report["runtime_or_hardware_validated"])
            self.assertEqual(report["candidate_volta_pte_encoder_profile"], "r580-source-exact")

            wrapper_path = candidate / "uvm_volta_mmu.c"
            wrapper = wrapper_path.read_text()
            wrapper_path.write_text(wrapper.replace(
                "uvm_hal_mmu_mode_volta(UVM_PAGE_SIZE_64K)",
                "uvm_hal_mmu_mode_volta(UVM_PAGE_SIZE_128K)",
            ))
            with self.assertRaisesRegex(ValueError, "source contract failed"):
                audit(r580, r595, candidate)


if __name__ == "__main__":
    unittest.main()
