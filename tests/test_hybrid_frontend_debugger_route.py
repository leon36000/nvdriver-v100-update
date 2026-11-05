# SPDX-License-Identifier: MIT
"""Run the production debugger-control route against CPU-only fake providers."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/hybrid_frontend.c"
FIXTURE = ROOT / "tests/fixtures/hybrid_front_debugger_exception_mask_route_test.c"
PRODUCTION_FUNCTIONS = (
    "hybrid_front_file_has_pending_quarantine",
    "hybrid_front_file_is_quarantined",
    "hybrid_front_find_root",
    "hybrid_front_find_object",
    "hybrid_front_debugger_pair_valid",
    "hybrid_front_debugger_exception_mask_valid",
    "hybrid_front_rm_control_ioctl",
    "hybrid_front_debugger_exception_mask_ioctl",
    "hybrid_front_gpu_ancestor",
)


def extract_function(source: str, symbol: str) -> str:
    """Extract a C definition by balanced braces, skipping its prototypes."""
    signature = re.compile(
        r"\bstatic\s+(?:(?:bool|long)\s+|"
        r"struct\s+hybrid_front_[A-Za-z0-9_]+\s*\*\s*)"
        + re.escape(symbol) + r"\s*\("
    )
    for match in signature.finditer(source):
        open_paren = source.find("(", match.start())
        depth = 0
        close_paren = None
        for index in range(open_paren, len(source)):
            if source[index] == "(":
                depth += 1
            elif source[index] == ")":
                depth -= 1
                if depth == 0:
                    close_paren = index
                    break
        if close_paren is None:
            continue
        body_start = source.find("{", close_paren + 1)
        declaration_end = source.find(";", close_paren + 1)
        if body_start < 0 or (declaration_end >= 0 and declaration_end < body_start):
            continue

        depth = 0
        index = body_start
        state = "code"
        while index < len(source):
            char = source[index]
            following = source[index + 1] if index + 1 < len(source) else ""
            if state == "code":
                if char == "/" and following == "*":
                    state = "block_comment"
                    index += 1
                elif char == "/" and following == "/":
                    state = "line_comment"
                    index += 1
                elif char == '"':
                    state = "string"
                elif char == "'":
                    state = "char"
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        return source[match.start():index + 1]
            elif state == "block_comment":
                if char == "*" and following == "/":
                    state = "code"
                    index += 1
            elif state == "line_comment":
                if char == "\n":
                    state = "code"
            elif state == "string":
                if char == "\\":
                    index += 1
                elif char == '"':
                    state = "code"
            elif state == "char":
                if char == "\\":
                    index += 1
                elif char == "'":
                    state = "code"
            index += 1
    raise AssertionError(f"production function definition missing: {symbol}")


class HybridFrontendDebuggerRouteTests(unittest.TestCase):
    def test_production_route_selects_registered_owner_without_cross_provider_fallback(self):
        production = SOURCE.read_text(encoding="utf-8")
        exact_functions = "\n\n".join(
            extract_function(production, symbol)
            for symbol in PRODUCTION_FUNCTIONS
        )
        harness = FIXTURE.read_text(encoding="utf-8")

        with tempfile.TemporaryDirectory(prefix="hybrid-debugger-route-") as tmp:
            c_file = Path(tmp) / "debugger_route.c"
            binary = Path(tmp) / "debugger_route"
            c_file.write_text(
                harness.replace("__PRODUCTION_FUNCTIONS__", exact_functions),
                encoding="utf-8",
            )
            compile_result = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Werror",
                 str(c_file), "-o", str(binary)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(
                compile_result.returncode, 0,
                compile_result.stdout + compile_result.stderr,
            )
            run_result = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=False,
                timeout=5,
            )
            self.assertEqual(run_result.returncode, 0,
                             run_result.stdout + run_result.stderr)
            self.assertEqual(
                run_result.stdout.strip(),
                "production frontend debugger route passed",
            )

    def test_production_route_rejects_open_owner_in_r580_uvm_build(self):
        production = SOURCE.read_text(encoding="utf-8")
        exact_functions = "\n\n".join(
            extract_function(production, symbol)
            for symbol in PRODUCTION_FUNCTIONS
        )
        harness = FIXTURE.read_text(encoding="utf-8")

        with tempfile.TemporaryDirectory(prefix="hybrid-debugger-route-r580-") as tmp:
            c_file = Path(tmp) / "debugger_route_r580.c"
            binary = Path(tmp) / "debugger_route_r580"
            c_file.write_text(
                harness.replace("__PRODUCTION_FUNCTIONS__", exact_functions),
                encoding="utf-8",
            )
            compile_result = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Werror",
                 "-DHYBRID580_UVM_ABI_R580", str(c_file), "-o", str(binary)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(
                compile_result.returncode, 0,
                compile_result.stdout + compile_result.stderr,
            )
            run_result = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=False,
                timeout=5,
            )
            self.assertEqual(run_result.returncode, 0,
                             run_result.stdout + run_result.stderr)
            self.assertEqual(
                run_result.stdout.strip(),
                "production frontend debugger route passed",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
