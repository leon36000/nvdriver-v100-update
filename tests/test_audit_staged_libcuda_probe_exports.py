# SPDX-License-Identifier: MIT
"""CPU tests for static CUDA probe/libcuda symbol-surface auditing."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.audit_staged_libcuda_probe_exports import (  # noqa: E402
    extract_probe_symbols,
    parse_nm_exports,
)


class AuditStagedLibcudaProbeExportsTests(unittest.TestCase):
    def test_extracts_core_and_conditional_symbols(self):
        source = '''
        LOAD(init, "cuInit");
        LOAD(copy, "cuMemcpyDtoH_v2");
        auto x = symbol<decltype(graph)>("cuGraphCreate");
        dlsym(library, "cuMemPrefetchAsync_v2");
        '''
        result = extract_probe_symbols(source)
        self.assertEqual(result["core"], ["cuInit", "cuMemcpyDtoH_v2"])
        self.assertEqual(result["conditional"], ["cuGraphCreate", "cuMemPrefetchAsync_v2"])
        self.assertEqual(len(result["all"]), 4)

    def test_requires_recognizable_core_lookup(self):
        with self.assertRaisesRegex(ValueError, "no recognizable mandatory"):
            extract_probe_symbols('dlsym(library, "cuInit");')

    def test_nm_parser_keeps_defined_cuda_exports_and_strips_versions(self):
        exports = parse_nm_exports("""\
0000000000001000 T cuInit
0000000000002000 T cuGraphCreate@@libcuda.so.1
                 U cuMissing
0000000000003000 W helper
""")
        self.assertEqual(exports, {"cuInit", "cuGraphCreate"})


if __name__ == "__main__":
    unittest.main()
