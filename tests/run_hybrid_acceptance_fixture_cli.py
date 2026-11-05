# SPDX-License-Identifier: MIT
"""Test-only CLI shim that pins temporary CPU fixtures in its own process.

This module exists so the acceptance runner's report, observer, and argument
handling paths can be exercised with synthetic executables. It is not a
hardware acceptance entrypoint and must not be used outside tests.
"""

from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_hybrid_acceptance as acceptance  # noqa: E402


def _argument_path(flag: str, default: Path) -> Path:
    try:
        return Path(sys.argv[sys.argv.index(flag) + 1]).resolve()
    except ValueError:
        return default.resolve()


def main() -> int:
    probe = _argument_path("--probe", acceptance.DEFAULT_PROBE)
    module = _argument_path("--module", acceptance.DEFAULT_MODULE)
    # Missing-path cases are deliberately left to the production validation
    # path. Existing test fixtures are pinned by their exact bytes in-process.
    if not probe.is_file() or not module.is_file():
        return acceptance.main()
    probe_sha256 = acceptance.file_identity(probe)["sha256"]
    module_sha256 = acceptance.file_identity(module)["sha256"]
    with patch.object(acceptance, "PINNED_PROBE_SHA256", probe_sha256), \
            patch.object(acceptance, "PINNED_MODULE_SHA256", module_sha256):
        return acceptance.main()


if __name__ == "__main__":
    raise SystemExit(main())
