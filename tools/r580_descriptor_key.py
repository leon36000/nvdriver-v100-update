#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode the R580 _nv031364rm descriptor key from its +0x12c8 word.

This implements only the statically traced _nv031364rm call path into
_nv031399rm (EDI=0, EDX=0). It does not assign hardware meaning to the word.
"""
from __future__ import annotations

import argparse
import json


def decode_descriptor_key(selector: int) -> dict[str, int]:
    """Return the four 32-bit descriptor words for a raw +0x12c8 value."""
    if type(selector) is not int or not 0 <= selector <= 0xFFFFFFFF:
        raise ValueError("selector must be an unsigned 32-bit integer")

    family = (selector >> 8) & 0xFF
    variant = (selector >> 4) & 0x0F
    if family == 0x23 and variant == 0x0A:
        variant = 0x04

    return {
        "0x88": 0,
        "0x8c": 0,
        "0x90": (family << 4) | variant,
        "0x94": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("selector", help="unsigned 32-bit value read from record +0x12c8 (decimal or 0x-prefixed)")
    args = parser.parse_args(argv)
    try:
        selector = int(args.selector, 0)
        key = decode_descriptor_key(selector)
    except ValueError as exc:
        parser.error(str(exc))

    print(json.dumps({"selector": selector, "descriptor_key": key}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
