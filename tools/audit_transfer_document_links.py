#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit or annotate Markdown links to artifacts excluded from a Git transfer."""

from __future__ import annotations

import argparse
import json
import posixpath
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(
    r"(?P<image>!)?\[(?P<label>(?:\\.|[^\]])*)\]"
    r"\((?P<destination><[^>]+>|(?:\\.|[^)])+)\)"
)
FENCE_RE = re.compile(r"^\s*(```+|~~~+)")


def _is_fenced_line(line: str, fence_char: str | None) -> tuple[bool, str | None]:
    match = FENCE_RE.match(line)
    if match is None:
        return fence_char is not None, fence_char
    marker = match.group(1)[0]
    if fence_char is None:
        return True, marker
    if marker == fence_char:
        return True, None
    return True, fence_char


def _destination_path(destination: str, document: str) -> str | None:
    value = destination.strip()
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1]
    value = value.replace("\\ ", " ")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or value.startswith(("/", "#")):
        return None
    path = unquote(parsed.path)
    if not path:
        return None
    return posixpath.normpath(posixpath.join(posixpath.dirname(document), path))


def _is_in_index(path: str, tracked_paths: set[str]) -> bool:
    if path in tracked_paths:
        return True
    prefix = path.rstrip("/") + "/"
    return any(candidate.startswith(prefix) for candidate in tracked_paths)


def _markdown_files(root: Path, tracked_paths: set[str]) -> list[str]:
    return sorted(
        path for path in tracked_paths
        if path.endswith(".md") and (path == "README.md" or path.startswith("docs/"))
        and (root / path).is_file()
    )


def find_excluded_links(
    root: Path, tracked_paths: set[str]
) -> list[dict[str, str | int]]:
    excluded: list[dict[str, str | int]] = []
    for document in _markdown_files(root, tracked_paths):
        fence_char = None
        text = (root / document).read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            fenced, fence_char = _is_fenced_line(line, fence_char)
            if fenced:
                continue
            for match in LINK_RE.finditer(line):
                path = _destination_path(match.group("destination"), document)
                if path is not None and not _is_in_index(path, tracked_paths):
                    excluded.append({
                        "document": document,
                        "line": line_number,
                        "label": match.group("label"),
                        "target": path,
                    })
    return excluded


def _plain_local_reference(match: re.Match[str], target: str) -> str:
    label = match.group("label").strip()
    image = bool(match.group("image"))
    label_as_path = label.strip("`")
    basename = PurePosixPath(target).name
    if label_as_path in {target, basename}:
        visible = f"`{target}`"
        return f"{visible} (local-only; excluded from GitLab transfer)"
    else:
        visible = label or f"`{basename}`"
    kind = "local-only image" if image else "local-only artifact"
    return f"{visible} ({kind}; excluded from GitLab transfer; source: `{target}`)"


def annotate_excluded_links(root: Path, tracked_paths: set[str]) -> int:
    changed = 0
    for document in _markdown_files(root, tracked_paths):
        path = root / document
        original = path.read_text(encoding="utf-8")
        lines = original.splitlines(keepends=True)
        fence_char = None
        rewritten: list[str] = []
        for line in lines:
            fenced, fence_char = _is_fenced_line(line, fence_char)
            if fenced:
                rewritten.append(line)
                continue

            def replace(match: re.Match[str]) -> str:
                nonlocal changed
                target = _destination_path(match.group("destination"), document)
                if target is None or _is_in_index(target, tracked_paths):
                    return match.group(0)
                changed += 1
                return _plain_local_reference(match, target)

            rewritten.append(LINK_RE.sub(replace, line))
        updated = "".join(rewritten)
        if updated != original:
            path.write_text(updated, encoding="utf-8")
    return changed


def _tracked_paths(root: Path) -> set[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return {path.decode("utf-8") for path in result.stdout.split(b"\0") if path}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT,
                        help="canonical repository root (default: this checkout)")
    parser.add_argument("--annotate-excluded", action="store_true",
                        help="replace links missing from the Git index with explicit local-only text")
    args = parser.parse_args(argv)
    root = args.root.resolve(strict=True)
    tracked = _tracked_paths(root)
    changed = annotate_excluded_links(root, tracked) if args.annotate_excluded else 0
    excluded = find_excluded_links(root, tracked)
    print(json.dumps({
        "schema": "transfer-document-link-audit-v1",
        "markdown_documents_scanned": len(_markdown_files(root, tracked)),
        "annotated_links": changed,
        "excluded_links_remaining": len(excluded),
        "examples": excluded[:10],
    }, ensure_ascii=False, indent=2))
    return 1 if excluded else 0


if __name__ == "__main__":
    sys.exit(main())
