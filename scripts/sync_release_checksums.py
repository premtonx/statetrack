#!/usr/bin/env python3
"""Rewrite the `### Checksums` table in a release-notes file from SHA256SUMS.txt.

Why this exists: the release workflow rebuilds every archive, and build
timestamps differ from a developer's local run, so a table committed to git can
never match the `SHA256SUMS.txt` the release actually serves. Publishing a
checksum that no download satisfies is worse than publishing none — it looks
authoritative while being wrong — so the table is regenerated from the files
being uploaded, in the same job, immediately before upload.

Usage:
    sync_release_checksums.py RELEASE_NOTES.md SHA256SUMS.txt
"""

from __future__ import annotations

import re
import sys

FENCE = "```"
# `### Checksums` followed by the first fenced block.
PATTERN = re.compile(r"(### Checksums\s*\n\s*)```.*?```", re.DOTALL)


def read_rows(sums_path: str) -> list[str]:
    rows = []
    with open(sums_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            # SHA256SUMS.txt marks binary mode as `hash *name`.
            digest, name = line.split(" ", 1)
            rows.append(f"{digest}  {name.lstrip('*')}")
    return rows


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    notes_path, sums_path = argv[1], argv[2]
    rows = read_rows(sums_path)
    if not rows:
        print(f"{sums_path} contained no checksums", file=sys.stderr)
        return 1

    with open(notes_path, encoding="utf-8") as fh:
        text = fh.read()

    block = FENCE + "\n" + "\n".join(rows) + "\n" + FENCE
    text, count = PATTERN.subn(lambda m: m.group(1) + block, text, count=1)
    if count != 1:
        print(f"could not locate the ### Checksums block in {notes_path}", file=sys.stderr)
        return 1

    # newline="\n" keeps the file stable on Windows checkouts, where the default
    # would write CRLF and make the diff noisy for no reason.
    with open(notes_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)

    print(f"{notes_path}: wrote {len(rows)} checksums")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
