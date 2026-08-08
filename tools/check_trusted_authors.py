#!/usr/bin/env python3
"""Fail if any catalog entry's "author" isn't a known key in trusted_authors.json.

Presence, not the true/false value, is what's required here - an author can be
explicitly untrusted (false) and still pass this check, since that's a real
reviewed decision. What must never happen is an entry whose author was never
recorded at all, trusted or not.
"""
import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRUSTED_AUTHORS_FILE = ROOT / "trusted_authors.json"


def main() -> int:
    known = json.loads(TRUSTED_AUTHORS_FILE.read_text())
    known.pop("$comment", None)

    missing: dict[str, list[str]] = {}
    for path in sorted(glob.glob(str(ROOT / "apps" / "**" / "*.json"), recursive=True)):
        entry = json.loads(Path(path).read_text())
        author = entry.get("author")
        if not author:
            continue
        if author not in known:
            missing.setdefault(author, []).append(str(Path(path).relative_to(ROOT)))

    if not missing:
        print(f"OK: every author across the catalog is present in {TRUSTED_AUTHORS_FILE.name}.")
        return 0

    print(f"FAIL: {len(missing)} author(s) not found in {TRUSTED_AUTHORS_FILE.name}:\n")
    for author, files in sorted(missing.items()):
        print(f'  "{author}"  (used by: {", ".join(files)})')
    print(
        f"\nAdd each missing author as a key in {TRUSTED_AUTHORS_FILE.name} "
        "(true if trusted, false if reviewed and not trusted) before this PR can be merged."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
