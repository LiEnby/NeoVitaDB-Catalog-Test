#!/usr/bin/env python3
"""Promote new entries from this (staging) catalog to the official one.

An entry counts as "new" when its apps/<platform>/<file>.json exists here but
has no same-named counterpart in the official catalog's apps/<platform>/ -
see README's "Adding your homebrew" section for the staging-then-promotion
flow this automates. Only brand-new files are touched: an entry that exists
in both catalogs but has drifted (edited here after already being promoted,
say) is left alone - reconciling an existing prod entry is a different, more
sensitive operation than shipping a new one, and not something this script
guesses at.

For each new entry this copies its JSON file and icon over, then validates
the official catalog's apps/ still passes its own schema - using the
official repo's own tools/build_catalog.py, not this one, since that's the
copy that's actually authoritative for what gets published. On failure
(schema violation, or an id/icon collision with something already in prod)
everything just-copied is rolled back and nothing is committed. On success,
one commit is created listing every promoted entry by name. Nothing is
pushed - review with `git show`, then push by hand (or pass --push).

Usage:
    python tools/promote.py                     # promote + commit
    python tools/promote.py --dry-run            # show what would be promoted
    python tools/promote.py --prod-dir ../other-catalog
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLATFORMS = ["vita", "psp"]


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout.strip()


def ensure_clean(repo_dir: Path, label: str) -> None:
    status = git("status", "--porcelain", cwd=repo_dir)
    if status:
        raise SystemExit(
            f"{label} ({repo_dir}) has uncommitted changes - commit, stash, "
            f"or discard them before promoting:\n{status}"
        )


def sync_prod(prod_dir: Path) -> None:
    """Fast-forward only: refuses to guess through a real divergence."""
    git("fetch", "origin", cwd=prod_dir)
    try:
        git("merge", "--ff-only", "origin/main", cwd=prod_dir)
    except subprocess.CalledProcessError as e:
        raise SystemExit(
            f"{prod_dir} can't fast-forward to origin/main - resolve manually:\n{e.stderr}"
        )


def find_new_entries(test_dir: Path, prod_dir: Path) -> list[tuple[str, Path]]:
    """(platform, path-in-test) for every apps/<platform>/*.json that has no
    same-named counterpart in the prod catalog yet."""
    new_entries = []
    for platform in PLATFORMS:
        test_platform_dir = test_dir / "apps" / platform
        prod_platform_dir = prod_dir / "apps" / platform
        if not test_platform_dir.exists():
            continue
        for path in sorted(test_platform_dir.glob("*.json")):
            if path.name.startswith("_"):
                continue
            if not (prod_platform_dir / path.name).exists():
                new_entries.append((platform, path))
    return new_entries


def load_prod_build_catalog(prod_dir: Path):
    """Import the prod repo's own tools/build_catalog.py so validation uses
    its schema and rules - the two catalogs are meant to stay identical, but
    prod's copy is the one that's actually authoritative."""
    module_path = prod_dir / "tools" / "build_catalog.py"
    spec = importlib.util.spec_from_file_location("prod_build_catalog", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_entry(platform: str, test_path: Path, test_dir: Path, prod_dir: Path) -> list[Path]:
    prod_path = prod_dir / "apps" / platform / test_path.name
    prod_path.write_text(test_path.read_text())

    entry = json.loads(test_path.read_text())
    icon_name = entry["icon"]
    icon_subdir = "icons_vita" if platform == "vita" else "icons_psp"
    src_icon = test_dir / icon_subdir / icon_name
    dst_icon = prod_dir / icon_subdir / icon_name
    if not src_icon.exists():
        raise SystemExit(f"{test_path.name}: icon {icon_name} not found at {src_icon}")
    shutil.copyfile(src_icon, dst_icon)
    return [prod_path, dst_icon]


def commit_message(promoted: list[tuple[str, dict]]) -> str:
    count = len(promoted)
    title = f"Promote {count} new {'entry' if count == 1 else 'entries'} from the test catalog"
    lines = [f"- {entry['name']} ({platform}, id {entry['id']})" for platform, entry in promoted]
    return title + "\n\n" + "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--test-dir", type=Path, default=ROOT,
        help="Path to the staging catalog's working copy (default: this repo)",
    )
    parser.add_argument(
        "--prod-dir", type=Path, default=ROOT.parent / "NeoVitaDB-Catalog",
        help="Path to the official catalog's working copy (default: sibling NeoVitaDB-Catalog/)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show what would be promoted, change nothing")
    parser.add_argument("--no-sync", action="store_true", help="Skip fetching/fast-forwarding the prod checkout first")
    parser.add_argument("--push", action="store_true", help="Push the promotion commit after creating it")
    args = parser.parse_args()

    test_dir = args.test_dir.resolve()
    prod_dir = args.prod_dir.resolve()
    if not (prod_dir / "tools" / "build_catalog.py").exists():
        raise SystemExit(f"{prod_dir} doesn't look like a NeoVitaDB catalog checkout (no tools/build_catalog.py)")

    ensure_clean(prod_dir, "Official catalog")
    if not args.no_sync:
        sync_prod(prod_dir)

    new_entries = find_new_entries(test_dir, prod_dir)
    if not new_entries:
        log("Nothing new to promote.")
        return

    log(f"{len(new_entries)} new entr{'y' if len(new_entries) == 1 else 'ies'}:")
    for platform, path in new_entries:
        log(f"  - {path.relative_to(test_dir)}")

    if args.dry_run:
        return

    promoted = []
    copied_paths = []
    for platform, test_path in new_entries:
        entry = json.loads(test_path.read_text())
        copied_paths += copy_entry(platform, test_path, test_dir, prod_dir)
        promoted.append((platform, entry))

    prod_build_catalog = load_prod_build_catalog(prod_dir)
    prod_entries = []
    for path in sorted((prod_dir / "apps").glob("**/*.json")):
        if path.name.startswith("_"):
            continue
        prod_entries.append((path, json.loads(path.read_text())))
    try:
        prod_build_catalog.validate(prod_entries)
    except SystemExit as e:
        for path in copied_paths:
            path.unlink(missing_ok=True)
        raise SystemExit(f"Validation failed after copying, rolled back: {e}")

    message = commit_message(promoted)
    git("add", *[str(p.relative_to(prod_dir)) for p in copied_paths], cwd=prod_dir)
    git("commit", "-m", message, cwd=prod_dir)
    log(f"Committed in {prod_dir}:\n{message}")

    if args.push:
        git("push", cwd=prod_dir)
        log("Pushed.")
    else:
        log("Not pushed - review with `git show`, then `git push` in the official catalog.")


if __name__ == "__main__":
    main()
