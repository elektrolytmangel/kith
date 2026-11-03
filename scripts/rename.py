#!/usr/bin/env python3
"""Rebrand this template for a new project.

Replaces the working name `kith` everywhere (file contents and paths), in
every casing it appears in, plus the GitHub owner and the Kotlin
package:

  kith-core        -> acme-sync-core      (crates, npm, docker, prose)
  kith_ffi         -> acme_sync_ffi       (Rust identifiers, libraries)
  Kith / KithFFI   -> AcmeSync / AcmeSyncFFI  (Swift, types)
  kithVersion      -> acmeSyncVersion     (generated camelCase)
  KITH_RELAY_ADDR  -> ACME_SYNC_RELAY_ADDR
  dev.kith         -> com.acme.sync       (Kotlin package + directories)
  elektrolytmangel -> acme-corp           (GitHub owner: URLs, npm scope, CODEOWNERS)

Usage:
  python3 scripts/rename.py --name acme-sync --owner acme-corp --kotlin-package com.acme.sync
  python3 scripts/rename.py ... --dry-run     # list what would change

Run it on a clean git tree, then `cargo build && python3 scripts/reqs.py --write`.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OLD = "kith"
OLD_KOTLIN = "dev.kith"
OLD_OWNER = "elektrolytmangel"
SKIP_DIRS = {".git", "target", "node_modules", "pkg", "build", ".gradle", ".build"}
SKIP_FILES = {"rename.py"}


def variants(name: str) -> dict[str, str]:
    parts = [p for p in re.split(r"[-_\s]+", name) if p]
    if not parts or not all(re.fullmatch(r"[a-z][a-z0-9]*", p) for p in parts):
        sys.exit("name must be lowercase words separated by '-' or '_' (e.g. acme-sync)")
    pascal = "".join(p.capitalize() for p in parts)
    return {
        "kebab": "-".join(parts),
        "snake": "_".join(parts),
        "pascal": pascal,
        "camel": pascal[0].lower() + pascal[1:],
        "upper": "_".join(parts).upper(),
    }


def make_replacer(v: dict[str, str], owner: str | None, kotlin_pkg: str):
    rules: list[tuple[re.Pattern[str], str]] = [
        (re.compile(re.escape(OLD_KOTLIN)), kotlin_pkg),
        (re.compile(r"dev/kith"), kotlin_pkg.replace(".", "/")),
        (re.compile(r"KITH"), v["upper"]),
        (re.compile(r"Kith"), v["pascal"]),
        (re.compile(r"kith(?=[A-Z])"), v["camel"]),
        (re.compile(r"kith(?=_)"), v["snake"]),
        (re.compile(r"kith"), v["kebab"]),
    ]
    if owner:
        rules.append((re.compile(rf"\b{re.escape(OLD_OWNER)}\b"), owner))

    def apply(text: str) -> str:
        for pat, rep in rules:
            text = pat.sub(rep, text)
        return text

    return apply


def walk() -> list[Path]:
    out = []
    for p in ROOT.rglob("*"):
        rel = p.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in rel.parts) or p.name in SKIP_FILES:
            continue
        out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="new project name, e.g. acme-sync")
    ap.add_argument("--owner", help=f"GitHub user/org replacing {OLD_OWNER}")
    ap.add_argument("--kotlin-package", help="Kotlin/Java package (default: dev.<name without dashes>)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    v = variants(args.name)
    kotlin_pkg = args.kotlin_package or f"dev.{v['snake'].replace('_', '')}"
    if not re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+", kotlin_pkg):
        sys.exit("--kotlin-package must look like com.example.app")
    rep = make_replacer(v, args.owner, kotlin_pkg)

    paths = walk()
    changed = 0
    for p in paths:
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        new = rep(text)
        if new != text:
            changed += 1
            print(f"edit   {p.relative_to(ROOT)}")
            if not args.dry_run:
                p.write_text(new, encoding="utf-8")

    moved = 0
    # Only files are moved; directories follow implicitly and empty ones are pruned.
    for p in sorted(paths, key=lambda x: len(x.parts), reverse=True):
        if not p.is_file():
            continue
        rel = p.relative_to(ROOT).as_posix()
        new_rel = rep(rel)
        if new_rel != rel:
            moved += 1
            print(f"move   {rel} -> {new_rel}")
            if not args.dry_run:
                dest = ROOT / new_rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                p.rename(dest)
    # Remove directories left empty by the moves.
    if not args.dry_run:
        for d in sorted((x for x in ROOT.rglob("*") if x.is_dir()), key=lambda x: len(x.parts), reverse=True):
            if ".git" not in d.parts and not any(d.iterdir()):
                d.rmdir()

    print(f"{'would change' if args.dry_run else 'changed'} {changed} files, {moved} paths")
    return 0


if __name__ == "__main__":
    sys.exit(main())
