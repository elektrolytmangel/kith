#!/usr/bin/env python3
"""Fail if a production Rust file grows past a size budget.

Counts the lines of each tracked `.rs` file up to its first `#[cfg(test)]`
(test modules and `tests.rs` / `tests/` files do not count). Split a file by
concern when it gets here (see PLAN.md, "Code structure refactor") instead of
raising the limit.
"""
import subprocess
import sys

LIMIT = 1100


def production_lines(path: str) -> int:
    with open(path, encoding="utf-8") as f:
        n = 0
        for line in f:
            if line.strip() == "#[cfg(test)]":
                break
            n += 1
    return n


def main() -> int:
    files = subprocess.run(
        ["git", "ls-files", "*.rs"], check=True, capture_output=True, text=True
    ).stdout.split()
    too_long = []
    for path in files:
        name = path.rsplit("/", 1)[-1]
        if name in ("tests.rs", "test.rs") or "/tests/" in path:
            continue
        n = production_lines(path)
        if n > LIMIT:
            too_long.append((n, path))
    for n, path in sorted(too_long, reverse=True):
        print(f"error: {path} has {n} production lines (limit {LIMIT}); split it by concern")
    if not too_long:
        print(f"ok: no production file over {LIMIT} lines")
    return 1 if too_long else 0


if __name__ == "__main__":
    sys.exit(main())
