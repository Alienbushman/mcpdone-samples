"""Shared file discovery. One copy, imported by every check.

Every check used to carry its own `_SKIP_DIRS` set and its own
`_should_skip`, ten near-identical copies that had already drifted: three of
the TS checks deliberately trimmed `test`/`tests`/`fixtures` out of their
copy and left a comment explaining why, rather than fixing the shared
problem. This module is that fix, in the same spirit as `guards.mjs` on the
posting side: one copy, so a correction lands once.

Two real defects motivated it, both the same shape and both the worst thing
a security scanner can do -- report `OK - 0 findings` after examining zero
files:

1. **Pruning was matched against the absolute path.** `_should_skip` tested
   `any(part in _SKIP_DIRS for part in path.parts)` on the full path, so a
   checkout living under any directory named `dist`, `build`, `env`, `venv`
   or `node_modules` had *every* file skipped. Pointing the tool straight at
   the code did not help: the offending component sat above the scan root.
   Reproduced on the `command_injection_bad` fixture, which drops from 16
   findings to 0 when its parent directory is renamed `dist`. In CI this is
   worse than useless, because the run goes green having read nothing.

   Fixed here by pruning **relative to the scan root**, so components above
   the root are never inspected. `jsparse.iter_source_files` already got
   this right and documented it; the Python side never did.

2. **A published package is almost entirely build output.** An npm tarball
   ships `package/dist/*.js` and no sources at all, so pruning `dist`
   discarded the entire package. Reproduced on the real
   `@corralimited/snapdiff-mcp` tree: the same five files report 1 HIGH
   under `src/` and 0 findings under `dist/`, byte for byte identical.

   Fixed by `include_build`: build directories are residue in a repository
   and the product in a package, so the caller says which it is looking at.
   `mcp_audit.cli` decides by falling back (see `run_all_checks`) rather
   than asking the user to know.

The invariant these two share, and the one worth keeping: **"0 findings"
must never be indistinguishable from "0 files examined."** `count_analyzable`
exists so the CLI can tell the difference and say so.
"""
from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from pathlib import Path

# Directories that never contain first-party source worth auditing.
# Build outputs are deliberately NOT here -- see BUILD_DIRS.
SKIP_DIRS: frozenset[str] = frozenset({
    ".venv", "venv", "env", ".git", "site-packages",
    ".tox", ".nox", "__pycache__", "node_modules",
})

# Build output. Residue in a repository, the shipped product in a package,
# so these are pruned only when `include_build` is False.
BUILD_DIRS: frozenset[str] = frozenset({"dist", "build", "out"})

# TS/JS additions: caches, vendored trees, and test/example trees. Kept
# separate from SKIP_DIRS because the Python checks scan test trees on
# purpose (their own fixtures live in one).
TS_EXTRA_SKIP_DIRS: frozenset[str] = frozenset({
    "coverage", ".next", ".nuxt", ".svelte-kit", ".turbo",
    ".vercel", ".cache", "bower_components", "vendor",
    "test", "tests", "__tests__", "__mocks__", "e2e", "fixtures",
    "examples", "example", "demo", "benchmark", "benchmarks", "evals",
})

PY_EXTENSIONS: frozenset[str] = frozenset({".py"})

TS_EXTENSIONS: frozenset[str] = frozenset(
    {".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
)

# Dependency manifests. `starlette_badhost` reads these rather than source,
# so a repo with no source but a real manifest has still been examined.
MANIFEST_NAMES: frozenset[str] = frozenset({
    "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile.lock",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
})


def skip_dirs_for(*, typescript: bool = False, include_build: bool = False) -> frozenset[str]:
    """The pruning set for one scan.

    `typescript` adds the TS-only caches and test trees. `include_build`
    keeps `dist`/`build`/`out` in the walk, for scanning a published package
    whose only code is compiled output.
    """
    dirs = set(SKIP_DIRS)
    if typescript:
        dirs |= TS_EXTRA_SKIP_DIRS
    if not include_build:
        dirs |= BUILD_DIRS
    return frozenset(dirs)


def is_skipped(
    path: Path,
    root: Path,
    *,
    typescript: bool = False,
    include_build: bool = False,
) -> bool:
    """True when `path` lies inside a pruned directory **below `root`**.

    Components of `root` itself are never inspected. This is the whole point
    of the function: matching on the absolute path meant a checkout under
    `~/build/` was skipped in its entirety, silently.

    A `path` outside `root` is not skipped -- callers pass paths they found
    by walking `root`, and a non-relative path is a caller bug, not a
    reason to silently drop a file.
    """
    try:
        rel = Path(path).resolve().relative_to(Path(root).resolve())
    except (ValueError, OSError):
        return False
    pruned = skip_dirs_for(typescript=typescript, include_build=include_build)
    # rel.parts includes the filename; a file named `dist` is not a directory.
    return any(part in pruned for part in rel.parts[:-1])


def iter_files(
    root: Path,
    suffixes: Iterable[str],
    *,
    typescript: bool = False,
    include_build: bool = False,
) -> Iterator[Path]:
    """Yield files under `root` whose suffix is in `suffixes`, pruning as
    `is_skipped` would but without paying `relative_to` per file.

    Directory and file names are sorted so output is byte-identical across
    runs, matching `jsparse.iter_source_files`.
    """
    root = Path(root)
    wanted = frozenset(suffixes)
    if root.is_file():
        if root.suffix in wanted:
            yield root
        return
    pruned = skip_dirs_for(typescript=typescript, include_build=include_build)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in pruned)
        base = Path(dirpath)
        for name in sorted(filenames):
            if Path(name).suffix in wanted:
                yield base / name


def iter_manifests(root: Path, *, include_build: bool = False) -> Iterator[Path]:
    """Yield dependency manifests under `root`."""
    root = Path(root)
    pruned = skip_dirs_for(include_build=include_build)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in pruned)
        base = Path(dirpath)
        for name in sorted(filenames):
            if name in MANIFEST_NAMES or name.startswith("requirements"):
                yield base / name


def count_sources(root: Path, *, include_build: bool = False) -> int:
    """How many Python or TS/JS source files are readable under `root`.

    Deliberately excludes manifests. This is the number that decides whether
    build output has to be reconsidered, and a manifest cannot answer that:
    every published npm package carries a `package.json`, so counting it
    would make a tarball whose only code sits in `dist/` look non-empty and
    suppress the fallback entirely. That was the first version of this
    function and it silently defeated its own purpose.

    The TS test-tree exclusions are deliberately not applied: this asks "was
    there anything here at all", and narrowing it would reintroduce the
    silent-clean bug from the other side.
    """
    return sum(
        1
        for _ in iter_files(
            root, PY_EXTENSIONS | TS_EXTENSIONS, include_build=include_build
        )
    )


def count_analyzable(root: Path, *, include_build: bool = False) -> int:
    """How many files any check could have opened under `root`.

    Used by the CLI to tell "we looked and found nothing wrong" apart from
    "we looked at nothing." Counts sources *and* dependency manifests,
    because a repo with no source but a real `pyproject.toml` has genuinely
    been examined by `starlette_badhost` and is not an empty scan.
    """
    seen: set[Path] = set()
    for path in iter_files(
        root, PY_EXTENSIONS | TS_EXTENSIONS, include_build=include_build
    ):
        seen.add(path)
    for path in iter_manifests(root, include_build=include_build):
        seen.add(path)
    return len(seen)
