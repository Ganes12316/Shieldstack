"""Shared repository file selection for all ShieldStack detectors."""

from fnmatch import fnmatchcase
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", "venv", "__pycache__", "dist", "build", "vendor"}
FIXTURE_DIRS = {"tests", "test", "__tests__", "fixtures", "samples", "examples", "research_apps"}
FIXTURE_FILE_PATTERNS = ("*test*.py", "*.test.js", "*.spec.js", "*.test.tsx")


def is_fixture_path(path: Path, root: Path) -> bool:
    """Return whether a repo-relative path is excluded as test/sample material."""
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        return False

    parts = relative.split("/")
    if (
        root.name in FIXTURE_DIRS
        or root.name.startswith("sample_")
        or any(part in FIXTURE_DIRS or part.startswith("sample_") for part in parts[:-1])
    ):
        return True
    filename = parts[-1]
    if any(fnmatchcase(filename.lower(), pattern) for pattern in FIXTURE_FILE_PATTERNS):
        return True

    ignore_file = root / ".shieldstackignore"
    try:
        patterns = ignore_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        patterns = []
    for raw_pattern in patterns:
        pattern = raw_pattern.strip()
        if not pattern or pattern.startswith("#"):
            continue
        pattern = pattern.lstrip("/")
        if fnmatchcase(relative, pattern) or any(
            fnmatchcase("/".join(parts[:index]), pattern)
            for index in range(1, len(parts))
        ):
            return True
    return False


def should_skip_path(path: Path, root: Path, include_fixtures: bool = False) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    if any(part in SKIP_DIRS for part in relative.parts):
        return True
    if path.name.endswith(".min.js"):
        return True
    return not include_fixtures and is_fixture_path(path, root)


def iter_scannable_files(root: Path, extensions, include_fixtures: bool = False):
    for path in root.rglob("*"):
        if path.is_file() and (path.suffix in extensions or path.name == ".env"):
            if not should_skip_path(path, root, include_fixtures):
                yield path


def count_skipped_fixture_files(root: Path, extensions) -> int:
    return sum(
        1
        for path in root.rglob("*")
        if path.is_file()
        and (path.suffix in extensions or path.name == ".env")
        and not any(part in SKIP_DIRS for part in path.relative_to(root).parts)
        and not path.name.endswith(".min.js")
        and is_fixture_path(path, root)
    )
