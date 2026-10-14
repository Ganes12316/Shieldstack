"""Fetch a public GitHub source snapshot into a temporary directory."""

import json
import logging
import re
import shutil
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

# Limits apply to the complete lookup, download, and extraction operation.
CLONE_TIMEOUT_SECONDS = 60
MAX_REPO_SIZE_MB = 100
MAX_REPO_SIZE_BYTES = MAX_REPO_SIZE_MB * 1_048_576
CHUNK_SIZE = 64 * 1024
logger = logging.getLogger(__name__)


class RepoLoadError(Exception):
    """Raised with a safe, user-facing repository fetch message."""


def _dir_size_bytes(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def _repo_parts(url: str) -> tuple[str, str]:
    match = re.fullmatch(
        r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?",
        url,
    )
    if not match:
        raise RepoLoadError("Invalid repository URL. Only HTTPS GitHub URLs are supported.")
    return match.group(1), match.group(2)


def _request(url: str, started: float):
    remaining = CLONE_TIMEOUT_SECONDS - (time.monotonic() - started)
    if remaining <= 0:
        raise TimeoutError
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ShieldStack-Repository-Scanner", "Accept": "application/vnd.github+json"},
    )
    return urllib.request.urlopen(request, timeout=min(10, remaining))


def _extract_archive(archive_path: Path, destination: Path, started: float) -> None:
    """Extract files without trusting ZIP paths, links, or declared sizes."""
    try:
        with zipfile.ZipFile(archive_path) as archive:
            entries = archive.infolist()
            if sum(item.file_size for item in entries) > MAX_REPO_SIZE_BYTES:
                raise RepoLoadError(
                    f"Repository is too large. The scanner accepts repos up to {MAX_REPO_SIZE_MB} MB."
                )

            roots = set()
            for item in entries:
                path = PurePosixPath(item.filename)
                if path.is_absolute() or ".." in path.parts or "\\" in item.filename or not path.parts:
                    raise RepoLoadError("GitHub returned an invalid repository archive.")
                roots.add(path.parts[0])
            if len(roots) != 1:
                raise RepoLoadError("GitHub returned an invalid repository archive.")
            actual_size = 0

            for item in entries:
                if time.monotonic() - started > CLONE_TIMEOUT_SECONDS:
                    raise TimeoutError
                path = PurePosixPath(item.filename)
                relative = path.parts[1:]
                if not relative:
                    continue
                mode = item.external_attr >> 16
                if stat.S_ISLNK(mode):
                    continue
                output = destination.joinpath(*relative)
                if item.is_dir():
                    output.mkdir(parents=True, exist_ok=True)
                    continue
                output.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(item) as source, output.open("wb") as target:
                    while True:
                        if time.monotonic() - started > CLONE_TIMEOUT_SECONDS:
                            raise TimeoutError
                        chunk = source.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        actual_size += len(chunk)
                        if actual_size > MAX_REPO_SIZE_BYTES:
                            raise RepoLoadError(
                                f"Repository is too large. The scanner accepts repos up to {MAX_REPO_SIZE_MB} MB."
                            )
                        target.write(chunk)
    except zipfile.BadZipFile:
        raise RepoLoadError("GitHub returned an invalid repository archive.") from None


def load_repo(repo_url: str) -> Path:
    """Download a public repository's source snapshot and return its temp path.

    Git history is intentionally omitted: the scanner only needs source files.
    The temporary directory is removed by the API after scanning.
    """
    url = repo_url.strip()
    owner, repo = _repo_parts(url)
    started = time.monotonic()
    temp_dir = Path(tempfile.mkdtemp(prefix="shieldstack_"))
    archive_path = temp_dir / "source.zip"
    source_dir = temp_dir / "source"

    try:
        api_url = f"https://api.github.com/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}"
        try:
            with _request(api_url, started) as response:
                metadata = json.loads(response.read(1024 * 1024))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise RepoLoadError(
                    "Repository not found or not publicly accessible. Check the URL and use a public repository."
                ) from None
            raise
        branch = metadata.get("default_branch")
        if not isinstance(branch, str) or not branch:
            raise RepoLoadError("GitHub did not provide a default branch for that repository.")

        archive_url = (
            f"https://codeload.github.com/{urllib.parse.quote(owner)}/"
            f"{urllib.parse.quote(repo)}/zip/refs/heads/{urllib.parse.quote(branch, safe='/')}"
        )
        with _request(archive_url, started) as response, archive_path.open("wb") as archive_file:
            downloaded = 0
            while True:
                if time.monotonic() - started > CLONE_TIMEOUT_SECONDS:
                    raise TimeoutError
                chunk = response.read(CHUNK_SIZE)
                if not chunk:
                    break
                downloaded += len(chunk)
                if downloaded > MAX_REPO_SIZE_BYTES:
                    raise RepoLoadError(
                        f"Repository archive exceeds {MAX_REPO_SIZE_MB} MB. Try a smaller repository."
                    )
                archive_file.write(chunk)

        _extract_archive(archive_path, source_dir, started)
        archive_path.unlink(missing_ok=True)
        # Keep the returned path as the temp root so API cleanup removes everything.
        for item in source_dir.iterdir():
            shutil.move(str(item), str(temp_dir / item.name))
        source_dir.rmdir()
        size_bytes = _dir_size_bytes(temp_dir)
        if size_bytes > MAX_REPO_SIZE_BYTES:
            raise RepoLoadError(
                f"Repository is too large. The scanner accepts repos up to {MAX_REPO_SIZE_MB} MB."
            )
        return temp_dir
    except RepoLoadError:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    except TimeoutError:
        elapsed = time.monotonic() - started
        logger.warning("GitHub source archive timed out after %.1f seconds for a submitted repository URL", elapsed)
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise RepoLoadError(
            f"Repository download exceeded the {CLONE_TIMEOUT_SECONDS}-second limit. Try a smaller repository."
        ) from None
    except Exception as exc:
        elapsed = time.monotonic() - started
        logger.warning("GitHub source archive fetch failed after %.1f seconds (%s)", elapsed, type(exc).__name__)
        shutil.rmtree(temp_dir, ignore_errors=True)
        if isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError, OSError)):
            raise RepoLoadError("The scan server could not download that repository from GitHub. Please try again later.") from None
        raise RepoLoadError("Couldn't download that public GitHub repository.") from None
