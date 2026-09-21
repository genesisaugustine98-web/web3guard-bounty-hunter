"""Target acquisition for non-GitHub sources — zero-dollar, no API keys.

Bug-bounty programs do not all publish on GitHub. This module resolves a
target string into a local checkout using only free, unauthenticated
transports:

- **Git remotes** (any host): ``https://``/``http://``/``git@``/``ssh://``
  URLs ending in ``.git`` or recognized as GitLab/Bitbucket/SourceHut/
  Gitea/Codeberg/cgit/Trac/gogglesmm shapes. Cloned with
  ``git clone --depth 1``, exactly like the GitHub path.
- **GitLab subgroups** — ``https://gitlab.com/group/subgroup/project``
  (deeply nested paths are legal on GitLab and clone fine over HTTPS).
- **SourceHut** — ``https://git.sr.ht/~user/repo`` clones directly.
- **Bitbucket** — ``https://bitbucket.org/user/repo`` (append ``.git``).
- **Gitea / Codeberg / self-hosted forges** — same; ``.git`` appended
  when missing.
- **cgit instances** (e.g. kernel.org) — ``https://host/cgit/repo`` gets
  ``.git`` appended; ``/about/`` and ``/plain/`` URLs are normalized.
- **Tarball archives** — ``.tar.gz``/``.tgz``/``.tar.bz2``/``.tar.xz``/
  ``.zip`` URLs (GitHub/GitLab/Bitbucket "Download ZIP", cgit
  ``/snapshot/``, any release asset). Downloaded to a temp dir and
  extracted; the single top-level directory (or the extraction root when
  several exist) becomes the target.
- **Single files** — a raw ``.sol``/``.vy``/``.move``/... URL is wrapped
  in a minimal single-file target directory so the rest of the pipeline
  is unchanged.
- **Bare shorthand** — ``owner/repo`` is expanded to GitHub; prefixed
  shorthands ``gl:owner/repo``, ``bb:owner/repo``, ``sr:~user/repo``,
  ``cb:owner/repo`` expand to GitLab, Bitbucket, SourceHut, Codeberg.

Everything here is offline-orchestration of public HTTP/git transports:
no API tokens are required, nothing is uploaded, and every artifact lands
in a fresh temp directory the caller owns.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

LOGGER = logging.getLogger("web3guard.fetch")

_GIT_SUFFIX = ".git"

# Hosts whose /user/repo HTTPS URL is a plain git smart-HTTP endpoint
# (possibly after appending .git). Everything else with an explicit
# .git suffix is treated as git regardless of host.
_KNOWN_FORGE_HOSTS = (
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "git.sr.ht",
    "codeberg.org",
    "git.kernel.org",
)

_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip")

# File extensions the pipeline can actually analyze (mirrors the language
# registry's extension table). A single-file fetch only proceeds when the
# URL ends in one of these.
_ANALYZABLE_SUFFIXES = (
    ".sol", ".vy", ".vyper", ".move", ".cairo", ".clar", ".fc", ".func",
    ".rs", ".ts", ".js", ".mjs", ".cjs",
)

_SHORTHAND_RE = re.compile(
    r"^(?P<prefix>gl|bb|sr|cb|gh):(?P<path>.+)$"
)
_OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class FetchError(RuntimeError):
    """Raised when a target cannot be resolved to a local directory."""


def _looks_like_git_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https", "ssh", "git"):
        return False
    if url.endswith(_GIT_SUFFIX):
        return True
    host = (parsed.hostname or "").lower()
    if host in _KNOWN_FORGE_HOSTS:
        return True
    # scp-style remotes: git@host:path
    if url.startswith("git@") and ":" in url:
        return True
    # Explicit git protocol
    if parsed.scheme == "git":
        return True
    return False


def _looks_like_archive(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(s) for s in _ARCHIVE_SUFFIXES)


def _looks_like_single_file(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(s) for s in _ANALYZABLE_SUFFIXES)


def expand_shorthand(target: str) -> str:
    """Expand ``prefix:path`` shorthands to canonical HTTPS URLs."""
    m = _SHORTHAND_RE.match(target.strip())
    if not m:
        return target.strip()
    prefix, path = m.group("prefix"), m.group("path").strip("/")
    if prefix == "gh":
        return f"https://github.com/{path}"
    if prefix == "gl":
        return f"https://gitlab.com/{path}"
    if prefix == "bb":
        return f"https://bitbucket.org/{path}.git"
    if prefix == "cb":
        return f"https://codeberg.org/{path}.git"
    if prefix == "sr":
        return f"https://git.sr.ht/{path}"
    return target.strip()


def normalize_git_url(url: str) -> str:
    """Canonicalize forge-specific HTML URLs into cloneable git URLs."""
    url = url.rstrip("/")
    lower = url.lower()
    # cgit: strip /about, /plain, /log, /tree page paths; append .git
    if "/cgit/" in lower:
        for seg in ("/about", "/plain", "/log", "/tree", "/commit", "/snapshot"):
            if seg + "/" in url or url.endswith(seg):
                url = url.split(seg)[0]
        url = url.rstrip("/")
        if not url.endswith(_GIT_SUFFIX):
            url += _GIT_SUFFIX
        return url
    if "/-/tree/" in url or "/-/blob/" in url:
        # GitLab web UI URL -> project root
        url = url.split("/-/")[0]
    if "/tree/" in url or "/blob/" in url or "/src/" in url:
        # GitHub/Gitea/Codeberg web UI URL -> project root
        url = re.split(r"/(tree|blob|src)/", url)[0]
    if "bitbucket.org/" in lower and not url.endswith(_GIT_SUFFIX):
        url += _GIT_SUFFIX
    if "codeberg.org/" in lower and not url.endswith(_GIT_SUFFIX):
        url += _GIT_SUFFIX
    if not url.endswith(_GIT_SUFFIX) and "/cgit" in lower:
        url += _GIT_SUFFIX
    return url


def _git_clone(url: str, dest: Path, timeout: int = 180) -> None:
    cmd = ["git", "clone", "--depth", "1", url, str(dest)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as e:
        raise FetchError("git is not installed on this host") from e
    except subprocess.TimeoutExpired as e:
        raise FetchError(f"git clone timed out after {timeout}s: {url}") from e
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        hint = ""
        if "Authentication failed" in stderr or "could not read Username" in stderr:
            hint = (
                " (repository requires credentials; Web3Guard never uses "
                "stored keys for fetching — clone manually and scan the "
                "local path)"
            )
        raise FetchError(f"git clone failed for {url}: {stderr[:400]}{hint}")
    if not dest.is_dir():
        raise FetchError(f"git clone produced no directory for {url}")


def _http_download(url: str, dest: Path, timeout: int = 120) -> None:
    req = Request(url, headers={"User-Agent": "web3guard/3.0 (+fetch)"})
    try:
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-configured URL
            data = resp.read()
    except Exception as e:  # noqa: BLE001
        raise FetchError(f"download failed for {url}: {e}") from e
    dest.write_bytes(data)


def _extract_archive(archive: Path, dest_root: Path) -> Path:
    """Extract ``archive`` under ``dest_root`` and return the target dir."""
    lower = archive.name.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            # Zip-slip guard: refuse members that escape the extraction root.
            for member in zf.namelist():
                target = (dest_root / member).resolve()
                if not str(target).startswith(str(dest_root.resolve())):
                    raise FetchError(f"archive member escapes extraction root: {member}")
            zf.extractall(dest_root)
    else:
        mode = "r:*"
        if lower.endswith((".tar.bz2",)):
            mode = "r:bz2"
        elif lower.endswith((".tar.xz",)):
            mode = "r:xz"
        elif lower.endswith((".tgz", ".tar.gz")):
            mode = "r:gz"
        with tarfile.open(archive, mode) as tf:  # noqa: S202 - guarded below
            for member in tf.getmembers():
                target = (dest_root / member.name).resolve()
                if not str(target).startswith(str(dest_root.resolve())):
                    raise FetchError(f"archive member escapes extraction root: {member.name}")
            tf.extractall(dest_root)

    entries = [p for p in dest_root.iterdir() if not p.name.startswith(".")]
    dirs = [p for p in entries if p.is_dir()]
    if len(dirs) == 1 and len(entries) == 1:
        return dirs[0]
    return dest_root


def fetch_target(target: str, workdir: Path | None = None) -> Path:
    """Resolve ``target`` to a local directory.

    Supported shapes (all free, no credentials):

    - local paths (returned as-is when they exist)
    - any git remote URL (GitHub, GitLab, Bitbucket, SourceHut, Codeberg,
      cgit, self-hosted Gitea/GitLab, ssh remotes)
    - archive URLs (.tar.gz/.tgz/.tar.bz2/.tar.xz/.zip) from any host
      (GitHub/GitLab "Download ZIP", cgit /snapshot/, release assets)
    - single raw source files (wrapped in a one-file target)
    - shorthands: ``gh:owner/repo``, ``gl:owner/repo``, ``bb:owner/repo``,
      ``cb:owner/repo``, ``sr:~user/repo``, and bare ``owner/repo``
      (GitHub)
    """
    raw = str(target).strip()
    if raw.startswith(("http://", "https://", "git@", "git://", "ssh://")):
        resolved = raw
    else:
        resolved = expand_shorthand(raw)
        # Bare owner/repo shorthand -> GitHub
        if resolved == raw and "/" in raw and "://" not in raw and not raw.startswith("git@"):
            if _OWNER_REPO_RE.match(raw) and Path(raw).expanduser().exists() is False:
                resolved = f"https://github.com/{raw}"

    # Local path short-circuit.
    p = Path(resolved).expanduser()
    if not resolved.startswith(("http://", "https://", "git@", "git://", "ssh://")):
        rp = p.resolve()
        if rp.is_dir():
            return rp
        if _OWNER_REPO_RE.match(resolved):
            resolved = f"https://github.com/{resolved}"
        else:
            raise FetchError(f"local target does not exist: {resolved}")

    tmp_root = Path(tempfile.mkdtemp(prefix="web3guard-target-", dir=str(workdir) if workdir else None))

    # 1. Git remote?
    if _looks_like_git_url(resolved):
        clone_url = normalize_git_url(resolved)
        _git_clone(clone_url, tmp_root / "repo")
        return tmp_root / "repo"

    # 2. Archive?
    if _looks_like_archive(resolved):
        ext = _archive_ext_of(resolved) or ".bin"
        archive = tmp_root / f"artifact{ext}"
        _http_download(resolved, archive)
        return _extract_archive(archive, tmp_root / "extracted")

    # 3. Single analyzable file?
    if _looks_like_single_file(resolved):
        dest = tmp_root / "src" / Path(urlparse(resolved).path).name
        dest.parent.mkdir(parents=True, exist_ok=True)
        _http_download(resolved, dest)
        return tmp_root / "src"

    # 4. Last resort: maybe the host serves git at /user/repo even though
    #    it did not match known forge shapes (self-hosted Gitea etc.).
    #    Try .git-clone first, then a common codeload archive, then give up.
    candidate = normalize_git_url(resolved)
    try:
        _git_clone(candidate, tmp_root / "repo")
        return tmp_root / "repo"
    except FetchError:
        LOGGER.info("git fallback failed for %s; trying archive endpoints", resolved)
    # Host-specific archive guesses (all public, no auth).
    parsed = urlparse(resolved)
    guesses: list[str] = []
    if parsed.scheme in ("http", "https"):
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
        guesses = [
            f"{base}/-/archive/main/{(parsed.path.rstrip('/').rsplit('/', 1)[-1])}-main.tar.gz",
            f"{base}/archive/main.zip",
            f"{base}/archive/master.zip",
            f"{base}/~{parsed.path.strip('/')}.tar.gz",
        ]
    for guess in guesses:
        try:
            archive = tmp_root / ("guess" + _archive_ext_of(guess))
            _http_download(guess, archive)
            return _extract_archive(archive, tmp_root / "extracted")
        except FetchError:
            continue
    raise FetchError(
        f"could not resolve target {target!r}: not a git remote, archive, "
        "single source file, or local path"
    )


def _archive_ext_of(url: str) -> str:
    path = urlparse(url).path.lower()
    for suffix in _ARCHIVE_SUFFIXES:
        if path.endswith(suffix):
            return suffix
    return ".zip"


def cleanup_target(path: Path) -> None:
    """Remove a fetch's temp tree (best effort)."""
    try:
        # The fetch root is the mkdtemp parent two levels up from a clone,
        # or the extraction root for archives.
        candidate = path
        for _ in range(2):
            if candidate.parent.name.startswith("web3guard-target-"):
                shutil.rmtree(candidate.parent, ignore_errors=True)
                return
            candidate = candidate.parent
    except Exception:  # noqa: BLE001
        pass
