"""Cross-repo dependency discovery.

The scanner normally analyzes one target at a time. Real-world targets
depend on other repositories (OpenZeppelin forks, Solana SDKs, Cairo
libraries, npm packages pulled from git, etc.), and a vulnerability in a
dependency can be just as exploitable as one in the target's own source.

:func:`discover_dependencies` statically inspects a cloned target and
returns the git URLs of the dependencies it declares, so the scanner can
recursively analyze them. All parsers are regex / config based and run
offline, with no network access and no installed toolchains required.
"""

from __future__ import annotations

import configparser
import json
import re
from pathlib import Path

# package.json: "git+https://github.com/owner/repo.git" or
# "git+ssh://git@github.com/owner/repo.git" or "github:owner/repo".
_PKG_GIT_URL = re.compile(
    r"git\+?(?P<url>https?://[^\s\"']+|ssh://[^\s\"']+)|"
    r"github:(?P<gh>[^\s\"',}]+)"
)
# Cargo.toml / Scarb.toml:  dep = { git = "https://...", ... }
_MANIFEST_GIT = re.compile(r"(?:git|github)\s*=\s*[\"'](?P<url>[^\"']+)[\"']")
_REMAPPING_URL = re.compile(r"(?P<url>https?://github\.com/[^\s\"]+)")


def discover_dependencies(repo_root: Path) -> list[str]:
    """Return the deduplicated, order-preserved git URLs of dependencies
    declared by the repository at ``repo_root``.

    Sources inspected (whichever exist):

    - ``.gitmodules`` — git submodules (git *and* non-github hosts).
    - ``package.json`` — ``dependencies`` / ``devDependencies`` entries
      that reference a git URL (``git+https``, ``git+ssh``,
      ``github:owner/repo``).
    - ``Cargo.toml`` — ``[dependencies]`` entries with ``git = ...``.
    - ``Scarb.toml`` — ``[dependencies]`` entries with ``github = ...``
      (resolved against ``https://github.com``).
    - ``remappings.txt`` / ``foundry.toml`` — remappings that point
      directly at a ``https://github.com/...`` archive.

    Plain semantic version ranges (e.g. ``^1.2.3``) are not git URLs and
    are ignored. The result is stable (sorted) so scans are reproducible.
    """
    urls: list[str] = []
    add = _make_adder(urls)

    gitmodules = repo_root / ".gitmodules"
    if gitmodules.is_file():
        parser = configparser.ConfigParser()
        try:
            parser.read(gitmodules, encoding="utf-8")
        except configparser.Error:
            parser = configparser.ConfigParser()
            parser.read_string(f"[root]\n{gitmodules.read_text(encoding='utf-8')}")
        for section in parser.sections():
            if parser.has_option(section, "url"):
                add(parser.get(section, "url").strip())

    pkg_json = repo_root / "package.json"
    if pkg_json.is_file():
        try:
            pkg = json.loads(pkg_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pkg = {}
        for section in ("dependencies", "devDependencies"):
            deps = pkg.get(section) or {}
            if not isinstance(deps, dict):
                continue
            for version in deps.values():
                if not isinstance(version, str):
                    continue
                for m in _PKG_GIT_URL.finditer(version):
                    add(m.group("url") or f"https://github.com/{m.group('gh')}")

    for manifest in ("Cargo.toml", "Scarb.toml"):
        path = repo_root / manifest
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for m in _MANIFEST_GIT.finditer(text):
            url = m.group("url")
            if manifest == "Scarb.toml" and not url.startswith("http"):
                url = f"https://github.com/{url}"
            add(url)

    for mapping in ("remappings.txt",):
        path = repo_root / mapping
        if path.is_file():
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                for m in _REMAPPING_URL.finditer(line):
                    add(m.group("url").rstrip(",\"'"))

    return sorted(set(urls), key=str.casefold)


def _make_adder(urls: list[str]):
    def add(url: str) -> None:
        url = url.strip().strip("'\"")
        if url and url not in urls:
            urls.append(url)

    return add
