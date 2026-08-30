"""CI toolchain wiring must stay in place across workflow edits."""
from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = PROJECT_ROOT / ".github/workflows/bounty-hunter.yml"
SCRIPT = PROJECT_ROOT / "scripts/setup-toolchains.sh"


def test_toolchain_script_exists_and_is_shell_valid() -> None:
    assert SCRIPT.is_file()
    text = SCRIPT.read_text()
    assert "install_clarinet" in text
    assert "install_scarb" in text
    assert "install_blueprint" in text
    assert "install_aptos" in text
    assert "install_solana" in text


def test_both_scan_jobs_install_language_toolchains() -> None:
    text = WORKFLOW.read_text()
    # There are exactly two scan jobs (scan-on-command + scan) and each
    # must set up Node and call the toolchain script.
    assert text.count("actions/setup-node@v4") == 2
    assert text.count("bash scripts/setup-toolchains.sh") == 2
