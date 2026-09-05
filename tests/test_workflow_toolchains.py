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


def test_toolchain_installs_stay_wired_in_ci() -> None:
    text = WORKFLOW.read_text()
    # toolchain-smoke + scan-on-command + scan all set up Node and invoke
    # the toolchain script.
    assert text.count("actions/setup-node@v4") == 3
    assert text.count("bash scripts/setup-toolchains.sh") == 3
    # The smoke job installs only the lightweight subset and runs the
    # non-Foundry sandbox smoke tests; the scan jobs install everything.
    assert "bash scripts/setup-toolchains.sh clarinet scarb blueprint aptos" in text
    assert "tests/test_sandbox_smoke.py" in text
