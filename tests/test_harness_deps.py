"""Tests for dependency-aware harness bundling (Fix #11).

Everything here runs WITHOUT network: fixtures are synthetic on-disk
projects. The only test touching ``forge`` is guarded by
``pytest.mark.skipif`` so CI never fails where Foundry is absent.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.invariants.deps import (  # noqa: E402
    bundle_dependencies,
    collect_closure,
    extract_imports,
    parse_remappings_txt,
)
from web3guard.invariants.fuzz import FOUNDRY_FORGE, discover_forge  # noqa: E402
from web3guard.invariants.harness import write_project  # noqa: E402

_FORGE_AVAILABLE = shutil.which("forge") is not None or FOUNDRY_FORGE.exists()

# ---------------------------------------------------------------------------
# Fixture project
# ---------------------------------------------------------------------------
#
#   proj/
#     remappings.txt            ->  @oz/=lib/oz/
#     src/
#       Vault.sol               ->  @oz/token/ERC20.sol, ./helpers/Fees.sol
#       helpers/
#         Fees.sol              ->  @oz/token/IERC20.sol
#     lib/
#       oz/
#         token/
#           ERC20.sol           ->  ./IERC20.sol
#           IERC20.sol
#
# This exercises: remapped imports, relative imports, transitive imports,
# and a file (IERC20.sol) reached both relatively (from ERC20.sol) and via
# remapping (from Fees.sol).


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


@pytest.fixture()
def dep_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    _write(proj / "remappings.txt", "@oz/=lib/oz/\n")
    _write(
        proj / "src" / "Vault.sol",
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        'import "@oz/token/ERC20.sol";\n'
        'import "./helpers/Fees.sol";\n'
        "contract Vault {}\n",
    )
    _write(
        proj / "src" / "helpers" / "Fees.sol",
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        'import "@oz/token/IERC20.sol";\n'
        "library Fees {}\n",
    )
    _write(
        proj / "lib" / "oz" / "token" / "ERC20.sol",
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        'import "./IERC20.sol";\n'
        "contract ERC20 {}\n",
    )
    _write(
        proj / "lib" / "oz" / "token" / "IERC20.sol",
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ninterface IERC20 {}\n",
    )
    return proj


# ---------------------------------------------------------------------------
# Import parsing
# ---------------------------------------------------------------------------


def test_extract_imports_all_forms() -> None:
    src = """
    // import "commented/out.sol";
    /* import "also/commented.sol"; */
    import "plain.sol";
    import * as ns from "ns.sol";
    import {A, B} from "named.sol";
    import {C as D} from 'single.sol';
    """
    assert extract_imports(src) == [
        "plain.sol",
        "ns.sol",
        "named.sol",
        "single.sol",
    ]


def test_parse_remappings_txt_with_context() -> None:
    remaps = parse_remappings_txt(
        "@oz/=lib/oz/\n"
        "lib/chainlink-ace/:@openzeppelin/contracts/=lib/oz/contracts/\n"
        "# a comment\n"
        "forge-std/=lib/forge-std/src/\n"
    )
    assert len(remaps) == 3
    assert remaps[0].context is None
    assert remaps[0].prefix == "@oz/"
    assert remaps[1].context == "lib/chainlink-ace/"
    assert remaps[1].prefix == "@openzeppelin/contracts/"
    assert remaps[2].prefix == "forge-std/"


# ---------------------------------------------------------------------------
# Closure resolution
# ---------------------------------------------------------------------------


def test_closure_resolves_transitive_imports(
    dep_project: Path,
) -> None:
    closure = collect_closure(dep_project / "src" / "Vault.sol", "src/Vault.sol")
    assert closure.unresolvable == []
    placed = {h for _, h in closure.files}
    # Remapped deps land in the generated dep lib dir...
    assert "lib/__web3guard_dep0__/token/ERC20.sol" in placed
    # ...and IERC20.sol is placed consistently however it was reached.
    assert "lib/__web3guard_dep0__/token/IERC20.sol" in placed
    # Relative deps land relative to the target's harness location.
    assert "src/helpers/Fees.sol" in placed
    assert closure.remap_lines == ["@oz/=lib/__web3guard_dep0__/"]


def test_closure_unresolvable_import_warns(tmp_path: Path) -> None:
    target = _write(
        tmp_path / "Lonely.sol",
        'pragma solidity ^0.8.20;\nimport "@missing/pkg/Thing.sol";\ncontract Lonely {}\n',
    )
    closure = collect_closure(target, "src/Lonely.sol")
    assert len(closure.unresolvable) == 1
    import_path, _importer = closure.unresolvable[0]
    assert import_path == "@missing/pkg/Thing.sol"


def test_closure_no_project_root_uses_relative_only(
    tmp_path: Path,
) -> None:
    sibling = _write(tmp_path / "Helper.sol", "pragma solidity ^0.8.20;\ncontract Helper {}\n")
    _ = sibling
    target = _write(
        tmp_path / "Main.sol",
        'pragma solidity ^0.8.20;\nimport "./Helper.sol";\ncontract Main {}\n',
    )
    closure = collect_closure(target, "src/Main.sol")
    assert closure.unresolvable == []
    assert "src/Helper.sol" in {h for _, h in closure.files}


# ---------------------------------------------------------------------------
# Bundling
# ---------------------------------------------------------------------------


def test_bundle_produces_layout_and_remappings(
    dep_project: Path,
) -> None:
    files = {
        "src/Vault.sol": "target-source",
        "foundry.toml": "[profile.default]\n",
        "test/Invariant.t.sol": "test-source",
    }
    notes: list[str] = []
    bundled = bundle_dependencies(
        files,
        str(dep_project / "src" / "Vault.sol"),
        notes,
        target_harness_path="src/Vault.sol",
    )
    # Original keys preserved...
    assert bundled["src/Vault.sol"] == "target-source"
    assert bundled["test/Invariant.t.sol"] == "test-source"
    # ...deps added...
    assert "contract ERC20" in bundled["lib/__web3guard_dep0__/token/ERC20.sol"]
    assert "library Fees" in bundled["src/helpers/Fees.sol"]
    # ...remappings generated...
    assert "@oz/=lib/__web3guard_dep0__/" in bundled["remappings.txt"]
    # ...and a note recorded.
    assert any("Fix #11" in n for n in notes)


def test_bundle_unresolvable_import_names_it_in_notes(
    tmp_path: Path,
) -> None:
    target = _write(
        tmp_path / "Lonely.sol",
        'pragma solidity ^0.8.20;\nimport "@missing/pkg/Thing.sol";\ncontract Lonely {}\n',
    )
    notes: list[str] = []
    bundled = bundle_dependencies(
        {"src/Lonely.sol": "x"},
        str(target),
        notes,
        target_harness_path="src/Lonely.sol",
    )
    assert bundled["src/Lonely.sol"] == "x"
    assert any("@missing/pkg/Thing.sol" in n for n in notes), notes


def test_bundle_isolated_fixture_unchanged() -> None:
    files = {"src/Vault.sol": "x", "foundry.toml": "y"}
    assert bundle_dependencies(files, "") == files
    assert bundle_dependencies(files, "/nonexistent/Vault.sol") == files
    assert bundle_dependencies(files, "/tmp/notsolidity.txt") == files


def test_bundle_does_not_overwrite_renderer_files(
    dep_project: Path,
) -> None:
    # A dep landing on an existing renderer path keeps the renderer's copy.
    files = {"lib/__web3guard_dep0__/token/ERC20.sol": "renderer-wins"}
    bundled = bundle_dependencies(
        files,
        str(dep_project / "src" / "Vault.sol"),
        target_harness_path="src/Vault.sol",
    )
    assert bundled["lib/__web3guard_dep0__/token/ERC20.sol"] == "renderer-wins"


# ---------------------------------------------------------------------------
# End-to-end: the bundled project compiles with forge
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _FORGE_AVAILABLE, reason="forge not installed")
def test_bundled_project_compiles_with_forge(dep_project: Path, tmp_path: Path) -> None:
    import subprocess

    target = dep_project / "src" / "Vault.sol"
    files = {
        "src/Vault.sol": target.read_text(),
        "foundry.toml": (
            '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\ntest = "test"\n'
        ),
        "test/Invariant.t.sol": (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            'import "../src/Vault.sol";\n'
            "contract InvariantTest {\n"
            "    Vault v;\n"
            "    function setUp() public { v = new Vault(); }\n"
            "}\n"
        ),
    }
    bundled = bundle_dependencies(files, str(target), target_harness_path="src/Vault.sol")
    project_dir = tmp_path / "harness"
    write_project(project_dir, bundled)
    forge = discover_forge(None) or "forge"
    proc = subprocess.run(
        [forge, "build"],
        cwd=project_dir,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
