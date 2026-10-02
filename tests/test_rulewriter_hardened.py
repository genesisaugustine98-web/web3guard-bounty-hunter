"""Tests for the Phase 3 rule-writer hardening.

Covers the four proof obligations:

(a) the template registry is wide (>= 15 Solidity templates),
(b) a temporal ghost-state invariant catches a planted cumulative-drain bug,
(c) a confidently-wrong fake LLM produces ZERO findings out of the pipeline,
(d) every finding the pipeline emits carries a machine-checked proof artifact.

All LLM clients are scripted fakes; nothing touches the network. The
forge end-to-end tests are skipped where the toolchain cannot actually run
under the sandbox (they run in CI and in properly permissioned environments).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from web3guard.ai.provider import ChatResponse  # noqa: E402
from web3guard.invariants import proof_gate as gate  # noqa: E402
from web3guard.invariants import templates as tmpl  # noqa: E402
from web3guard.invariants.fuzz import discover_forge  # noqa: E402
from web3guard.invariants.models import CampaignResult, FuzzBounds, Invariant  # noqa: E402
from web3guard.invariants.pipeline import run_invariant_pipeline  # noqa: E402
from web3guard.scanner import Finding  # noqa: E402
from web3guard.security.sandbox_guard import run_sandboxed  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, name: str, src: str) -> Path:
    p = tmp_path / name
    p.write_text(src)
    return p


class FakeClient:
    """Scripted stand-in for the router client; never touches the network."""

    def __init__(self, content: str) -> None:
        self._content = content

    @property
    def is_active(self) -> bool:
        return True

    def chat(self, system: str, user: str, **kwargs) -> ChatResponse:
        return ChatResponse(
            content=self._content,
            model="fake",
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
            finish_reason="stop",
            raw={},
            provider="fake",
            latency_ms=0,
            cost_usd=0.0,
        )


def _forge_usable() -> bool:
    """True when the sandbox can actually execute the forge binary."""
    forge = discover_forge({})
    if not forge:
        return False
    try:
        rc, out, _err = run_sandboxed(
            [forge, "--version"],
            cwd=Path("/tmp"),
            timeout=30,
            extra_env={"HOME": "/tmp"},
        )
        return rc == 0 and "forge" in out.lower()
    except Exception:  # noqa: BLE001 - any failure means "cannot run"
        return False


_FORGE_USABLE = _forge_usable()

_BOUNDS = {"runs": 64, "depth": 8, "timeout_seconds": 180}


def _run(path: Path, client: FakeClient | None, notes: list[str]) -> list[Finding]:
    import web3guard.invariants.pipeline as pipeline_mod
    import web3guard.invariants.synthesize as synth_mod

    real_synth = synth_mod.build_router_client
    real_pipe = pipeline_mod.build_router_client
    synth_mod.build_router_client = lambda config: client  # type: ignore[assignment]
    pipeline_mod.build_router_client = lambda config: client  # type: ignore[assignment]
    try:
        return run_invariant_pipeline(
            path, {"invariants": _BOUNDS}, notes=notes,
        )
    finally:
        synth_mod.build_router_client = real_synth  # type: ignore[assignment]
        pipeline_mod.build_router_client = real_pipe  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# (a) The template registry is wide
# ---------------------------------------------------------------------------


def test_template_registry_has_at_least_15_solidity_templates() -> None:
    assert len(tmpl.SOLIDITY_TEMPLATES) >= 15, (
        f"expected a wide registry, got {len(tmpl.SOLIDITY_TEMPLATES)}"
    )


def test_template_registry_ids_unique_and_well_formed() -> None:
    ids = [s.id for s in tmpl.all_templates()]
    assert len(ids) == len(set(ids)), "duplicate template ids"
    for spec in tmpl.all_templates():
        assert spec.id.startswith("tmpl-"), spec.id
        assert spec.statement.strip(), spec.id
        assert spec.rationale.strip(), spec.id
        assert spec.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}, spec.id
        assert spec.assertion.strip() or spec.body.strip(), spec.id


def test_template_registry_covers_required_categories() -> None:
    ids = {s.id for s in tmpl.SOLIDITY_TEMPLATES}
    required = {
        # balance / supply conservation
        "tmpl-solvency-1-1",
        "tmpl-total-deposited-gte-withdrawn",
        "tmpl-no-unbacked-balance",
        "tmpl-mint-burn-balanced",
        # temporal (ghost state)
        "tmpl-cum-withdraw-lte-deposit",
        "tmpl-cum-flow-conservation",
        # access control
        "tmpl-owner-nonzero",
        "tmpl-owner-immutable",
        # arithmetic bounds
        "tmpl-share-price-positive",
        "tmpl-share-price-nonzero-min",
        "tmpl-fee-bounded",
        # pausing correctness
        "tmpl-pause-halts-deposits",
        # fee accounting
        "tmpl-fee-recipient-set",
        # allowance handling
        "tmpl-allowance-lte-approved",
        # oracle staleness
        "tmpl-oracle-fresh",
    }
    missing = required - ids
    assert not missing, f"registry missing categories: {missing}"


def test_ghost_variable_names_are_consistent() -> None:
    seen: dict[str, str] = {}
    for spec in tmpl.SOLIDITY_TEMPLATES:
        if spec.ghost is None:
            continue
        for vname, vtype in spec.ghost.vars:
            if vname in seen:
                assert seen[vname] == vtype, (
                    f"ghost variable {vname} declared with conflicting types"
                )
            seen[vname] = vtype
    assert seen, "expected ghost variables to exist"


def test_ghost_harness_renders_without_forge() -> None:
    """Pure string-level check of the ghost project shape."""
    src = (
        "pragma solidity ^0.8.20;\n"
        "contract V {\n"
        "    mapping(address => uint256) public balances;\n"
        "    uint256 public totalDeposited;\n"
        "    uint256 public totalWithdrawn;\n"
        "    function deposit(uint8 amt) external {\n"
        "        balances[msg.sender] += amt; totalDeposited += amt;\n"
        "    }\n"
        "    function withdraw(uint8 amt) external {\n"
        "        require(balances[msg.sender] >= amt);\n"
        "        balances[msg.sender] -= amt; totalWithdrawn += amt;\n"
        "    }\n"
        "}\n"
    )
    invs = tmpl.template_invariants(src, "solidity")
    assert tmpl.needs_ghost_mode(invs)
    kept, notes = tmpl.resolve_ghost_templates(invs, src)
    assert kept, f"all ghost templates dropped: {notes}"
    files, render_notes = tmpl.render_ghost_project(
        src, "V", kept, FuzzBounds(runs=8, depth=4)
    )
    test_src = files["test/Invariant.t.sol"]
    assert "contract GhostHandler" in test_src
    assert "function targetContracts()" in test_src
    assert "ghost_cumDeposited" in test_src
    assert "try target.deposit" in test_src
    assert "import \"forge-std" not in test_src  # forge-std-free by design
    assert render_notes == [] or isinstance(render_notes, list)


# ---------------------------------------------------------------------------
# Fixtures: planted cumulative-drain bug + fixed twin
# ---------------------------------------------------------------------------

_BUGGY_VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract CumDrainVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;

    function deposit(uint8 amt) external {
        balances[msg.sender] += amt;
        totalDeposited += amt;
    }

    function withdraw(uint8 amt) external {
        uint256 bal = balances[msg.sender];
        require(bal >= amt, "insufficient");
        balances[msg.sender] = bal - amt;
        totalWithdrawn += amt;
        // PLANTED BUG: phantom multiplier inflates the cumulative counter,
        // so the vault believes far more left than ever entered.
        totalWithdrawn += uint256(amt) * 999;
    }
}
"""

_FIXED_VAULT = _BUGGY_VAULT.replace(
    """        totalWithdrawn += amt;
        // PLANTED BUG: phantom multiplier inflates the cumulative counter,
        // so the vault believes far more left than ever entered.
        totalWithdrawn += uint256(amt) * 999;
""",
    """        totalWithdrawn += amt;
""",
).replace("contract CumDrainVault", "contract FixedVault")

_NO_RULES = FakeClient("[]")


@pytest.mark.skipif(not _FORGE_USABLE, reason="forge cannot run under the sandbox here")
def test_e2e_ghost_catches_cumulative_drain(tmp_path: Path) -> None:
    """(b) the temporal ghost invariant catches the planted drain bug."""
    target = _write(tmp_path, "CumDrainVault.sol", _BUGGY_VAULT)
    notes: list[str] = []
    findings = _run(target, _NO_RULES, notes)
    assert not any("SKIPPED" in n for n in notes), notes
    by_id = {f.metadata.get("invariant_id") for f in findings}
    assert "tmpl-cum-withdraw-lte-deposit" in by_id, (
        f"ghost temporal invariant did not fire; got {sorted(by_id)}"
    )
    # (d) every emitted finding carries its proof artifact.
    assert findings, "expected findings on the buggy vault"
    for f in findings:
        proof = (f.metadata or {}).get("proof")
        assert isinstance(proof, dict), f"finding {f.fingerprint} has no proof"
        assert proof.get("engine") == "foundry-invariant"
        assert proof.get("trace"), f"finding {f.fingerprint} has empty trace"
        assert any("calldata=" in line for line in proof["trace"])
        assert f.dynamically_confirmed is True


@pytest.mark.skipif(not _FORGE_USABLE, reason="forge cannot run under the sandbox here")
def test_e2e_ghost_clean_vault_no_findings(tmp_path: Path) -> None:
    """The fixed twin stays clean: ghost accounting, no false positives."""
    target = _write(tmp_path, "FixedVault.sol", _FIXED_VAULT)
    notes: list[str] = []
    findings = _run(target, _NO_RULES, notes)
    assert not any("SKIPPED" in n for n in notes), notes
    assert findings == [], [f.metadata.get("invariant_id") for f in findings]


# ---------------------------------------------------------------------------
# (c) A confidently-wrong LLM must produce ZERO findings
# ---------------------------------------------------------------------------

# Five bogus rules in the "wrong with confidence" style from the adversarial
# review: an unknown function, a tautology, two rules already false at
# deployment, and a magic-constant hallucination.
_BOGUS_LLM_JSON = json.dumps([
    {
        "id": "reserve-always-full",
        "statement": "I am highly confident this vault must always hold "
                     "exactly 999999 in reserves.",
        "assertion": "target.totalDeposited() == 999999",
        "variables": ["totalDeposited"],
        "functions": ["deposit"],
        "rationale": "Authoritative reserve invariant. Trust me.",
        "bug_class": "accounting-desync",
    },
    {
        "id": "phantom-counter-static",
        "statement": "The phantom counter is provably constant at zero.",
        "assertion": "target.phantomCounter() == 0",
        "variables": [],
        "functions": [],
        "rationale": "Certain of this.",
        "bug_class": "other",
    },
    {
        "id": "supply-never-negative",
        "statement": "Deposits can never be negative (mathematically certain).",
        "assertion": "target.totalDeposited() >= 0",
        "variables": ["totalDeposited"],
        "functions": [],
        "rationale": "Unsigned integers cannot be negative.",
        "bug_class": "rounding",
    },
    {
        "id": "genesis-supply-exact",
        "statement": "The vault launched with exactly 100 units deposited.",
        "assertion": "target.totalDeposited() == 100",
        "variables": ["totalDeposited"],
        "functions": [],
        "rationale": "I recall the deployment clearly.",
        "bug_class": "accounting-desync",
    },
    {
        "id": "withdrawals-self-consistent",
        "statement": "Withdrawals equal themselves (tautological safety).",
        "assertion": "target.totalWithdrawn() <= target.totalWithdrawn()",
        "variables": ["totalWithdrawn"],
        "functions": [],
        "rationale": "Self-consistency is guaranteed.",
        "bug_class": "other",
    },
])

_BOGUS_CLIENT = FakeClient(_BOGUS_LLM_JSON)


@pytest.mark.skipif(not _FORGE_USABLE, reason="forge cannot run under the sandbox here")
def test_e2e_confidently_wrong_llm_yields_zero_findings(tmp_path: Path) -> None:
    """(c) bogus-but-confident rules on a clean contract -> zero findings."""
    target = _write(tmp_path, "FixedVault.sol", _FIXED_VAULT)
    notes: list[str] = []
    findings = _run(target, _BOGUS_CLIENT, notes)
    assert not any("SKIPPED" in n for n in notes), notes
    assert findings == [], [
        (f.metadata.get("invariant_id"), f.description) for f in findings
    ]
    # The gate quarantined every bogus rule LOUDLY (nothing silent).
    quarantined_ids = {
        n.split("'")[1] for n in notes if "QUARANTINED" in n
    }
    for bogus_id in (
        "reserve-always-full",
        "phantom-counter-static",
        "supply-never-negative",
        "genesis-supply-exact",
        "withdrawals-self-consistent",
    ):
        assert bogus_id in quarantined_ids, (
            f"bogus rule {bogus_id} was not quarantined; notes: {notes}"
        )


@pytest.mark.skipif(not _FORGE_USABLE, reason="forge cannot run under the sandbox here")
def test_e2e_baseline_false_template_is_quarantined_not_reported(
    tmp_path: Path,
) -> None:
    """A template rule that contradicts the contract's construction is a bad
    RULE, not a bug: quarantined post-campaign, zero findings, loud note."""
    src = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract HighFee {\n"
        "    uint256 public feeBps = 20000;\n"
        "    function deposit(uint256 amt) external {}\n"
        "}\n"
    )
    target = _write(tmp_path, "HighFee.sol", src)
    notes: list[str] = []
    findings = _run(target, _NO_RULES, notes)
    assert not any("SKIPPED" in n for n in notes), notes
    assert findings == []
    assert any(
        "tmpl-fee-bounded" in n and "QUARANTINED" in n for n in notes
    ), notes
    # ...and NOT mislabeled as a compile failure.
    assert not any("did not compile" in n for n in notes), notes


# ---------------------------------------------------------------------------
# Proof-gate unit tests (no forge needed)
# ---------------------------------------------------------------------------

_CLEAN_SRC = (
    "pragma solidity ^0.8.20;\n"
    "contract C {\n"
    "    uint256 public totalDeposited;\n"
    "    int128 public pnl;\n"
    "    function deposit(uint256 amt) external {}\n"
    "}\n"
)


def _inv(id: str, assertion: str, source: str = "llm") -> Invariant:
    return Invariant(id=id, statement="s", assertion=assertion, source=source)


def test_validate_rules_quarantines_unknown_function() -> None:
    res = gate.validate_rules(
        [_inv("bad", "target.nope() == 0"), _inv("good", "target.totalDeposited() >= 1")],
        _CLEAN_SRC,
    )
    assert [i.id for i in res.valid] == ["good"]
    assert [q.invariant_id for q in res.quarantined] == ["bad"]
    assert res.quarantined[0].stage == "pre-render"


def test_validate_rules_quarantines_uint_tautology_but_keeps_int() -> None:
    res = gate.validate_rules(
        [
            _inv("uint-taut", "target.totalDeposited() >= 0"),
            _inv("int-ok", "target.pnl() >= 0"),
        ],
        _CLEAN_SRC,
    )
    assert [i.id for i in res.valid] == ["int-ok"]
    assert [q.invariant_id for q in res.quarantined] == ["uint-taut"]


def test_validate_rules_quarantines_self_comparison() -> None:
    res = gate.validate_rules(
        [_inv("self", "target.totalDeposited() <= target.totalDeposited()")],
        _CLEAN_SRC,
    )
    assert res.valid == []
    assert [q.invariant_id for q in res.quarantined] == ["self"]


def test_validate_rules_rejects_ghost_refs_in_llm_rules() -> None:
    res = gate.validate_rules(
        [_inv("sneaky", "handler.ghost_cumDeposited() > 0")],
        _CLEAN_SRC,
        ghost_ids=tmpl.GHOST_TEMPLATE_IDS,
        handler_refs=tmpl.handler_reference_names(),
    )
    assert res.valid == []
    assert [q.invariant_id for q in res.quarantined] == ["sneaky"]


def test_validate_rules_accepts_template_ghost_refs() -> None:
    res = gate.validate_rules(
        [
            _inv("tmpl-cum-withdraw-lte-deposit",
                 "target.totalWithdrawn() <= handler.ghost_cumDeposited()",
                 source="template"),
        ],
        _CLEAN_SRC + "uint256 public totalWithdrawn;\n",
        ghost_ids=tmpl.GHOST_TEMPLATE_IDS,
        handler_refs=tmpl.handler_reference_names(),
        body_ids=tmpl.BODY_TEMPLATE_IDS,
    )
    assert [i.id for i in res.valid] == ["tmpl-cum-withdraw-lte-deposit"]
    assert res.quarantined == []


def test_validate_rules_magic_constant_warns_but_does_not_block() -> None:
    res = gate.validate_rules(
        [_inv("fixed-supply", "target.totalDeposited() == 1000000")], _CLEAN_SRC
    )
    assert [i.id for i in res.valid] == ["fixed-supply"]
    assert res.quarantined == []
    assert any("magic constant" in n for n in res.notes)


def _finding(
    inv_id: str,
    poc: str,
    engine: str = "foundry-invariant",
    category: str = "invariant-violation",
) -> Finding:
    return Finding(
        target="T",
        language="solidity",
        file="T.sol",
        function=f"invariant_{inv_id}",
        category=category,
        severity="HIGH",
        confidence=0.9,
        description="d",
        reasoning="r",
        status="POTENTIAL",
        poc_code=poc,
        exploit_log="log",
        fingerprint=f"fp-{inv_id}",
        tool_consensus=[engine],
        dynamically_confirmed=True,
        metadata={"invariant_id": inv_id, "engine": engine,
                  "invariant_source": "llm"},
    )


_GOOD_POC = (
    "# Forge invariant counterexample (machine-checked).\n"
    "# Call sequence that breaks it:\n"
    "  1. sender=0xabc addr=[test/Invariant.t.sol:GhostHandler]0x123 "
    "calldata=deposit(uint256) args=[1]\n"
)


def test_gate_rejects_finding_with_empty_trace_and_quarantines_rule() -> None:
    poc = (
        "# Forge invariant counterexample (machine-checked).\n"
        "# Call sequence that breaks it:\n"
        "  (forge did not print a call sequence)\n"
    )
    verdict = gate.gate_findings(
        [_finding("baseline-false", poc)], {"baseline-false"}, CampaignResult(
            compile_ok=True, clean=False, engine="foundry-invariant",
        ),
    )
    assert verdict.admitted == []
    assert len(verdict.rejected) == 1
    assert [q.invariant_id for q in verdict.post_quarantined] == ["baseline-false"]
    assert verdict.post_quarantined[0].stage == "post-campaign"


def test_gate_rejects_unattributable_finding() -> None:
    verdict = gate.gate_findings(
        [_finding("mystery-rule", _GOOD_POC)], {"some-other-rule"},
        CampaignResult(compile_ok=True, engine="foundry-invariant"),
    )
    assert verdict.admitted == []
    assert "unattributable" in verdict.rejected[0].reason


def test_gate_rejects_finding_when_campaign_did_not_compile() -> None:
    verdict = gate.gate_findings(
        [_finding("r1", _GOOD_POC)], {"r1"},
        CampaignResult(compile_ok=False, engine="foundry-invariant"),
    )
    assert verdict.admitted == []


def test_gate_admits_finding_with_proof_and_attaches_artifact() -> None:
    verdict = gate.gate_findings(
        [_finding("real-bug", _GOOD_POC)], {"real-bug"},
        CampaignResult(compile_ok=True, runs=64, calls=128,
                       engine="foundry-invariant"),
    )
    assert len(verdict.admitted) == 1
    proof = verdict.admitted[0].metadata["proof"]
    assert proof["engine"] == "foundry-invariant"
    assert proof["invariant_id"] == "real-bug"
    assert proof["invariant_source"] == "llm"
    assert any("calldata=" in line for line in proof["trace"])
    assert proof["reproduction"]


def test_apply_proof_gate_is_loud_about_rejections() -> None:
    notes: list[str] = []
    admitted = gate.apply_proof_gate(
        [_finding("mystery", _GOOD_POC)], [_inv("known", "target.x() == 1")],
        CampaignResult(compile_ok=True, engine="foundry-invariant"),
        notes=notes,
    )
    assert admitted == []
    assert any("REJECTED" in n for n in notes)


def test_extract_baseline_failures_parses_forge_shape() -> None:
    output = (
        "[FAIL: failed to set up invariant testing environment: "
        "panic: assertion failed (0x01)] "
        "invariant_reserve_always_full() (runs: 0, calls: 0, reverts: 0)\n"
    )
    inv = _inv("reserve-always-full", "target.totalDeposited() == 999999")
    assert gate.extract_baseline_failures(output, [inv]) == ["reserve-always-full"]
    assert gate.extract_baseline_failures("Suite result: ok", [inv]) == []
