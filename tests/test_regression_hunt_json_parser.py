"""Regression tests for Fix C (weakness-hunt round, target 3).

The 2 lottery cases (b02-e4-low/med) were mislabeled "did not compile":
the fuzzer CATCHES the bug at both budgets and forge emits a
machine-readable JSON failure event naming the violated invariant, but the
sandbox truncated campaign output at 8,192 bytes, the truncation landed
mid-table and destroyed the parseable ``[FAIL]`` text block, the parser
ignored JSON events, and the pipeline misreported a real catch.

These tests pin the fix: forge's NDJSON failure events (emitted on stderr
in plain text mode, at the very END of the output so they survive
truncation) are now the PRIMARY signal, the human-readable ``[FAIL]``
blocks are the fallback, and sequences are recovered even when the
``[FAIL]`` header was truncated away.

The main fixture below is derived from a REAL b02-e4-low campaign run:
stdout truncated by the real SandboxGuard at 8,192 bytes (``[FAIL]``
headers destroyed, trailing runs-line + sequence tail + JSON event on
stderr surviving), with only the boilerplate head abridged.
"""

from __future__ import annotations

from web3guard.invariants import proof_gate
from web3guard.invariants.fuzz import (
    _CAMPAIGN_OUTPUT_CAP_BYTES,
    _recover_truncated_sequences,
    parse_forge_json_events,
    parse_forge_output,
)
from web3guard.invariants.models import CampaignResult, Invariant
from web3guard.security.sandbox_guard import SandboxGuard, SandboxPolicy


def _lottery_invariant() -> Invariant:
    return Invariant(
        id="lottery-fair",
        statement="Winner must not be the last entrant",
        assertion="target.drawn() == false || target.winner() != target.lastPlayer()",
        bug_class="other",
        severity="HIGH",
        source="llm",
    )


# ---------------------------------------------------------------------------
# Fixture: real b02-e4-low campaign output, truncated at 8,192 bytes.
# ---------------------------------------------------------------------------

_TRUNCATED_E4_STDOUT = 'Compiling 6 files with Solc 0.8.34\nSolc 0.8.34 finished in 99.25ms\nCompiler run successful with warnings:\nWarning (5159): "selfdestruct" has been deprecated. [...]\n\nRan 1 test for test/Invariant.t.sol:InvariantTest\n...[truncated by SandboxGuard]...d2D8E52E42Ca96Fb33a813BBe calldata=enter() args=[]\n\t\tsender=0x85a4c74125bFaA9F98496d2559b00a23c8FDFFcA addr=[src/LotteryDepth21.sol:LotteryDepth21]0xE8279BE14E9fe2Ad2D8E52E42Ca96Fb33a813BBe calldata=enter() args=[]\n\t\tsender=0xc78EC835a768962cAb00695093cFF46BcC4403b2 addr=[src/LotteryDepth21.sol:LotteryDepth21]0xE8279BE14E9fe2Ad2D8E52E42Ca96Fb33a813BBe calldata=enter() args=[]\n\t\tsender=0x00000000000000000000000000000000DeaDBeef addr=[test/AttackHandler.sol:AttackHandler]0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f calldata=act_enter(uint256,uint256) args=[159467244477025783664078862837434440285920122037 [1.594e47], 3]\n\t\tsender=0x00000000000000000000000000000000DeaDBeef addr=[src/LotteryDepth21.sol:LotteryDepth21]0xE8279BE14E9fe2Ad2D8E52E42Ca96Fb33a813BBe calldata=enter() args=[]\n\t\tsender=0x00000000000000000000000000000000000000BA addr=[src/LotteryDepth21.sol:LotteryDepth21]0xE8279BE14E9fe2Ad2D8E52E42Ca96Fb33a813BBe calldata=enter() args=[]\n\t\tsender=0xD5825c4e6b4E3398d3855FD35133eB478261f70A addr=[test/AttackHandler.sol:AttackHandler]0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f calldata=act_enter(uint256,uint256) args=[3945, 3770]\n\t\tsender=0x00000000000000000000000000000000000001c2 addr=[src/LotteryDepth21.sol:LotteryDepth21]0xE8279BE14E9fe2Ad2D8E52E42Ca96Fb33a813BBe calldata=enter() args=[]\n\t\tsender=0x00000000000000000000000000000000DeaDBeef addr=[test/AttackHandler.sol:AttackHandler]0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f calldata=act_enter(uint256,uint256) args=[32501213753346059511358211640 [3.25e28], 472126103605176242893449044949473489 [4.721e35]]\n\t\tsender=0xad94787EB5F0Ba0D73487eB5245e474C36b324A4 addr=[src/LotteryDepth21.sol:LotteryDepth21]0xE8279BE14E9fe2Ad2D8E52E42Ca96Fb33a813BBe calldata=enter() args=[]\n\t\tsender=0x00000000000000000000000000000000DeaDBeef addr=[test/AttackHandler.sol:AttackHandler]0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f calldata=act_phishOrigin(uint256,uint256,uint256,uint256) args=[53546942319224614219990881997338032365473967929360931116145707 [5.354e61], 2076610845296159486278065306373 [2.076e30], 69940674513141329094872001003930905281900922980529307209965 [6.994e58], 12193311852082848 [1.219e16]]\n\t\tsender=0x000000000000000000000000000000000000066D addr=[test/AttackHandler.sol:AttackHandler]0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f calldata=act_phishOrigin(uint256,uint256,uint256,uint256) args=[6091752493093218896346462850177650778580624749766364496219757402153863 [6.091e69], 12945320989235422235918257805034552064338993201654451 [1.294e52], 969388948845512919640373578903731312154411068939807102 [9.693e53], 621503 [6.215e5]]\n\t\tsender=0xE05598ee33F60Ba9B12F6fE855b81a66b9a7c78F addr=[test/AttackHandler.sol:AttackHandler]0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f calldata=act_enter(uint256,uint256) args=[521738134457674997808160380637 [5.217e29], 285684152383617349559173456350614455802113397131616490667667312809730085 [2.856e71]]\n\t\tsender=0xb7Aa008Bc00802F72A34DCcf4f43C4A209b797E7 addr=[src/LotteryDepth21.sol:LotteryDepth21]0xE8279BE14E9fe2Ad2D8E52E42Ca96Fb33a813BBe calldata=enter() args=[]\n\t\tsender=0xe03cC15Dd293CfB9470b2eEC75B25bf6786F8C1c addr=[test/AttackHandler.sol:AttackHandler]0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f calldata=act_enter(uint256,uint256) args=[4019, 1337]\n\t\tsender=0x00000000000000000000000000000000DeaDBeef addr=[test/AttackHandler.sol:AttackHandler]0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f calldata=act_enter(uint256,uint256) args=[279548890968465390157168665799800480530727 [2.795e41], 243385929242248055623264596838019016441308536252028018535054088780416854 [2.433e71]]\n\t\tsender=0xf1140a1AC3F04540C15E0933672DB121A0ba0BE4 addr=[test/AttackHandler.sol:AttackHandler]0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f calldata=act_phishOrigin(uint256,uint256,uint256,uint256) args=[4, 2485863461 [2.485e9], 10000000000000000000 [1e19], 3547]\n invariant_lottery_fair() (runs: 1, calls: 64, reverts: 30)\n\nEncountered a total of 1 failing tests, 1 tests succeeded\n\nTip: Run `forge test --rerun` to retry only the 1 failed test\n\nFuzz seed: 0x539 (use `--fuzz-seed` to reproduce)\n'

_E4_STDERR = '{"timestamp":1790931542,"event":"failure","invariant":"invariant_lottery_fair","target":"test/Invariant.t.sol:InvariantTest","reason":"panic: assertion failed (0x01)"}\n'

_E4_EVENT_LINE = (
    '{"timestamp":1790931542,"event":"failure",'
    '"invariant":"invariant_lottery_fair",'
    '"target":"test/Invariant.t.sol:InvariantTest",'
    '"reason":"panic: assertion failed (0x01)"}'
)


def test_parse_forge_json_events_extracts_failure_events() -> None:
    text = (
        "Warning: nightly build etc.\n"
        + _E4_EVENT_LINE
        + "\n"
        + '{"timestamp":1,"event":"failure","invariant":"invariant_other",'
          '"target":"t","reason":"x"}\n'
    )
    events = parse_forge_json_events(text)
    assert [e["invariant"] for e in events] == [
        "invariant_lottery_fair",
        "invariant_other",
    ]
    assert events[0]["reason"] == "panic: assertion failed (0x01)"


def test_parse_forge_json_events_ignores_noise() -> None:
    text = "\n".join(
        [
            "not json at all",
            '{"timestamp":2,"event":"success","invariant":"invariant_x"}',
            '{"timestamp":3,"event":"failure"}',  # no invariant named
            '{"timestamp":4, broken json',
            "[FAIL: panic: assertion failed (0x01)]",
            "   ",
            '{"timestamp":5,"event":"failure","invariant":""}',  # empty name
        ]
    )
    assert parse_forge_json_events(text) == []
    assert parse_forge_json_events("") == []


def test_parse_forge_json_events_skips_giant_lines() -> None:
    # A --json suite blob is one giant line; the event scanner must not
    # choke on it (it just skips it).
    giant = '{"test/Invariant.t.sol:InvariantTest": ' + '"x",' * 3000 + "}"
    events = parse_forge_json_events(giant + "\n" + _E4_EVENT_LINE)
    assert len(events) == 1 and events[0]["invariant"] == "invariant_lottery_fair"


def test_truncated_e4_output_still_caught() -> None:
    """The core regression: b02-e4's truncated output is a CATCH, not
    'did not compile'."""
    inv = _lottery_invariant()
    output = _TRUNCATED_E4_STDOUT + "\n" + _E4_STDERR
    assert "[FAIL" not in output  # the truncation destroyed the text block
    findings, campaign = parse_forge_output(
        output, [inv], contract_name="LotteryDepth21",
        target_label="LotteryDepth21.sol:LotteryDepth21",
    )
    assert campaign.compile_ok
    assert not campaign.clean
    assert len(findings) == 1
    f = findings[0]
    assert f.function == "invariant_lottery_fair"
    assert f.metadata["invariant_id"] == "lottery-fair"
    assert f.metadata["proof_signal"] == "forge-json-event"
    # The batch matches on the invariant id appearing in the finding text.
    assert "lottery-fair" in f.description
    # The surviving sequence tail was recovered for the PoC.
    assert "calldata=" in f.poc_code
    assert "enter()" in f.poc_code
    # The JSON event itself is embedded as the machine verdict.
    assert '"event":"failure"' in f.poc_code.replace(" ", "")
    assert f.confidence >= 0.8
    assert f.dynamically_confirmed is True


def test_truncated_e4_output_never_says_did_not_compile() -> None:
    inv = _lottery_invariant()
    output = _TRUNCATED_E4_STDOUT + "\n" + _E4_STDERR
    _findings, campaign = parse_forge_output(output, [inv], forge_rc=1)
    # compile_ok=True: the events prove forge compiled and ran.
    assert campaign.compile_ok


def test_json_event_without_any_sequence_still_caught() -> None:
    """Extreme truncation: the event survives but zero sequence lines do.
    Still a machine-checked catch — never silent, never 'did not compile'."""
    inv = _lottery_invariant()
    findings, campaign = parse_forge_output(
        _E4_EVENT_LINE + "\n", [inv], forge_rc=1,
    )
    assert campaign.compile_ok
    assert len(findings) == 1
    f = findings[0]
    assert f.function == "invariant_lottery_fair"
    # The event line is in the PoC so the proof gate can verify it.
    assert "invariant_lottery_fair" in f.poc_code
    assert f.metadata["proof_signal"] == "forge-json-event"


def test_json_event_for_unknown_invariant_still_counts() -> None:
    """Parity with the legacy text path: the harness auto-adds invariants
    (e.g. invariant_attacker_no_profit) that are not in the caller's list,
    and the old parser reported every named [FAIL] block. A JSON event for
    such an invariant is likewise a real catch, with metadata derived
    from the function name."""
    clean_log = (
        "Ran 1 test for test/Invariant.t.sol:InvariantTest\n"
        "[PASS] invariant_lottery_fair() (runs: 64, calls: 960, reverts: 0)\n"
        "Suite result: ok. 1 passed; 0 failed; 0 skipped\n"
    )
    event = _E4_EVENT_LINE.replace("invariant_lottery_fair", "invariant_ghost")
    findings, campaign = parse_forge_output(
        clean_log + "\n" + event + "\n", [_lottery_invariant()], forge_rc=0,
    )
    assert len(findings) == 1
    assert findings[0].metadata["invariant_id"] == "ghost"
    assert findings[0].metadata["proof_signal"] == "forge-json-event"
    assert campaign.compile_ok and not campaign.clean


def test_text_blocks_still_work_as_fallback() -> None:
    """No JSON events: the classic [FAIL] text path is unchanged."""
    inv = _lottery_invariant()
    log = (
        "Ran 1 test for test/Invariant.t.sol:InvariantTest\n"
        "[FAIL: panic: assertion failed (0x01)] invariant_lottery_fair() "
        "(runs: 1, calls: 64, reverts: 30)\n"
        "\t[Sequence]\n"
        "\t\tsender=0xabc addr=[src/Lottery.sol:Lottery]0xdef "
        "calldata=enter() args=[]\n"
        " invariant_lottery_fair() (runs: 1, calls: 64, reverts: 30)\n"
        "Suite result: FAILED. 0 passed; 1 failed\n"
    )
    findings, campaign = parse_forge_output(log, [inv], forge_rc=1)
    assert campaign.compile_ok and not campaign.clean
    assert len(findings) == 1
    assert findings[0].function == "invariant_lottery_fair"
    assert "proof_signal" not in findings[0].metadata  # text path, not event
    assert "calldata=enter()" in findings[0].poc_code


def test_truncation_simulation_with_real_sandbox_truncator() -> None:
    """Deliberately truncated output: build a long campaign log with the
    [FAIL] block in the middle, truncate it with the REAL SandboxGuard at
    the old 8,192-byte cap, and show the parser still extracts the catch
    from the surviving JSON event."""
    inv = _lottery_invariant()
    filler = "trace line with calldata noise " + "ab" * 40 + "\n"
    fail_block = (
        "[FAIL: panic: assertion failed (0x01)] invariant_lottery_fair() "
        "(runs: 1, calls: 64, reverts: 30)\n"
        "\t[Sequence]\n"
        + "".join(
            f"\t\tsender=0x{i:040x} addr=[src/L.sol:L]0x{'f'*40} "
            f"calldata=enter() args=[]\n"
            for i in range(30)
        )
        + " invariant_lottery_fair() (runs: 1, calls: 64, reverts: 30)\n"
    )
    # [FAIL] block sits >8 KiB into stdout: the old truncation kills it.
    stdout = "Compiling...\n" + filler * 400 + fail_block + filler * 10
    assert len(stdout) > 16384
    stderr = "Warning: nightly build\n\n" + _E4_EVENT_LINE + "\n"
    guard = SandboxGuard(SandboxPolicy(max_revert_reason_bytes=8192))
    truncated = guard.truncate_revert_reason(stdout) + "\n" + guard.truncate_revert_reason(stderr)
    assert "[FAIL" not in truncated  # the text block really is gone
    assert '"event":"failure"' in truncated  # but the event survives
    findings, campaign = parse_forge_output(truncated, [inv], forge_rc=1)
    assert campaign.compile_ok
    assert len(findings) == 1
    assert findings[0].function == "invariant_lottery_fair"


def test_recover_truncated_sequences_backward_scan() -> None:
    lines = [
        "Compiling... done",
        "Ran 1 test",
        "\t\tsender=0xaaa addr=[src/L.sol:L]0xbbb calldata=enter() args=[]",
        "\t\tsender=0xccc addr=[src/L.sol:L]0xddd calldata=draw() args=[]",
        " invariant_lottery_fair() (runs: 1, calls: 64, reverts: 30)",
        "",
        "Encountered a total of 1 failing tests",
    ]
    out = "\n".join(lines)
    got = _recover_truncated_sequences(out, {"invariant_lottery_fair"})
    assert len(got["invariant_lottery_fair"]) == 2
    assert "calldata=draw()" in got["invariant_lottery_fair"][1]
    # Unknown invariants are ignored.
    assert _recover_truncated_sequences(out, {"invariant_nope"}) == {}


def test_forge_rc_zero_with_truncated_suite_line_is_clean() -> None:
    """No suite line, no events, but forge exited 0: ground truth is clean
    (previously mislabeled 'did not compile')."""
    _findings, campaign = parse_forge_output(
        "Compiling...\nRan 1 test\n[truncated]\n",
        [_lottery_invariant()],
        forge_rc=0,
    )
    assert campaign.compile_ok
    assert campaign.clean


def test_garbage_output_with_nonzero_rc_is_not_a_catch() -> None:
    _findings, campaign = parse_forge_output(
        "some garbage\nwith no structure\n", [_lottery_invariant()], forge_rc=1,
    )
    assert _findings == []
    assert not campaign.compile_ok
    assert not campaign.clean


def test_baseline_failure_emits_no_json_event() -> None:
    """A rule false at deployment produces 'failed to set up invariant
    testing environment' and NO failure event (verified against forge
    1.6.0-nightly) — so the event signal can never be a bad rule."""
    log = (
        "[FAIL: failed to set up invariant testing environment: rule false] "
        "invariant_lottery_fair() (runs: 0, calls: 0, reverts: 0)\n"
    )
    assert parse_forge_json_events(log) == []


def test_campaign_output_cap_covers_old_truncation_limit() -> None:
    assert _CAMPAIGN_OUTPUT_CAP_BYTES > 8192


# ---------------------------------------------------------------------------
# Proof-gate interaction: the event line is an acceptable machine trace.
# ---------------------------------------------------------------------------


def _event_only_finding():
    from web3guard.scanner import Finding

    return Finding(
        target="LotteryDepth21",
        language="solidity",
        file="LotteryDepth21.sol",
        function="invariant_lottery_fair",
        category="invariant-violation",
        severity="HIGH",
        confidence=0.8,
        description="Foundry invariant fuzzing broke 'lottery-fair': ...",
        status="POTENTIAL",
        poc_code=(
            "# Forge invariant counterexample (machine-checked).\n"
            "# Forge's own JSON event stream reports this invariant violated:\n"
            "#   " + _E4_EVENT_LINE + "\n"
            "# Call sequence that breaks it:\n"
            "  (call sequence truncated from forge output)\n"
        ),
        fingerprint="invariant-test",
        tool_consensus=["foundry-invariant"],
        dynamically_confirmed=True,
        metadata={"invariant_id": "lottery-fair", "engine": "foundry-invariant"},
    )


def test_proof_gate_admits_event_only_poc() -> None:
    f = _event_only_finding()
    campaign = CampaignResult(engine="foundry-invariant", compile_ok=True)
    verdict = proof_gate.gate_findings(
        [f], {"lottery-fair"}, campaign, target_label="LotteryDepth21",
    )
    assert len(verdict.admitted) == 1
    assert not verdict.rejected
    assert verdict.admitted[0].metadata["proof"]["engine"] == "foundry-invariant"


def test_proof_gate_still_rejects_traceless_poc() -> None:
    """The gate is not weakened: a PoC with neither a call sequence nor a
    forge failure event is still rejected (fail-closed)."""
    f = _event_only_finding()
    f.poc_code = "# nothing verifiable here\n  (no sequence recorded)\n"
    campaign = CampaignResult(engine="foundry-invariant", compile_ok=True)
    verdict = proof_gate.gate_findings(
        [f], {"lottery-fair"}, campaign, target_label="LotteryDepth21",
    )
    assert verdict.admitted == []
    assert len(verdict.rejected) == 1


def test_event_poc_is_deterministic_across_runs() -> None:
    """The embedded JSON event must not leak the per-run timestamp into the
    PoC: two campaigns with different event timestamps must produce
    byte-identical PoCs (fixed-seed reproducibility)."""
    inv = _lottery_invariant()
    log1 = (_TRUNCATED_E4_STDOUT + "\n" + _E4_STDERR).replace(
        '"timestamp":1790931542', '"timestamp":1111111111'
    )
    log2 = (_TRUNCATED_E4_STDOUT + "\n" + _E4_STDERR).replace(
        '"timestamp":1790931542', '"timestamp":9999999999'
    )
    f1, _ = parse_forge_output(log1, [inv], forge_rc=1)
    f2, _ = parse_forge_output(log2, [inv], forge_rc=1)
    assert len(f1) == len(f2) == 1
    assert f1[0].poc_code == f2[0].poc_code
    assert "timestamp" not in f1[0].poc_code
