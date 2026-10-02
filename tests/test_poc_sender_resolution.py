"""Unit tests for PoC sender-seed resolution (mined-sender evidence).

The ghost/attack handler pranks as ``wgSenderPool[seed % len]``, so
forge's ``sender=`` field shows the outer EOA — not the address the
target actually saw. These tests pin the pool extraction, passthrough
detection, and seed resolution that make PoCs truthful.
"""

from web3guard.invariants.fuzz import (
    _annotate_step_sender,
    _extract_passthrough_names,
    _extract_sender_pool,
)

_TEST_SRC = """
        wgSenderPool.push(address(this));
        wgSenderPool.push(address(uint160(0xB0B)));
        wgSenderPool.push(address(uint160(57005)));
        wgSenderPool.push(address(someVar));
    function mint(address p0, uint256 p1, uint256 _wgSender) public {
    function deposit(uint256 p0, uint256 _wgSender) public {
    function plain(uint256 p0) public {
"""


def test_extract_sender_pool_in_order() -> None:
    pool = _extract_sender_pool(_TEST_SRC)
    assert pool == [
        "address(this)",
        "0x0000000000000000000000000000000000000b0b",
        "0x000000000000000000000000000000000000dead",
        "address(someVar)",
    ]


def test_extract_sender_pool_empty() -> None:
    assert _extract_sender_pool("") == []
    assert _extract_sender_pool("no pushes here") == []


def test_extract_passthrough_names() -> None:
    names = _extract_passthrough_names(_TEST_SRC)
    assert names == {"mint", "deposit"}


def test_annotate_resolves_passthrough_seed() -> None:
    pool = _extract_sender_pool(_TEST_SRC)
    pt = _extract_passthrough_names(_TEST_SRC)
    step = (
        "sender=0x0000000000000000000000000000000000000a33 "
        "addr=[x]0x0 calldata=mint(address,uint256,uint256) "
        "args=[0x1234, 99, 8]"
    )
    # 8 % 4 == 0 -> address(this)
    out = _annotate_step_sender(step, pool, pt)
    assert "[target saw sender address(this)]" in out
    # seed 7 % 4 == 3 -> address(someVar)
    step2 = step.replace(", 8]", ", 7]")
    out2 = _annotate_step_sender(step2, pool, pt)
    assert "[target saw sender address(someVar)]" in out2
    # seed 6 % 4 == 2 -> the mined 0xdead
    step3 = step.replace(", 8]", ", 6]")
    out3 = _annotate_step_sender(step3, pool, pt)
    assert "0x000000000000000000000000000000000000dead" in out3


def test_annotate_leaves_non_passthrough_alone() -> None:
    pool = _extract_sender_pool(_TEST_SRC)
    pt = _extract_passthrough_names(_TEST_SRC)
    step = "sender=0xabc addr=[x]0x0 calldata=plain(uint256) args=[99]"
    assert _annotate_step_sender(step, pool, pt) == step


def test_annotate_no_pool_noop() -> None:
    step = "sender=0xabc calldata=mint(address,uint256,uint256) args=[1, 2, 3]"
    assert _annotate_step_sender(step, [], {"mint"}) == step
    assert _annotate_step_sender(step, ["0x1"], set()) == step


def test_annotate_bad_seed_noop() -> None:
    pool = _extract_sender_pool(_TEST_SRC)
    pt = _extract_passthrough_names(_TEST_SRC)
    step = "sender=0xabc calldata=mint(address,uint256,uint256) args=[1, 2, notanint]"
    assert _annotate_step_sender(step, pool, pt) == step
