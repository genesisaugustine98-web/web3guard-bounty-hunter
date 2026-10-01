"""Regression tests for the deepened non-EVM detectors (Phase 1).

Each detector gets a positive case (must fire) and a negative case
(must stay silent) so future edits cannot silently weaken them.
"""
from web3guard.discovery.static_analyzer import (
    _detect_cairo,
    _detect_clarity,
    _detect_func,
    _detect_move,
    _detect_rust_solana,
    _detect_ts_sdk,
)


def _cats(detector, code: str, name: str = "t") -> set[str]:
    ext = {
        _detect_move: "move", _detect_cairo: "cairo",
        _detect_clarity: "clar", _detect_func: "fc",
        _detect_rust_solana: "rs", _detect_ts_sdk: "ts",
    }[detector]
    return {i.category for i in detector(code, f"{name}.{ext}")}


# --- Move ---------------------------------------------------------------

def test_move_entry_without_signer() -> None:
    vuln = ("module m::v { struct V has key { x: u64 } "
            "public entry fun set(x: u64) { "
            "let v = borrow_global_mut<V>(@0x1); v.x = x; } }")
    assert "access-control" in _cats(_detect_move, vuln)
    safe = ("module m::v { struct V has key { x: u64 } "
            "public entry fun set(s: &signer, x: u64) acquires V { "
            "let v = borrow_global_mut<V>(@0x1); v.x = x; } }")
    assert "access-control" not in _cats(_detect_move, safe)


def test_move_from_without_exists() -> None:
    vuln = ("module m::v { struct C has key {} "
            "public fun take(a: &signer): C { move_from<C>(@0x1) } }")
    assert "denial-of-service" in _cats(_detect_move, vuln)
    safe = ("module m::v { struct C has key {} "
            "public fun take(a: &signer): C { "
            "assert!(exists<C>(@0x1), 1); move_from<C>(@0x1) } }")
    assert "denial-of-service" not in _cats(_detect_move, safe)


def test_move_unrestricted_mint() -> None:
    vuln = ("module m::c { public fun mint(x: u64): Coin { "
            "coin::mint(x, &cap) } }")
    assert "access-control" in _cats(_detect_move, vuln)
    safe = ("module m::c { public fun mint(cap: &MintCapability, x: u64) { "
            "coin::mint(x, cap) } }")
    assert "access-control" not in _cats(_detect_move, safe)


# --- Cairo --------------------------------------------------------------

def test_cairo_owner_takeover() -> None:
    vuln = ("#[starknet::contract] mod M { "
            "#[storage] struct Storage { owner: ContractAddress, } "
            "#[external(v0)] fn set_owner(ref self: ContractState, "
            "o: ContractAddress) { self.owner.write(o); } }")
    assert "access-control" in _cats(_detect_cairo, vuln)
    safe = ("#[starknet::contract] mod M { "
            "#[storage] struct Storage { owner: ContractAddress, } "
            "#[external(v0)] fn set_owner(ref self: ContractState, "
            "o: ContractAddress) { assert(caller_is_owner(), 'no'); "
            "self.owner.write(o); } }")
    assert "access-control" not in _cats(_detect_cairo, safe)


def test_cairo_timestamp_randomness() -> None:
    vuln = ("#[starknet::contract] mod M { "
            "#[external(v0)] fn play(ref self: ContractState) { "
            "let t = get_block_timestamp(); let w = t % 100; } }")
    assert "randomness" in _cats(_detect_cairo, vuln)
    safe = ("#[starknet::contract] mod M { "
            "#[external(v0)] fn poke(ref self: ContractState) { "
            "let t = get_block_timestamp(); "
            "assert(t > self.last.read(), 'time'); } }")
    assert "randomness" not in _cats(_detect_cairo, safe)


# --- Clarity ------------------------------------------------------------

def test_clarity_unwrap_panic_dos() -> None:
    vuln = ("(define-public (f (x uint)) (begin "
            "(unwrap-panic (map-get? m x)) (ok true)))")
    assert "denial-of-service" in _cats(_detect_clarity, vuln)
    safe = ("(define-private (g (x uint)) (begin "
            "(unwrap-panic (map-get? m x)) (ok true)))")
    assert "denial-of-service" not in _cats(_detect_clarity, safe)


def test_clarity_discarded_transfer() -> None:
    vuln = ("(define-public (pay (amt uint)) (begin "
            "(stx-transfer? amt tx-sender 'ST1X) (ok true)))")
    assert "unchecked-external-call" in _cats(
        _detect_clarity, vuln) and any(
        i.title == "Token transfer response is discarded"
        for i in _detect_clarity(vuln, "t.clar"))
    safe = ("(define-public (pay (amt uint)) (begin "
            "(try! (stx-transfer? amt tx-sender 'ST1X)) (ok true)))")
    assert not any(i.title == "Token transfer response is discarded"
                   for i in _detect_clarity(safe, "t.clar"))


def test_clarity_privileged_var_set() -> None:
    vuln = ("(define-public (set-o (o principal)) (begin "
            "(var-set owner o) (ok true)))")
    assert any(i.title == "Privileged var-set without caller authorization"
               for i in _detect_clarity(vuln, "t.clar"))
    safe = ("(define-public (set-o (o principal)) (begin "
            "(asserts! (is-eq contract-caller (var-get owner)) (err u1)) "
            "(var-set owner o) (ok true)))")
    assert not any(
        i.title == "Privileged var-set without caller authorization"
        for i in _detect_clarity(safe, "t.clar"))


# --- FunC ---------------------------------------------------------------

def test_func_funds_without_sender_check() -> None:
    vuln = ("() recv_internal(int v, cell m, slice b) impure { "
            "accept(); send_raw_message(m, 64); }")
    assert "access-control" in _cats(_detect_func, vuln)
    safe = ("() recv_internal(int v, cell m, slice b) impure { "
            "accept(); throw_unless(100, equal?(sender(), owner())); "
            "send_raw_message(m, 64); }")
    assert "access-control" not in _cats(_detect_func, safe)


def test_func_missing_bounce_handling() -> None:
    vuln = ("() recv_internal(int v, cell m, slice b) impure { "
            "accept(); send_raw_message(m, 0); }")
    assert "denial-of-service" in _cats(_detect_func, vuln)
    safe = vuln + "\n;; bounced\n() on_bounce(slice b) impure { ;; bounced\n}"
    assert "denial-of-service" not in _cats(_detect_func, safe)


# --- Solana -------------------------------------------------------------

def test_solana_missing_signer() -> None:
    vuln = ("#[derive(Accounts)] pub struct W<'info> { "
            "#[account(mut)] pub v: Account<'info, V>, } "
            "#[program] pub mod m { use super::*; "
            "pub fn go(ctx: Context<W>) -> Result<()> { "
            "**ctx.accounts.v.to_account_info().try_borrow_mut_lamports()? "
            "-= 1; Ok(()) } }")
    assert any(i.title == "Instruction mutates state with no signer account"
               for i in _detect_rust_solana(vuln, "t.rs"))
    safe = vuln.replace("pub v: Account<'info, V>,",
                        "pub v: Account<'info, V>, pub s: Signer<'info>,")
    assert not any(
        i.title == "Instruction mutates state with no signer account"
        for i in _detect_rust_solana(safe, "t.rs"))


def test_solana_pda_without_bump() -> None:
    vuln = ("#[derive(Accounts)] pub struct P<'info> { "
            "#[account(init, payer = u, space = 40, seeds = [b\"v\"])] "
            "pub v: Account<'info, V>, }")
    assert "access-control" in _cats(_detect_rust_solana, vuln)
    safe = vuln.replace('seeds = [b"v"]', 'seeds = [b"v"], bump')
    assert "access-control" not in _cats(_detect_rust_solana, safe)


def test_solana_unbounded_vec() -> None:
    vuln = "#[account] pub struct V { pub items: Vec<u64>, }"
    assert "denial-of-service" in _cats(_detect_rust_solana, vuln)
    safe = "#[account] pub struct V { #[max_len(16)] pub items: Vec<u64>, }"
    assert "denial-of-service" not in _cats(_detect_rust_solana, safe)


# --- TypeScript ---------------------------------------------------------

def test_ts_hardcoded_private_key() -> None:
    vuln = 'const PRIVATE_KEY = "0x' + "ab" * 32 + '";'
    assert any(i.severity == "CRITICAL"
               for i in _detect_ts_sdk(vuln, "t.ts"))
    safe = "const w = new ethers.Wallet(process.env.PRIVATE_KEY!, p);"
    assert not any(i.severity == "CRITICAL"
                   for i in _detect_ts_sdk(safe, "t.ts"))


def test_ts_hardcoded_mnemonic() -> None:
    vuln = ('const mnemonic = "abandon abandon abandon abandon abandon '
            'abandon abandon abandon abandon abandon abandon about";')
    assert any(i.severity == "CRITICAL"
               for i in _detect_ts_sdk(vuln, "t.ts"))


def test_ts_math_random_secret() -> None:
    vuln = "const nonce = Math.floor(Math.random() * 1e9); // signing nonce"
    assert "randomness" in _cats(_detect_ts_sdk, vuln)
    safe = "const jitter = Math.floor(Math.random() * 100); // backoff"
    assert "randomness" not in _cats(_detect_ts_sdk, safe)


def test_ts_hardcoded_api_key() -> None:
    vuln = ('const P = new ethers.JsonRpcProvider('
            '"https://eth-mainnet.g.alchemy.com/v2/abcd1234EFGH5678ijkl");')
    assert "secret-leak" in _cats(_detect_ts_sdk, vuln)
    safe = 'const u = "https://api.example.com/v2/users";'
    assert "secret-leak" not in _cats(_detect_ts_sdk, safe)
