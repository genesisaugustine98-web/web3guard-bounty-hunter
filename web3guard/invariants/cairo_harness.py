"""Cairo invariant harness (Phase 6).

Renders a self-contained snforge (Starknet Foundry) project for Cairo
(Starknet) contracts:

- ``Scarb.toml`` — package manifest with the ``starknet`` dependency, the
  ``starknet-contract`` target, and ``snforge_std``/``cairo_test``
  dev-dependencies resolved from the Scarb registry (no git needed).
- ``src/lib.cairo`` — the target contract source, verbatim.
- ``tests/invariants.cairo`` — one fuzzed test per invariant. Each test
  deploys a fresh contract instance, executes a randomized sequence of
  state-changing calls driven by the fuzzer's ``ops: Array<felt252>``
  argument, then asserts the invariant. snforge's ``#[fuzzer]`` runs each
  test ``runs`` times with fresh random ``ops``.

Because Cairo entry points are reached through a generated dispatcher
trait, the renderer parses the target's external function signatures
(name, parameter types, ``ref``/view mutability, return type) with a
conservative regex. Only primitive parameter types are fuzzed
(``felt252``, ``u8``–``u128``, ``u256``, ``bool``, ``ContractAddress``);
anything else is skipped with a note. Constructor calldata is filled
with deterministic (seeded) non-zero felts of the right shape.

Invariant assertions are translated by
:func:`translate_assertion_to_cairo`, which accepts a strict grammar —
``dispatcher.<getter>() <op> <literal | dispatcher.<getter>() |
zero-address>`` joined by ``&&``/``||`` — and rejects anything else.
A rejected assertion is reported as untranslatable (honest skip), never
silently dropped or treated as passing.

The module is unit-testable WITHOUT snforge: rendering and assertion
translation are pure string building. Execution needs the persistent
toolchain at ``~/workspace/tools/starknet-foundry`` (snforge, scarb,
universal-sierra-compiler) — see :mod:`web3guard.invariants.fuzz_cairo`.
"""

from __future__ import annotations

import logging
import random
import re

from web3guard.invariants.harness import _sanitize_fn, register_renderer
from web3guard.invariants.models import FuzzBounds, Invariant

LOGGER = logging.getLogger("web3guard.invariants.cairo_harness")

#: Pinned to the installed toolchain (~/workspace/tools). Bump together.
SNFORGE_STD_VERSION = "0.64.0"
STARKNET_DEP_VERSION = "2.20.0"
CAIRO_TEST_VERSION = "2.20.0"

#: Fixed seed so campaigns are reproducible run-to-run.
DEFAULT_SEED = 20261001

#: 2^251 - 1-ish bound not needed; felt252 values from the fuzzer are
#: always < PRIME < 2^252, and u256 covers that range.
_PRIME_FELT_BOUND = (1 << 252) - 1


class UntranslatableAssertion(ValueError):
    """An invariant assertion is outside the strict Cairo grammar."""


class CairoFunction:
    """A parsed external function of the target contract."""

    def __init__(
        self,
        name: str,
        params: list[tuple[str, str]],
        return_type: str,
        mutability: str,  # "external" | "view"
    ) -> None:
        self.name = name
        self.params = params            # (type, name), excluding `self`
        self.return_type = return_type
        self.mutability = mutability

    @property
    def state_changing(self) -> bool:
        return self.mutability == "external"


# ---------------------------------------------------------------------------
# Source introspection (regex-based; conservative by design)
# ---------------------------------------------------------------------------

_CONTRACT_MOD_RE = re.compile(
    r"#\[starknet::contract\]\s*(?:pub\s+)?mod\s+(\w+)"
)
_FN_RE = re.compile(
    r"fn\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^{\n;]+))?"
)
_CONSTRUCTOR_RE = re.compile(
    r"#\[constructor\]\s*fn\s+constructor\s*\(([^)]*)\)"
)
_PARAM_RE = re.compile(r"^\s*(\w+)\s*:\s*([\w:<>,\s]+?)\s*$")

#: Parameter types the fuzz arms know how to build from a felt252.
_SUPPORTED_PARAM_TYPES = frozenset({
    "felt252", "u8", "u16", "u32", "u64", "u128", "u256",
    "bool", "ContractAddress",
})

#: Return types allowed in the generated dispatcher trait.
_SUPPORTED_RETURN_TYPES = _SUPPORTED_PARAM_TYPES | frozenset({"", "()"})


def extract_contract_mod(source: str) -> str:
    """Return the ``#[starknet::contract]`` module name."""
    m = _CONTRACT_MOD_RE.search(source)
    if not m:
        raise ValueError(
            "no #[starknet::contract] module found in source; "
            "not a Starknet contract"
        )
    return m.group(1)


def _split_params(raw: str) -> list[tuple[str, str]]:
    params: list[tuple[str, str]] = []
    for part in raw.split(","):
        part = part.strip()
        if not part or part == "self":
            continue
        m = _PARAM_RE.match(part)
        if not m:
            continue
        pname, ptype = m.group(1).strip(), m.group(2).strip()
        # drop `ref ` on non-self params (rare); keep the base type
        ptype = re.sub(r"^ref\s+", "", ptype).strip()
        params.append((ptype, pname))
    return params


def extract_functions(source: str) -> list[CairoFunction]:
    """Parse external/view functions out of Cairo contract source."""
    fns: list[CairoFunction] = []
    for m in _FN_RE.finditer(source):
        name = m.group(1)
        if name in ("constructor",):
            continue
        raw_params = m.group(2)
        # Classify by the self parameter.
        if re.search(r"\bref\s+self\s*:\s*ContractState\b", raw_params):
            mutability = "external"
        elif re.search(r"\bself\s*:\s*@ContractState\b", raw_params):
            mutability = "view"
        elif re.search(r"\bself\s*:\s*ContractState\b", raw_params):
            mutability = "external"
        else:
            continue  # free function / trait decl without self: skip
        params = _split_params(raw_params)
        return_type = (m.group(3) or "").strip()
        fns.append(CairoFunction(name, params, return_type, mutability))
    return fns


def extract_constructor_params(source: str) -> list[tuple[str, str]]:
    """Parse ``#[constructor]`` parameters (excluding ``ref self``)."""
    m = _CONSTRUCTOR_RE.search(source)
    if not m:
        return []
    params = _split_params(m.group(1))
    return [(t, n) for t, n in params if n != "self"]


# ---------------------------------------------------------------------------
# Assertion translation (strict grammar)
# ---------------------------------------------------------------------------

_OPERAND_RE = (
    r"(?:dispatcher\.[a-z][a-z0-9_]*\(\)"
    r"|\d+"
    r"|contract_address_const::<0>\(\))"
)
_COMPARISON_RE = re.compile(
    rf"\s*({_OPERAND_RE})\s*(==|!=|<=|>=|<|>)\s*({_OPERAND_RE})\s*"
)


def translate_assertion_to_cairo(expr: str) -> str:
    """Translate a template/LLM assertion into strict Cairo.

    Accepted grammar (anything else raises :class:`UntranslatableAssertion`)::

        comparison (("&&" | "||") comparison)*
        comparison := operand ("==" | "!=" | "<=" | ">=" | "<" | ">") operand
        operand    := "dispatcher." ident "()"
                    | integer literal
                    | "contract_address_const::<0>()"

    ``target.`` is rewritten to ``dispatcher.`` and ``address(0)`` to the
    Cairo zero-address expression first.
    """
    e = expr.replace("target.", "dispatcher.")
    e = e.replace("address(0)", "contract_address_const::<0>()")
    parts = re.split(r"(&&|\|\|)", e)
    for k, part in enumerate(parts):
        if k % 2 == 1:
            if part not in ("&&", "||"):
                raise UntranslatableAssertion(
                    f"bad conjunction {part!r} in {expr!r}"
                )
            continue
        if not _COMPARISON_RE.fullmatch(part):
            raise UntranslatableAssertion(
                f"comparison {part!r} is outside the Cairo invariant grammar "
                f"(full assertion: {expr!r})"
            )
    return e


# ---------------------------------------------------------------------------
# Code generation
# ---------------------------------------------------------------------------

_DISPATCHER_METHOD_RE = re.compile(r"^[A-Za-z_]\w*$")


def _dispatcher_trait(fns: list[CairoFunction]) -> tuple[str, list[str]]:
    """Generate the ``#[starknet::interface]`` trait + skip notes."""
    lines = ["#[starknet::interface]", "trait W3gTarget<TContractState> {"]
    notes: list[str] = []
    for fn in fns:
        if not _DISPATCHER_METHOD_RE.match(fn.name):
            notes.append(f"function '{fn.name}' has an unusual name; skipped.")
            continue
        if fn.return_type not in _SUPPORTED_RETURN_TYPES:
            notes.append(
                f"function '{fn.name}' has unsupported return type "
                f"'{fn.return_type}'; skipped."
            )
            continue
        self_decl = (
            "ref self: TContractState"
            if fn.mutability == "external"
            else "self: @TContractState"
        )
        params = ", ".join(f"{n}: {t}" for t, n in fn.params)
        sig = f"    fn {fn.name}({self_decl}"
        if params:
            sig += ", " + params
        sig += ");" if not fn.return_type else f") -> {fn.return_type};"
        lines.append(sig)
    lines.append("}")
    return "\n".join(lines), notes


def _arg_extraction_cairo(ptype: str, pname: str) -> str:
    """Cairo statements binding ``pname`` from fresh LCG randomness.

    Each call site first runs ``let (__r<tag>, __s<tag>) = __w3g_next(__seed);``
    and sets ``__seed = __s<tag>``; the statements below then derive
    ``pname`` from ``__r<tag>``. Every branch is infallible by construction
    (values are masked into range).
    """
    tag = pname  # unique per arm via the __a_ prefix on pname
    conv = (
        f"                let __u{tag}: u256 = __r{tag}.into();\n"
    )
    if ptype == "felt252":
        return f"                let __a{pname}: felt252 = __r{tag};\n"
    if ptype in ("u8", "u16", "u32", "u64", "u128"):
        bits = {"u8": 8, "u16": 16, "u32": 32, "u64": 64, "u128": 128}[ptype]
        mask = f"0x{(1 << bits) - 1:x}_u256"
        return (
            conv
            + f"                let __a{pname}: {ptype} = "
            + f"((__u{tag} % {mask}).try_into().unwrap());\n"
        )
    if ptype == "u256":
        return conv + f"                let __a{pname}: u256 = __u{tag};\n"
    if ptype == "bool":
        # Use bit 64+: an LCG's low bits have tiny periods (bit 0 flips
        # every output), so the raw low bit would be constant per run.
        return (
            conv
            + f"                let __a{pname}: bool = (((__u{tag}.low / 0x10000000000000000_u128) % 2) == 1);\n"
        )
    if ptype == "ContractAddress":
        # Mask below 2^160 < PRIME so both try_into conversions are safe.
        return (
            conv
            + f"                let __m{tag}: u256 = __u{tag} % 0x10000000000000000000000000000000000000000_u256;\n"
            + f"                let __ff{tag}: felt252 = __m{tag}.try_into().unwrap();\n"
            + f"                let __a{pname}: ContractAddress = __ff{tag}.try_into().unwrap();\n"
        )
    raise ValueError(f"unsupported param type {ptype!r}")


def _serialize_cairo(ptype: str, var: str) -> list[str]:
    """Cairo statements appending ``var`` (bound as ``__a<var>``) to ``__cd``.

    Follows Starknet calldata conventions (u256 = low, high).
    """
    v = f"__a{var}"
    if ptype == "u256":
        return [
            f"                __cd.append(({v}.low).into());",
            f"                __cd.append(({v}.high).into());",
        ]
    if ptype == "bool":
        return [f"                __cd.append(if {v} {{ 1 }} else {{ 0 }});"]
    if ptype == "ContractAddress":
        return [f"                __cd.append({v}.into());"]
    # felt252 and all smaller ints serialize as a single felt.
    return [f"                __cd.append({v}.into());"]


def _fuzz_arm(index: int, fn: CairoFunction) -> tuple[str, list[str]]:
    """Generate one ``match`` arm calling ``fn`` with LCG-derived args.

    Uses the low-level ``call_contract_syscall`` (returns a ``Result``)
    instead of the generated dispatcher so that a reverted call is
    *absorbed* — the sequence continues — exactly like Foundry/Medusa
    handler semantics. Only the final invariant ``assert`` can fail the
    test, so a ``[FAIL]`` always means the invariant itself broke.
    """
    notes: list[str] = []
    for ptype, _pname in fn.params:
        if ptype not in _SUPPORTED_PARAM_TYPES:
            notes.append(
                f"function '{fn.name}' takes unsupported type '{ptype}'; "
                "not fuzzed."
            )
            return "", notes
    body: list[str] = []
    for ptype, pname in fn.params:
        var = f"_{pname}"
        body.append(f"                let (__r{var}, __s{var}) = __w3g_next(__seed);")
        body.append(f"                __seed = __s{var};")
        body.append(_arg_extraction_cairo(ptype, var).rstrip("\n"))
    body.append("                let mut __cd: Array<felt252> = array![];")
    for ptype, pname in fn.params:
        body.extend(_serialize_cairo(ptype, f"_{pname}"))
    body.append(
        f"                let _r{index} = starknet::syscalls::call_contract_syscall("
    )
    body.append(f"                    __target, selector!(\"{fn.name}\"), __cd.span());")
    body.append("                // Reverts are absorbed: the sequence continues.")
    arm = (
        f"            {index} => {{\n"
        + "\n".join(body)
        + "\n            },\n"
    )
    return arm, notes


def _constructor_calldata(params: list[tuple[str, str]], seed: int) -> str:
    """Deterministic (seeded) constructor calldata as felt literals.

    u256 serializes as two felts (low, high); everything else as one.
    """
    rng = random.Random(seed)
    felts: list[str] = []
    for ptype, _pname in params:
        if ptype not in _SUPPORTED_PARAM_TYPES:
            raise ValueError(
                f"constructor takes unsupported type '{ptype}'; "
                "cannot build deploy calldata"
            )
        if ptype == "u256":
            felts.append(str(rng.randrange(1 << 200)))
            felts.append(str(rng.randrange(1 << 200)))
        elif ptype == "bool":
            felts.append(str(rng.randrange(2)))
        else:
            felts.append(str(rng.randrange(1 << 64)))
    return ", ".join(felts)


def _render_test_file(
    contract_mod: str,
    fns: list[CairoFunction],
    ctor_params: list[tuple[str, str]],
    invariants: list[Invariant],
    bounds: FuzzBounds,
) -> tuple[str, list[str]]:
    """Render ``tests/invariants.cairo``; returns (content, notes)."""
    notes: list[str] = []
    trait_src, trait_notes = _dispatcher_trait(fns)
    notes.extend(trait_notes)

    state_changing = [fn for fn in fns if fn.state_changing]
    if len(state_changing) > 255:
        # `which` is a u8; more arms than that cannot be addressed.
        notes.append(
            f"{len(state_changing)} fuzzable functions found; only the "
            "first 255 are fuzzed."
        )
        state_changing = state_changing[:255]
    arms: list[str] = []
    for idx, fn in enumerate(state_changing):
        arm, arm_notes = _fuzz_arm(idx, fn)
        notes.extend(arm_notes)
        if arm:
            arms.append(arm)
    n_fns = len(arms)
    if n_fns == 0:
        notes.append(
            "no fuzzable state-changing functions found; the campaign "
            "will deploy and check invariants once without any calls."
        )

    try:
        ctor_calldata = _constructor_calldata(ctor_params, DEFAULT_SEED)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    ctor_array = f"@array![{ctor_calldata}]" if ctor_calldata else "@array![]"

    parts: list[str] = [
        "// Web3Guard-generated Cairo invariant harness (Phase 6).",
        "// One fuzzed test per invariant: snforge deploys a fresh contract,",
        "// expands the fuzzed `seed` into a randomized call sequence with an",
        "// in-test LCG, then asserts the invariant.",
        "use snforge_std::{declare, ContractClassTrait, DeclareResultTrait};",
        "use starknet::{contract_address_const, ContractAddress};",
        "use core::num::traits::OverflowingAdd;",
        "",
        trait_src,
        "",
        "// Deterministic LCG: the fuzzer varies `seed` across runs; this",
        "// expands one seed into a full call sequence. All arithmetic wraps",
        "// at 2^128 (well below PRIME), so nothing can panic.",
        "fn __w3g_next(seed: felt252) -> (felt252, felt252) {",
        "    let s: u128 = {",
        "        let su: u256 = seed.into();",
        "        su.low",
        "    };",
        "    let (_, prod_lo) = core::integer::u128_wide_mul(",
        "        s, 6364136223846793005_u128);",
        "    let (ns, _overflowed): (u128, bool) =",
        "        prod_lo.overflowing_add(1442695040888963407_u128);",
        "    let v: felt252 = ns.into();",
        "    (v, v)",
        "}",
        "",
        "fn __w3g_deploy() -> W3gTargetDispatcher {",
        f"    let (contract_address, _) = declare(\"{contract_mod}\")",
        "        .unwrap()",
        "        .contract_class()",
        f"        .deploy({ctor_array})",
        "        .unwrap();",
        "    W3gTargetDispatcher { contract_address }",
        "}",
        "",
    ]

    # Only invariants whose assertions survive translation get a test.
    translatable: list[tuple[Invariant, str]] = []
    for inv in invariants:
        try:
            cairo_assertion = translate_assertion_to_cairo(inv.assertion)
        except UntranslatableAssertion as exc:
            notes.append(
                f"invariant '{inv.id}' is outside the Cairo assertion grammar "
                f"({exc}); skipped, NOT treated as passing."
            )
            continue
        translatable.append((inv, cairo_assertion))
    if not translatable:
        notes.append("no translatable invariants; emitting a deploy-only test.")

    match_arms = "".join(arms) if arms else "            _ => {},\n"
    for inv, cairo_assertion in translatable:
        fn_name = _sanitize_fn("invariant_" + inv.id)
        # assert messages are short-strings: cap at 31 chars.
        msg = inv.id[:31]
        parts.append("#[test]")
        parts.append(
            f"#[fuzzer(runs: {bounds.runs}, seed: {DEFAULT_SEED})]"
        )
        parts.append(f"fn {fn_name}(seed: felt252) {{")
        parts.append("    let dispatcher = __w3g_deploy();")
        parts.append("    let __target = dispatcher.contract_address;")
        if n_fns:
            parts.append("    let mut __seed: felt252 = seed;")
            parts.append("    let mut __step: usize = 0;")
            parts.append(f"    while __step < {bounds.depth} {{")
            parts.append("        let (__r, __s) = __w3g_next(__seed);")
            parts.append("        __seed = __s;")
            parts.append("        let __ru: u256 = __r.into();")
            # High bits: an LCG's low bits have tiny periods (bit 0 flips
            # every output, and we draw twice per step), so selecting the
            # function from the raw low bits would call the same function
            # every step. Bits 64+ are the well-mixed ones.
            parts.append("        let __r128: u128 = __ru.low;")
            parts.append(
                f"        let which: u8 = (((__r128 / 0x10000000000000000_u128)"
                f" % {n_fns}_u128).try_into().unwrap());"
            )
            parts.append("        match which {")
            parts.append(match_arms.rstrip("\n"))
            parts.append("            _ => {},")
            parts.append("        };")
            parts.append("        __step += 1;")
            parts.append("    };")
        parts.append(f"    assert({cairo_assertion}, '{msg}');")
        parts.append("}")
        parts.append("")

    if not translatable:
        parts.append("#[test]")
        parts.append("fn w3g_deploy_only() {")
        parts.append("    let _d = __w3g_deploy();")
        parts.append("}")

    return "\n".join(parts) + "\n", notes


def _sanitize_pkg(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_]", "_", name).lower()
    if clean and clean[0].isdigit():
        clean = "w3g_" + clean
    return clean or "w3g_target"


_SCARB_TOML_TEMPLATE = """\
# Web3Guard-generated Scarb.toml (Phase 6 Cairo invariant harness).
# Pinned to the persistent toolchain in ~/workspace/tools.
[package]
name = "__PKG__"
version = "0.1.0"
edition = "2024_07"

[dependencies]
starknet = "__STARKNET__"

[[target.starknet-contract]]
sierra = true

[dev-dependencies]
snforge_std = "__SNFORGE_STD__"
cairo_test = "__CAIRO_TEST__"

[tool.scarb]
allow-prebuilt-plugins = ["snforge_std"]
"""


# Pre-resolved dependency lock for the pinned toolchain (snforge_std
# 0.64.0). Scarb verifies this against its local cache WITHOUT touching
# the network — which matters because campaigns run sandboxed as
# ``nobody`` with no registry access. Without a lock file, scarb tries to
# refresh the registry index and the campaign fails. The project package
# entry is templated with the sanitized package name.
_SCARB_LOCK_TEMPLATE = """\
# Code generated by scarb DO NOT EDIT.
# (Web3Guard Phase 6: pre-resolved for offline sandboxed campaigns.)
version = 1

[[package]]
name = "snforge_scarb_plugin"
version = "0.64.0"
source = "registry+https://scarbs.xyz/"
checksum = "sha256:b6e330b8303add0d1a32e636e4e0d2b44a6b4ff5632bfe0ce66f136a701ae151"

[[package]]
name = "snforge_std"
version = "0.64.0"
source = "registry+https://scarbs.xyz/"
checksum = "sha256:ea9ca83895fd0ae4b99c5cf93b384b8045dc0dca80a075ecef1ee9fdf5ffa6f5"
dependencies = [
 "snforge_scarb_plugin",
]

[[package]]
name = "__PKG__"
version = "0.1.0"
dependencies = [
 "snforge_std",
]
"""


def render_cairo_project(
    contract_source: str,
    contract_name: str,
    invariants: list[Invariant],
    bounds: FuzzBounds,
) -> dict[str, str]:
    """Render a complete snforge project as {relative_path: content}."""
    contract_mod = extract_contract_mod(contract_source)
    fns = extract_functions(contract_source)
    ctor_params = extract_constructor_params(contract_source)
    test_src, _notes = _render_test_file(
        contract_mod, fns, ctor_params, invariants, bounds
    )
    pkg = _sanitize_pkg(contract_name)
    scarb_toml = (
        _SCARB_TOML_TEMPLATE.replace("__PKG__", pkg)
        .replace("__STARKNET__", STARKNET_DEP_VERSION)
        .replace("__SNFORGE_STD__", SNFORGE_STD_VERSION)
        .replace("__CAIRO_TEST__", CAIRO_TEST_VERSION)
    )
    scarb_lock = _SCARB_LOCK_TEMPLATE.replace("__PKG__", pkg)
    return {
        "Scarb.toml": scarb_toml,
        "Scarb.lock": scarb_lock,
        "src/lib.cairo": contract_source,
        "tests/invariants.cairo": test_src,
    }


register_renderer("cairo", render_cairo_project)


__all__ = [
    "CAIRO_TEST_VERSION",
    "DEFAULT_SEED",
    "SNFORGE_STD_VERSION",
    "STARKNET_DEP_VERSION",
    "CairoFunction",
    "UntranslatableAssertion",
    "extract_constructor_params",
    "extract_contract_mod",
    "extract_functions",
    "render_cairo_project",
    "translate_assertion_to_cairo",
]
