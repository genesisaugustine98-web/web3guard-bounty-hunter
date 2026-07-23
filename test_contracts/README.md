# Test Contracts

This directory contains Solidity contracts used to validate that Web3Guard's
detection engine actually works.

## Vulnerable contracts (`vulnerable/`)

These are INTENTIONALLY VULNERABLE. Each one demonstrates a single, well-known
vulnerability class. A correctly-tuned scanner MUST flag them with
`status = "vulnerable"`.

| File                            | Vulnerability class                              |
|---------------------------------|--------------------------------------------------|
| `ReentrancyVault.sol`           | Classic reentrancy (CEI violation)               |
| `AccessControlFlaw.sol`         | Missing access control on privileged functions  |
| `OracleManipulation.sol`        | Spot price from single (manipulable) DEX pair    |
| `SignatureReplay.sol`           | EIP-712 / domain-separator missing chainid       |
| `ProxyUpgrade.sol`              | Unprotected `upgradeTo` + uninitialized impl     |
| `RandomnessLottery.sol`         | `block.timestamp` / `blockhash` as RNG          |
| `ArithmeticVault.sol`           | ERC-4626 first-deposit inflation + rounding      |

## Clean contracts (`clean/`)

These follow current best practices and should NOT trigger any critical
findings. A scanner that flags these has a high false-positive rate.

| File                  | Description                            |
|-----------------------|----------------------------------------|
| `SafeVault.sol`       | ReentrancyGuard + CEI + Ownable + Pausable |
| `SafeERC20.sol`       | OpenZeppelin ERC-20 + AccessControl    |

## How to self-test

```bash
# 1. Scan a vulnerable contract
python core_scanner.py \
  --targets-config "file://$(pwd)/test_contracts/vulnerable|max" \
  --nim-api-key "$NIM_API_KEY"

# 2. Confirm the report flags the right thing
cat WEB3GUARD_EXPLOIT_REPORT.txt
grep "CONFIRMED EXPLOIT" WEB3GUARD_EXPLOIT_REPORT.txt

# 3. Inspect the PoC Foundry test
ls exploit_sandboxes/
cd exploit_sandboxes/<hash>/
forge test --match-test test_autonomous_exploit -vvv
```

Expected: each `vulnerable/*.sol` produces at least one CONFIRMED EXPLOIT
entry, and `clean/*.sol` produces none.
