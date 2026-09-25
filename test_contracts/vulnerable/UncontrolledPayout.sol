// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title UncontrolledPayout - pays caller-supplied amounts from a ledger (DO NOT USE)
/// @notice INTENTIONALLY VULNERABLE for scanner testing.
///
/// Both flaws are pure business logic: no missing modifier, no reentrancy
/// shape, no arithmetic overflow. The ledger is read as a *gate* only and
/// the paid amount comes straight from the caller's parameter.
contract UncontrolledPayout {
    IERC20 public immutable token;
    mapping(address => uint256) public claimable;
    uint256 public constant FEE_BPS = 30; // intended: 0.3% = /10_000

    constructor(IERC20 _token) {
        token = _token;
        claimable[msg.sender] = 1000e18;
    }

    function register(uint256 amount) external {
        claimable[msg.sender] = amount;
    }

    // VULN: pays `amount` (caller-supplied) instead of the entitled
    // amount; the ledger mapping is honored in name only.
    function claim(uint256 amount) external {
        require(claimable[msg.sender] > 0, "not entitled");
        token.transfer(msg.sender, amount);
        delete claimable[msg.sender];
    }

    // VULN: fee math mixes basis points with a 1e18 divisor, so the
    // intended 0.3% fee is ~1e14x smaller than designed.
    function claimWithFee(uint256 amount) external {
        require(claimable[msg.sender] > 0, "not entitled");
        uint256 fee = amount * FEE_BPS / 1e18;
        token.transfer(msg.sender, amount - fee);
        delete claimable[msg.sender];
    }
}
