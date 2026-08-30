// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// INTENTIONAL VULNERABILITY: single-source spot-price oracle
// (flash-loan/bid-sandwich manipulable).
contract SpotOracle {
    uint256 public lastPrice;
    address public pool;

    constructor(address _pool) { pool = _pool; }

    // VULN: one-shot spot price from a single pool; no TWAP,
    // no staleness check, no deviation bounds.
    function refresh() external {
        (uint112 r0, uint112 r1, ) = IPair(pool).getReserves();
        lastPrice = (uint256(r0) * 1e18) / r1;
    }

    function getPrice() external view returns (uint256) {
        return lastPrice;
    }
}

interface IPair {
    function getReserves() external view
        returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}
