// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerableVault4626 - ERC-4626 first-deposit inflation attack (DO NOT USE)
/// @notice INTENTIONALLY VULNERABLE for scanner testing.
/// VULN: share inflation via virtual shares OR rounding, no deposit/withdraw limits.
contract VulnerableVault4626 {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;

    // VULN: when totalShares == 0, attacker deposits 1 wei and gets 1 share,
    // then donates a huge amount directly to the vault to inflate share price,
    // then subsequent depositors lose funds.
    function deposit() external payable {
        uint256 amount = msg.value;
        uint256 share;
        if (totalShares == 0) {
            share = amount; // VULN: should be amount - 1 or use virtual shares
        } else {
            share = amount * totalShares / totalAssets;
        }
        shares[msg.sender] += share;
        totalShares += share;
        totalAssets += amount;
        balanceOf[msg.sender] += amount;
    }

    // VULN: rounding down in withdraw favors the attacker
    function withdraw(uint256 share) external {
        uint256 amount = share * totalAssets / totalShares;
        shares[msg.sender] -= share;
        totalShares -= share;
        totalAssets -= amount;
        balanceOf[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send fail");
    }
}
