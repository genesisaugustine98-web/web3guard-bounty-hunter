// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerableBank - Classic reentrancy (DO NOT USE)
/// @notice This contract is INTENTIONALLY VULNERABLE for testing scanners.
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "insufficient");
        // VULN: external call BEFORE state update — classic reentrancy
        (bool ok,) = msg.sender.call{value: _amount}("");
        require(ok, "send fail");
        balances[msg.sender] -= _amount;
    }

    function balanceOf(address u) external view returns (uint256) {
        return balances[u];
    }
}
