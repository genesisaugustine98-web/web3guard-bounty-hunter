// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerableVault - Missing access control (DO NOT USE)
/// @notice INTENTIONALLY VULNERABLE for scanner testing.
contract VulnerableVault {
    address public owner;
    uint256 public feeBps;
    mapping(address => bool) public whitelist;
    mapping(address => uint256) public deposits;

    constructor() {
        owner = msg.sender;
    }

    // VULN: no access control — anyone can become owner
    function setOwner(address _newOwner) external {
        owner = _newOwner;
    }

    // VULN: no access control — anyone can set fee up to 100%
    function setFee(uint256 _feeBps) external {
        feeBps = _feeBps;
    }

    // VULN: anyone can whitelist themselves
    function addToWhitelist(address _user) external {
        whitelist[_user] = true;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) external {
        require(deposits[msg.sender] >= _amount, "insufficient");
        deposits[msg.sender] -= _amount;
        (bool ok,) = msg.sender.call{value: _amount}("");
        require(ok, "send fail");
    }
}
