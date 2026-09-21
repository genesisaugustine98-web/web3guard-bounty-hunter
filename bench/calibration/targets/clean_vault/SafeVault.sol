// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title SafeVault - Hardened reference implementation
/// @notice This contract should NOT trigger any critical findings.
///         Used as a true-negative test case for the scanner.
contract SafeVault is ReentrancyGuard, Ownable, Pausable {
    mapping(address => uint256) private _balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    error InsufficientBalance();
    error ZeroAmount();
    error ZeroAddress();

    constructor() Ownable(msg.sender) {}

    function deposit() external payable whenNotPaused {
        if (msg.value == 0) revert ZeroAmount();
        _balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert ZeroAmount();
        uint256 bal = _balances[msg.sender];
        if (amount > bal) revert InsufficientBalance();

        // CEI: state update BEFORE external call
        unchecked { _balances[msg.sender] = bal - amount; }

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "ETH send failed");

        emit Withdraw(msg.sender, amount);
    }

    function balanceOf(address user) external view returns (uint256) {
        return _balances[user];
    }

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    receive() external payable { revert ZeroAmount(); }
    fallback() external payable { revert ZeroAmount(); }
}
