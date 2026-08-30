// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// INTENTIONAL VULNERABILITY: tx.origin used for authorization.
contract TxOriginLottery {
    address public owner;
    mapping(address => uint256) public wins;

    constructor() { owner = msg.sender; }

    // VULN: tx.origin used for authorization.
    function claim() external {
        require(tx.origin == owner, "not owner");
        wins[msg.sender] += 1;
    }
}
