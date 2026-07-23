// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerableLottery - Weak randomness (DO NOT USE)
/// @notice INTENTIONALLY VULNERABLE for scanner testing.
/// VULN: block.timestamp + blockhash used as randomness source.
contract VulnerableLottery {
    address[] public players;
    uint256 public ticketPrice = 0.01 ether;

    function enter() external payable {
        require(msg.value == ticketPrice, "wrong price");
        players.push(msg.sender);
    }

    function pickWinner() external {
        require(players.length > 0, "no players");
        // VULN: block.timestamp predictable, blockhash only valid for last 256 blocks
        uint256 winnerIndex = uint256(blockhash(block.number - 1)) % players.length;
        address winner = players[winnerIndex];
        players = new address[](0);
        (bool ok,) = winner.call{value: address(this).balance}("");
        require(ok, "transfer fail");
    }
}
