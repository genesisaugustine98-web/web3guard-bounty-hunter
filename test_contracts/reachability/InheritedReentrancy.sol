// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BaseVault {
    mapping(address => uint256) public balances;

    function _withdraw() internal {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        balances[msg.sender] = 0;
    }
}

contract InheritedReentrancy is BaseVault {
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        _withdraw();
    }
}
