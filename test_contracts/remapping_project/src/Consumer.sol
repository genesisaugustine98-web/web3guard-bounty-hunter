// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "mylib/contracts/Helper.sol";

contract Consumer {
    function sum(uint256 a, uint256 b) external pure returns (uint256) {
        return Helper.add(a, b);
    }
}
