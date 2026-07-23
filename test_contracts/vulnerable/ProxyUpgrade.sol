// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerableProxy - Unprotected upgrade (DO NOT USE)
/// @notice INTENTIONALLY VULNERABLE for scanner testing.
/// VULN: upgradeTo is callable by anyone; implementation not initialized.
contract VulnerableProxy {
    address public implementation;
    address public admin;
    uint256[50] private _gap;

    // VULN: no access control on upgradeTo
    function upgradeTo(address newImpl) external {
        implementation = newImpl;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/// @title VulnerableImplementation - Uninitialized (DO NOT USE)
/// @notice INTENTIONALLY VULNERABLE for scanner testing.
contract VulnerableImplementation {
    address public owner;

    // VULN: no initializer modifier, owner stays at 0
    function initialize(address _owner) external {
        owner = _owner;
    }

    // Anyone can call this since owner == address(0) is falsy but == msg.sender check missing
    function adminKill() external {
        selfdestruct(payable(msg.sender));
    }
}
