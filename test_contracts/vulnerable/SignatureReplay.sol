// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerableMetaTx - Signature replay (DO NOT USE)
/// @notice INTENTIONALLY VULNERABLE for scanner testing.
/// VULN: signature replay across chains (no chainid in domain separator).
contract VulnerableMetaTx {
    address public owner;
    mapping(bytes32 => bool) public used;

    constructor() { owner = msg.sender; }

    function executeMetaTx(
        address from,
        address to,
        uint256 value,
        bytes calldata data,
        bytes calldata signature
    ) external payable {
        // VULN: domain separator doesn't include chainid
        bytes32 hash = keccak256(abi.encodePacked(
            from, to, value, keccak256(data)
        ));
        // VULN: no nonce in the signed payload
        require(!used[hash], "used");
        used[hash] = true;
        require(ecrecover(hash, _v(signature), _r(signature), _s(signature)) == from, "bad sig");
        (bool ok,) = to.call{value: value}(data);
        require(ok, "call fail");
    }

    function _v(bytes calldata s) internal pure returns (uint8) { return uint8(s[64]); }
    function _r(bytes calldata s) internal pure returns (bytes32) { return bytes32(s[0:32]); }
    function _s(bytes calldata s) internal pure returns (bytes32) { return bytes32(s[32:64]); }

    receive() external payable {}
}
