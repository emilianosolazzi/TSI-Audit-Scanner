// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

library FrozenStateVerifier {
    function freeze(bytes memory payload, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(payload, nonce));
    }

    function verify(bytes32 frozenHash, bytes memory payload, uint256 nonce, uint256) internal pure returns (bool) {
        return frozenHash == keccak256(abi.encode(payload, nonce));
    }
}
