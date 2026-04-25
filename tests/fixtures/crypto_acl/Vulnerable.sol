// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Vulnerable contract for crypto-ACL detector self-test.
/// Hits CRYPTO-IDM-001, CRYPTO-MAL-001, CRYPTO-CTX-001, CRYPTO-RPL-001.
contract VulnerableCryptoAcl {
    mapping(bytes20 => bool) public isAuthorizedSigner; // IDM: truncated authority

    function register(bytes calldata pubkey) external {
        // CRYPTO-IDM-001: truncated identity bound to authority.
        isAuthorizedSigner[bytes20(keccak256(pubkey))] = true;
    }

    function exec(
        address to,
        uint256 amt,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // CRYPTO-CTX-001: digest omits chainId + address(this).
        // CRYPTO-RPL-001: no nonce read+write, no usedHashes guard.
        bytes32 d = keccak256(abi.encode(to, amt));
        // CRYPTO-MAL-001: raw ecrecover, no canonical-s bound, no OZ wrapper.
        address signer = ecrecover(d, v, r, s);
        require(signer != address(0), "bad sig");
    }
}
