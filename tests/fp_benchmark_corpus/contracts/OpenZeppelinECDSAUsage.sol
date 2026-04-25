pragma solidity 0.8.20;

contract OpenZeppelinECDSAUsage {
    bytes32 public immutable DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(block.chainid, address(this)));
    }

    function verify(bytes32 structHash, uint8 v, bytes32 r, bytes32 s, address expectedSigner) external returns (bool) {
        require(uint256(s) <= HALF_ORDER, "non-canonical s");
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash, nonces[expectedSigner]));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad signature");
        require(signer == expectedSigner, "wrong signer");
        nonces[expectedSigner] += 1;
        return true;
    }
}