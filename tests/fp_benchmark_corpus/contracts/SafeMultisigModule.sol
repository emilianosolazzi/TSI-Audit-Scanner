pragma solidity 0.8.20;

contract SafeMultisigModule {
    mapping(address => bool) public isOwner;
    mapping(bytes32 => bool) public usedHashes;
    uint256 public threshold;

    constructor(address ownerA, address ownerB) {
        isOwner[ownerA] = true;
        isOwner[ownerB] = true;
        threshold = 2;
    }

    function execute(bytes32 txHash, address signerA, address signerB) external returns (bool) {
        require(!usedHashes[txHash], "replay");
        require(signerA != signerB, "duplicate signer");
        require(isOwner[signerA] && isOwner[signerB], "not owners");
        require(threshold == 2, "bad threshold");
        usedHashes[txHash] = true;
        return true;
    }
}