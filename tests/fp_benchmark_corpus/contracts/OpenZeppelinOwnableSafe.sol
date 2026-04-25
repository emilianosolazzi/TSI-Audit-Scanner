pragma solidity 0.8.20;

contract OpenZeppelinOwnableSafe {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero owner");
        owner = newOwner;
    }

    function setFee(uint256 newFeeBps) external onlyOwner {
        require(newFeeBps <= 1_000, "fee too high");
    }
}