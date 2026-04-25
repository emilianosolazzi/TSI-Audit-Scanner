pragma solidity 0.8.20;

contract CompoundCometFacadeSafe {
    mapping(address => uint256) public collateral;
    bool public supplyPaused;

    modifier whenSupplyOpen() {
        require(!supplyPaused, "supply paused");
        _;
    }

    function supply(uint256 amount) external whenSupplyOpen {
        require(amount > 0, "zero amount");
        collateral[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external whenSupplyOpen {
        require(collateral[msg.sender] >= amount, "insufficient collateral");
        collateral[msg.sender] -= amount;
    }
}