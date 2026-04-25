pragma solidity 0.8.20;

contract AaveV3PoolFacadeSafe {
    address public riskAdmin;
    bool public paused;

    modifier onlyRiskAdmin() {
        require(msg.sender == riskAdmin, "not risk admin");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    constructor(address admin) {
        riskAdmin = admin;
    }

    function setPause(bool value) external onlyRiskAdmin {
        paused = value;
    }

    function executeOperation(address initiator, uint256 amount, uint256 premium) external whenNotPaused returns (bool) {
        require(initiator == address(this), "bad initiator");
        require(amount + premium >= amount, "overflow");
        return true;
    }
}