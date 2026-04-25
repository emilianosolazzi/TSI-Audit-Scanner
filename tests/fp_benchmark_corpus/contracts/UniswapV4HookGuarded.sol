pragma solidity 0.8.20;

contract UniswapV4HookGuarded {
    address public immutable poolManager;
    bytes32 private transientDelta;

    modifier onlyPoolManager() {
        require(msg.sender == poolManager, "not pool manager");
        _;
    }

    constructor(address manager) {
        require(manager != address(0), "zero manager");
        poolManager = manager;
    }

    function beforeSwap(bytes32 poolKey, int256 amountSpecified) external onlyPoolManager returns (bytes4) {
        transientDelta = keccak256(abi.encode(poolKey, amountSpecified));
        return this.beforeSwap.selector;
    }

    function afterSwap(bytes32 poolKey, int256 amountSpecified) external onlyPoolManager returns (bytes4) {
        require(transientDelta == keccak256(abi.encode(poolKey, amountSpecified)), "delta mismatch");
        transientDelta = bytes32(0);
        return this.afterSwap.selector;
    }
}