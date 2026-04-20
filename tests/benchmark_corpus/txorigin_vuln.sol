pragma solidity ^0.8.20;

contract TxOriginVuln {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function privilegedAction() external view returns (bool) {
        return tx.origin == owner;
    }
}
