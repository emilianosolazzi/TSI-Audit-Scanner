pragma solidity 0.8.20;

library LocalSafeCast {
    function toUint128(uint256 value) internal pure returns (uint128) {
        require(value <= type(uint128).max, "SafeCast: overflow");
        return uint128(value);
    }
}

contract OpenZeppelinSafeCastUsage {
    using LocalSafeCast for uint256;

    function checkpoint(uint256 timestamp) external pure returns (uint128) {
        return timestamp.toUint128();
    }
}