pragma solidity 0.8.20;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract ChainlinkTwapSafe {
    AggregatorV3Interface public immutable feed;
    uint256 public constant MAX_DELAY = 1 hours;

    constructor(AggregatorV3Interface priceFeed) {
        feed = priceFeed;
    }

    function readPrice(uint256 twapPrice) external view returns (uint256) {
        (uint80 roundId, int256 answer,, uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
        require(answer > 0, "bad answer");
        require(updatedAt != 0 && block.timestamp - updatedAt <= MAX_DELAY, "stale");
        require(answeredInRound >= roundId, "stale round");
        uint256 spot = uint256(answer);
        uint256 diff = spot > twapPrice ? spot - twapPrice : twapPrice - spot;
        require(diff * 10_000 / twapPrice <= 500, "twap bound");
        return spot;
    }
}