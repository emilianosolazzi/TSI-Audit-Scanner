// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Contradiction, FindingKind, Observation, TSISeverity} from "src/core/TSITypes.sol";
import {ITSIAdapter} from "src/interfaces/ITSIAdapter.sol";

interface ISpotTwapOracle {
    function spotPriceX96() external view returns (uint256);
    function twapPriceX96() external view returns (uint256);
}

contract UniswapV2TwapSkewAdapter is ITSIAdapter {
    ISpotTwapOracle public immutable oracle;

    constructor(address oracleAddress) {
        oracle = ISpotTwapOracle(oracleAddress);
    }

    function adapterName() external pure returns (string memory) {
        return "UniswapV2TwapSkewAdapter";
    }

    function adapterPath() external pure returns (string memory) {
        return "src/adapters/UniswapV2TwapSkewAdapter.sol";
    }

    function findingId() external pure returns (string memory) {
        return "TSI-071";
    }

    function defaultTitle() external pure returns (string memory) {
        return "Uniswap spot price drifts from TWAP beyond safe oracle bounds";
    }

    function findingKind() external pure returns (FindingKind) {
        return FindingKind.OracleCompositionVulnerability;
    }

    function defaultSeverity() external pure returns (TSISeverity) {
        return TSISeverity.HIGH;
    }

    function defaultConfidenceScore() external pure returns (uint8) {
        return 80;
    }

    function forkRequired() external pure returns (bool) {
        return false;
    }

    function captureTau1(bytes calldata context) external view returns (Observation memory) {
        uint256 thresholdBps = _decodeThreshold(context);
        uint256 twap = oracle.twapPriceX96();

        return Observation({
            label: "uniswap.twapPriceX96",
            blockNumber: block.number,
            stateHash: keccak256(abi.encode(twap, thresholdBps, "twap")),
            numericValue: int256(twap),
            extraData: abi.encode(thresholdBps)
        });
    }

    function captureTau2(bytes calldata context) external view returns (Observation memory) {
        uint256 thresholdBps = _decodeThreshold(context);
        uint256 spot = oracle.spotPriceX96();

        return Observation({
            label: "uniswap.spotPriceX96",
            blockNumber: block.number,
            stateHash: keccak256(abi.encode(spot, thresholdBps, "spot")),
            numericValue: int256(spot),
            extraData: abi.encode(thresholdBps)
        });
    }

    function hasContradiction(Observation calldata tau1, Observation calldata tau2) external pure returns (bool, string memory) {
        uint256 thresholdBps = abi.decode(tau1.extraData, (uint256));
        uint256 twap = uint256(tau1.numericValue >= 0 ? tau1.numericValue : -tau1.numericValue);
        uint256 spot = uint256(tau2.numericValue >= 0 ? tau2.numericValue : -tau2.numericValue);

        if (twap == 0) {
            return (spot > 0, "TWAP zero while spot is non-zero");
        }

        uint256 deviation = twap > spot ? twap - spot : spot - twap;
        uint256 deviationBps = (deviation * 10_000) / twap;
        if (deviationBps > thresholdBps) {
            return (true, "Spot/TWAP deviation exceeds configured safety threshold");
        }
        return (false, "No spot/TWAP skew detected");
    }

    function buildContradiction(bytes calldata context) external view returns (Contradiction memory) {
        Observation memory tau1 = this.captureTau1(context);
        Observation memory tau2 = this.captureTau2(context);
        (bool mismatch, string memory rationale) = this.hasContradiction(tau1, tau2);

        return Contradiction({
            kind: FindingKind.OracleCompositionVulnerability,
            tau1: tau1,
            tau2: tau2,
            contradiction: mismatch,
            rationale: rationale
        });
    }

    function executeExploit(bytes calldata) external pure returns (bytes memory) {
        revert("UniswapV2TwapSkewAdapter: detection only");
    }

    function _decodeThreshold(bytes calldata context) internal pure returns (uint256) {
        if (context.length == 0) {
            return 150;
        }
        return abi.decode(context, (uint256));
    }
}