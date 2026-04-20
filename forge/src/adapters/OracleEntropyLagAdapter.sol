// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Contradiction, FindingKind, Observation, TSISeverity} from "src/core/TSITypes.sol";
import {ITSIAdapter} from "src/interfaces/ITSIAdapter.sol";

interface IAggregatorV3Entropy {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );

    function getRoundData(uint80 _roundId) external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

contract OracleEntropyLagAdapter is ITSIAdapter {
    IAggregatorV3Entropy public immutable oracle;
    uint256 public immutable heartbeatSeconds;

    constructor(address oracleAddress, uint256 heartbeat) {
        oracle = IAggregatorV3Entropy(oracleAddress);
        heartbeatSeconds = heartbeat;
    }

    function adapterName() external pure returns (string memory) {
        return "OracleEntropyLagAdapter";
    }

    function adapterPath() external pure returns (string memory) {
        return "src/adapters/OracleEntropyLagAdapter.sol";
    }

    function findingId() external pure returns (string memory) {
        return "TSI-021";
    }

    function defaultTitle() external pure returns (string memory) {
        return "Sequential oracle rounds diverge beyond freshness expectations";
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

    function captureTau1(bytes calldata) external view returns (Observation memory) {
        (uint80 latestId,,,,) = oracle.latestRoundData();
        require(latestId > 0, "OracleEntropyLagAdapter: missing previous round");
        (uint80 prevRoundId, int256 prevAnswer,, uint256 prevUpdatedAt,) = oracle.getRoundData(uint80(latestId - 1));

        return Observation({
            label: "oracle.roundN-1",
            blockNumber: block.number > 0 ? block.number - 1 : 0,
            stateHash: keccak256(abi.encode(prevRoundId, prevAnswer, prevUpdatedAt)),
            numericValue: prevAnswer,
            extraData: abi.encode(prevRoundId, prevUpdatedAt)
        });
    }

    function captureTau2(bytes calldata) external view returns (Observation memory) {
        (uint80 roundId, int256 answer,, uint256 updatedAt,) = oracle.latestRoundData();
        uint256 staleness = block.timestamp > updatedAt ? block.timestamp - updatedAt : 0;

        return Observation({
            label: "oracle.roundN",
            blockNumber: block.number,
            stateHash: keccak256(abi.encode(roundId, answer, updatedAt)),
            numericValue: answer,
            extraData: abi.encode(roundId, updatedAt, staleness, heartbeatSeconds)
        });
    }

    function hasContradiction(
        Observation calldata tau1,
        Observation calldata tau2
    ) external pure returns (bool, string memory) {
        (, uint256 prevUpdatedAt) = abi.decode(tau1.extraData, (uint80, uint256));
        (, uint256 updatedAt, uint256 staleness, uint256 heartbeat) = abi.decode(tau2.extraData, (uint80, uint256, uint256, uint256));
        uint256 roundInterval = updatedAt > prevUpdatedAt ? updatedAt - prevUpdatedAt : 0;
        bool priceChanged = tau1.numericValue != tau2.numericValue;
        bool lagExists = staleness > 0 || roundInterval > heartbeat;

        if (priceChanged || lagExists) {
            return (true, "Oracle entropy lag detected across sequential rounds");
        }
        return (false, "No oracle entropy lag detected");
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
        revert("OracleEntropyLagAdapter: detection only");
    }
}
