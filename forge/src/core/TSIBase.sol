// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {
    Contradiction,
    ContradictionPhase,
    ContradictionScore,
    Observation,
    TSIFinding,
    TSISeverity
} from "src/core/TSITypes.sol";
import {ITSIAdapter} from "src/interfaces/ITSIAdapter.sol";
import {StateOps} from "src/lib/StateOps.sol";
import {ContradictionMath} from "src/lib/ContradictionMath.sol";
import {TSISeverityScore} from "src/lib/TSISeverityScore.sol";
import {ExploitWindowMetrics} from "src/lib/ExploitWindowMetrics.sol";

abstract contract TSIBase {
    using StateOps for Observation;
    using ContradictionMath for Observation;

    function captureContradiction(
        ITSIAdapter adapter,
        bytes memory context
    ) internal view returns (Contradiction memory contradiction) {
        Observation memory tau1 = adapter.captureTau1(context);
        Observation memory tau2 = adapter.captureTau2(context);
        (bool mismatch, string memory rationale) = adapter.hasContradiction(tau1, tau2);

        contradiction = Contradiction({
            kind: adapter.findingKind(),
            tau1: tau1,
            tau2: tau2,
            contradiction: mismatch,
            rationale: rationale
        });
    }

    function assertContradiction(
        ITSIAdapter adapter,
        bytes memory context,
        string memory errorMessage
    ) internal view returns (Contradiction memory contradiction) {
        contradiction = captureContradiction(adapter, context);
        require(contradiction.contradiction, errorMessage);
    }

    function scoreContradiction(
        ITSIAdapter adapter,
        bytes memory context,
        uint8 confidence
    ) internal view returns (ContradictionScore memory) {
        Observation memory tau1 = adapter.captureTau1(context);
        Observation memory tau2 = adapter.captureTau2(context);
        return ContradictionMath.score(tau1, tau2, confidence);
    }

    function buildFinding(
        ITSIAdapter adapter,
        bytes memory context,
        uint8 confidence
    ) internal view returns (TSIFinding memory finding) {
        Contradiction memory contradiction = captureContradiction(adapter, context);
        ContradictionScore memory score = scoreContradiction(adapter, context, confidence);

        uint8 baselineWeight = TSISeverityScore.severityWeight(adapter.defaultSeverity());
        uint8 effectiveWeight = score.severityWeight > baselineWeight ? score.severityWeight : baselineWeight;

        finding = TSIFinding({
            id: adapter.findingId(),
            title: adapter.defaultTitle(),
            adapterName: adapter.adapterName(),
            adapterPath: adapter.adapterPath(),
            kind: adapter.findingKind(),
            severity: TSISeverityScore.severityFromWeight(effectiveWeight),
            confidenceScore: confidence,
            severityWeight: effectiveWeight,
            forkRequired: adapter.forkRequired(),
            contradiction: contradiction.contradiction,
            status: contradiction.contradiction ? "confirmed" : "clean",
            rationale: contradiction.rationale,
            tau1Label: contradiction.tau1.label,
            tau1BlockNumber: contradiction.tau1.blockNumber,
            tau1Value: contradiction.tau1.numericValue,
            tau2Label: contradiction.tau2.label,
            tau2BlockNumber: contradiction.tau2.blockNumber,
            tau2Value: contradiction.tau2.numericValue,
            magnitude: score.magnitude,
            relativeDeviationBps: score.relativeDeviationBps,
            isProfitable: score.isProfitable
        });
    }

    function buildSkippedFinding(
        ITSIAdapter adapter,
        string memory rationale
    ) internal pure returns (TSIFinding memory finding) {
        finding = TSIFinding({
            id: adapter.findingId(),
            title: adapter.defaultTitle(),
            adapterName: adapter.adapterName(),
            adapterPath: adapter.adapterPath(),
            kind: adapter.findingKind(),
            severity: adapter.defaultSeverity(),
            confidenceScore: adapter.defaultConfidenceScore(),
            severityWeight: TSISeverityScore.severityWeight(adapter.defaultSeverity()),
            forkRequired: adapter.forkRequired(),
            contradiction: false,
            status: "skipped",
            rationale: rationale,
            tau1Label: "",
            tau1BlockNumber: 0,
            tau1Value: 0,
            tau2Label: "",
            tau2BlockNumber: 0,
            tau2Value: 0,
            magnitude: 0,
            relativeDeviationBps: 0,
            isProfitable: false
        });
    }

    function assertMinimumMagnitude(
        Contradiction memory contradiction,
        uint256 minMagnitude,
        string memory errorMessage
    ) internal pure {
        uint256 mag = ContradictionMath.magnitude(contradiction.tau1, contradiction.tau2);
        require(mag >= minMagnitude, errorMessage);
    }

    function assertMinimumSeverity(
        ContradictionScore memory cs,
        TSISeverity minSeverity,
        string memory errorMessage
    ) internal pure {
        uint8 minWeight = TSISeverityScore.severityWeight(minSeverity);
        require(cs.severityWeight >= minWeight, errorMessage);
    }

    function assertProfitable(
        Contradiction memory contradiction,
        uint256 gasEstimateWei,
        uint256 slippageBps,
        string memory errorMessage
    ) internal pure {
        int256 delta = contradiction.tau1.numericValue - contradiction.tau2.numericValue;
        require(
            ExploitWindowMetrics.isProfitable(delta, gasEstimateWei, slippageBps),
            errorMessage
        );
    }

    function assertCausalOrder(
        Observation memory tau1,
        Observation memory tau2,
        string memory errorMessage
    ) internal pure {
        require(tau1.blockNumber <= tau2.blockNumber, errorMessage);
    }

    function assertSameBlock(
        Observation memory tau1,
        Observation memory tau2,
        string memory errorMessage
    ) internal pure {
        require(tau1.blockNumber == tau2.blockNumber, errorMessage);
    }

    function assertPhaseProgression(
        ContradictionPhase[] memory phases,
        string memory errorMessage
    ) internal pure {
        for (uint256 i = 1; i < phases.length; ++i) {
            require(uint8(phases[i]) == uint8(phases[i - 1]) + 1, errorMessage);
        }
    }
}
