// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {TSISeverity} from "src/core/TSITypes.sol";

library TSISeverityScore {
    function severityWeight(TSISeverity sev) internal pure returns (uint8) {
        if (sev == TSISeverity.CRITICAL) return 100;
        if (sev == TSISeverity.HIGH) return 70;
        if (sev == TSISeverity.MEDIUM) return 40;
        if (sev == TSISeverity.LOW) return 20;
        return 5;
    }

    function severityFromWeight(uint8 w) internal pure returns (TSISeverity) {
        if (w >= 100) return TSISeverity.CRITICAL;
        if (w >= 70) return TSISeverity.HIGH;
        if (w >= 40) return TSISeverity.MEDIUM;
        if (w >= 20) return TSISeverity.LOW;
        return TSISeverity.INFO;
    }

    function securityScore(uint8[] memory weights, uint8[] memory confidences) internal pure returns (uint256) {
        require(weights.length == confidences.length, "TSISeverityScore: length mismatch");
        if (weights.length == 0) return 100;

        uint256 totalWeightScaled;
        uint256 maxWeightScaled = weights.length * uint256(100) * uint256(100);

        for (uint256 i; i < weights.length; ++i) {
            totalWeightScaled += uint256(weights[i]) * uint256(confidences[i]);
        }

        uint256 penalty = (totalWeightScaled * 100) / maxWeightScaled;
        return penalty >= 100 ? 0 : 100 - penalty;
    }

    function riskLevel(uint256 score, uint256 criticalCount, uint256 highCount) internal pure returns (TSISeverity) {
        if (criticalCount > 0) return TSISeverity.CRITICAL;
        if (highCount > 2) return TSISeverity.HIGH;
        if (highCount > 0 || score < 70) return TSISeverity.MEDIUM;
        if (score < 90) return TSISeverity.LOW;
        return TSISeverity.INFO;
    }

    function deploymentWindowRisk(
        uint256 deployBlock,
        uint256 initBlock,
        uint256 secondsPerBlock
    ) internal pure returns (TSISeverity) {
        require(initBlock >= deployBlock, "TSISeverityScore: initBlock before deployBlock");
        uint256 gapBlocks = initBlock - deployBlock;

        if (gapBlocks == 0) return TSISeverity.INFO;

        uint256 blocksPerMinute = secondsPerBlock == 0 ? 5 : 60 / secondsPerBlock;
        uint256 blocksPerHour = secondsPerBlock == 0 ? 300 : 3600 / secondsPerBlock;

        if (gapBlocks < blocksPerMinute) return TSISeverity.LOW;
        if (gapBlocks < blocksPerHour) return TSISeverity.MEDIUM;
        return TSISeverity.HIGH;
    }
}
