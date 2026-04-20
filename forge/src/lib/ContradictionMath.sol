// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Observation, ContradictionScore} from "src/core/TSITypes.sol";

library ContradictionMath {
    function magnitude(Observation memory tau1, Observation memory tau2) internal pure returns (uint256) {
        int256 delta = tau2.numericValue - tau1.numericValue;
        return delta >= 0 ? uint256(delta) : uint256(-delta);
    }

    function relativeDeviationBps(Observation memory tau1, Observation memory tau2) internal pure returns (uint256) {
        if (tau1.numericValue == 0) return 0;
        uint256 mag = magnitude(tau1, tau2);
        uint256 base = tau1.numericValue >= 0 ? uint256(tau1.numericValue) : uint256(-tau1.numericValue);
        return (mag * 10_000) / base;
    }

    function semanticDistance(Observation memory tau1, Observation memory tau2) internal pure returns (uint256 dist) {
        uint256 val = uint256(tau1.stateHash ^ tau2.stateHash);
        while (val != 0) {
            dist += val & 1;
            val >>= 1;
        }
    }

    function score(
        Observation memory tau1,
        Observation memory tau2,
        uint8 confidence
    ) internal pure returns (ContradictionScore memory cs) {
        uint256 mag = magnitude(tau1, tau2);
        uint256 bps = relativeDeviationBps(tau1, tau2);
        bool diverges = mag > 0 || tau1.stateHash != tau2.stateHash;

        uint8 sevWeight;
        if (bps >= 5_000 || mag >= 1e18) {
            sevWeight = 100;
        } else if (bps >= 1_000) {
            sevWeight = 70;
        } else if (bps >= 500) {
            sevWeight = 40;
        } else if (bps >= 100) {
            sevWeight = 20;
        } else {
            sevWeight = 5;
        }

        cs = ContradictionScore({
            magnitude: mag,
            relativeDeviationBps: bps,
            confidenceScore: confidence,
            severityWeight: sevWeight,
            isProfitable: diverges && confidence >= 50
        });
    }
}
