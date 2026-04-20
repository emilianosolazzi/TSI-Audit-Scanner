// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Observation} from "src/core/TSITypes.sol";

library StateOps {
    function hashObservation(Observation memory observation) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                observation.label,
                observation.blockNumber,
                observation.stateHash,
                observation.numericValue,
                observation.extraData
            )
        );
    }

    function differs(Observation memory tau1, Observation memory tau2) internal pure returns (bool) {
        return
            tau1.stateHash != tau2.stateHash ||
            tau1.numericValue != tau2.numericValue ||
            keccak256(tau1.extraData) != keccak256(tau2.extraData);
    }
}
