// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Contradiction, FindingKind, Observation, TSISeverity} from "src/core/TSITypes.sol";

interface ITSIAdapter {
    function adapterName() external pure returns (string memory);

    function adapterPath() external pure returns (string memory);

    function findingId() external pure returns (string memory);

    function defaultTitle() external pure returns (string memory);

    function findingKind() external pure returns (FindingKind);

    function defaultSeverity() external pure returns (TSISeverity);

    function defaultConfidenceScore() external pure returns (uint8);

    function forkRequired() external pure returns (bool);

    function captureTau1(bytes calldata context) external view returns (Observation memory);

    function captureTau2(bytes calldata context) external view returns (Observation memory);

    function hasContradiction(
        Observation calldata tau1,
        Observation calldata tau2
    ) external pure returns (bool, string memory);

    function buildContradiction(bytes calldata context) external view returns (Contradiction memory);

    function executeExploit(bytes calldata attackData) external returns (bytes memory result);
}
