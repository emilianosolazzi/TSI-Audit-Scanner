// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Contradiction, FindingKind, Observation, TSISeverity} from "src/core/TSITypes.sol";
import {ITSIAdapter} from "src/interfaces/ITSIAdapter.sol";

interface ISSVNetworkAdapter {
    struct Cluster {
        uint32 validatorCount;
        uint64 networkFeeIndex;
        uint64 index;
        bool active;
        uint256 balance;
    }
}

interface ISSVViewsAdapter {
    function getBalance(
        address owner,
        uint64[] memory operatorIds,
        ISSVNetworkAdapter.Cluster memory cluster
    ) external view returns (uint256);
}

contract SSVStateContradictionAdapter is ITSIAdapter {
    struct SSVContext {
        address owner;
        uint64[] operatorIds;
        ISSVNetworkAdapter.Cluster cluster;
    }

    ISSVViewsAdapter public immutable ssvViews;

    constructor(address ssvViewsAddress) {
        ssvViews = ISSVViewsAdapter(ssvViewsAddress);
    }

    function adapterName() external pure returns (string memory) {
        return "SSVStateContradictionAdapter";
    }

    function adapterPath() external pure returns (string memory) {
        return "src/adapters/SSVStateContradictionAdapter.sol";
    }

    function findingId() external pure returns (string memory) {
        return "TSI-031";
    }

    function defaultTitle() external pure returns (string memory) {
        return "SSV cluster struct state disagrees with view-derived balance";
    }

    function findingKind() external pure returns (FindingKind) {
        return FindingKind.TemporalStateInconsistency;
    }

    function defaultSeverity() external pure returns (TSISeverity) {
        return TSISeverity.HIGH;
    }

    function defaultConfidenceScore() external pure returns (uint8) {
        return 75;
    }

    function forkRequired() external pure returns (bool) {
        return false;
    }

    function captureTau1(bytes calldata context) external view returns (Observation memory) {
        SSVContext memory ctx = abi.decode(context, (SSVContext));
        bytes32 stateHash = keccak256(abi.encode(ctx.owner, ctx.operatorIds, ctx.cluster.balance));

        return Observation({
            label: "ssv.struct.balance",
            blockNumber: block.number,
            stateHash: stateHash,
            numericValue: int256(ctx.cluster.balance),
            extraData: abi.encode(ctx.cluster)
        });
    }

    function captureTau2(bytes calldata context) external view returns (Observation memory) {
        SSVContext memory ctx = abi.decode(context, (SSVContext));
        uint256 computedBalance = ssvViews.getBalance(ctx.owner, ctx.operatorIds, ctx.cluster);
        bytes32 stateHash = keccak256(abi.encode(ctx.owner, ctx.operatorIds, computedBalance));

        return Observation({
            label: "ssv.getBalance()",
            blockNumber: block.number,
            stateHash: stateHash,
            numericValue: int256(computedBalance),
            extraData: abi.encode(computedBalance)
        });
    }

    function hasContradiction(
        Observation calldata tau1,
        Observation calldata tau2
    ) external pure returns (bool, string memory) {
        bool mismatch = tau1.numericValue != tau2.numericValue || tau1.stateHash != tau2.stateHash;
        if (mismatch) {
            return (true, "SSV contradiction: struct.balance != getBalance() at same block");
        }
        return (false, "No contradiction detected");
    }

    function buildContradiction(bytes calldata context) external view returns (Contradiction memory) {
        Observation memory tau1 = this.captureTau1(context);
        Observation memory tau2 = this.captureTau2(context);
        (bool mismatch, string memory rationale) = this.hasContradiction(tau1, tau2);

        return Contradiction({
            kind: FindingKind.TemporalStateInconsistency,
            tau1: tau1,
            tau2: tau2,
            contradiction: mismatch,
            rationale: rationale
        });
    }

    function executeExploit(bytes calldata) external pure returns (bytes memory) {
        return abi.encode("Not implemented in adapter-only mode");
    }
}
