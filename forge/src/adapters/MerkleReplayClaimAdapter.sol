// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Contradiction, FindingKind, Observation, TSISeverity} from "src/core/TSITypes.sol";
import {ITSIAdapter} from "src/interfaces/ITSIAdapter.sol";

interface IReplayClaimLedger {
    function isClaimed(bytes32 claimId) external view returns (bool);
    function executionHash(bytes32 claimId) external view returns (bytes32);
}

contract MerkleReplayClaimAdapter is ITSIAdapter {
    struct ClaimContext {
        bytes32 claimId;
        bool expectedClaimed;
        bytes32 expectedExecutionHash;
    }

    IReplayClaimLedger public immutable ledger;

    constructor(address ledgerAddress) {
        ledger = IReplayClaimLedger(ledgerAddress);
    }

    function adapterName() external pure returns (string memory) {
        return "MerkleReplayClaimAdapter";
    }

    function adapterPath() external pure returns (string memory) {
        return "src/adapters/MerkleReplayClaimAdapter.sol";
    }

    function findingId() external pure returns (string memory) {
        return "TSI-061";
    }

    function defaultTitle() external pure returns (string memory) {
        return "Claim replay ledger disagrees with signed distribution state";
    }

    function findingKind() external pure returns (FindingKind) {
        return FindingKind.ReplayClaimMismatch;
    }

    function defaultSeverity() external pure returns (TSISeverity) {
        return TSISeverity.HIGH;
    }

    function defaultConfidenceScore() external pure returns (uint8) {
        return 85;
    }

    function forkRequired() external pure returns (bool) {
        return false;
    }

    function captureTau1(bytes calldata context) external view returns (Observation memory) {
        ClaimContext memory claim = abi.decode(context, (ClaimContext));

        return Observation({
            label: "merkle.expectedClaimState",
            blockNumber: block.number,
            stateHash: keccak256(abi.encode(claim.claimId, claim.expectedClaimed, claim.expectedExecutionHash)),
            numericValue: claim.expectedClaimed ? int256(1) : int256(0),
            extraData: abi.encode(claim.claimId, claim.expectedExecutionHash)
        });
    }

    function captureTau2(bytes calldata context) external view returns (Observation memory) {
        ClaimContext memory claim = abi.decode(context, (ClaimContext));
        bool claimed = ledger.isClaimed(claim.claimId);
        bytes32 observedExecutionHash = ledger.executionHash(claim.claimId);

        return Observation({
            label: "merkle.ledgerClaimState",
            blockNumber: block.number,
            stateHash: keccak256(abi.encode(claim.claimId, claimed, observedExecutionHash)),
            numericValue: claimed ? int256(1) : int256(0),
            extraData: abi.encode(claim.claimId, observedExecutionHash)
        });
    }

    function hasContradiction(Observation calldata tau1, Observation calldata tau2) external pure returns (bool, string memory) {
        if (tau1.stateHash != tau2.stateHash || tau1.numericValue != tau2.numericValue) {
            return (true, "Replay claim state disagrees with on-chain consumption ledger");
        }
        return (false, "No replay claim mismatch detected");
    }

    function buildContradiction(bytes calldata context) external view returns (Contradiction memory) {
        Observation memory tau1 = this.captureTau1(context);
        Observation memory tau2 = this.captureTau2(context);
        (bool mismatch, string memory rationale) = this.hasContradiction(tau1, tau2);

        return Contradiction({
            kind: FindingKind.ReplayClaimMismatch,
            tau1: tau1,
            tau2: tau2,
            contradiction: mismatch,
            rationale: rationale
        });
    }

    function executeExploit(bytes calldata) external pure returns (bytes memory) {
        revert("MerkleReplayClaimAdapter: detection only");
    }
}