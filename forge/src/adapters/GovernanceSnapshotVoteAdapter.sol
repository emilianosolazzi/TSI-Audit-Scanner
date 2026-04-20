// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Contradiction, FindingKind, Observation, TSISeverity} from "src/core/TSITypes.sol";
import {ITSIAdapter} from "src/interfaces/ITSIAdapter.sol";

interface IGovernanceVoteSource {
    function getVotes(address account) external view returns (uint256);
    function getPastVotes(address account, uint256 blockNumber) external view returns (uint256);
}

contract GovernanceSnapshotVoteAdapter is ITSIAdapter {
    struct SnapshotContext {
        address voter;
        uint256 snapshotBlock;
    }

    IGovernanceVoteSource public immutable voteSource;

    constructor(address voteSourceAddress) {
        voteSource = IGovernanceVoteSource(voteSourceAddress);
    }

    function adapterName() external pure returns (string memory) {
        return "GovernanceSnapshotVoteAdapter";
    }

    function adapterPath() external pure returns (string memory) {
        return "src/adapters/GovernanceSnapshotVoteAdapter.sol";
    }

    function findingId() external pure returns (string memory) {
        return "TSI-051";
    }

    function defaultTitle() external pure returns (string memory) {
        return "Governance execution reads live votes after snapshot finalization";
    }

    function findingKind() external pure returns (FindingKind) {
        return FindingKind.SnapshotFinalizationMismatch;
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
        SnapshotContext memory snapshot = abi.decode(context, (SnapshotContext));
        uint256 votes = voteSource.getPastVotes(snapshot.voter, snapshot.snapshotBlock);

        return Observation({
            label: "governance.snapshotVotes",
            blockNumber: snapshot.snapshotBlock,
            stateHash: keccak256(abi.encode(snapshot.voter, snapshot.snapshotBlock, votes)),
            numericValue: int256(votes),
            extraData: abi.encode(snapshot.voter, snapshot.snapshotBlock)
        });
    }

    function captureTau2(bytes calldata context) external view returns (Observation memory) {
        SnapshotContext memory snapshot = abi.decode(context, (SnapshotContext));
        uint256 votes = voteSource.getVotes(snapshot.voter);

        return Observation({
            label: "governance.liveVotes",
            blockNumber: block.number,
            stateHash: keccak256(abi.encode(snapshot.voter, block.number, votes)),
            numericValue: int256(votes),
            extraData: abi.encode(snapshot.voter, block.number)
        });
    }

    function hasContradiction(Observation calldata tau1, Observation calldata tau2) external pure returns (bool, string memory) {
        if (tau1.numericValue != tau2.numericValue) {
            return (true, "Finalized governance snapshot diverges from live voting power");
        }
        return (false, "No governance snapshot mismatch detected");
    }

    function buildContradiction(bytes calldata context) external view returns (Contradiction memory) {
        Observation memory tau1 = this.captureTau1(context);
        Observation memory tau2 = this.captureTau2(context);
        (bool mismatch, string memory rationale) = this.hasContradiction(tau1, tau2);

        return Contradiction({
            kind: FindingKind.SnapshotFinalizationMismatch,
            tau1: tau1,
            tau2: tau2,
            contradiction: mismatch,
            rationale: rationale
        });
    }

    function executeExploit(bytes calldata) external pure returns (bytes memory) {
        revert("GovernanceSnapshotVoteAdapter: detection only");
    }
}