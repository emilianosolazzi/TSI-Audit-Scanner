// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import {TSIBase} from "src/core/TSIBase.sol";
import {Contradiction, TSISeverity} from "src/core/TSITypes.sol";
import {
    GovernanceSnapshotVoteAdapter
} from "src/adapters/GovernanceSnapshotVoteAdapter.sol";
import {MockGovernanceVoteSource} from "test/helpers/TSIMockProtocols.sol";

contract GovernanceSnapshotVoteAdapterTest is Test, TSIBase {
    MockGovernanceVoteSource internal voteSource;
    GovernanceSnapshotVoteAdapter internal adapter;
    address internal voter = address(0xBEEF);

    function setUp() public {
        vm.roll(100);
        voteSource = new MockGovernanceVoteSource();
        adapter = new GovernanceSnapshotVoteAdapter(address(voteSource));
    }

    function test_detects_live_votes_drifting_from_snapshot() public {
        voteSource.setVotes(voter, 1_500e18, 42, 1_000e18);
        bytes memory context = abi.encode(
            GovernanceSnapshotVoteAdapter.SnapshotContext({voter: voter, snapshotBlock: 42})
        );

        Contradiction memory contradiction = assertContradiction(adapter, context, "expected governance mismatch");
        assertLt(contradiction.tau1.blockNumber, contradiction.tau2.blockNumber);
        assertMinimumSeverity(scoreContradiction(adapter, context, 80), TSISeverity.HIGH, "expected HIGH severity");
    }

    function test_no_contradiction_when_snapshot_matches_live_votes() public {
        voteSource.setVotes(voter, 1_000e18, 42, 1_000e18);
        bytes memory context = abi.encode(
            GovernanceSnapshotVoteAdapter.SnapshotContext({voter: voter, snapshotBlock: 42})
        );

        Contradiction memory contradiction = captureContradiction(adapter, context);
        assertFalse(contradiction.contradiction, "unexpected governance contradiction");
    }
}