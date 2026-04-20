// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import {TSIBase} from "src/core/TSIBase.sol";
import {Contradiction} from "src/core/TSITypes.sol";
import {MerkleReplayClaimAdapter} from "src/adapters/MerkleReplayClaimAdapter.sol";
import {MockReplayClaimLedger} from "test/helpers/TSIMockProtocols.sol";

contract MerkleReplayClaimAdapterTest is Test, TSIBase {
    MockReplayClaimLedger internal ledger;
    MerkleReplayClaimAdapter internal adapter;

    function setUp() public {
        ledger = new MockReplayClaimLedger();
        adapter = new MerkleReplayClaimAdapter(address(ledger));
    }

    function test_detects_claim_replay_state_mismatch() public {
        bytes32 claimId = keccak256("claim-1");
        ledger.setClaim(claimId, true, keccak256("executed"));
        bytes memory context = abi.encode(
            MerkleReplayClaimAdapter.ClaimContext({
                claimId: claimId,
                expectedClaimed: false,
                expectedExecutionHash: keccak256("expected")
            })
        );

        Contradiction memory contradiction = assertContradiction(adapter, context, "expected replay mismatch");
        assertEq(uint256(contradiction.tau1.numericValue), 0);
        assertEq(uint256(contradiction.tau2.numericValue), 1);
    }

    function test_no_contradiction_when_claim_state_matches() public {
        bytes32 claimId = keccak256("claim-2");
        bytes32 executionHash = keccak256("expected");
        ledger.setClaim(claimId, true, executionHash);
        bytes memory context = abi.encode(
            MerkleReplayClaimAdapter.ClaimContext({
                claimId: claimId,
                expectedClaimed: true,
                expectedExecutionHash: executionHash
            })
        );

        Contradiction memory contradiction = captureContradiction(adapter, context);
        assertFalse(contradiction.contradiction, "unexpected replay mismatch");
    }
}