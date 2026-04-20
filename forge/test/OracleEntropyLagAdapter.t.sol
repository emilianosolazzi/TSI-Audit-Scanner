// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import {TSIBase} from "src/core/TSIBase.sol";
import {Contradiction, ContradictionScore, TSISeverity} from "src/core/TSITypes.sol";
import {OracleEntropyLagAdapter} from "src/adapters/OracleEntropyLagAdapter.sol";
import {MockChainlinkFeed} from "test/helpers/TSIMockProtocols.sol";

contract OracleEntropyLagAdapterTest is Test, TSIBase {
    MockChainlinkFeed internal feed;
    OracleEntropyLagAdapter internal adapter;

    function setUp() public {
        feed = new MockChainlinkFeed();
        vm.warp(10_000);
        vm.roll(10);
    }

    function test_detects_entropy_lag_when_price_changes_and_stales() public {
        uint256 nowTs = block.timestamp;
        feed.setRound(1, 2000e8, nowTs - 3600);
        feed.setRound(2, 1800e8, nowTs - 1800);
        adapter = new OracleEntropyLagAdapter(address(feed), 600);

        Contradiction memory contradiction = assertContradiction(adapter, bytes(""), "expected oracle entropy lag contradiction");
        ContradictionScore memory score = scoreContradiction(adapter, bytes(""), 70);

        assertCausalOrder(contradiction.tau1, contradiction.tau2, "tau ordering broken");
        assertMinimumSeverity(score, TSISeverity.HIGH, "severity should be HIGH for 10%+ move");
        assertGt(uint256(contradiction.tau1.numericValue), uint256(contradiction.tau2.numericValue));
    }

    function test_no_contradiction_when_rounds_match_and_not_stale() public {
        uint256 nowTs = block.timestamp;
        feed.setRound(1, 2000e8, nowTs);
        feed.setRound(2, 2000e8, nowTs);
        adapter = new OracleEntropyLagAdapter(address(feed), 600);

        Contradiction memory contradiction = captureContradiction(adapter, bytes(""));
        assertFalse(contradiction.contradiction, "unexpected contradiction on matching oracle rounds");
    }
}
