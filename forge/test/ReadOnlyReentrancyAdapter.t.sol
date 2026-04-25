// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import {TSIBase} from "src/core/TSIBase.sol";
import {Contradiction, TSISeverity} from "src/core/TSITypes.sol";
import {ReadOnlyReentrancyAdapter} from "src/adapters/ReadOnlyReentrancyAdapter.sol";
import {MockReadOnlyReentrancyVault} from "test/helpers/TSIMockProtocols.sol";

contract ReadOnlyReentrancyAdapterTest is Test, TSIBase {
    MockReadOnlyReentrancyVault internal vault;
    ReadOnlyReentrancyAdapter internal adapter;

    function setUp() public {
        vault = new MockReadOnlyReentrancyVault(1_000 ether, 1_000 ether);
        adapter = new ReadOnlyReentrancyAdapter(address(vault));
    }

    function test_detects_quote_mismatch_during_callback_window() public {
        bytes memory context = abi.encode(100 ether);
        adapter.executeExploit(abi.encode(100 ether, 300 ether));

        Contradiction memory contradiction =
            assertContradiction(adapter, context, "expected read-only reentrancy quote mismatch");

        assertGt(uint256(contradiction.tau1.numericValue), uint256(contradiction.tau2.numericValue));
        assertSameBlock(contradiction.tau1, contradiction.tau2, "expected same-block read-only mismatch");
        assertMinimumSeverity(scoreContradiction(adapter, context, 88), TSISeverity.HIGH, "expected HIGH severity");
    }

    function test_no_contradiction_without_callback_window() public view {
        Contradiction memory contradiction = captureContradiction(adapter, abi.encode(100 ether));
        assertFalse(contradiction.contradiction, "unexpected read-only reentrancy mismatch");
    }
}
