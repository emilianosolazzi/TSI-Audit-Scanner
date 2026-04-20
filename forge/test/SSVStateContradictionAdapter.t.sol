// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import {TSIBase} from "src/core/TSIBase.sol";
import {Contradiction} from "src/core/TSITypes.sol";
import {
    SSVStateContradictionAdapter,
    ISSVNetworkAdapter,
    ISSVViewsAdapter
} from "src/adapters/SSVStateContradictionAdapter.sol";
import {MockSSVViews} from "test/helpers/TSIMockProtocols.sol";

contract SSVStateContradictionAdapterTest is Test, TSIBase {
    MockSSVViews internal mockViews;
    SSVStateContradictionAdapter internal adapter;

    function setUp() public {
        mockViews = new MockSSVViews();
        adapter = new SSVStateContradictionAdapter(address(mockViews));
    }

    function test_detects_same_block_balance_contradiction() public {
        mockViews.setBalance(125 ether);

        uint64[] memory operatorIds = new uint64[](2);
        operatorIds[0] = 11;
        operatorIds[1] = 22;
        ISSVNetworkAdapter.Cluster memory cluster = ISSVNetworkAdapter.Cluster({
            validatorCount: 3,
            networkFeeIndex: 7,
            index: 8,
            active: true,
            balance: 100 ether
        });

        bytes memory context = abi.encode(
            SSVStateContradictionAdapter.SSVContext({owner: address(this), operatorIds: operatorIds, cluster: cluster})
        );

        Contradiction memory contradiction = assertContradiction(adapter, context, "expected SSV contradiction");
        assertSameBlock(contradiction.tau1, contradiction.tau2, "ssv contradiction should be same-block");
        assertEq(uint256(contradiction.tau1.numericValue), 100 ether);
        assertEq(uint256(contradiction.tau2.numericValue), 125 ether);
    }

    function test_no_contradiction_when_computed_balance_matches_struct() public {
        mockViews.setBalance(100 ether);

        uint64[] memory operatorIds = new uint64[](1);
        operatorIds[0] = 11;
        ISSVNetworkAdapter.Cluster memory cluster = ISSVNetworkAdapter.Cluster({
            validatorCount: 1,
            networkFeeIndex: 2,
            index: 3,
            active: true,
            balance: 100 ether
        });

        bytes memory context = abi.encode(
            SSVStateContradictionAdapter.SSVContext({owner: address(this), operatorIds: operatorIds, cluster: cluster})
        );

        Contradiction memory contradiction = captureContradiction(adapter, context);
        assertFalse(contradiction.contradiction, "unexpected contradiction when balances match");
    }
}
