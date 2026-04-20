// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import {TSIBase} from "src/core/TSIBase.sol";
import {Contradiction, TSISeverity} from "src/core/TSITypes.sol";
import {UniswapV2TwapSkewAdapter} from "src/adapters/UniswapV2TwapSkewAdapter.sol";
import {MockSpotTwapOracle} from "test/helpers/TSIMockProtocols.sol";

contract UniswapV2TwapSkewAdapterTest is Test, TSIBase {
    MockSpotTwapOracle internal oracle;
    UniswapV2TwapSkewAdapter internal adapter;

    function setUp() public {
        oracle = new MockSpotTwapOracle();
        adapter = new UniswapV2TwapSkewAdapter(address(oracle));
    }

    function test_detects_spot_twap_skew_above_threshold() public {
        oracle.setPrices(1_100e18, 1_000e18);
        bytes memory context = abi.encode(uint256(150));

        Contradiction memory contradiction = assertContradiction(adapter, context, "expected spot/twap skew");
        assertGt(uint256(contradiction.tau2.numericValue), uint256(contradiction.tau1.numericValue));
        assertMinimumSeverity(scoreContradiction(adapter, context, 80), TSISeverity.HIGH, "expected HIGH severity");
    }

    function test_no_contradiction_below_threshold() public {
        oracle.setPrices(1_010e18, 1_000e18);
        Contradiction memory contradiction = captureContradiction(adapter, abi.encode(uint256(150)));
        assertFalse(contradiction.contradiction, "unexpected spot/twap contradiction");
    }
}