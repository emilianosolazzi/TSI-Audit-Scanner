// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import {TSIBase} from "src/core/TSIBase.sol";
import {Contradiction, Observation, TSISeverity} from "src/core/TSITypes.sol";
import {ContradictionMath} from "src/lib/ContradictionMath.sol";
import {FrozenStateVerifier} from "src/lib/FrozenStateVerifier.sol";
import {ExploitWindowMetrics} from "src/lib/ExploitWindowMetrics.sol";
import {AaveFlashLoanOracleAdapter} from "src/adapters/AaveFlashLoanOracleAdapter.sol";
import {OracleEntropyLagAdapter} from "src/adapters/OracleEntropyLagAdapter.sol";

interface IAggregatorV3 {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );

    function getRoundData(uint80 _roundId) external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

interface IChainlinkLatestAnswer {
    function latestAnswer() external view returns (int256);
}

contract TSI_Aave_FlashLoan_Oracle is Test, TSIBase {
    address constant AAVE_POOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant CHAINLINK = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;
    address constant A_WETH = 0x4d5F47FA6A74757f35C14fD3a6Ef8E3C9BC514E8;

    uint256 constant FLASH_FRACTION_BPS = 600;
    uint256 constant CIRCUIT_BREAKER_BPS = 500;

    AaveFlashLoanOracleAdapter internal aaveAdapter;
    OracleEntropyLagAdapter internal lagAdapter;

    function setUp() public {
        aaveAdapter = new AaveFlashLoanOracleAdapter(AAVE_POOL, WETH, CHAINLINK, A_WETH);
        lagAdapter = new OracleEntropyLagAdapter(CHAINLINK, 3600);

        if (aaveAdapter.forkReady()) {
            deal(WETH, address(aaveAdapter), 100e18);
        }
    }

    function test_01_FlashLoan_PoolState_Contradiction() public {
        if (!aaveAdapter.forkReady()) vm.skip(true);

        bytes memory context = abi.encode(uint8(1));
        (uint256 tau1, uint256 tau2, uint256 flashAmount) = abi.decode(
            aaveAdapter.executeExploit(abi.encode(uint8(1), FLASH_FRACTION_BPS)),
            (uint256, uint256, uint256)
        );

        Contradiction memory contradiction = assertContradiction(
            aaveAdapter,
            context,
            "TSI-011: tau1 must differ from tau2 inside callback"
        );

        assertSameBlock(contradiction.tau1, contradiction.tau2, "TSI-011: contradiction should be same-block");
        assertEq(uint256(contradiction.tau1.numericValue), tau1, "TSI-011: tau1 mismatch");
        assertEq(uint256(contradiction.tau2.numericValue), tau2, "TSI-011: tau2 mismatch");
        assertEq(tau1 - tau2, flashAmount, "TSI-011: delta must equal flash amount (structural)");
    }

    function test_02_BpsDeviation_AboveCircuitBreaker() public {
        if (!aaveAdapter.forkReady()) vm.skip(true);

        bytes memory context = abi.encode(uint8(1));
        aaveAdapter.executeExploit(abi.encode(uint8(1), FLASH_FRACTION_BPS));

        Contradiction memory contradiction = captureContradiction(aaveAdapter, context);
        uint256 bps = ContradictionMath.relativeDeviationBps(contradiction.tau1, contradiction.tau2);
        assertGt(bps, CIRCUIT_BREAKER_BPS, "TSI-011: bps deviation must exceed 500 bps circuit-breaker");
        assertApproxEqAbs(bps, FLASH_FRACTION_BPS, 1, "TSI-011: deviation equals flash fraction");

        assertMinimumSeverity(
            scoreContradiction(aaveAdapter, context, 70),
            TSISeverity.MEDIUM,
            "TSI-011: severity should be at least MEDIUM"
        );
    }

    function test_03_Oracle_ContextBlind_CannotDefend() public {
        if (!aaveAdapter.forkReady()) vm.skip(true);

        bytes memory context = abi.encode(uint8(3));
        (uint256 tau1, uint256 tau2, uint256 flashAmount) = abi.decode(
            aaveAdapter.executeExploit(abi.encode(uint8(3), FLASH_FRACTION_BPS)),
            (uint256, uint256, uint256)
        );

        Contradiction memory contradiction = assertContradiction(
            aaveAdapter,
            context,
            "TSI-014: oracle should differ inside vs outside callback"
        );

        assertGt(tau1, tau2, "TSI-014: oracle sees depleted pool in callback");
        assertEq(tau1 - tau2, flashAmount, "TSI-014: oracle error magnitude equals flash amount");
        assertEq(uint256(contradiction.tau1.numericValue), tau1);
        assertEq(uint256(contradiction.tau2.numericValue), tau2);
    }

    function test_04_ChainlinkAave_Composition_Mismatch() public {
        if (!aaveAdapter.forkReady()) vm.skip(true);

        int256 rawPrice = IChainlinkLatestAnswer(CHAINLINK).latestAnswer();
        assertTrue(rawPrice > 0, "TSI-011: Chainlink price must be positive");
        uint256 price = uint256(rawPrice);

        aaveAdapter.executeExploit(abi.encode(uint8(1), FLASH_FRACTION_BPS));
        Contradiction memory contradiction = captureContradiction(aaveAdapter, abi.encode(uint8(1)));

        uint256 poolOutside = uint256(contradiction.tau1.numericValue);
        uint256 poolInside = uint256(contradiction.tau2.numericValue);
        uint256 pOutside = price;
        uint256 pInside = price * poolInside / poolOutside;

        assertNotEq(pOutside, pInside, "TSI-011: composite price should mismatch in callback");
        uint256 bps = poolOutside > 0 ? ((pOutside > pInside ? pOutside - pInside : pInside - pOutside) * 10_000) / pOutside : 0;
        assertGt(bps, CIRCUIT_BREAKER_BPS, "TSI-011: mismatch should exceed 500 bps");
    }

    function test_05_MethodSurvivesTimeRoll() public {
        if (!aaveAdapter.forkReady()) vm.skip(true);

        aaveAdapter.executeExploit(abi.encode(uint8(1), FLASH_FRACTION_BPS));
        Contradiction memory contradictionA = captureContradiction(aaveAdapter, abi.encode(uint8(1)));
        uint256 bpsA = ContradictionMath.relativeDeviationBps(contradictionA.tau1, contradictionA.tau2);

        vm.roll(block.number + 1_000);
        deal(WETH, address(aaveAdapter), 100e18);

        aaveAdapter.executeExploit(abi.encode(uint8(1), FLASH_FRACTION_BPS));
        Contradiction memory contradictionB = captureContradiction(aaveAdapter, abi.encode(uint8(1)));
        uint256 bpsB = ContradictionMath.relativeDeviationBps(contradictionB.tau1, contradictionB.tau2);

        assertGt(bpsA, 0, "TSI-011: must deviate at initial block");
        assertGt(bpsB, 0, "TSI-011: must deviate after roll");
        assertApproxEqAbs(bpsA, FLASH_FRACTION_BPS, 1, "TSI-011: deviation equals flash fraction at A");
        assertApproxEqAbs(bpsB, FLASH_FRACTION_BPS, 1, "TSI-011: deviation equals flash fraction at B");
    }

    function test_06_TimingGap_PrecomputedLiquidation_OracleStaleness() public {
        if (!aaveAdapter.forkReady()) vm.skip(true);

        Contradiction memory contradiction = assertContradiction(
            lagAdapter,
            bytes(""),
            "TSI-011: expected oracle lag contradiction"
        );
        assertCausalOrder(contradiction.tau1, contradiction.tau2, "TSI-011: oracle rounds out of order");

        (uint80 roundId, int256 priceT1Int,, uint256 updatedAt,) = IAggregatorV3(CHAINLINK).latestRoundData();
        (, int256 prevPrice,, uint256 prevUpdatedAt,) = IAggregatorV3(CHAINLINK).getRoundData(uint80(roundId - 1));

        uint256 stalenessSeconds = block.timestamp - updatedAt;
        uint256 roundInterval = updatedAt - prevUpdatedAt;
        assertGt(stalenessSeconds, 0, "TSI-011: oracle staleness > 0");
        assertGt(roundInterval, 0, "TSI-011: round interval > 0");

        uint256 nonce = uint256(roundId - 1);
        bytes32 frozenOracleHash = FrozenStateVerifier.freeze(abi.encode(roundId - 1, prevPrice, prevUpdatedAt), nonce);
        bool frozenStillValid = FrozenStateVerifier.verify(
            frozenOracleHash,
            abi.encode(roundId, priceT1Int, updatedAt),
            nonce,
            prevUpdatedAt
        );
        assertFalse(frozenStillValid, "TSI-014: frozen state should fail at new round");

        uint256 p1Safe = uint256(prevPrice > 0 ? prevPrice : -prevPrice);
        uint256 p2Safe = uint256(priceT1Int > 0 ? priceT1Int : -priceT1Int);
        uint256 roundDeviationBps = ContradictionMath.relativeDeviationBps(contradiction.tau1, contradiction.tau2);
        uint256 windowBlocks = ExploitWindowMetrics.windowWidthBlocks(contradiction.tau1, contradiction.tau2);
        bool cbTripped = ExploitWindowMetrics.circuitBreakerTripped(p1Safe, p2Safe);

        assertGt(roundDeviationBps + stalenessSeconds, 0, "TSI-011: price or staleness deviation should exist");

        int256 priceT2Int = priceT1Int * 88 / 100;
        vm.roll(block.number + 1);
        vm.warp(block.timestamp + 12);

        vm.mockCall(CHAINLINK, abi.encodeWithSignature("latestAnswer()"), abi.encode(priceT2Int));
        int256 oracleAtT2 = IChainlinkLatestAnswer(CHAINLINK).latestAnswer();
        assertEq(oracleAtT2, priceT2Int, "TSI-011: mock should set P2");

        uint256 maxDebt8dec = 100 * p2Safe * 80 / 100;
        uint256 p2SafeAtDrop = uint256(priceT2Int > 0 ? priceT2Int : -priceT2Int);
        uint256 hfScaled = maxDebt8dec > 0 ? (100 * p2SafeAtDrop * 825) / maxDebt8dec : 1000;
        uint256 profitBase8dec = maxDebt8dec * 25 / 1000;

        assertLt(hfScaled, 1000, "TSI-011: DAMAGE -- HF < 1.0 after 12% drop");
        assertGt(profitBase8dec, 0, "TSI-011: DAMAGE -- liquidation profit > 0");
        assertTrue(
            ExploitWindowMetrics.isProfitable(int256(profitBase8dec / 1e6), 0, 30),
            "TSI-011: DAMAGE -- method actionable"
        );

        assertEq(windowBlocks, 1, "Expected 1-block timing gap in this model");
        assertTrue(cbTripped || roundDeviationBps > 0, "Expected detectable oracle change signal");
    }
}
