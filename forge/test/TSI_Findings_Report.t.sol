// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import {TSIBase} from "src/core/TSIBase.sol";
import {TSIFinding} from "src/core/TSITypes.sol";
import {TSIStringify} from "src/lib/TSIStringify.sol";
import {AaveFlashLoanOracleAdapter} from "src/adapters/AaveFlashLoanOracleAdapter.sol";
import {ERC4626DonationPreviewAdapter} from "src/adapters/ERC4626DonationPreviewAdapter.sol";
import {GovernanceSnapshotVoteAdapter} from "src/adapters/GovernanceSnapshotVoteAdapter.sol";
import {MerkleReplayClaimAdapter} from "src/adapters/MerkleReplayClaimAdapter.sol";
import {OracleEntropyLagAdapter} from "src/adapters/OracleEntropyLagAdapter.sol";
import {SSVStateContradictionAdapter, ISSVNetworkAdapter} from "src/adapters/SSVStateContradictionAdapter.sol";
import {UniswapV2TwapSkewAdapter} from "src/adapters/UniswapV2TwapSkewAdapter.sol";
import {
    MockChainlinkFeed,
    MockERC4626DonationVault,
    MockGovernanceVoteSource,
    MockReplayClaimLedger,
    MockSpotTwapOracle,
    MockSSVViews
} from "test/helpers/TSIMockProtocols.sol";

contract TSI_Findings_Report is Test, TSIBase {
    using TSIStringify for *;

    address constant AAVE_POOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant CHAINLINK = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;
    address constant A_WETH = 0x4d5F47FA6A74757f35C14fD3a6Ef8E3C9BC514E8;

    function test_emit_adapter_findings_json() public {
        vm.warp(10_000);
        vm.roll(100);

        TSIFinding[] memory findings = new TSIFinding[](7);
        uint256 index;

        AaveFlashLoanOracleAdapter aaveAdapter = new AaveFlashLoanOracleAdapter(AAVE_POOL, WETH, CHAINLINK, A_WETH);
        if (aaveAdapter.forkReady()) {
            deal(WETH, address(aaveAdapter), 100e18);
            aaveAdapter.executeExploit(abi.encode(uint8(1), uint256(600)));
            findings[index++] = buildFinding(aaveAdapter, abi.encode(uint8(1)), 90);
        } else {
            findings[index++] = buildSkippedFinding(aaveAdapter, "Mainnet fork RPC not configured for Aave adapter");
        }

        MockChainlinkFeed feed = new MockChainlinkFeed();
        feed.setRound(1, 2000e8, block.timestamp - 3600);
        feed.setRound(2, 1800e8, block.timestamp - 1800);
        OracleEntropyLagAdapter lagAdapter = new OracleEntropyLagAdapter(address(feed), 600);
        findings[index++] = buildFinding(lagAdapter, bytes(""), lagAdapter.defaultConfidenceScore());

        MockSSVViews ssvViews = new MockSSVViews();
        ssvViews.setBalance(125 ether);
        SSVStateContradictionAdapter ssvAdapter = new SSVStateContradictionAdapter(address(ssvViews));
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
        findings[index++] = buildFinding(
            ssvAdapter,
            abi.encode(SSVStateContradictionAdapter.SSVContext({owner: address(this), operatorIds: operatorIds, cluster: cluster})),
            ssvAdapter.defaultConfidenceScore()
        );

        MockERC4626DonationVault vault = new MockERC4626DonationVault(1_000 ether, 1_000 ether);
        ERC4626DonationPreviewAdapter erc4626Adapter = new ERC4626DonationPreviewAdapter(address(vault));
        erc4626Adapter.executeExploit(abi.encode(100 ether, 400 ether));
        findings[index++] = buildFinding(erc4626Adapter, abi.encode(100 ether), erc4626Adapter.defaultConfidenceScore());

        MockGovernanceVoteSource voteSource = new MockGovernanceVoteSource();
        address voter = address(0xBEEF);
        voteSource.setVotes(voter, 1_500e18, 42, 1_000e18);
        GovernanceSnapshotVoteAdapter governanceAdapter = new GovernanceSnapshotVoteAdapter(address(voteSource));
        findings[index++] = buildFinding(
            governanceAdapter,
            abi.encode(GovernanceSnapshotVoteAdapter.SnapshotContext({voter: voter, snapshotBlock: 42})),
            governanceAdapter.defaultConfidenceScore()
        );

        MockReplayClaimLedger replayLedger = new MockReplayClaimLedger();
        bytes32 claimId = keccak256("claim-1");
        replayLedger.setClaim(claimId, true, keccak256("executed"));
        MerkleReplayClaimAdapter replayAdapter = new MerkleReplayClaimAdapter(address(replayLedger));
        findings[index++] = buildFinding(
            replayAdapter,
            abi.encode(
                MerkleReplayClaimAdapter.ClaimContext({
                    claimId: claimId,
                    expectedClaimed: false,
                    expectedExecutionHash: keccak256("expected")
                })
            ),
            replayAdapter.defaultConfidenceScore()
        );

        MockSpotTwapOracle twapOracle = new MockSpotTwapOracle();
        twapOracle.setPrices(1_100e18, 1_000e18);
        UniswapV2TwapSkewAdapter twapAdapter = new UniswapV2TwapSkewAdapter(address(twapOracle));
        findings[index++] = buildFinding(twapAdapter, abi.encode(uint256(150)), twapAdapter.defaultConfidenceScore());

        string memory artifactsDir = string.concat(vm.projectRoot(), "/artifacts");
        vm.createDir(artifactsDir, true);
        string memory findingsPath = string.concat(artifactsDir, "/tsi_adapter_findings.json");
        vm.writeJson(_renderFindingsJson(findings), findingsPath);

        assertTrue(vm.isFile(findingsPath), "expected findings JSON artifact");
    }

    function _renderFindingsJson(TSIFinding[] memory findings) internal returns (string memory) {
        string memory arrayJson = "[";

        for (uint256 i = 0; i < findings.length; ++i) {
            if (i > 0) {
                arrayJson = string.concat(arrayJson, ",");
            }
            arrayJson = string.concat(arrayJson, _serializeFinding(findings[i], i));
        }

        arrayJson = string.concat(arrayJson, "]");
        return string.concat(
            "{\"schema_version\":\"1\",\"finding_count\":",
            vm.toString(findings.length),
            ",\"findings\":",
            arrayJson,
            "}"
        );
    }

    function _serializeFinding(TSIFinding memory finding, uint256 index) internal returns (string memory) {
        string memory objectKey = string.concat("finding_", vm.toString(index));
        vm.serializeString(objectKey, "id", finding.id);
        vm.serializeString(objectKey, "title", finding.title);
        vm.serializeString(objectKey, "adapter_name", finding.adapterName);
        vm.serializeString(objectKey, "adapter_path", finding.adapterPath);
        vm.serializeString(objectKey, "finding_kind", TSIStringify.findingKindToString(finding.kind));
        vm.serializeString(objectKey, "severity", TSIStringify.severityToString(finding.severity));
        vm.serializeUint(objectKey, "confidence_score", finding.confidenceScore);
        vm.serializeUint(objectKey, "severity_weight", finding.severityWeight);
        vm.serializeBool(objectKey, "fork_required", finding.forkRequired);
        vm.serializeBool(objectKey, "contradiction", finding.contradiction);
        vm.serializeString(objectKey, "status", finding.status);
        vm.serializeString(objectKey, "rationale", finding.rationale);
        vm.serializeString(objectKey, "tau1_label", finding.tau1Label);
        vm.serializeUint(objectKey, "tau1_block_number", finding.tau1BlockNumber);
        vm.serializeInt(objectKey, "tau1_value", finding.tau1Value);
        vm.serializeString(objectKey, "tau2_label", finding.tau2Label);
        vm.serializeUint(objectKey, "tau2_block_number", finding.tau2BlockNumber);
        vm.serializeInt(objectKey, "tau2_value", finding.tau2Value);
        vm.serializeUint(objectKey, "magnitude", finding.magnitude);
        vm.serializeUint(objectKey, "relative_deviation_bps", finding.relativeDeviationBps);
        return vm.serializeBool(objectKey, "is_profitable", finding.isProfitable);
    }
}