// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {
    IGovernanceVoteSource
} from "src/adapters/GovernanceSnapshotVoteAdapter.sol";
import {IReplayClaimLedger} from "src/adapters/MerkleReplayClaimAdapter.sol";
import {ISpotTwapOracle} from "src/adapters/UniswapV2TwapSkewAdapter.sol";
import {
    IERC4626DonationVault
} from "src/adapters/ERC4626DonationPreviewAdapter.sol";
import {
    ISSVNetworkAdapter,
    ISSVViewsAdapter
} from "src/adapters/SSVStateContradictionAdapter.sol";

contract MockERC4626DonationVault is IERC4626DonationVault {
    uint256 public totalAssets;
    uint256 public totalSupply;

    constructor(uint256 assets, uint256 supply) {
        totalAssets = assets;
        totalSupply = supply;
    }

    function previewDeposit(uint256 assets) external view returns (uint256) {
        if (totalSupply == 0 || totalAssets == 0) {
            return assets;
        }
        return (assets * totalSupply) / totalAssets;
    }

    function donate(uint256 assets) external {
        totalAssets += assets;
    }
}

contract MockGovernanceVoteSource is IGovernanceVoteSource {
    mapping(address => uint256) internal currentVotes;
    mapping(address => mapping(uint256 => uint256)) internal historicVotes;

    function setVotes(address account, uint256 liveVotes, uint256 snapshotBlock, uint256 snapshotVotes) external {
        currentVotes[account] = liveVotes;
        historicVotes[account][snapshotBlock] = snapshotVotes;
    }

    function getVotes(address account) external view returns (uint256) {
        return currentVotes[account];
    }

    function getPastVotes(address account, uint256 blockNumber) external view returns (uint256) {
        return historicVotes[account][blockNumber];
    }
}

contract MockReplayClaimLedger is IReplayClaimLedger {
    mapping(bytes32 => bool) internal claimed;
    mapping(bytes32 => bytes32) internal hashes;

    function setClaim(bytes32 claimId, bool isClaimed_, bytes32 executionHash_) external {
        claimed[claimId] = isClaimed_;
        hashes[claimId] = executionHash_;
    }

    function isClaimed(bytes32 claimId) external view returns (bool) {
        return claimed[claimId];
    }

    function executionHash(bytes32 claimId) external view returns (bytes32) {
        return hashes[claimId];
    }
}

contract MockSpotTwapOracle is ISpotTwapOracle {
    uint256 internal spot;
    uint256 internal twap;

    function setPrices(uint256 spotPriceX96_, uint256 twapPriceX96_) external {
        spot = spotPriceX96_;
        twap = twapPriceX96_;
    }

    function spotPriceX96() external view returns (uint256) {
        return spot;
    }

    function twapPriceX96() external view returns (uint256) {
        return twap;
    }
}

contract MockChainlinkFeed {
    struct Round {
        int256 answer;
        uint256 updatedAt;
    }

    mapping(uint80 => Round) internal rounds;
    uint80 internal latestRoundId;

    function setRound(uint80 roundId, int256 answer, uint256 updatedAt) external {
        rounds[roundId] = Round(answer, updatedAt);
        if (roundId > latestRoundId) {
            latestRoundId = roundId;
        }
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        Round memory round = rounds[latestRoundId];
        return (latestRoundId, round.answer, round.updatedAt, round.updatedAt, latestRoundId);
    }

    function getRoundData(uint80 roundId) external view returns (uint80, int256, uint256, uint256, uint80) {
        Round memory round = rounds[roundId];
        return (roundId, round.answer, round.updatedAt, round.updatedAt, roundId);
    }
}

contract MockSSVViews is ISSVViewsAdapter {
    uint256 internal nextBalance;

    function setBalance(uint256 balance) external {
        nextBalance = balance;
    }

    function getBalance(
        address,
        uint64[] memory,
        ISSVNetworkAdapter.Cluster memory
    ) external view returns (uint256) {
        return nextBalance;
    }
}