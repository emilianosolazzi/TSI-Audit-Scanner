// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Contradiction, FindingKind, Observation, TSISeverity} from "src/core/TSITypes.sol";
import {ITSIAdapter} from "src/interfaces/ITSIAdapter.sol";

interface IERC4626DonationVault {
    function previewDeposit(uint256 assets) external view returns (uint256);
    function totalAssets() external view returns (uint256);
    function donate(uint256 assets) external;
}

contract ERC4626DonationPreviewAdapter is ITSIAdapter {
    IERC4626DonationVault public immutable vault;

    uint256 private _lastDepositAssets;
    uint256 private _tau1Preview;
    uint256 private _tau2Preview;
    bool private _hasPreviewShift;

    constructor(address vaultAddress) {
        vault = IERC4626DonationVault(vaultAddress);
    }

    function adapterName() external pure returns (string memory) {
        return "ERC4626DonationPreviewAdapter";
    }

    function adapterPath() external pure returns (string memory) {
        return "src/adapters/ERC4626DonationPreviewAdapter.sol";
    }

    function findingId() external pure returns (string memory) {
        return "TSI-041";
    }

    function defaultTitle() external pure returns (string memory) {
        return "ERC4626 donation invalidates previewDeposit assumptions";
    }

    function findingKind() external pure returns (FindingKind) {
        return FindingKind.SameBlockStateInvalidation;
    }

    function defaultSeverity() external pure returns (TSISeverity) {
        return TSISeverity.HIGH;
    }

    function defaultConfidenceScore() external pure returns (uint8) {
        return 85;
    }

    function forkRequired() external pure returns (bool) {
        return false;
    }

    function captureTau1(bytes calldata context) external view returns (Observation memory) {
        uint256 depositAssets = _decodeDepositAssets(context);
        uint256 preview = _hasPreviewShift && depositAssets == _lastDepositAssets ? _tau1Preview : vault.previewDeposit(depositAssets);

        return Observation({
            label: "erc4626.previewDeposit.beforeDonation",
            blockNumber: block.number,
            stateHash: keccak256(abi.encode("before", depositAssets, preview)),
            numericValue: int256(preview),
            extraData: abi.encode(depositAssets)
        });
    }

    function captureTau2(bytes calldata context) external view returns (Observation memory) {
        uint256 depositAssets = _decodeDepositAssets(context);
        uint256 preview = _hasPreviewShift && depositAssets == _lastDepositAssets ? _tau2Preview : vault.previewDeposit(depositAssets);

        return Observation({
            label: "erc4626.previewDeposit.afterDonation",
            blockNumber: block.number,
            stateHash: keccak256(abi.encode("after", depositAssets, preview)),
            numericValue: int256(preview),
            extraData: abi.encode(depositAssets)
        });
    }

    function hasContradiction(Observation calldata tau1, Observation calldata tau2) external pure returns (bool, string memory) {
        if (tau1.numericValue != tau2.numericValue) {
            return (true, "Same-block ERC4626 donation changes previewed share output");
        }
        return (false, "No ERC4626 preview invalidation detected");
    }

    function buildContradiction(bytes calldata context) external view returns (Contradiction memory) {
        Observation memory tau1 = this.captureTau1(context);
        Observation memory tau2 = this.captureTau2(context);
        (bool mismatch, string memory rationale) = this.hasContradiction(tau1, tau2);

        return Contradiction({
            kind: FindingKind.SameBlockStateInvalidation,
            tau1: tau1,
            tau2: tau2,
            contradiction: mismatch,
            rationale: rationale
        });
    }

    function executeExploit(bytes calldata attackData) external returns (bytes memory) {
        (uint256 depositAssets, uint256 donationAssets) = abi.decode(attackData, (uint256, uint256));
        _lastDepositAssets = depositAssets;
        _tau1Preview = vault.previewDeposit(depositAssets);
        vault.donate(donationAssets);
        _tau2Preview = vault.previewDeposit(depositAssets);
        _hasPreviewShift = true;
        return abi.encode(_tau1Preview, _tau2Preview, donationAssets);
    }

    function _decodeDepositAssets(bytes calldata context) internal view returns (uint256) {
        if (context.length == 0) {
            return _lastDepositAssets;
        }
        return abi.decode(context, (uint256));
    }
}