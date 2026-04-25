// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Contradiction, FindingKind, Observation, TSISeverity} from "src/core/TSITypes.sol";
import {ITSIAdapter} from "src/interfaces/ITSIAdapter.sol";

interface IReadOnlyReentrancyVault {
    function quoteRedeem(uint256 shares) external view returns (uint256);

    function triggerReadOnlyWindow(uint256 transientAssetsOut, address callbackTarget, bytes calldata callbackData)
        external
        returns (bytes memory);
}

interface IReadOnlyReentrancyObserver {
    function onReadOnlyReentrant(bytes calldata callbackData) external returns (bytes memory);
}

contract ReadOnlyReentrancyAdapter is ITSIAdapter, IReadOnlyReentrancyObserver {
    IReadOnlyReentrancyVault public immutable vault;

    uint256 private _lastShares;
    uint256 private _tau1Quote;
    uint256 private _tau2Quote;
    bool private _hasCallbackQuote;

    constructor(address vaultAddress) {
        vault = IReadOnlyReentrancyVault(vaultAddress);
    }

    function adapterName() external pure returns (string memory) {
        return "ReadOnlyReentrancyAdapter";
    }

    function adapterPath() external pure returns (string memory) {
        return "src/adapters/ReadOnlyReentrancyAdapter.sol";
    }

    function findingId() external pure returns (string memory) {
        return "TSI-081";
    }

    function defaultTitle() external pure returns (string memory) {
        return "Read-only reentrancy invalidates same-block view quote";
    }

    function findingKind() external pure returns (FindingKind) {
        return FindingKind.ReadOnlyReentrancy;
    }

    function defaultSeverity() external pure returns (TSISeverity) {
        return TSISeverity.HIGH;
    }

    function defaultConfidenceScore() external pure returns (uint8) {
        return 88;
    }

    function forkRequired() external pure returns (bool) {
        return false;
    }

    function captureTau1(bytes calldata context) external view returns (Observation memory) {
        uint256 shares = _decodeShares(context);
        uint256 quote = _hasCallbackQuote && shares == _lastShares ? _tau1Quote : vault.quoteRedeem(shares);

        return Observation({
            label: "readonly.quote.beforeCallback",
            blockNumber: block.number,
            stateHash: keccak256(abi.encode("before", shares, quote)),
            numericValue: int256(quote),
            extraData: abi.encode(shares)
        });
    }

    function captureTau2(bytes calldata context) external view returns (Observation memory) {
        uint256 shares = _decodeShares(context);
        uint256 quote = _hasCallbackQuote && shares == _lastShares ? _tau2Quote : vault.quoteRedeem(shares);

        return Observation({
            label: "readonly.quote.duringCallback",
            blockNumber: block.number,
            stateHash: keccak256(abi.encode("during", shares, quote)),
            numericValue: int256(quote),
            extraData: abi.encode(shares)
        });
    }

    function hasContradiction(Observation calldata tau1, Observation calldata tau2)
        external
        pure
        returns (bool, string memory)
    {
        if (tau1.blockNumber == tau2.blockNumber && tau1.numericValue != tau2.numericValue) {
            return (true, "Same-block callback observes a different view quote before state is finalized");
        }
        return (false, "No read-only reentrancy quote mismatch detected");
    }

    function buildContradiction(bytes calldata context) external view returns (Contradiction memory) {
        Observation memory tau1 = this.captureTau1(context);
        Observation memory tau2 = this.captureTau2(context);
        (bool mismatch, string memory rationale) = this.hasContradiction(tau1, tau2);

        return Contradiction({
            kind: FindingKind.ReadOnlyReentrancy, tau1: tau1, tau2: tau2, contradiction: mismatch, rationale: rationale
        });
    }

    function executeExploit(bytes calldata attackData) external returns (bytes memory) {
        (uint256 shares, uint256 transientAssetsOut) = abi.decode(attackData, (uint256, uint256));
        _lastShares = shares;
        _tau1Quote = vault.quoteRedeem(shares);
        _tau2Quote = _tau1Quote;
        _hasCallbackQuote = false;

        vault.triggerReadOnlyWindow(transientAssetsOut, address(this), abi.encode(shares));
        require(_hasCallbackQuote, "ReadOnlyReentrancyAdapter: callback quote missing");

        return abi.encode(_tau1Quote, _tau2Quote, transientAssetsOut);
    }

    function onReadOnlyReentrant(bytes calldata callbackData) external returns (bytes memory) {
        require(msg.sender == address(vault), "ReadOnlyReentrancyAdapter: caller must be vault");
        uint256 shares = _decodeShares(callbackData);
        _tau2Quote = vault.quoteRedeem(shares);
        _hasCallbackQuote = true;
        return abi.encode(_tau2Quote);
    }

    function _decodeShares(bytes calldata context) internal view returns (uint256) {
        if (context.length == 0) {
            return _lastShares;
        }
        return abi.decode(context, (uint256));
    }
}
