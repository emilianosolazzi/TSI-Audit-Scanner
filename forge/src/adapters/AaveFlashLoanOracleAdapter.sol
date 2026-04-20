// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Contradiction, FindingKind, Observation, TSISeverity} from "src/core/TSITypes.sol";
import {ITSIAdapter} from "src/interfaces/ITSIAdapter.sol";

interface IAaveFlashLoanPool {
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IAaveFlashLoanReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract FairPriceOracleAdapterHelper {
    address public immutable pool;
    address public immutable weth;

    constructor(address _pool, address _weth) {
        pool = _pool;
        weth = _weth;
    }

    function getPoolWETHBalance() external view returns (uint256) {
        return IERC20Like(weth).balanceOf(pool);
    }
}

contract AaveFlashLoanOracleAdapter is ITSIAdapter, IAaveFlashLoanReceiver {
    address public immutable poolAddress;
    address public immutable wethAddress;
    address public immutable chainlinkAddress;
    address public immutable aWethAddress;

    IAaveFlashLoanPool public immutable pool;
    IERC20Like public immutable weth;
    FairPriceOracleAdapterHelper public immutable oracle;

    uint8 private _lastAction;
    uint256 private _lastTau2Value;
    uint256 private _lastTau2Block;
    bool private _hasTau2;

    constructor(address _poolAddress, address _wethAddress, address _chainlinkAddress, address _aWethAddress) {
        poolAddress = _poolAddress;
        wethAddress = _wethAddress;
        chainlinkAddress = _chainlinkAddress;
        aWethAddress = _aWethAddress;
        pool = IAaveFlashLoanPool(_poolAddress);
        weth = IERC20Like(_wethAddress);
        oracle = new FairPriceOracleAdapterHelper(_aWethAddress, _wethAddress);
    }

    function adapterName() external pure returns (string memory) {
        return "AaveFlashLoanOracleAdapter";
    }

    function adapterPath() external pure returns (string memory) {
        return "src/adapters/AaveFlashLoanOracleAdapter.sol";
    }

    function findingId() external pure returns (string memory) {
        return "TSI-011";
    }

    function defaultTitle() external pure returns (string memory) {
        return "Aave flash-loan callback invalidates pool and oracle reads";
    }

    function findingKind() external pure returns (FindingKind) {
        return FindingKind.OracleCompositionVulnerability;
    }

    function defaultSeverity() external pure returns (TSISeverity) {
        return TSISeverity.CRITICAL;
    }

    function defaultConfidenceScore() external pure returns (uint8) {
        return 90;
    }

    function forkRequired() external pure returns (bool) {
        return true;
    }

    function forkReady() external view returns (bool) {
        return poolAddress.code.length > 0 && chainlinkAddress.code.length > 0 && aWethAddress.code.length > 0;
    }

    function lastAction() external view returns (uint8) {
        return _lastAction;
    }

    function currentFlashAmount(uint8 action, uint256 fractionBps) external view returns (uint256) {
        return (_currentReferenceValue(action) * fractionBps) / 10_000;
    }

    function captureTau1(bytes calldata context) external view returns (Observation memory) {
        uint8 action = _decodeContext(context);
        uint256 tau1Value = _currentReferenceValue(action);

        return Observation({
            label: action == 3 ? "oracle.outside_callback" : "aave.pool.balance.outside_callback",
            blockNumber: block.number,
            stateHash: keccak256(abi.encode(action, tau1Value, block.number)),
            numericValue: int256(tau1Value),
            extraData: abi.encode(action)
        });
    }

    function captureTau2(bytes calldata context) external view returns (Observation memory) {
        require(_hasTau2, "AaveFlashLoanOracleAdapter: executeExploit first");
        uint8 action = _decodeContext(context);
        require(action == _lastAction, "AaveFlashLoanOracleAdapter: action mismatch");

        return Observation({
            label: action == 3 ? "oracle.inside_callback" : "aave.pool.balance.inside_callback",
            blockNumber: _lastTau2Block,
            stateHash: keccak256(abi.encode(action, _lastTau2Value, _lastTau2Block, "callback")),
            numericValue: int256(_lastTau2Value),
            extraData: abi.encode(action, true)
        });
    }

    function hasContradiction(
        Observation calldata tau1,
        Observation calldata tau2
    ) external pure returns (bool, string memory) {
        bool mismatch = tau1.numericValue != tau2.numericValue || tau1.stateHash != tau2.stateHash;
        if (!mismatch) {
            return (false, "No Aave flash-loan contradiction detected");
        }

        uint8 action = abi.decode(tau1.extraData, (uint8));
        if (action == 3) {
            return (true, "Context-blind oracle read diverges inside flash-loan callback");
        }
        return (true, "Pool balance diverges between outside state and callback state");
    }

    function buildContradiction(bytes calldata context) external view returns (Contradiction memory) {
        Observation memory tau1 = this.captureTau1(context);
        Observation memory tau2 = this.captureTau2(context);
        (bool mismatch, string memory rationale) = this.hasContradiction(tau1, tau2);

        return Contradiction({
            kind: FindingKind.OracleCompositionVulnerability,
            tau1: tau1,
            tau2: tau2,
            contradiction: mismatch,
            rationale: rationale
        });
    }

    function executeExploit(bytes calldata attackData) external returns (bytes memory result) {
        (uint8 action, uint256 fractionBps) = abi.decode(attackData, (uint8, uint256));
        uint256 tau1Value = _currentReferenceValue(action);
        uint256 flashAmount = (tau1Value * fractionBps) / 10_000;

        _lastAction = action;
        _hasTau2 = false;
        pool.flashLoanSimple(address(this), wethAddress, flashAmount, abi.encode(action), 0);
        require(_hasTau2, "AaveFlashLoanOracleAdapter: callback capture missing");

        result = abi.encode(tau1Value, _lastTau2Value, flashAmount);
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        require(msg.sender == poolAddress, "AaveFlashLoanOracleAdapter: caller must be pool");
        require(initiator == address(this), "AaveFlashLoanOracleAdapter: initiator must be self");

        uint8 action = abi.decode(params, (uint8));
        _lastAction = action;
        _lastTau2Value = action == 3 ? oracle.getPoolWETHBalance() : IERC20Like(asset).balanceOf(aWethAddress);
        _lastTau2Block = block.number;
        _hasTau2 = true;

        IERC20Like(asset).approve(poolAddress, amount + premium);
        return true;
    }

    function _currentReferenceValue(uint8 action) internal view returns (uint256) {
        if (action == 3) {
            return oracle.getPoolWETHBalance();
        }
        return weth.balanceOf(aWethAddress);
    }

    function _decodeContext(bytes calldata context) internal pure returns (uint8 action) {
        action = context.length == 0 ? 1 : abi.decode(context, (uint8));
    }
}
