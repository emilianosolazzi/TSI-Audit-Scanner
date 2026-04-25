#!/usr/bin/env python3
"""Integration coverage for end-to-end local repo scans."""

from pathlib import Path

from repo_scanner import RepoScanner, ScanStatus, SolidityFile


def test_local_repo_scan_produces_stable_risk_summary(tmp_path: Path):
    project_dir = tmp_path / "sample_project"
    contracts_dir = project_dir / "contracts"
    contracts_dir.mkdir(parents=True)

    vulnerable_contract = '''
    pragma solidity ^0.8.20;

    contract Vault {
        mapping(address => uint256) public balances;

        function deposit() external payable {
            balances[msg.sender] += msg.value;
        }

        function withdraw() external {
            uint256 amount = balances[msg.sender];
            (bool ok,) = msg.sender.call{value: amount}("");
            require(ok, "send failed");
            balances[msg.sender] = 0;
        }
    }
    '''
    (contracts_dir / "Vault.sol").write_text(vulnerable_contract, encoding="utf-8")

    scanner = RepoScanner(workspace_dir=str(tmp_path / "workspace"))
    result = scanner.scan_local(str(project_dir), scope_paths=["contracts/"])

    assert result.status == ScanStatus.COMPLETE
    assert result.files_scanned == 1
    assert isinstance(result.summary, dict)
    assert "risk_level" in result.summary
    assert "risk_score" in result.summary
    assert result.summary.get("total_findings", 0) >= 1

    finding_ids = {f.get("id") for f in result.findings}
    assert "SWC-107" in finding_ids


def test_repo_scanner_filters_safe_v4_downcast_shapes(tmp_path: Path):
    source = '''
    pragma solidity ^0.8.24;

    contract SafeHookShapes {
        error HookFeeExceedsReturnDelta(uint256 fee);
        uint256 private constant MAX_AFTER_SWAP_RETURN_DELTA = uint256(uint128(type(int128).max));

        function recover(uint256 rawCurrency) external pure returns (address) {
            return address(uint160(rawCurrency));
        }

        function afterSwap(uint256 fee) external pure returns (bytes4, int128) {
            if (fee > MAX_AFTER_SWAP_RETURN_DELTA) revert HookFeeExceedsReturnDelta(fee);
            _settle();
            _settle();
            _settle();
            _settle();
            return (this.afterSwap.selector, int128(uint128(fee)));
        }

        function _settle() internal pure {}
    }
    '''
    sol_file = SolidityFile(
        path="src/SafeHookShapes.sol",
        absolute_path=str(tmp_path / "SafeHookShapes.sol"),
        size_bytes=len(source),
        pragma_version="^0.8.24",
        contract_names=["SafeHookShapes"],
    )

    scanner = RepoScanner(workspace_dir=str(tmp_path / "workspace"))
    findings = scanner._analyze_source(source, sol_file)

    assert [f for f in findings if f.get("id") == "TOKEN-007"] == []
