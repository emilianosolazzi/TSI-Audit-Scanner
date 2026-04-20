#!/usr/bin/env python3
"""Integration coverage for end-to-end local repo scans."""

from pathlib import Path

from repo_scanner import RepoScanner, ScanStatus


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
