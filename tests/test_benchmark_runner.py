#!/usr/bin/env python3
"""Regression tests for benchmark precision and false-positive accounting."""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scripts.run_benchmark import compute_metrics


def test_false_positive_metrics_count_safe_unexpected_findings():
    scan_result = {
        "findings": [
            {"file": "contracts/SafeUnexpected.sol", "id": "SWC-107", "category": "REENTRANCY"},
            {"file": "contracts/SafeUnexpected.sol", "id": "SWC-107", "category": "REENTRANCY", "line_number": 12},
            {"file": "contracts/SafeAllowed.sol", "id": "TOKEN-007", "category": "TOKEN"},
            {"file": "contracts/Vulnerable.sol", "id": "SWC-115", "category": "ACCESS_CONTROL"},
        ]
    }
    manifest = {
        "cases": [
            {"file": "contracts/SafeUnexpected.sol", "classification": "safe", "expected_findings": []},
            {"file": "contracts/SafeAllowed.sol", "classification": "safe", "allowed_findings": ["TOKEN-007"]},
            {"file": "contracts/Vulnerable.sol", "classification": "vulnerable", "expected_findings": ["SWC-115"]},
        ]
    }

    metrics = compute_metrics(scan_result, manifest)
    summary = metrics["summary"]

    assert summary["tp"] == 1
    assert summary["fp"] == 2
    assert summary["fn"] == 0
    assert summary["safe_cases"] == 2
    assert summary["safe_cases_with_unexpected_findings"] == 1
    assert summary["safe_case_false_positive_rate"] == 0.5
    assert summary["allowed_limitations"] == 1
    assert summary["false_positives_by_category"] == {"REENTRANCY": 2}
    assert summary["false_positives_by_id"] == {"SWC-107": 2}
    assert len(metrics["cases"][0]["unexpected_finding_details"]) == 2


def test_legacy_must_find_manifest_still_computes_recall():
    scan_result = {"findings": [{"file": "txorigin_vuln.sol", "id": "SWC-115"}]}
    manifest = {"cases": [{"file": "txorigin_vuln.sol", "must_find": ["SWC-115"]}]}

    metrics = compute_metrics(scan_result, manifest)

    assert metrics["summary"]["precision"] == 1.0
    assert metrics["summary"]["recall"] == 1.0
    assert metrics["cases"][0]["classification"] == "vulnerable"