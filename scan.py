#!/usr/bin/env python3
"""
One-click full e2e scanner.

Runs ALL pipeline stages in one process, no manual orchestration required:

    Phase 1  Clone / locate target repo
    Phase 2  Detect framework (foundry, hardhat, ...)
    Phase 3  Discover Solidity / Vyper sources
    Phase 4  Pattern + AST analyzers (incl. CryptoAccessControlAnalyzer)
    Phase 5  FindingValidator (triage + dedupe)
    Phase 6  ExploitVerifier (algebraic / semantic confirmation)
    Phase 7  Foundry TSI plugin (runtime adapters in ./forge)

Usage:
    python scan.py <github-url-or-local-path>
    python scan.py <path> --out result.json
    python scan.py <path> --no-forge        # skip Phase 7
    python scan.py <path> --include-tests
    python scan.py <path> --scope contracts/core contracts/lending

Exit code is 0 unless the scan itself failed.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from repo_scanner import RepoScanner, ScanStatus
from report_generator import generate_markdown_report, generate_sarif_report


_SARIF_SEVERITY = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "GAS": "note",
    "INFO": "none",
}


def _scan_result_to_report_dict(d: dict, target: str) -> dict:
    """Adapt a ScanResult.to_dict() payload into the shape that
    `report_generator` expects (modeled after AdvancedAuditor output)."""
    findings = d.get("findings", []) or []
    repo = d.get("repo", {}) or {}

    by_sev: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1

    crit = by_sev.get("CRITICAL", 0)
    high = by_sev.get("HIGH", 0)
    med = by_sev.get("MEDIUM", 0)
    low = by_sev.get("LOW", 0)
    # Crude security score; mirrors AdvancedAuditor weighting roughly.
    score = max(0, 100 - (crit * 25 + high * 10 + med * 4 + low * 1))
    if crit:
        risk = "CRITICAL"
    elif high:
        risk = "HIGH"
    elif med:
        risk = "MEDIUM"
    elif low:
        risk = "LOW"
    else:
        risk = "SAFE"

    return {
        "timestamp": d.get("completed_at") or d.get("started_at"),
        "duration_ms": float(d.get("duration_seconds", 0)) * 1000.0,
        "contract": {
            "address": repo.get("url") or target,
            "name": Path(target).name or "repo-scan",
            "chain": "git-repo",
            "verified": True,
            "proxy": False,
        },
        "scores": {"security_score": score, "risk_level": risk},
        "summary": {
            "total_findings": len(findings),
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "info": by_sev.get("INFO", 0),
            "gas": by_sev.get("GAS", 0),
        },
        "analysis": {
            "interfaces": [],
            "defi_protocols": [],
            "access_control": None,
            "functions": {},
        },
        "findings": findings,
    }


def _sarif_with_real_paths(report_dict: dict) -> dict:
    """generate_sarif_report uses contract.address as the file URI which is
    fine for on-chain scans but useless for repo scans. Patch each result's
    artifactLocation to point at the per-finding `file_path` (or `file`)."""
    sarif = generate_sarif_report(report_dict)
    findings = report_dict.get("findings", [])
    runs = sarif.get("runs", [])
    if not runs:
        return sarif
    results = runs[0].get("results", [])
    for finding, result in zip(findings, results):
        path = finding.get("file_path") or finding.get("file")
        if not path:
            continue
        line = finding.get("line_number") or 1
        result["locations"] = [{
            "physicalLocation": {
                "artifactLocation": {"uri": str(path).replace("\\", "/")},
                "region": {"startLine": int(line)},
            }
        }]
    return sarif


def _print_section(title: str) -> None:
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def _print_phase_summary(d: dict) -> None:
    findings = d.get("findings", []) or []
    verifications = d.get("exploit_verifications", []) or []
    triage = d.get("triage", {}) or {}
    summary = d.get("summary", {}) or {}
    forge = summary.get("forge_plugin", {}) or {}

    _print_section("Pipeline result")
    print(f"  status:                {d.get('status')}")
    print(f"  duration:              {d.get('duration_seconds', 0):.1f}s")
    print(f"  files scanned:         {d.get('files_scanned', 0)}")
    print(f"  total findings:        {len(findings)}")
    print(f"  exploit verifications: {len(verifications)}")
    print(f"  triage tiers:          {triage.get('triage') or triage.get('findings_by_tier') or 'n/a'}")
    print(f"  forge plugin status:   {forge.get('status', 'not_run')}")
    forge_norm = forge.get("normalized_findings") or []
    if forge_norm:
        print(f"  forge plugin findings: {len(forge_norm)}")

    # Top-severity preview
    by_sev: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
    if by_sev:
        _print_section("Findings by severity")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "GAS"):
            if sev in by_sev:
                print(f"  {sev:8s} {by_sev[sev]}")

    # Verifier verdicts
    confirmed = [v for v in verifications if v.get("exploit_class") == "confirmed"]
    if confirmed:
        _print_section(f"Verifier-CONFIRMED ({len(confirmed)})")
        for v in confirmed[:25]:
            adj = v.get("severity_adjustment") or "no_change"
            print(f"  {v.get('finding_id'):20s} {v.get('attack_vector','-'):40s} adj={adj}")
            print(f"    -> {v.get('file')}:{v.get('line_number')}  conf={v.get('confidence', 0):.2f}")


def main() -> int:
    parser = argparse.ArgumentParser(description="One-click full e2e Solidity audit scanner")
    parser.add_argument("target", help="GitHub URL or local repo path")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--scope", nargs="*", help="Limit scan to these subpaths")
    parser.add_argument("--include-tests", action="store_true", help="Also scan .t.sol/.s.sol files")
    parser.add_argument("--no-forge", action="store_true", help="Skip Phase 7 (Foundry TSI plugin)")
    parser.add_argument("--forge-plugin-dir", default=None, help="Override path to TSI plugin dir (default ./forge)")
    parser.add_argument("--forge-match-contract", default="TSI_Findings_Report")
    parser.add_argument("--forge-fork-url", default=None, help="Optional RPC URL for forked TSI execution")
    parser.add_argument("--out", default=None, help="Path to write full result JSON (default scan_results/<id>.json)")
    parser.add_argument(
        "--format",
        nargs="+",
        choices=["json", "sarif", "markdown"],
        default=["json"],
        help="Output formats to emit (default json). Multiple allowed; sibling files are written next to --out.",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    started = datetime.now(timezone.utc)
    _print_section(f"One-click scan: {args.target}")
    print(f"  started:        {started.isoformat()}")
    print(f"  branch:         {args.branch}")
    print(f"  include_tests:  {args.include_tests}")
    print(f"  forge plugin:   {'disabled' if args.no_forge else 'enabled'}")

    scanner = RepoScanner()
    target = args.target

    # Treat as local path if it exists, else treat as repo URL
    is_local = Path(target).exists()
    if is_local:
        result = scanner.scan_repo(
            repo_url=str(Path(target).resolve()),
            branch=args.branch,
            include_tests=args.include_tests,
            scope_paths=args.scope,
            run_forge_plugin=not args.no_forge,
            forge_plugin_dir=args.forge_plugin_dir,
            forge_match_contract=args.forge_match_contract,
            forge_fork_url=args.forge_fork_url,
        )
    else:
        result = scanner.scan_repo(
            repo_url=target,
            branch=args.branch,
            include_tests=args.include_tests,
            scope_paths=args.scope,
            run_forge_plugin=not args.no_forge,
            forge_plugin_dir=args.forge_plugin_dir,
            forge_match_contract=args.forge_match_contract,
            forge_fork_url=args.forge_fork_url,
        )

    d = result.to_dict()
    _print_phase_summary(d)

    # Write result JSON
    out_path: Path
    if args.out:
        out_path = Path(args.out)
    else:
        results_dir = Path("scan_results")
        results_dir.mkdir(parents=True, exist_ok=True)
        stamp = started.strftime("%Y%m%d_%H%M%S")
        slug = Path(target).name or "scan"
        out_path = results_dir / f"{slug}_{stamp}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(d, indent=2, default=str), encoding="utf-8")

    written = [out_path]
    formats = set(args.format)
    if formats - {"json"}:
        report_dict = _scan_result_to_report_dict(d, target)
        if "sarif" in formats:
            sarif_path = out_path.with_suffix(".sarif")
            sarif_path.write_text(
                json.dumps(_sarif_with_real_paths(report_dict), indent=2, default=str),
                encoding="utf-8",
            )
            written.append(sarif_path)
        if "markdown" in formats:
            md_path = out_path.with_suffix(".md")
            md_path.write_text(
                generate_markdown_report(report_dict),
                encoding="utf-8",
            )
            written.append(md_path)

    _print_section("Output")
    for p in written:
        print(f"  {p.suffix.lstrip('.') or 'json':8s} -> {p}")
    print()

    if result.status == ScanStatus.FAILED:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
