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
    _print_section("Output")
    print(f"  full result JSON: {out_path}")
    print()

    if result.status == ScanStatus.FAILED:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
