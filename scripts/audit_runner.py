#!/usr/bin/env python3
"""Unified front door for scanner, report, plugin, and benchmark workflows."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import List


def _run(cmd: List[str], root_dir: Path) -> int:
    proc = subprocess.run(cmd, cwd=str(root_dir), check=False)
    return proc.returncode


def main() -> None:
    root_dir = Path(__file__).resolve().parents[1]
    scripts_dir = root_dir / "scripts"

    parser = argparse.ArgumentParser(
        description="Unified runner for repo scan, E2E reporting, TSI plugin, and benchmarks"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run full_e2e_report.py only")
    scan.add_argument("--url", help="Repository URL to scan")
    scan.add_argument("--input-scan", help="Existing scan JSON path to post-process")
    scan.add_argument("--outdir", default="speed_tests/unified_scan", help="Output directory")
    scan.add_argument("--branch", default="main", help="Git branch")
    scan.add_argument("--workspace-dir", help="Optional existing workspace directory for source loading")

    e2e = subparsers.add_parser("e2e", help="Run intelligent_e2e_flow.py")
    e2e.add_argument("--url", help="Repository URL to scan")
    e2e.add_argument("--input-scan", help="Use existing scan JSON instead of rescanning")
    e2e.add_argument("--outdir", default="speed_tests/unified_e2e", help="Output directory")
    e2e.add_argument("--branch", default="main", help="Git branch")
    e2e.add_argument("--max-confirmed-true", type=int, default=0)
    e2e.add_argument("--max-critical-manual", type=int, default=0)
    e2e.add_argument("--max-high-manual", type=int, default=3)
    e2e.add_argument("--tsi-plugin-dir", default="forge")
    e2e.add_argument("--tsi-fork-url")
    e2e.add_argument("--tsi-match-contract", default="TSI_Aave_FlashLoan_Oracle")
    e2e.add_argument("--tsi-findings-contract", default=None)
    e2e.add_argument("--tsi-findings-artifact", default="artifacts/tsi_adapter_findings.json")
    e2e.add_argument("--tsi-enforce-pass", action="store_true")

    plugin = subparsers.add_parser("plugin", help="Run tsi_plugin_runner.py")
    plugin.add_argument("--outdir", default="speed_tests/unified_plugin", help="Output directory")
    plugin.add_argument("--tsi-plugin-dir", default="forge")
    plugin.add_argument("--tsi-fork-url")
    plugin.add_argument("--tsi-match-contract", default="TSI_Aave_FlashLoan_Oracle")
    plugin.add_argument("--tsi-findings-contract", default=None)
    plugin.add_argument("--tsi-findings-artifact", default="artifacts/tsi_adapter_findings.json")

    benchmark = subparsers.add_parser("benchmark", help="Run benchmark corpus")
    benchmark.add_argument("--corpus", default="tests/benchmark_corpus", help="Path to benchmark corpus directory")
    benchmark.add_argument("--output", default="benchmarks/results/latest.json", help="Output report path")
    benchmark.add_argument("--min-precision", type=float, default=0.8)
    benchmark.add_argument("--min-recall", type=float, default=0.8)
    benchmark.add_argument("--max-safe-fp-rate", type=float, default=0.0)
    benchmark.add_argument("--with-forge-plugin", action="store_true")

    all_cmd = subparsers.add_parser("all", help="Run benchmark, then full E2E, then plugin-backed grading")
    all_cmd.add_argument("--url", help="Repository URL to scan")
    all_cmd.add_argument("--input-scan", help="Use existing scan JSON instead of rescanning")
    all_cmd.add_argument("--outdir", default="speed_tests/unified_all", help="Output directory")
    all_cmd.add_argument("--branch", default="main", help="Git branch")
    all_cmd.add_argument("--corpus", default="tests/benchmark_corpus", help="Path to benchmark corpus directory")
    all_cmd.add_argument("--benchmark-output", default="benchmarks/results/latest.json", help="Output report path")
    all_cmd.add_argument("--min-precision", type=float, default=0.8)
    all_cmd.add_argument("--min-recall", type=float, default=0.8)
    all_cmd.add_argument("--max-safe-fp-rate", type=float, default=0.0)
    all_cmd.add_argument("--benchmark-with-forge-plugin", action="store_true")
    all_cmd.add_argument("--max-confirmed-true", type=int, default=0)
    all_cmd.add_argument("--max-critical-manual", type=int, default=0)
    all_cmd.add_argument("--max-high-manual", type=int, default=3)
    all_cmd.add_argument("--tsi-plugin-dir", default="forge")
    all_cmd.add_argument("--tsi-fork-url")
    all_cmd.add_argument("--tsi-match-contract", default="TSI_Aave_FlashLoan_Oracle")
    all_cmd.add_argument("--tsi-findings-contract", default=None)
    all_cmd.add_argument("--tsi-findings-artifact", default="artifacts/tsi_adapter_findings.json")
    all_cmd.add_argument("--tsi-enforce-pass", action="store_true")

    args = parser.parse_args()

    if args.command == "scan":
        cmd = [
            sys.executable,
            str(scripts_dir / "full_e2e_report.py"),
            "--outdir",
            args.outdir,
            "--branch",
            args.branch,
        ]
        if args.input_scan:
            cmd.extend(["--input-scan", args.input_scan])
        elif args.url:
            cmd.extend(["--url", args.url])
        if args.workspace_dir:
            cmd.extend(["--workspace-dir", args.workspace_dir])
        raise SystemExit(_run(cmd, root_dir))

    if args.command == "e2e":
        cmd = [
            sys.executable,
            str(scripts_dir / "intelligent_e2e_flow.py"),
            "--outdir",
            args.outdir,
            "--branch",
            args.branch,
            "--max-confirmed-true",
            str(args.max_confirmed_true),
            "--max-critical-manual",
            str(args.max_critical_manual),
            "--max-high-manual",
            str(args.max_high_manual),
            "--tsi-plugin-dir",
            args.tsi_plugin_dir,
            "--tsi-match-contract",
            args.tsi_match_contract,
            "--tsi-findings-artifact",
            args.tsi_findings_artifact,
        ]
        if args.tsi_findings_contract:
            cmd.extend(["--tsi-findings-contract", args.tsi_findings_contract])
        if args.input_scan:
            cmd.extend(["--input-scan", args.input_scan])
        elif args.url:
            cmd.extend(["--url", args.url])
        if args.tsi_fork_url:
            cmd.extend(["--tsi-fork-url", args.tsi_fork_url])
        if args.tsi_enforce_pass:
            cmd.append("--tsi-enforce-pass")
        raise SystemExit(_run(cmd, root_dir))

    if args.command == "plugin":
        cmd = [
            sys.executable,
            str(scripts_dir / "tsi_plugin_runner.py"),
            "--outdir",
            args.outdir,
            "--tsi-plugin-dir",
            args.tsi_plugin_dir,
            "--tsi-match-contract",
            args.tsi_match_contract,
            "--tsi-findings-artifact",
            args.tsi_findings_artifact,
        ]
        if args.tsi_findings_contract:
            cmd.extend(["--tsi-findings-contract", args.tsi_findings_contract])
        if args.tsi_fork_url:
            cmd.extend(["--tsi-fork-url", args.tsi_fork_url])
        raise SystemExit(_run(cmd, root_dir))

    if args.command == "benchmark":
        cmd = [
            sys.executable,
            str(scripts_dir / "run_benchmark.py"),
            "--corpus",
            args.corpus,
            "--output",
            args.output,
            "--min-precision",
            str(args.min_precision),
            "--min-recall",
            str(args.min_recall),
            "--max-safe-fp-rate",
            str(args.max_safe_fp_rate),
        ]
        if args.with_forge_plugin:
            cmd.append("--with-forge-plugin")
        raise SystemExit(_run(cmd, root_dir))

    if args.command == "all":
        benchmark_cmd = [
            sys.executable,
            str(scripts_dir / "run_benchmark.py"),
            "--corpus",
            args.corpus,
            "--output",
            args.benchmark_output,
            "--min-precision",
            str(args.min_precision),
            "--min-recall",
            str(args.min_recall),
            "--max-safe-fp-rate",
            str(args.max_safe_fp_rate),
        ]
        if args.benchmark_with_forge_plugin:
            benchmark_cmd.append("--with-forge-plugin")
        rc = _run(benchmark_cmd, root_dir)
        if rc != 0:
            raise SystemExit(rc)

        e2e_cmd = [
            sys.executable,
            str(scripts_dir / "intelligent_e2e_flow.py"),
            "--outdir",
            args.outdir,
            "--branch",
            args.branch,
            "--max-confirmed-true",
            str(args.max_confirmed_true),
            "--max-critical-manual",
            str(args.max_critical_manual),
            "--max-high-manual",
            str(args.max_high_manual),
            "--tsi-plugin-dir",
            args.tsi_plugin_dir,
            "--tsi-match-contract",
            args.tsi_match_contract,
            "--tsi-findings-artifact",
            args.tsi_findings_artifact,
        ]
        if args.tsi_findings_contract:
            e2e_cmd.extend(["--tsi-findings-contract", args.tsi_findings_contract])
        if args.input_scan:
            e2e_cmd.extend(["--input-scan", args.input_scan])
        elif args.url:
            e2e_cmd.extend(["--url", args.url])
        if args.tsi_fork_url:
            e2e_cmd.extend(["--tsi-fork-url", args.tsi_fork_url])
        if args.tsi_enforce_pass:
            e2e_cmd.append("--tsi-enforce-pass")
        raise SystemExit(_run(e2e_cmd, root_dir))


if __name__ == "__main__":
    main()