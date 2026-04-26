#!/usr/bin/env python3
"""Run fully automated repo scan + intelligent validation + grading.

Pipeline:
1. Acquire scan data (run fresh scan or consume existing JSON)
2. Generate full E2E report via scripts/full_e2e_report.py
3. Compute grade and CI gate status from report dispositions
4. Emit machine and markdown summaries for stack-native reporting
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tsi_plugin_runner import run_tsi_plugin


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _run_full_e2e_report(
    root_dir: Path,
    outdir: Path,
    url: str | None,
    branch: str,
    input_scan: Path | None,
    workspace_dir: Path | None,
    no_forge_plugin: bool,
) -> None:
    cmd: List[str] = [
        sys.executable,
        str(root_dir / "scripts" / "full_e2e_report.py"),
        "--outdir",
        str(outdir),
        "--branch",
        branch,
    ]

    if input_scan is not None:
        cmd.extend(["--input-scan", str(input_scan)])
    else:
        if not url:
            raise SystemExit("Either --url or --input-scan must be provided")
        cmd.extend(["--url", url])

    if workspace_dir is not None:
        cmd.extend(["--workspace-dir", str(workspace_dir)])

    if no_forge_plugin:
        # Intelligent flow runs the plugin in a dedicated step after base report generation.
        cmd.append("--no-forge-plugin")

    subprocess.run(cmd, check=True, cwd=str(root_dir))


def _score_findings(all_findings: List[Dict[str, Any]]) -> Tuple[float, Dict[str, int]]:
    counts = {
        "confirmed_true": 0,
        "needs_manual_review_critical": 0,
        "needs_manual_review_high": 0,
        "high_priority_candidate": 0,
    }

    for finding in all_findings:
        disposition = finding.get("disposition")
        severity = (finding.get("severity") or "").upper()

        if disposition == "confirmed_true":
            counts["confirmed_true"] += 1
        elif disposition == "high_priority_candidate":
            counts["high_priority_candidate"] += 1
        elif disposition == "needs_manual_review":
            if severity == "CRITICAL":
                counts["needs_manual_review_critical"] += 1
            elif severity == "HIGH":
                counts["needs_manual_review_high"] += 1

    score = 10.0
    score -= counts["confirmed_true"] * 2.0
    score -= counts["needs_manual_review_critical"] * 0.50
    score -= counts["needs_manual_review_high"] * 0.25
    score -= counts["high_priority_candidate"] * 0.20
    score = max(0.0, min(10.0, round(score, 2)))
    return score, counts


def _build_gate_result(
    all_findings: List[Dict[str, Any]],
    max_confirmed_true: int,
    max_critical_manual: int,
    max_high_manual: int,
) -> Dict[str, Any]:
    confirmed_true = sum(1 for f in all_findings if f.get("disposition") == "confirmed_true")
    critical_manual = sum(
        1
        for f in all_findings
        if f.get("disposition") == "needs_manual_review" and (f.get("severity") or "").upper() == "CRITICAL"
    )
    high_manual = sum(
        1
        for f in all_findings
        if f.get("disposition") == "needs_manual_review" and (f.get("severity") or "").upper() == "HIGH"
    )

    checks = {
        "confirmed_true_within_limit": confirmed_true <= max_confirmed_true,
        "critical_manual_within_limit": critical_manual <= max_critical_manual,
        "high_manual_within_limit": high_manual <= max_high_manual,
    }

    return {
        "pass": all(checks.values()),
        "checks": checks,
        "actual": {
            "confirmed_true": confirmed_true,
            "needs_manual_review_critical": critical_manual,
            "needs_manual_review_high": high_manual,
        },
        "limits": {
            "max_confirmed_true": max_confirmed_true,
            "max_critical_manual": max_critical_manual,
            "max_high_manual": max_high_manual,
        },
    }


def _build_counts_by_status(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    return dict(Counter((finding.get("disposition") or "unknown") for finding in findings))


def _build_top_review_queue(findings: List[Dict[str, Any]], limit: int = 50) -> List[Dict[str, Any]]:
    queue = [
        finding
        for finding in findings
        if finding.get("disposition") in ("confirmed_true", "high_priority_candidate", "candidate", "needs_manual_review")
    ]

    sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "GAS": 0}
    disp_rank = {
        "confirmed_true": 4,
        "high_priority_candidate": 3,
        "needs_manual_review": 2,
        "candidate": 1,
    }

    queue.sort(
        key=lambda finding: (
            disp_rank.get(finding.get("disposition") or "", 0),
            sev_rank.get((finding.get("severity") or "INFO").upper(), 0),
            1 if finding.get("source") == "forge_plugin" else 0,
        ),
        reverse=True,
    )
    return queue[:limit]


def _render_markdown(summary: Dict[str, Any]) -> str:
    forge_findings = summary.get("forge_findings", [])
    lines = [
        "# Intelligent E2E Flow Summary",
        "## TSI Plugin",
        "",
        f"- Status: {summary.get('tsi_plugin', {}).get('status', 'not_run')}",
        f"- Contract: {summary.get('tsi_plugin', {}).get('match_contract', 'n/a')}",
        f"- Findings contract: {summary.get('tsi_plugin', {}).get('findings_contract', 'n/a')}",
        f"- Plugin dir: {summary.get('tsi_plugin', {}).get('plugin_dir', 'n/a')}",
        f"- Result JSON: {summary.get('tsi_plugin', {}).get('result_path', 'n/a')}",
        f"- Output log: {summary.get('tsi_plugin', {}).get('log_path', 'n/a')}",
        f"- Findings JSON: {summary.get('tsi_plugin', {}).get('findings_path', 'n/a')}",
        f"- Findings count: {summary.get('tsi_plugin', {}).get('findings_count', 0)}",
        "",
        "",
        f"- Generated: {summary['generated_at']}",
        f"- Repo: {summary.get('repo_url') or 'n/a'}",
        f"- Branch: {summary.get('branch') or 'main'}",
        f"- Report: {summary.get('report_json_path')}",
        f"- Grade: {summary['grade_score_10']}/10",
        f"- Gate: {'PASS' if summary['gate']['pass'] else 'FAIL'}",
        "",
        "## Status Counts",
        "",
    ]

    for key, value in summary.get("counts_by_status", {}).items():
        lines.append(f"- {key}: {value}")

    lines += [
        "",
        "## Gate Details",
        "",
        f"- confirmed_true: {summary['gate']['actual']['confirmed_true']} (limit {summary['gate']['limits']['max_confirmed_true']})",
        f"- needs_manual_review CRITICAL: {summary['gate']['actual']['needs_manual_review_critical']} (limit {summary['gate']['limits']['max_critical_manual']})",
        f"- needs_manual_review HIGH: {summary['gate']['actual']['needs_manual_review_high']} (limit {summary['gate']['limits']['max_high_manual']})",
        "",
        "## Top Priority Items",
        "",
    ]

    queue = summary.get("top_review_queue", [])
    if not queue:
        lines.append("No queued items.")
    else:
        for index, item in enumerate(queue[:20], 1):
            lines.append(
                f"{index}. {item.get('id')} | {item.get('severity')} | {item.get('file')}:{item.get('line_number')} | {item.get('disposition')}"
            )
            lines.append(f"   - {item.get('title')}")
            lines.append(f"   - reason: {item.get('reason')}")

    lines += [
        "",
        "## Forge Findings",
        "",
    ]

    if not forge_findings:
        lines.append("No structured Forge findings emitted.")
    else:
        for index, item in enumerate(forge_findings, 1):
            lines.append(
                f"{index}. {item.get('id')} | {item.get('severity')} | {item.get('adapter_name')} | {item.get('status')}"
            )
            lines.append(f"   - {item.get('title')}")
            lines.append(f"   - reason: {item.get('reason')}")

    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="No-touch intelligent E2E scan flow")
    parser.add_argument("--url", help="Repository URL to scan")
    parser.add_argument("--branch", default="main", help="Git branch to scan")
    parser.add_argument("--input-scan", help="Use existing scan JSON instead of rescanning")
    parser.add_argument("--outdir", default="speed_tests/automation", help="Output directory")
    parser.add_argument("--max-confirmed-true", type=int, default=0, help="Gate limit for confirmed true findings")
    parser.add_argument(
        "--max-critical-manual",
        type=int,
        default=0,
        help="Gate limit for CRITICAL findings still in needs_manual_review",
    )
    parser.add_argument(
        "--max-high-manual",
        type=int,
        default=3,
        help="Gate limit for HIGH findings still in needs_manual_review",
    )
    parser.add_argument(
        "--tsi-plugin-dir",
        default="forge",
        help="Path to Foundry TSI plugin harness",
    )
    parser.add_argument("--tsi-fork-url", help="Optional RPC URL for forked TSI execution")
    parser.add_argument(
        "--tsi-match-contract",
        default="TSI_Aave_FlashLoan_Oracle",
        help="Foundry --match-contract target for TSI plugin",
    )
    parser.add_argument(
        "--tsi-findings-contract",
        default=None,
        help=(
            "Contract to emit structured findings JSON. "
            "Defaults to --tsi-match-contract; set TSI_Findings_Report for legacy adapter output."
        ),
    )
    parser.add_argument(
        "--tsi-findings-artifact",
        default="artifacts/tsi_adapter_findings.json",
        help="Relative path (inside plugin dir) to structured findings JSON artifact",
    )
    parser.add_argument(
        "--tsi-enforce-pass",
        action="store_true",
        help="Fail the pipeline when the TSI plugin status is not pass",
    )
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parents[1]
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    input_scan = Path(args.input_scan) if args.input_scan else None
    workspace_dir = None
    if input_scan is not None:
        sibling_workspace = input_scan.parent / "workspace"
        if sibling_workspace.exists() and sibling_workspace.is_dir():
            workspace_dir = sibling_workspace

    _run_full_e2e_report(
        root_dir=root_dir,
        outdir=outdir,
        url=args.url,
        branch=args.branch,
        input_scan=input_scan,
        workspace_dir=workspace_dir,
        no_forge_plugin=True,
    )

    report_json_path = outdir / "full_e2e_report.json"
    report_data = json.loads(report_json_path.read_text(encoding="utf-8"))

    all_findings = list(report_data.get("all_deduped_findings", []) or [])

    tsi_plugin = run_tsi_plugin(
        root_dir=root_dir,
        outdir=outdir,
        plugin_dir=Path(args.tsi_plugin_dir),
        fork_url=args.tsi_fork_url,
        match_contract=args.tsi_match_contract,
        findings_contract=args.tsi_findings_contract,
        findings_artifact=args.tsi_findings_artifact,
    )

    forge_findings = list(tsi_plugin.get("normalized_findings") or [])
    merged_findings = [
        {**finding, "source": finding.get("source", "repo_scanner")}
        for finding in all_findings
    ] + forge_findings
    merged_findings_path = outdir / "native_merged_findings.json"
    merged_findings_path.write_text(json.dumps(merged_findings, indent=2), encoding="utf-8")

    score, score_counts = _score_findings(merged_findings)
    gate = _build_gate_result(
        merged_findings,
        max_confirmed_true=args.max_confirmed_true,
        max_critical_manual=args.max_critical_manual,
        max_high_manual=args.max_high_manual,
    )

    tsi_check = (not args.tsi_enforce_pass) or tsi_plugin.get("status") == "pass"
    gate["checks"]["tsi_plugin_within_policy"] = tsi_check
    gate["actual"]["tsi_plugin_status"] = tsi_plugin.get("status")
    gate["limits"]["tsi_plugin_policy"] = "must_pass" if args.tsi_enforce_pass else "informational"
    gate["pass"] = gate["pass"] and tsi_check

    counts_by_status = _build_counts_by_status(merged_findings)
    top_review_queue = _build_top_review_queue(merged_findings)

    summary = {
        "generated_at": _utc_now(),
        "repo_url": report_data.get("scan", {}).get("repo", {}).get("url"),
        "branch": args.branch,
        "outdir": str(outdir),
        "report_json_path": str(report_json_path),
        "report_md_path": str(outdir / "full_e2e_report.md"),
        "grade_score_10": score,
        "score_components": score_counts,
        "counts_by_status": counts_by_status,
        "gate": gate,
        "tsi_plugin": tsi_plugin,
        "forge_findings": forge_findings,
        "native_merged_findings_path": str(merged_findings_path),
        "top_review_queue": top_review_queue,
    }

    machine_summary_path = outdir / "intelligent_flow_summary.json"
    markdown_summary_path = outdir / "intelligent_flow_summary.md"
    machine_summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    markdown_summary_path.write_text(_render_markdown(summary), encoding="utf-8")

    print(
        json.dumps(
            {
                "status": "pass" if gate["pass"] else "fail",
                "grade_score_10": score,
                "summary_json": str(machine_summary_path),
                "summary_md": str(markdown_summary_path),
                "report_json": str(report_json_path),
                "report_md": str(outdir / "full_e2e_report.md"),
            }
        )
    )

    if not gate["pass"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
