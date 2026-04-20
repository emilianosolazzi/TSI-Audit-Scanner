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
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _run_full_e2e_report(
    root_dir: Path,
    outdir: Path,
    url: str | None,
    branch: str,
    input_scan: Path | None,
    workspace_dir: Path | None,
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


def _render_markdown(summary: Dict[str, Any]) -> str:
    lines = [
        "# Intelligent E2E Flow Summary",
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
    )

    report_json_path = outdir / "full_e2e_report.json"
    report_data = json.loads(report_json_path.read_text(encoding="utf-8"))

    all_findings = list(report_data.get("all_deduped_findings", []) or [])
    score, score_counts = _score_findings(all_findings)
    gate = _build_gate_result(
        all_findings,
        max_confirmed_true=args.max_confirmed_true,
        max_critical_manual=args.max_critical_manual,
        max_high_manual=args.max_high_manual,
    )

    summary = {
        "generated_at": _utc_now(),
        "repo_url": report_data.get("scan", {}).get("repo", {}).get("url"),
        "branch": args.branch,
        "outdir": str(outdir),
        "report_json_path": str(report_json_path),
        "report_md_path": str(outdir / "full_e2e_report.md"),
        "grade_score_10": score,
        "score_components": score_counts,
        "counts_by_status": report_data.get("summary", {}).get("counts_by_status", {}),
        "gate": gate,
        "top_review_queue": report_data.get("top_review_queue", []),
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
