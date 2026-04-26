#!/usr/bin/env python3
"""Run or post-process full repo scan into an automated decision report.

Pipeline:
1. Scan repo (or load existing scan JSON)
2. Normalize findings and dedupe repeated pattern hits
3. Apply verification + validation-aware auto disposition
4. Emit JSON + Markdown final report
"""

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from repo_scanner import RepoScanner  # noqa: E402
from exploit_verifier import verify_all_findings  # noqa: E402


@dataclass
class Disposition:
    status: str
    reason: str


def _load_scan(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _dedupe_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    validation = finding.get("validation") or {}
    function_name = validation.get("function") or ""
    file_name = finding.get("file") or ""
    finding_id = finding.get("id") or "UNKNOWN"
    return finding_id, file_name, function_name


def _dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    best: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    severity_rank = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
        "GAS": 0,
    }

    for f in findings:
        k = _dedupe_key(f)
        curr = best.get(k)
        if curr is None:
            best[k] = f
            continue

        curr_score = (
            severity_rank.get(curr.get("severity", "INFO"), 0),
            float(curr.get("confidence", 0.0)),
        )
        new_score = (
            severity_rank.get(f.get("severity", "INFO"), 0),
            float(f.get("confidence", 0.0)),
        )
        if new_score > curr_score:
            best[k] = f

    return list(best.values())


def _verification_key_from_finding(finding: Dict[str, Any]) -> Tuple[str, str, int]:
    fid = finding.get("id") or ""
    file_name = finding.get("file") or ""
    line_number = int(finding.get("line_number") or 0)
    return fid, file_name, line_number


def _verification_key_from_verification(verification: Dict[str, Any]) -> Tuple[str, str, int]:
    fid = verification.get("finding_id") or ""
    file_name = verification.get("file") or ""
    line_number = int(verification.get("line_number") or 0)
    return fid, file_name, line_number


def _build_verification_index(scan_data: Dict[str, Any]) -> Dict[Tuple[str, str, int], Dict[str, Any]]:
    idx: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
    for v in scan_data.get("exploit_verifications", []) or []:
        key = _verification_key_from_verification(v)
        if key[0] and key not in idx:
            idx[key] = v
    return idx


def _load_file_sources_for_findings(
    outdir: Path,
    findings: List[Dict[str, Any]],
    workspace_dir_override: Optional[Path] = None,
) -> Dict[str, str]:
    workspace_dir = workspace_dir_override or (outdir / "workspace")
    if not workspace_dir.exists():
        return {}

    clone_candidates = [p for p in workspace_dir.iterdir() if p.is_dir()]
    if not clone_candidates:
        return {}

    clone_root = sorted(clone_candidates, key=lambda p: p.stat().st_mtime, reverse=True)[0]
    file_sources: Dict[str, str] = {}

    for f in findings:
        original_rel = f.get("file") or ""
        rel = original_rel.replace("\\", "/")
        if not rel or original_rel in file_sources:
            continue
        abs_path = clone_root / rel
        if abs_path.exists() and abs_path.is_file():
            source = abs_path.read_text(encoding="utf-8", errors="replace")
            # Keep original key shape expected by findings (backslashes on Windows)
            file_sources[original_rel] = source
            # Also store normalized key for cross-platform callers
            file_sources[rel] = source

    return file_sources


def _auto_disposition(finding: Dict[str, Any], verification: Optional[Dict[str, Any]]) -> Disposition:
    fid = finding.get("id", "UNKNOWN")
    sev = finding.get("severity", "INFO")
    validation = finding.get("validation") or {}
    tier = validation.get("tier", "needs_context")
    snippet = (finding.get("code_snippet") or "").lower()

    if verification:
        if verification.get("exploitable") is True:
            return Disposition("confirmed_true", "semantic verifier marked exploitable")
        if verification.get("exploit_class") == "disproven":
            return Disposition("probable_false_positive", "semantic verifier disproven")

    if fid == "ACCESS-002":
        return Disposition("accepted_risk_or_info", "governance centralization informational")

    if fid == "PAUSE-001" and "modifier only" in snippet:
        return Disposition("probable_false_positive", "pattern hit in modifier declaration context")

    if tier == "likely_noise":
        return Disposition("probable_false_positive", "validator marked likely_noise")

    if tier == "confirm_first" and sev in ("CRITICAL", "HIGH", "MEDIUM"):
        return Disposition("high_priority_candidate", "validator marked confirm_first")

    if tier == "confirm_first":
        return Disposition("candidate", "validator marked confirm_first")

    return Disposition("needs_manual_review", "requires protocol-specific context")


def _build_summary(dispositions: List[Disposition], total: int) -> Dict[str, Any]:
    counts = Counter(d.status for d in dispositions)
    probable_fp = counts.get("probable_false_positive", 0)
    needs_manual = counts.get("needs_manual_review", 0)

    return {
        "total_deduped_findings": total,
        "counts_by_status": dict(counts),
        "estimated_false_positive_floor_percent": round((probable_fp / total) * 100, 2) if total else 0.0,
        "estimated_false_positive_ceiling_percent": round(((probable_fp + needs_manual) / total) * 100, 2) if total else 0.0,
        "is_99_9_false_positive": bool(total and probable_fp / total >= 0.999),
    }


def _render_markdown(report: Dict[str, Any]) -> str:
    scan = report["scan"]
    summary = report["summary"]
    top = report["top_review_queue"]

    lines = [
        "# Full E2E Scan Report",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Repo: {scan.get('repo', {}).get('url', 'n/a')}",
        f"- Commit: {scan.get('repo', {}).get('commit', 'n/a')}",
        f"- Scan status: {scan.get('status', 'unknown')}",
        f"- Duration (s): {scan.get('duration_seconds', 0)}",
        f"- Raw findings: {scan.get('findings_count', 0)}",
        f"- Deduped findings: {summary.get('total_deduped_findings', 0)}",
        "",
        "## Auto Disposition Summary",
        "",
    ]

    for key, val in summary.get("counts_by_status", {}).items():
        lines.append(f"- {key}: {val}")

    lines += [
        "",
        f"- Estimated false-positive floor: {summary.get('estimated_false_positive_floor_percent', 0)}%",
        f"- Estimated false-positive ceiling: {summary.get('estimated_false_positive_ceiling_percent', 0)}%",
        f"- 99.9% false positive? {'yes' if summary.get('is_99_9_false_positive') else 'no'}",
        "",
        "## High-Priority Review Queue",
        "",
    ]

    if not top:
        lines.append("No high-priority candidates after auto disposition.")
    else:
        for i, item in enumerate(top, 1):
            lines.append(
                f"{i}. {item.get('id')} | {item.get('severity')} | {item.get('file')}:{item.get('line_number')} | {item.get('disposition')}"
            )
            lines.append(f"   - {item.get('title')}")
            lines.append(f"   - reason: {item.get('reason')}")

    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Automated full E2E scan reporting")
    parser.add_argument("--url", help="Repository URL to scan")
    parser.add_argument("--input-scan", help="Existing scan JSON path to post-process")
    parser.add_argument("--outdir", default="speed_tests/scroll_usx", help="Output directory")
    parser.add_argument("--branch", default="main", help="Git branch")
    parser.add_argument("--workspace-dir", help="Optional existing workspace directory for source loading")
    parser.add_argument(
        "--no-forge-plugin",
        action="store_true",
        help="Skip RepoScanner Phase 7 Forge plugin during base scan",
    )
    parser.add_argument(
        "--forge-plugin-dir",
        default=None,
        help="Override path to the Foundry TSI plugin harness when Phase 7 is enabled",
    )
    parser.add_argument(
        "--forge-match-contract",
        default="TSI_Findings_Report",
        help="Forge --match-contract for RepoScanner Phase 7 when enabled",
    )
    parser.add_argument(
        "--forge-fork-url",
        default=None,
        help="Optional fork RPC URL for RepoScanner Phase 7 when enabled",
    )
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    if args.input_scan:
        scan_data = _load_scan(Path(args.input_scan))
    else:
        if not args.url:
            raise SystemExit("Either --url or --input-scan must be provided")
        scanner = RepoScanner(workspace_dir=str(outdir / "workspace"))
        result = scanner.scan_repo(
            args.url,
            branch=args.branch,
            run_forge_plugin=not args.no_forge_plugin,
            forge_plugin_dir=args.forge_plugin_dir,
            forge_match_contract=args.forge_match_contract,
            forge_fork_url=args.forge_fork_url,
        )
        scan_data = result.to_dict()
        (outdir / "scan_result_full.json").write_text(json.dumps(scan_data, indent=2), encoding="utf-8")

    findings = list(scan_data.get("findings", []) or [])
    deduped = _dedupe_findings(findings)
    verification_idx = _build_verification_index(scan_data)

    workspace_dir = Path(args.workspace_dir) if args.workspace_dir else None
    file_sources = _load_file_sources_for_findings(outdir, deduped, workspace_dir_override=workspace_dir)
    if file_sources:
        semantic_results = verify_all_findings(deduped, file_sources)
        for v in semantic_results:
            vd = v.to_dict()
            key = _verification_key_from_verification(vd)
            if key[0]:
                # Fresh per-finding semantic verification is authoritative.
                verification_idx[key] = vd

    enriched: List[Dict[str, Any]] = []
    dispositions: List[Disposition] = []

    for f in deduped:
        verification = verification_idx.get(_verification_key_from_finding(f))
        disp = _auto_disposition(f, verification)
        dispositions.append(disp)

        row = {
            "id": f.get("id"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "file": f.get("file"),
            "line_number": f.get("line_number"),
            "disposition": disp.status,
            "reason": disp.reason,
            "validation_tier": (f.get("validation") or {}).get("tier"),
        }
        if verification:
            row["verification"] = {
                "exploit_class": verification.get("exploit_class"),
                "exploitable": verification.get("exploitable"),
                "confidence": verification.get("confidence"),
                "attack_vector": verification.get("attack_vector"),
            }
        enriched.append(row)

    summary = _build_summary(dispositions, len(deduped))

    priority = [
        e for e in enriched
        if e["disposition"] in ("high_priority_candidate", "candidate", "needs_manual_review")
    ]

    sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "GAS": 0}
    priority.sort(key=lambda x: sev_rank.get(x.get("severity", "INFO"), 0), reverse=True)

    report = {
        "generated_at": _utc_now(),
        "scan": {
            "repo": scan_data.get("repo", {}),
            "status": scan_data.get("status"),
            "duration_seconds": scan_data.get("duration_seconds"),
            "files_scanned": scan_data.get("files_scanned"),
            "findings_count": scan_data.get("findings_count"),
            "triage": scan_data.get("triage", {}),
        },
        "summary": summary,
        "top_review_queue": priority[:50],
        "all_deduped_findings": enriched,
    }

    json_path = outdir / "full_e2e_report.json"
    md_path = outdir / "full_e2e_report.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")

    print(json.dumps({
        "report_json": str(json_path),
        "report_md": str(md_path),
        "deduped_findings": summary["total_deduped_findings"],
        "false_positive_floor_percent": summary["estimated_false_positive_floor_percent"],
        "false_positive_ceiling_percent": summary["estimated_false_positive_ceiling_percent"],
        "is_99_9_false_positive": summary["is_99_9_false_positive"],
    }))


if __name__ == "__main__":
    main()
