#!/usr/bin/env python3
"""Run benchmark corpus and report precision/recall/false-positive drift."""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from repo_scanner import RepoScanner


def _case_expected(case: dict) -> set[str]:
    return set(case.get("expected_findings") or case.get("must_find") or [])


def _case_allowed(case: dict) -> set[str]:
    return set(case.get("allowed_findings") or case.get("known_limitations") or [])


def _case_kind(case: dict) -> str:
    explicit = str(case.get("classification") or case.get("kind") or "").lower()
    if explicit in {"safe", "known_safe", "false_positive"}:
        return "safe"
    if explicit in {"vulnerable", "positive", "must_find"}:
        return "vulnerable"
    return "vulnerable" if _case_expected(case) else "safe"


def _normalize_path(value: str) -> str:
    return str(value or "").replace("\\", "/").lstrip("./")


def _finding_detail(finding: dict) -> dict:
    return {
        "id": finding.get("id"),
        "severity": finding.get("severity"),
        "category": finding.get("category"),
        "title": finding.get("title"),
        "file": _normalize_path(finding.get("file") or finding.get("location") or ""),
        "line_number": finding.get("line_number"),
        "function_name": finding.get("function_name"),
        "code_snippet": finding.get("code_snippet"),
    }


def load_manifest(corpus_dir: Path) -> dict:
    manifest_path = corpus_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def compute_metrics(scan_result: dict, manifest: dict) -> dict:
    findings = scan_result.get("findings", []) or []
    findings_by_file = {}
    details_by_file = {}
    for finding in findings:
        rel_path = _normalize_path(finding.get("file", ""))
        file_name = Path(rel_path).name
        finding_id = finding.get("id")
        if not finding_id:
            continue
        for key in {rel_path, file_name}:
            findings_by_file.setdefault(key, set()).add(finding_id)
            details_by_file.setdefault(key, []).append(finding)

    cases = manifest.get("cases", [])
    tracked_ids = set()
    for case in cases:
        tracked_ids.update(_case_expected(case))
        tracked_ids.update(_case_allowed(case))

    tp = 0
    fp = 0
    fn = 0
    safe_cases = 0
    safe_cases_with_unexpected_findings = 0
    allowed_limitations = 0
    unexpected_safe_findings = 0
    fp_by_category = {}
    fp_by_id = {}
    per_case = []

    for case in cases:
        case_file = _normalize_path(case["file"])
        file_name = Path(case_file).name
        expected = _case_expected(case)
        allowed = _case_allowed(case)
        predicted = findings_by_file.get(case_file, findings_by_file.get(file_name, set()))
        predicted_details = details_by_file.get(case_file, details_by_file.get(file_name, []))
        predicted_tracked = predicted & tracked_ids if tracked_ids else predicted
        kind = _case_kind(case)
        allowed_details = [finding for finding in predicted_details if finding.get("id") in allowed]

        if kind == "safe":
            safe_cases += 1
            allowed_hits = predicted & allowed
            unexpected = predicted - allowed
            unexpected_details = [finding for finding in predicted_details if finding.get("id") in unexpected]
            case_tp = 0
            case_fp = len(unexpected_details) if unexpected_details else len(unexpected)
            case_fn = 0
            allowed_limitations += len(allowed_details) if allowed_details else len(allowed_hits)
            unexpected_safe_findings += case_fp
            if unexpected:
                safe_cases_with_unexpected_findings += 1
                for finding in unexpected_details:
                    finding_id = finding.get("id")
                    category = str(finding.get("category") or "UNKNOWN")
                    fp_by_category[category] = fp_by_category.get(category, 0) + 1
                    fp_by_id[finding_id] = fp_by_id.get(finding_id, 0) + 1
        else:
            unexpected = predicted_tracked - expected - allowed
            unexpected_details = [finding for finding in predicted_details if finding.get("id") in unexpected]
            case_tp = len(predicted_tracked & expected)
            case_fp = len(unexpected_details) if unexpected_details else len(unexpected)
            case_fn = len(expected - predicted_tracked)

        tp += case_tp
        fp += case_fp
        fn += case_fn

        per_case.append({
            "file": case_file,
            "classification": kind,
            "expected": sorted(expected),
            "allowed_findings": sorted(allowed),
            "predicted": sorted(predicted),
            "predicted_tracked": sorted(predicted_tracked),
            "tp": case_tp,
            "fp": case_fp,
            "fn": case_fn,
            "unexpected_findings": sorted(unexpected),
            "unexpected_finding_details": [_finding_detail(finding) for finding in unexpected_details],
            "allowed_finding_details": [_finding_detail(finding) for finding in allowed_details],
            "notes": case.get("notes", ""),
            "provenance": case.get("provenance", ""),
        })

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0

    safe_case_fp_rate = safe_cases_with_unexpected_findings / safe_cases if safe_cases else 0.0

    return {
        "summary": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "safe_cases": safe_cases,
            "safe_cases_with_unexpected_findings": safe_cases_with_unexpected_findings,
            "safe_case_false_positive_rate": round(safe_case_fp_rate, 4),
            "unexpected_safe_findings": unexpected_safe_findings,
            "allowed_limitations": allowed_limitations,
            "false_positives_by_category": dict(sorted(fp_by_category.items())),
            "false_positives_by_id": dict(sorted(fp_by_id.items())),
            "tracked_ids": sorted(tracked_ids),
        },
        "cases": per_case,
    }


def main():
    parser = argparse.ArgumentParser(description="Run scanner benchmark corpus")
    parser.add_argument("--corpus", default="tests/benchmark_corpus", help="Path to benchmark corpus directory")
    parser.add_argument("--output", default="benchmarks/results/latest.json", help="Output report path")
    parser.add_argument("--min-precision", type=float, default=0.8, help="Minimum required precision")
    parser.add_argument("--min-recall", type=float, default=0.8, help="Minimum required recall")
    parser.add_argument("--max-safe-fp-rate", type=float, default=0.0, help="Maximum allowed safe-case FP rate")
    parser.add_argument("--with-forge-plugin", action="store_true", help="Include Phase 7 Forge runtime adapter findings")
    args = parser.parse_args()

    corpus_dir = Path(args.corpus).resolve()
    manifest = load_manifest(corpus_dir)

    scanner = RepoScanner(workspace_dir=str(corpus_dir / ".workspace"))
    result = scanner.scan_local(str(corpus_dir), run_forge_plugin=args.with_forge_plugin)
    result_dict = result.to_dict()

    metrics = compute_metrics(result_dict, manifest)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "corpus": str(corpus_dir),
        "scan_status": result_dict.get("status"),
        "scanner_summary": result_dict.get("summary", {}),
        "metrics": metrics,
        "thresholds": {
            "min_precision": args.min_precision,
            "min_recall": args.min_recall,
            "max_safe_fp_rate": args.max_safe_fp_rate,
        },
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    precision = metrics["summary"]["precision"]
    recall = metrics["summary"]["recall"]
    safe_fp_rate = metrics["summary"]["safe_case_false_positive_rate"]

    print(f"Benchmark precision={precision:.4f} recall={recall:.4f} safe_fp_rate={safe_fp_rate:.4f}")
    print(f"Report written to {output_path}")

    if precision < args.min_precision or recall < args.min_recall or safe_fp_rate > args.max_safe_fp_rate:
        raise SystemExit(
            f"Benchmark below threshold (precision={precision:.4f}, recall={recall:.4f}, safe_fp_rate={safe_fp_rate:.4f})"
        )


if __name__ == "__main__":
    main()
