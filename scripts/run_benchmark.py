#!/usr/bin/env python3
"""Run benchmark corpus and report precision/recall for scanner drift tracking."""

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


def load_manifest(corpus_dir: Path) -> dict:
    manifest_path = corpus_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def compute_metrics(scan_result: dict, manifest: dict) -> dict:
    findings = scan_result.get("findings", []) or []
    findings_by_file = {}
    for finding in findings:
        file_name = Path(finding.get("file", "")).name
        findings_by_file.setdefault(file_name, set()).add(finding.get("id"))

    cases = manifest.get("cases", [])
    tracked_ids = set()
    for case in cases:
        tracked_ids.update(case.get("must_find", []))

    tp = 0
    fp = 0
    fn = 0
    per_case = []

    for case in cases:
        file_name = case["file"]
        expected = set(case.get("must_find", []))
        predicted = findings_by_file.get(file_name, set())
        predicted_tracked = predicted & tracked_ids if tracked_ids else set()

        case_tp = len(predicted_tracked & expected)
        case_fp = len(predicted_tracked - expected)
        case_fn = len(expected - predicted_tracked)

        tp += case_tp
        fp += case_fp
        fn += case_fn

        per_case.append({
            "file": file_name,
            "expected": sorted(expected),
            "predicted": sorted(predicted),
            "predicted_tracked": sorted(predicted_tracked),
            "tp": case_tp,
            "fp": case_fp,
            "fn": case_fn,
        })

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0

    return {
        "summary": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
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
    args = parser.parse_args()

    corpus_dir = Path(args.corpus).resolve()
    manifest = load_manifest(corpus_dir)

    scanner = RepoScanner(workspace_dir=str(corpus_dir / ".workspace"))
    result = scanner.scan_local(str(corpus_dir))
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
        },
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    precision = metrics["summary"]["precision"]
    recall = metrics["summary"]["recall"]

    print(f"Benchmark precision={precision:.4f} recall={recall:.4f}")
    print(f"Report written to {output_path}")

    if precision < args.min_precision or recall < args.min_recall:
        raise SystemExit(
            f"Benchmark below threshold (precision={precision:.4f}, recall={recall:.4f})"
        )


if __name__ == "__main__":
    main()
