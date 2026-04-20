#!/usr/bin/env python3
"""Run the Foundry TSI plugin and emit machine-readable results."""

from __future__ import annotations

import json
import shutil
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

_SUMMARY_RE = re.compile(r"(?P<passed>\d+) passed; (?P<failed>\d+) failed; (?P<skipped>\d+) skipped")
_FINDINGS_REPORT_CONTRACT = "TSI_Findings_Report"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_counts(output: str) -> Optional[Dict[str, int]]:
    matches = list(_SUMMARY_RE.finditer(output))
    if not matches:
        return None
    last = matches[-1]
    return {
        "passed": int(last.group("passed")),
        "failed": int(last.group("failed")),
        "skipped": int(last.group("skipped")),
    }


def _run_forge_command(cmd: list[str], cwd: Path) -> tuple[subprocess.CompletedProcess[str], str, Optional[Dict[str, int]]]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        check=False,
        capture_output=True,
        text=True,
    )
    combined_output = (proc.stdout or "") + ("\n" if proc.stderr else "") + (proc.stderr or "")
    return proc, combined_output, _parse_counts(combined_output)


def _normalize_forge_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    status = (finding.get("status") or "").lower()
    contradiction = bool(finding.get("contradiction"))

    if contradiction:
        disposition = "confirmed_true"
    elif status in {"skipped", "clean"}:
        disposition = "accepted_risk_or_info"
    else:
        disposition = "candidate"

    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence_score"),
        "disposition": disposition,
        "reason": finding.get("rationale"),
        "source": "forge_plugin",
        "adapter_name": finding.get("adapter_name"),
        "file": finding.get("adapter_path"),
        "line_number": 0,
        "finding_kind": finding.get("finding_kind"),
        "status": finding.get("status"),
        "magnitude": finding.get("magnitude"),
        "relative_deviation_bps": finding.get("relative_deviation_bps"),
        "fork_required": finding.get("fork_required"),
        "validation_tier": "forge_runtime",
    }


def run_tsi_plugin(
    root_dir: Path,
    outdir: Path,
    plugin_dir: Path,
    fork_url: str | None,
    match_contract: str,
) -> Dict[str, Any]:
    outdir.mkdir(parents=True, exist_ok=True)
    resolved_plugin_dir = plugin_dir if plugin_dir.is_absolute() else (root_dir / plugin_dir)

    result: Dict[str, Any] = {
        "generated_at": _utc_now(),
        "plugin_type": "foundry-tsi",
        "integration_mode": "main_pipeline_plugin",
        "plugin_dir": str(resolved_plugin_dir),
        "status": "not_run",
        "match_contract": match_contract,
    }

    if not resolved_plugin_dir.exists():
        result.update(
            {
                "status": "missing_plugin_dir",
                "error": f"Plugin directory does not exist: {resolved_plugin_dir}",
            }
        )
    else:
        cmd = ["forge", "test", "--match-contract", match_contract, "-vv"]
        if fork_url:
            cmd.extend(["--fork-url", fork_url])
        findings_artifact_path = resolved_plugin_dir / "artifacts" / "tsi_adapter_findings.json"
        if findings_artifact_path.exists():
            findings_artifact_path.unlink()

        try:
            proc, combined_output, counts = _run_forge_command(cmd, resolved_plugin_dir)

            result.update(
                {
                    "command": cmd,
                    "return_code": proc.returncode,
                    "has_fork_url": bool(fork_url),
                    "counts": counts,
                }
            )

            if proc.returncode == 0:
                if counts and counts["passed"] == 0 and counts["failed"] == 0 and counts["skipped"] > 0:
                    result["status"] = "skipped"
                else:
                    result["status"] = "pass"
            else:
                lowered = combined_output.lower()
                if "could not instantiate forked environment" in lowered:
                    result["status"] = "fork_error"
                else:
                    result["status"] = "failed"

            findings_cmd = ["forge", "test", "--match-contract", _FINDINGS_REPORT_CONTRACT, "-vv"]
            findings_proc, findings_output, findings_counts = _run_forge_command(findings_cmd, resolved_plugin_dir)
            result["findings_report"] = {
                "command": findings_cmd,
                "return_code": findings_proc.returncode,
                "counts": findings_counts,
            }

            findings_log_path = outdir / "tsi_findings_report_output.log"
            findings_log_path.write_text(findings_output, encoding="utf-8", errors="replace")
            result["findings_report"]["log_path"] = str(findings_log_path)

            if findings_proc.returncode != 0:
                result["status"] = "failed"
                result["findings_status"] = "failed"
            elif findings_artifact_path.exists():
                copied_findings_path = outdir / "tsi_adapter_findings.json"
                shutil.copyfile(findings_artifact_path, copied_findings_path)
                findings_payload = json.loads(copied_findings_path.read_text(encoding="utf-8"))
                findings = list(findings_payload.get("findings") or [])
                result["findings_status"] = "pass"
                result["findings_path"] = str(copied_findings_path)
                result["findings_count"] = len(findings)
                result["findings"] = findings
                result["normalized_findings"] = [_normalize_forge_finding(finding) for finding in findings]
            else:
                result["findings_status"] = "missing"

            log_path = outdir / "tsi_plugin_test_output.log"
            log_path.write_text(combined_output, encoding="utf-8", errors="replace")
            result["log_path"] = str(log_path)
        except FileNotFoundError:
            result.update(
                {
                    "status": "tool_missing",
                    "error": "forge not found on PATH",
                }
            )
        except Exception as exc:  # defensive catch to keep pipeline alive
            result.update(
                {
                    "status": "error",
                    "error": str(exc),
                }
            )

    result_path = outdir / "tsi_plugin_result.json"
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    result["result_path"] = str(result_path)
    return result
