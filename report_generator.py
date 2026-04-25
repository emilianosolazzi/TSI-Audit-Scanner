#!/usr/bin/env python3
"""
Report Generator — Markdown, SARIF, HTML output for audit reports.
Generates professional audit reports in multiple formats for CI/CD integration.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional


_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "GAS", "INFO"]
_SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "GAS": "⚡",
    "INFO": "ℹ️",
}


def _sorted_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    order = {severity: index for index, severity in enumerate(_SEVERITY_ORDER)}
    return sorted(
        findings,
        key=lambda finding: (
            order.get(str(finding.get("severity", "INFO")).upper(), 99),
            -(finding.get("confidence") or 0.0),
            finding.get("line_number") or 10**9,
        ),
    )


def _verification_exploitable(finding: Dict[str, Any]) -> Optional[bool]:
    verification = finding.get("verification") or {}
    if "exploitable" not in verification:
        return None

    value = verification.get("exploitable")
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return None


def _is_actionable_finding(finding: Dict[str, Any]) -> bool:
    if _verification_exploitable(finding) is False:
        return False

    validation = finding.get("validation") or {}
    if str(validation.get("tier", "")).lower() == "likely_noise":
        return False

    severity_adjustment = str(
        finding.get("severity_adjustment")
        or (finding.get("verification") or {}).get("severity_adjustment")
        or ""
    ).lower()
    if severity_adjustment.startswith("downgrade") or severity_adjustment in {"false_positive", "likely_noise"}:
        return False

    return True


def _actionable_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [finding for finding in findings if _is_actionable_finding(finding)]


def _summary_from_findings(findings: List[Dict[str, Any]], fallback: Dict[str, Any]) -> Dict[str, int]:
    summary = {key: 0 for key in ["critical", "high", "medium", "low", "gas", "info"]}
    if not findings:
        summary["total_findings"] = 0
        return summary

    for finding in findings:
        severity = str(finding.get("severity", "INFO")).lower()
        if severity in summary:
            summary[severity] += 1
    summary["total_findings"] = len(findings)
    return summary


def _risk_from_summary(summary: Dict[str, Any], fallback: str) -> str:
    if summary.get("critical", 0) > 0:
        return "CRITICAL"
    if summary.get("high", 0) > 0:
        return "HIGH"
    if summary.get("medium", 0) > 0:
        return "MEDIUM"
    if summary.get("low", 0) > 0 or summary.get("gas", 0) > 0 or summary.get("info", 0) > 0:
        return "LOW"
    return "SAFE" if fallback in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} else fallback


def _deployment_recommendation(score: float, risk: str, summary: Dict[str, Any]) -> Dict[str, str]:
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)

    if critical > 0 or risk == "CRITICAL":
        return {
            "decision": "DO NOT DEPLOY",
            "rationale": "Critical findings remain. Shipping in the current state creates an unacceptable chance of direct loss or control failure.",
        }
    if high > 0 or risk == "HIGH":
        return {
            "decision": "DELAY DEPLOYMENT",
            "rationale": "High-severity findings remain. Mainnet launch should wait until the value-loss paths are closed and regression-tested.",
        }
    if medium > 0 or risk == "MEDIUM" or score < 80:
        return {
            "decision": "DEPLOY WITH CONDITIONS",
            "rationale": "No critical blocker is present, but medium-risk issues still warrant remediation, tighter limits, and post-deploy monitoring.",
        }
    if risk == "LOW" or score < 95:
        return {
            "decision": "DEPLOY",
            "rationale": "Only lower-severity issues remain. The contract is fit to deploy with standard monitoring and a backlog for non-blocking hardening.",
        }
    return {
        "decision": "DEPLOY",
        "rationale": "No material issues were detected by the current pipeline. Continue with normal release controls and monitoring.",
    }


def _risk_badge(risk: str) -> str:
    return {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🔵 LOW",
        "SAFE": "🟢 SAFE",
    }.get(risk, risk)


def _extract_keywords(text: str) -> set[str]:
    keywords = set()
    stopwords = {
        "after", "before", "from", "that", "this", "with", "without", "into", "under",
        "over", "contract", "state", "value", "check", "using", "missing", "potential",
        "manual", "review", "line", "return", "calls", "function", "pattern", "maybe",
    }
    for token in text.lower().replace("_", " ").replace("-", " ").split():
        token = "".join(ch for ch in token if ch.isalnum())
        if len(token) >= 5 and token not in stopwords:
            keywords.add(token)
    return keywords


def _finding_story(finding: Dict[str, Any]) -> str:
    verification = finding.get("verification") or {}
    if verification.get("explanation"):
        return verification["explanation"]

    severity = str(finding.get("severity", "INFO")).upper()
    title = finding.get("title", "Finding")
    description = finding.get("description", "")
    recommendation = finding.get("recommendation", "")

    if severity in {"CRITICAL", "HIGH"}:
        return (
            f"An attacker can likely turn {title.lower()} into a real exploit path. "
            f"The current evidence indicates: {description}. The first containment step is: {recommendation}."
        )
    if severity == "MEDIUM":
        return (
            f"This issue is not an immediate stop-ship exploit on its own, but it can distort expected protocol behavior: {description}. "
            f"If it sits next to other accounting or control bugs, the impact can compound."
        )
    return (
        f"This is a hardening or quality issue rather than a direct exploit path. Current signal: {description}."
    )


def _finding_business_impact(finding: Dict[str, Any]) -> str:
    text = " ".join(
        str(finding.get(key, "")) for key in ("title", "category", "description", "recommendation")
    ).lower()
    if any(term in text for term in ["reentr", "withdraw", "balance", "drain", "fund"]):
        return "Likely user-facing impact is direct fund loss, incorrect redemption, or broken balance accounting."
    if any(term in text for term in ["oracle", "price", "twap", "liquidat", "collateral"]):
        return "Likely user-facing impact is valuation drift, bad collateral decisions, or exploitable pricing windows."
    if any(term in text for term in ["owner", "admin", "role", "access", "auth"]):
        return "Likely user-facing impact is unauthorized control, privilege escalation, or bypass of an expected trust boundary."
    if any(term in text for term in ["signature", "nonce", "replay", "domain", "ecrecover"]):
        return "Likely user-facing impact is replayable authorization or forged approval flow."
    if any(term in text for term in ["gas", "deadline", "slippage", "dos"]):
        return "Likely user-facing impact is operational fragility: transactions revert under realistic market or mempool conditions."
    return "Impact is protocol-specific, but the issue creates a gap between expected and actual behavior that deserves explicit remediation."


def _render_code_section(lines: List[str], heading: str, code: Optional[str]) -> None:
    if not code:
        return
    lines.append(f"**{heading}:**")
    lines.append("")
    lines.append("```solidity")
    lines.append(code)
    lines.append("```")
    lines.append("")


def _render_bullets(lines: List[str], items: List[str]) -> None:
    for item in items:
        lines.append(f"- {item}")
    lines.append("")


def _cross_finding_couplings(findings: List[Dict[str, Any]]) -> List[str]:
    top_findings = _sorted_findings([f for f in _actionable_findings(findings) if str(f.get("severity", "INFO")).upper() in {"CRITICAL", "HIGH", "MEDIUM"}])
    couplings: List[str] = []
    seen_pairs = set()

    for index, left in enumerate(top_findings):
        left_tokens = _extract_keywords(f"{left.get('title', '')} {left.get('description', '')}")
        for right in top_findings[index + 1:]:
            pair_key = tuple(sorted([left.get("id", ""), right.get("id", "")]))
            if pair_key in seen_pairs:
                continue
            right_tokens = _extract_keywords(f"{right.get('title', '')} {right.get('description', '')}")
            overlap = sorted(left_tokens & right_tokens)
            if overlap:
                token_preview = ", ".join(overlap[:3])
                couplings.append(
                    f"`{left.get('id', '')}` + `{right.get('id', '')}` can amplify each other because they share the same failure surface ({token_preview}). Resolve them as a pair, not as isolated bugs."
                )
                seen_pairs.add(pair_key)
            elif any(term in f"{left.get('description', '')} {right.get('description', '')}".lower() for term in ["withdraw", "redeem", "valuation", "oracle", "balance"]):
                couplings.append(
                    f"`{left.get('id', '')}` + `{right.get('id', '')}` sit on adjacent accounting paths. A fix that addresses only one side can leave the user-visible loss path partially open."
                )
                seen_pairs.add(pair_key)

    return couplings[:3]


def _required_fixes(findings: List[Dict[str, Any]], severities: set[str], actionable_only: bool = True) -> List[Dict[str, Any]]:
    wanted = {severity.upper() for severity in severities}
    candidates = _actionable_findings(findings) if actionable_only else findings
    return [f for f in _sorted_findings(candidates) if str(f.get("severity", "INFO")).upper() in wanted]


def _bonus_hardening_items(report_dict: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[str]:
    explicit = report_dict.get("bonus_hardening") or report_dict.get("hardening_suggestions") or []
    if explicit:
        return [str(item) for item in explicit]

    optional = []
    for finding in _required_fixes(findings, {"LOW", "GAS", "INFO"})[:5]:
        optional.append(f"{finding.get('title', 'Hardening item')}: {finding.get('recommendation', '')}")
    return optional


def generate_markdown_report(report_dict: Dict[str, Any]) -> str:
    """Generate a professional Markdown audit report."""
    contract = report_dict.get("contract", {})
    scores = report_dict.get("scores", {})
    summary = report_dict.get("summary", {})
    analysis = report_dict.get("analysis", {})
    findings = report_dict.get("findings", [])
    
    address = contract.get("address", "Unknown")
    name = contract.get("name", "Unknown Contract")
    chain = contract.get("chain", "Unknown")
    score = scores.get("security_score", 0)
    risk = scores.get("risk_level", "UNKNOWN")
    risk_badge = _risk_badge(risk)
    findings = _sorted_findings(findings)
    actionable_summary = _summary_from_findings(_actionable_findings(findings), summary)
    actionable_risk = _risk_from_summary(actionable_summary, risk)
    deployment = _deployment_recommendation(score, actionable_risk, actionable_summary)
    
    lines = []
    lines.append(f"# Security Audit Report — {name}")
    lines.append("")
    lines.append(f"> Generated by **TSI-Audit-Scanner** on {report_dict.get('timestamp', datetime.now().isoformat())}")
    lines.append("")
    
    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| **Contract** | `{address}` |")
    lines.append(f"| **Chain** | {chain} |")
    lines.append(f"| **Name** | {name} |")
    lines.append(f"| **Verified** | {'Yes' if contract.get('verified') else 'No'} |")
    lines.append(f"| **Security Score** | **{score}/100** |")
    lines.append(f"| **Risk Level** | {risk_badge} |")
    lines.append(f"| **Total Findings** | {summary.get('total_findings', 0)} |")
    lines.append(f"| **Duration** | {report_dict.get('duration_ms', 0):.0f}ms |")
    lines.append("")

    if contract.get("proxy"):
        lines.append(f"| **Proxy** | Yes → `{contract.get('implementation', 'Unknown')}` |")
        lines.append("")

    lines.append(
        f"This run scored **{score}/100** with **{risk}** risk. "
        f"Recommended release posture: **{deployment['decision']}**. {deployment['rationale']}"
    )
    if actionable_summary.get("total_findings", 0) != summary.get("total_findings", 0):
        lines.append("")
        lines.append(
            f"Verifier triage marked **{summary.get('total_findings', 0) - actionable_summary.get('total_findings', 0)}** raw finding(s) as non-actionable for release planning. They remain listed below for audit traceability."
        )
    lines.append("")

    # Deployment recommendation
    lines.append("## Deployment Recommendation")
    lines.append("")
    lines.append(f"**Decision:** {deployment['decision']}")
    lines.append("")
    lines.append(deployment["rationale"])
    lines.append("")
    top_required = _required_fixes(findings, {"CRITICAL", "HIGH"})[:3]
    if top_required:
        lines.append("Release blockers from this run:")
        lines.append("")
        _render_bullets(
            lines,
            [
                f"`{finding.get('id', '')}` {finding.get('title', '')}: {finding.get('recommendation', '')}"
                for finding in top_required
            ],
        )
    
    # Findings Breakdown
    lines.append("## Findings Breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| 🔴 Critical | {summary.get('critical', 0)} |")
    lines.append(f"| 🟠 High | {summary.get('high', 0)} |")
    lines.append(f"| 🟡 Medium | {summary.get('medium', 0)} |")
    lines.append(f"| 🔵 Low | {summary.get('low', 0)} |")
    lines.append(f"| ⚡ Gas | {summary.get('gas', 0)} |")
    lines.append(f"| ℹ️ Info | {summary.get('info', 0)} |")
    lines.append("")
    
    # Analysis
    lines.append("## Contract Analysis")
    lines.append("")
    interfaces = analysis.get("interfaces", [])
    protocols = analysis.get("defi_protocols", [])
    funcs = analysis.get("functions", {})
    
    lines.append(f"- **Interfaces:** {', '.join(interfaces) if interfaces else 'None detected'}")
    lines.append(f"- **DeFi Protocols:** {', '.join(protocols) if protocols else 'None detected'}")
    lines.append(f"- **Access Control:** {analysis.get('access_control') or 'Unknown'}")
    lines.append(f"- **Functions:** {funcs.get('total', 0)} total, {funcs.get('external', 0)} external, {funcs.get('payable', 0)} payable, {funcs.get('admin', 0)} admin")
    lines.append("")

    # Cross-finding coupling analysis
    lines.append("## Cross-Finding Coupling")
    lines.append("")
    couplings = _cross_finding_couplings(findings)
    if couplings:
        _render_bullets(lines, couplings)
    else:
        lines.append("No strong cross-finding coupling was detected by the current heuristic pass. Findings still need manual review for protocol-specific interaction effects.")
        lines.append("")

    # Priority remediation roadmap
    lines.append("## Priority Remediation Roadmap")
    lines.append("")
    roadmap = [
        ("Fix before mainnet", _required_fixes(findings, {"CRITICAL", "HIGH"})),
        ("Fix in next release", _required_fixes(findings, {"MEDIUM"})),
        ("Backlog / optional hardening", _required_fixes(findings, {"LOW", "GAS", "INFO"})),
    ]
    for heading, bucket in roadmap:
        lines.append(f"### {heading}")
        lines.append("")
        if bucket:
            _render_bullets(
                lines,
                [
                    f"`{finding.get('id', '')}` {finding.get('title', '')}: {finding.get('recommendation', '')}"
                    for finding in bucket[:5]
                ],
            )
        else:
            lines.append("No items in this bucket.")
            lines.append("")

    # Bonus hardening suggestions
    lines.append("## Bonus Hardening Suggestions")
    lines.append("")
    hardening_items = _bonus_hardening_items(report_dict, findings)
    if hardening_items:
        _render_bullets(lines, hardening_items[:5])
    else:
        lines.append("No optional hardening suggestions were identified beyond the required fixes in this run.")
        lines.append("")
    
    # Detailed Findings
    if findings:
        lines.append("## Detailed Findings")
        lines.append("")

        for sev in _SEVERITY_ORDER:
            sev_findings = [f for f in findings if f.get("severity") == sev]
            if not sev_findings:
                continue

            sev_icon = _SEVERITY_ICON.get(sev, "")
            lines.append(f"### {sev_icon} {sev} ({len(sev_findings)})")
            lines.append("")

            for i, f in enumerate(sev_findings, 1):
                lines.append(f"#### {i}. {f.get('title', 'Unknown')}")
                lines.append("")
                lines.append(f"- **ID:** `{f.get('id', '')}`")
                lines.append(f"- **Category:** {f.get('category', '')}")
                if f.get("line_number"):
                    lines.append(f"- **Location:** Line {f['line_number']}")
                lines.append(f"- **Confidence:** {f.get('confidence', 1.0):.0%}")
                lines.append("")

                lines.append("**Exploit Story:**")
                lines.append("")
                lines.append(_finding_story(f))
                lines.append("")

                lines.append("**Why It Matters:**")
                lines.append("")
                lines.append(_finding_business_impact(f))
                lines.append("")

                lines.append(f"**Recommendation:** {f.get('recommendation', '')}")
                lines.append("")

                verification = f.get("verification") or {}
                if verification:
                    lines.append("**Verification Signal:**")
                    lines.append("")
                    lines.append(verification.get("explanation", "Semantic verification metadata attached."))
                    lines.append("")
                    if verification.get("conditions_met"):
                        lines.append("Conditions met:")
                        lines.append("")
                        _render_bullets(lines, [str(item) for item in verification["conditions_met"]])
                    if verification.get("conditions_failed"):
                        lines.append("Conditions failed:")
                        lines.append("")
                        _render_bullets(lines, [str(item) for item in verification["conditions_failed"]])
                    if verification.get("poc_hint"):
                        lines.append("**PoC Hint:**")
                        lines.append("")
                        lines.append("```solidity")
                        lines.append(str(verification["poc_hint"]))
                        lines.append("```")
                        lines.append("")

                _render_code_section(lines, "Code Context", f.get("code_snippet"))
                _render_code_section(lines, "Pre-fix Code", f.get("pre_fix_snippet"))
                _render_code_section(lines, "Post-fix Code", f.get("post_fix_snippet"))

                regression_tests = f.get("regression_tests") or []
                if regression_tests:
                    lines.append("**Regression Tests:**")
                    lines.append("")
                    _render_bullets(lines, [str(test_name) for test_name in regression_tests])

                if f.get("description"):
                    lines.append(f"**Raw Description:** {f.get('description', '')}")
                    lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No security issues detected. Contract appears safe.")
        lines.append("")
    
    # Footer
    lines.append("---")
    lines.append("")
    lines.append(f"*Report generated by TSI-Audit-Scanner v2.0 | {len(findings)} patterns checked | Protection-first detection engine*")
    
    return "\n".join(lines)


def generate_sarif_report(report_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate SARIF v2.1.0 output for CI/CD integration.
    Compatible with GitHub Code Scanning, Azure DevOps, and other SARIF consumers.
    """
    findings = report_dict.get("findings", [])
    contract = report_dict.get("contract", {})
    
    # Map severity to SARIF levels
    severity_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "GAS": "note",
        "INFO": "none",
    }
    
    rules = []
    results = []
    seen_rules = set()
    
    for finding in findings:
        rule_id = finding.get("id", "UNKNOWN")
        
        # Add rule definition (deduplicated)
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": finding.get("title", ""),
                "shortDescription": {"text": finding.get("title", "")},
                "fullDescription": {"text": finding.get("description", "")},
                "helpUri": f"https://swcregistry.io/docs/{rule_id}" if rule_id.startswith("SWC-") else None,
                "defaultConfiguration": {
                    "level": severity_map.get(finding.get("severity", ""), "warning")
                },
                "properties": {
                    "category": finding.get("category", ""),
                    "confidence": finding.get("confidence", 1.0),
                }
            })
        
        # Build result
        result = {
            "ruleId": rule_id,
            "level": severity_map.get(finding.get("severity", ""), "warning"),
            "message": {
                "text": f"{finding.get('description', '')}. Recommendation: {finding.get('recommendation', '')}"
            },
            "properties": {
                "confidence": finding.get("confidence", 1.0),
                "severity_weight": finding.get("severity_weight", 0),
            }
        }
        
        # Add location if line number is known
        if finding.get("line_number"):
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": contract.get("address", "unknown"),
                        "uriBaseId": contract.get("chain", "ethereum")
                    },
                    "region": {
                        "startLine": finding["line_number"]
                    }
                }
            }]
        
        results.append(result)
    
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TSI-Audit-Scanner",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/TSI-Audit-Scanner",
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": report_dict.get("timestamp", datetime.now().isoformat()),
            }]
        }]
    }
    
    return sarif


def save_report(report_dict: Dict[str, Any], output_path: str, fmt: str = "json"):
    """Save report in specified format."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    
    if fmt == "markdown" or fmt == "md":
        content = generate_markdown_report(report_dict)
        if not output_path.endswith(".md"):
            output_path += ".md"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
    elif fmt == "sarif":
        content = generate_sarif_report(report_dict)
        if not output_path.endswith(".sarif"):
            output_path += ".sarif"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(content, f, indent=2)
    else:  # json
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2)
    
    return output_path
