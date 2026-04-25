"""One-shot on-chain audit runner.

Usage:
    python scripts/run_onchain_audit.py <address> [chain] [--out path.json]

Loads ETHERSCAN_API_KEY from .env if not in the environment, runs the
AdvancedAuditor, prints a one-page summary, and writes the full report
JSON to scan_results/onchain_<chain>_<addr>.json (or --out).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _load_dotenv() -> None:
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        os.environ.setdefault(k, v)


def _to_dict(obj):
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return obj.to_dict()
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_dict(v) for v in obj]
    return obj


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("address")
    p.add_argument("chain", nargs="?", default="ethereum")
    p.add_argument("--out", default=None)
    p.add_argument("--full", action="store_true")
    args = p.parse_args()

    _load_dotenv()
    api_key = os.environ.get("ETHERSCAN_API_KEY")
    if not api_key:
        print("ERROR: ETHERSCAN_API_KEY not set (env or .env).", file=sys.stderr)
        return 2

    from advanced_auditor import AdvancedAuditor  # noqa: E402

    auditor = AdvancedAuditor(api_key=api_key, chain=args.chain)
    report = auditor.audit(args.address, full=args.full)
    data = _to_dict(report)

    out_path = (
        Path(args.out)
        if args.out
        else ROOT / "scan_results" / f"onchain_{args.chain}_{args.address.lower()}.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    # Summary
    md = data.get("contract") or {}
    findings = data.get("findings") or []
    by_sev: dict[str, int] = {}
    for f in findings:
        s = (f.get("severity") or "INFO").upper()
        by_sev[s] = by_sev.get(s, 0) + 1
    print()
    print(f"  address       : {args.address}")
    print(f"  chain         : {args.chain}")
    print(f"  contract name : {md.get('name') or '-'}")
    print(f"  proxy         : {md.get('proxy')}  impl={md.get('implementation') or '-'}")
    print(f"  verified src  : {md.get('verified')}")
    print(f"  total findings: {len(findings)}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in by_sev:
            print(f"    {sev:8s} {by_sev[sev]}")
    scores = data.get("scores") or {}
    if scores:
        print(f"  security score: {scores.get('security_score')}")
        print(f"  risk level    : {scores.get('risk_level')}")
    print(f"  written -> {out_path.relative_to(ROOT)}")
    print()
    # Verifier dispositions summary
    verified = [f for f in findings if f.get("verification")]
    if verified:
        by_class: dict[str, int] = {}
        for f in verified:
            c = (f.get("verification") or {}).get("exploit_class", "?")
            by_class[c] = by_class.get(c, 0) + 1
        print(f"  verifier dispositions ({len(verified)} verified):")
        for cls in ("confirmed", "likely", "conditional", "inconclusive", "disproven"):
            if cls in by_class:
                print(f"    {cls:12s} {by_class[cls]}")
        print()
    # Top 10 findings by severity then confidence
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    top = sorted(
        findings,
        key=lambda f: (
            rank.get((f.get("severity") or "INFO").upper(), 0),
            float(f.get("confidence", 0) or 0),
        ),
        reverse=True,
    )[:10]
    if top:
        print("  Top findings:")
        for f in top:
            sev = (f.get("severity") or "?").upper()
            fid = f.get("id", "?")
            title = (f.get("title") or "")[:60]
            line = f.get("line_number") or ""
            conf = f.get("confidence", "")
            ver = (f.get("verification") or {}).get("exploit_class", "")
            tag = f"[{ver}]" if ver else ""
            print(f"    [{sev:8s}] {fid:18s} {title}  L{line} conf={conf} {tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
