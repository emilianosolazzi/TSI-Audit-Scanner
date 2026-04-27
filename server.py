#!/usr/bin/env python3
"""
Audit Service - Main API Server
REST API for smart contract auditing with usage tracking and rate limiting.
"""

import os
import sys
import json
import time
import re
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Optional, Any, List

try:
    from Crypto.Hash import keccak
except ImportError:
    keccak = None

# Flask
try:
    from flask import Flask, jsonify, request, g
    from flask_cors import CORS
except ImportError:
    print("Installing Flask dependencies...")
    os.system(f"{sys.executable} -m pip install flask flask-cors")
    from flask import Flask, jsonify, request, g
    from flask_cors import CORS

try:
    import redis
except ImportError:
    redis = None

# Local imports
from config import Config, TIERS, SUPPORTED_CHAINS, parse_explorer_url
from advanced_auditor import AdvancedAuditor, ChainClient, KNOWN_VULNERABILITIES
from repo_scanner import RepoScanner, ScanStatus
from scanner_scheduler import ScanScheduler, ScanTarget
from report_generator import generate_markdown_report, generate_sarif_report

# Initialize app
app = Flask(__name__)
CORS(app)

# Load configuration
config = Config.from_env()

# Setup logging
logging.basicConfig(
    level=getattr(logging, config.log_level),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AuditService")


class UsageCounterStore:
    """Persistent usage counters with Redis backend and in-memory fallback."""

    def __init__(self, redis_url: str):
        self._memory: Dict[str, Dict[str, Any]] = {}
        self._client = None
        self._backend = "memory"

        if redis is None:
            logger.warning("redis package unavailable, using in-memory usage counters")
            return

        try:
            client = redis.from_url(redis_url, decode_responses=True)
            client.ping()
            self._client = client
            self._backend = "redis"
            logger.info("Using Redis-backed usage counters")
        except Exception as exc:
            logger.warning(f"Redis not available, using in-memory usage counters: {exc}")

    @property
    def backend(self) -> str:
        return self._backend

    def _normalize_identifier(self, identifier: Optional[str]) -> str:
        return identifier or "anonymous"

    def _redis_keys(self, identifier: str) -> tuple[str, str]:
        safe_identifier = identifier.replace(" ", "_")
        return (
            f"usage:{safe_identifier}:minute",
            f"usage:{safe_identifier}:day",
        )

    def _seconds_until_utc_midnight(self) -> int:
        now = datetime.utcnow()
        tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        return max(int((tomorrow - now).total_seconds()), 1)

    def check_and_increment(self, identifier: Optional[str], minute_limit: int, day_limit: int) -> tuple[bool, str, Dict[str, int]]:
        identifier = self._normalize_identifier(identifier)

        if self._client is not None:
            minute_key, day_key = self._redis_keys(identifier)
            minute_count_raw = self._client.get(minute_key)
            day_count_raw = self._client.get(day_key)

            minute_count = int(minute_count_raw or 0)
            day_count = int(day_count_raw or 0)

            if minute_count >= minute_limit:
                return False, f"Rate limit exceeded: {minute_limit}/minute", {
                    "minute_count": minute_count,
                    "day_count": day_count,
                }
            if day_count >= day_limit:
                return False, f"Daily limit exceeded: {day_limit}/day", {
                    "minute_count": minute_count,
                    "day_count": day_count,
                }

            pipe = self._client.pipeline()
            pipe.incr(minute_key)
            pipe.ttl(minute_key)
            pipe.incr(day_key)
            pipe.ttl(day_key)
            new_minute_count, minute_ttl, new_day_count, day_ttl = pipe.execute()

            if minute_ttl is None or minute_ttl < 0:
                self._client.expire(minute_key, 60)
            if day_ttl is None or day_ttl < 0:
                self._client.expire(day_key, self._seconds_until_utc_midnight())

            return True, "", {
                "minute_count": int(new_minute_count),
                "day_count": int(new_day_count),
            }

        now = datetime.now()
        tracker = self._memory.setdefault(identifier, {
            "minute_count": 0,
            "minute_start": now,
            "day_count": 0,
            "day_start": now.date(),
        })

        if (now - tracker["minute_start"]).seconds >= 60:
            tracker["minute_count"] = 0
            tracker["minute_start"] = now

        if tracker["day_start"] != now.date():
            tracker["day_count"] = 0
            tracker["day_start"] = now.date()

        if tracker["minute_count"] >= minute_limit:
            return False, f"Rate limit exceeded: {minute_limit}/minute", {
                "minute_count": tracker["minute_count"],
                "day_count": tracker["day_count"],
            }
        if tracker["day_count"] >= day_limit:
            return False, f"Daily limit exceeded: {day_limit}/day", {
                "minute_count": tracker["minute_count"],
                "day_count": tracker["day_count"],
            }

        tracker["minute_count"] += 1
        tracker["day_count"] += 1

        return True, "", {
            "minute_count": tracker["minute_count"],
            "day_count": tracker["day_count"],
        }

    def get_usage(self, identifier: Optional[str]) -> Dict[str, int]:
        identifier = self._normalize_identifier(identifier)

        if self._client is not None:
            minute_key, day_key = self._redis_keys(identifier)
            return {
                "minute_count": int(self._client.get(minute_key) or 0),
                "day_count": int(self._client.get(day_key) or 0),
            }

        tracker = self._memory.get(identifier)
        if not tracker:
            return {"minute_count": 0, "day_count": 0}

        now = datetime.now()
        minute_count = tracker["minute_count"] if (now - tracker["minute_start"]).seconds < 60 else 0
        day_count = tracker["day_count"] if tracker["day_start"] == now.date() else 0
        return {
            "minute_count": minute_count,
            "day_count": day_count,
        }


usage_store = UsageCounterStore(config.redis_url)

# Scanner components
scanner = RepoScanner(
    workspace_dir=os.environ.get("SCANNER_WORKSPACE", os.path.join(os.getcwd(), "scanner_workspace")),
    github_token=os.environ.get("GITHUB_TOKEN"),
)
scheduler = ScanScheduler(
    db_path=os.environ.get("SCANNER_DB", "scan_history.db"),
    results_dir=os.environ.get("SCANNER_RESULTS", "scan_results"),
)

# ===================================================
# INPUT VALIDATION
# ===================================================

# Strict Ethereum address pattern
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
# Allowed GitHub URL pattern (prevent SSRF/injection)
REPO_URL_RE = re.compile(r"^https://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:\.git)?$")

def validate_address(address: str) -> bool:
    """Validate Ethereum address format."""
    return bool(ADDRESS_RE.match(address))

def validate_repo_url(url: str) -> bool:
    """Validate GitHub repository URL to prevent SSRF."""
    return bool(REPO_URL_RE.match(url))

def validate_local_path(path: str) -> bool:
    """Validate local path to prevent directory traversal."""
    real = os.path.realpath(path)
    allowed_base = os.path.realpath(
        os.environ.get("SCANNER_WORKSPACE", os.path.join(os.getcwd(), "scanner_workspace"))
    )
    return real == allowed_base or real.startswith(allowed_base + os.sep)


def _severity_rank(severity: str) -> int:
    return {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "GAS": 1,
        "INFO": 0,
    }.get(severity, 0)


def _extract_abi_function_names(abi: Optional[List[Dict[str, Any]]]) -> set:
    """Return normalized ABI function names."""
    if not abi:
        return set()
    return {
        item.get("name", "")
        for item in abi
        if item.get("type") == "function" and item.get("name")
    }


def _matches_any_prefix(function_names: set, prefixes: List[str]) -> bool:
    return any(
        any(name.lower().startswith(prefix) for prefix in prefixes)
        for name in function_names
    )


def _build_capability_flags(report, abi: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Build user-facing capability flags from ABI and audit metadata."""
    function_names = _extract_abi_function_names(abi)
    lowered = {name.lower() for name in function_names}
    access_control = report.access_control_pattern or "Unknown"

    mintable = (
        "mint" in lowered or
        _matches_any_prefix(function_names, ["mint", "issue", "allocate"])
    )
    pausable = any(name in lowered for name in {"pause", "unpause", "paused"})
    blacklist_capability = any(
        token in name
        for name in lowered
        for token in ["blacklist", "blocklist", "freeze", "frozen", "ban"]
    )
    owner_controlled = access_control in {"Ownable", "Ownable2Step"} or "owner" in lowered
    role_controlled = access_control == "AccessControl (OZ)" or {"grantrole", "revokerole", "hasrole"} <= lowered
    upgradeable = bool(report.metadata.proxy or report.metadata.implementation) or any(
        name in lowered for name in {"upgradeto", "upgradetoandcall", "implementation"}
    )

    return {
        "mintable": mintable,
        "pausable": pausable,
        "blacklist_capability": blacklist_capability,
        "owner_controlled": owner_controlled,
        "role_controlled": role_controlled,
        "upgradeable": upgradeable,
        "ownership_transferable": any(name in lowered for name in {"transferownership", "renounceownership", "acceptownership"}),
        "role_management_surface": any(name in lowered for name in {"grantrole", "revokerole", "renouncerole"}),
    }


EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
DEFAULT_ADMIN_ROLE = "0x" + "0" * 64


def _selector(signature: str) -> Optional[str]:
    if keccak is None:
        return None
    return "0x" + keccak.new(digest_bits=256, data=signature.encode()).hexdigest()[:8]


def _encode_uint256(value: int) -> str:
    return f"{value:064x}"


def _encode_bytes32(value: str) -> str:
    hex_value = value[2:] if value.startswith("0x") else value
    return hex_value.rjust(64, "0")


def _encode_address(address: str) -> str:
    return address.lower().replace("0x", "").rjust(64, "0")


def _decode_address(result: Optional[str]) -> Optional[str]:
    if not result or result == "0x":
        return None
    clean = result[2:] if result.startswith("0x") else result
    if len(clean) < 40:
        return None
    address = "0x" + clean[-40:]
    if re.fullmatch(r"0x0{40}", address):
        return None
    return address.lower()


def _decode_uint256(result: Optional[str]) -> Optional[int]:
    if not result or result == "0x":
        return None
    try:
        return int(result, 16)
    except (TypeError, ValueError):
        return None


def _decode_bool(result: Optional[str]) -> Optional[bool]:
    value = _decode_uint256(result)
    if value is None:
        return None
    return bool(value)


def _classify_address_type(client: ChainClient, address: Optional[str]) -> Optional[str]:
    if not address:
        return None
    code = client.get_code(address)
    if not code:
        return None
    return "contract" if code not in {"0x", "0x0"} else "eoa"


def _build_live_admin_snapshot(client: ChainClient, report, abi: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Build a lightweight live snapshot of upgrade/admin authority on-chain."""
    function_names = _extract_abi_function_names(abi)
    lowered = {name.lower() for name in function_names}
    state_address = (report.metadata.address or "").lower()

    snapshot: Dict[str, Any] = {
        "state_address": state_address,
        "implementation_address": report.metadata.implementation,
        "proxy_admin": None,
        "proxy_admin_type": None,
        "owner": None,
        "owner_type": None,
        "creator": report.metadata.creator.lower() if report.metadata.creator else None,
        "creator_type": None,
        "default_admin_role_member_count": None,
        "default_admin_role_holders": [],
        "creator_has_default_admin_role": None,
    }

    if snapshot["creator"]:
        snapshot["creator_type"] = _classify_address_type(client, snapshot["creator"])

    if report.metadata.proxy:
        proxy_admin_raw = client.get_storage_at(state_address, EIP1967_ADMIN_SLOT)
        snapshot["proxy_admin"] = _decode_address(proxy_admin_raw)
        snapshot["proxy_admin_type"] = _classify_address_type(client, snapshot["proxy_admin"])

    if "owner" in lowered:
        snapshot["owner"] = _decode_address(client.call_function(state_address, "0x8da5cb5b"))
    elif "getowner" in lowered:
        snapshot["owner"] = _decode_address(client.call_function(state_address, "0x893d20e8"))
    snapshot["owner_type"] = _classify_address_type(client, snapshot["owner"])

    has_role_selector = _selector("hasRole(bytes32,address)")
    get_role_member_count_selector = _selector("getRoleMemberCount(bytes32)")
    get_role_member_selector = _selector("getRoleMember(bytes32,uint256)")

    if "getrolemembercount" in lowered and get_role_member_count_selector and get_role_member_selector:
        calldata = get_role_member_count_selector + _encode_bytes32(DEFAULT_ADMIN_ROLE)
        member_count = _decode_uint256(client.call_function_data(state_address, calldata))
        snapshot["default_admin_role_member_count"] = member_count
        if member_count:
            for index in range(min(member_count, 3)):
                member_call = (
                    get_role_member_selector
                    + _encode_bytes32(DEFAULT_ADMIN_ROLE)
                    + _encode_uint256(index)
                )
                holder = _decode_address(client.call_function_data(state_address, member_call))
                if holder:
                    snapshot["default_admin_role_holders"].append({
                        "address": holder,
                        "type": _classify_address_type(client, holder),
                    })

    if snapshot["creator"] and "hasrole" in lowered and has_role_selector:
        calldata = has_role_selector + _encode_bytes32(DEFAULT_ADMIN_ROLE) + _encode_address(snapshot["creator"])
        snapshot["creator_has_default_admin_role"] = _decode_bool(client.call_function_data(state_address, calldata))

    return snapshot


def _build_summary_labels(flags: Dict[str, Any], risk_level: str) -> List[str]:
    """Build short UI labels for quick scan cards/tables."""
    labels: List[str] = [f"Risk:{risk_level}"]

    if flags.get("unverified_contract"):
        labels.append("Unverified")
    if flags.get("upgradeable"):
        labels.append("Upgradeable")
    if flags.get("owner_controlled"):
        labels.append("OwnerControlled")
    if flags.get("role_controlled"):
        labels.append("RoleControlled")
    if flags.get("mintable"):
        labels.append("Mintable")
    if flags.get("pausable"):
        labels.append("Pausable")
    if flags.get("blacklist_capability"):
        labels.append("BlacklistCapable")
    if flags.get("admin_surface_present"):
        labels.append("AdminSurface")
    if flags.get("live_eoa_admin"):
        labels.append("EOAAdmin")

    return labels


def _build_risk_badges(flags: Dict[str, Any], risk_level: str) -> List[Dict[str, str]]:
    """Build richer badge objects for frontend rendering."""
    severity_map = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "SAFE": "info",
    }
    badges: List[Dict[str, str]] = [{
        "label": f"Risk {risk_level}",
        "severity": severity_map.get(risk_level, "info"),
        "reason": "Overall quick-scan risk level",
    }]

    badge_rules = [
        ("unverified_contract", "Unverified Source", "high", "Source not verified on explorer"),
        ("upgradeable", "Upgradeable", "medium", "Proxy/upgrade path detected"),
        ("owner_controlled", "Owner Controlled", "medium", "Privileged owner control surface"),
        ("role_controlled", "Role Controlled", "low", "Role-based privileged controls"),
        ("mintable", "Mintable", "medium", "Token supply expansion capability"),
        ("pausable", "Pausable", "low", "Transfer/function pause capability"),
        ("blacklist_capability", "Blacklist Capability", "high", "Address blocking/freeze semantics present"),
        ("live_eoa_admin", "Live EOA Admin", "high", "Live on-chain admin authority appears to be held by an EOA"),
    ]

    for key, label, severity, reason in badge_rules:
        if flags.get(key):
            badges.append({"label": label, "severity": severity, "reason": reason})

    return badges


def _build_triage_response(report, abi: Optional[List[Dict[str, Any]]] = None, live_admin_snapshot: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a fast, plain-English contract triage view from a full audit report."""
    report_data = report.to_dict()
    contract = report_data["contract"]
    scores = report_data["scores"]
    summary = report_data["summary"]
    analysis = report_data["analysis"]
    findings = sorted(
        report_data["findings"],
        key=lambda finding: (
            -finding.get("vuln_score", 0),
            -_severity_rank(finding.get("severity", "INFO")),
            -finding.get("confidence", 0),
        ),
    )

    prominent_warnings: List[Dict[str, Any]] = []
    for finding in findings:
        if finding.get("severity") not in {"CRITICAL", "HIGH", "MEDIUM"}:
            continue
        prominent_warnings.append({
            "id": finding.get("id"),
            "severity": finding.get("severity"),
            "title": finding.get("title"),
            "category": finding.get("category"),
            "vuln_score": finding.get("vuln_score", 0.0),
            "why_it_matters": finding.get("description"),
            "recommendation": finding.get("recommendation"),
        })
        if len(prominent_warnings) >= 5:
            break

    top_vuln_score = findings[0].get("vuln_score", 0.0) if findings else 0.0

    flags = {
        "verified_source": contract.get("verified", False),
        "proxy_contract": contract.get("proxy", False),
        "implementation_address": contract.get("implementation"),
        "token_standard": analysis.get("interfaces", []),
        "detected_protocols": analysis.get("defi_protocols", []),
        "access_control_model": analysis.get("access_control") or "Unknown",
        "admin_surface_present": analysis.get("functions", {}).get("admin", 0) > 0,
        "payable_surface_present": analysis.get("functions", {}).get("payable", 0) > 0,
        "unverified_contract": not contract.get("verified", False),
    }
    flags.update(_build_capability_flags(report, abi))
    role_holders = (live_admin_snapshot or {}).get("default_admin_role_holders", [])
    eoa_role_holder = any(holder.get("type") == "eoa" for holder in role_holders)
    live_eoa_admin = any(
        admin_type == "eoa"
        for admin_type in [
            (live_admin_snapshot or {}).get("owner_type"),
            (live_admin_snapshot or {}).get("proxy_admin_type"),
            (live_admin_snapshot or {}).get("creator_type") if (live_admin_snapshot or {}).get("creator_has_default_admin_role") else None,
        ]
    ) or eoa_role_holder
    flags.update({
        "live_admin_snapshot_available": bool(live_admin_snapshot),
        "live_eoa_admin": live_eoa_admin,
    })
    summary_labels = _build_summary_labels(flags, scores["risk_level"])
    risk_badges = _build_risk_badges(flags, scores["risk_level"])

    if scores["risk_level"] == "CRITICAL":
        verdict = "Avoid interacting until the critical issues are reviewed."
    elif scores["risk_level"] == "HIGH":
        verdict = "High-risk contract. Manual review is required before use or integration."
    elif flags.get("live_eoa_admin") and (flags.get("upgradeable") or flags.get("role_controlled") or flags.get("admin_surface_present")):
        verdict = "Live on-chain admin authority appears EOA-held on a privileged control surface. Treat this as a high-priority manual review candidate."
    elif flags.get("unverified_contract") and (flags.get("upgradeable") or flags.get("owner_controlled")):
        verdict = "Caution: this contract is unverified and has privileged control/upgrade surface. Review thoroughly before interacting."
    elif scores["risk_level"] == "MEDIUM":
        verdict = "Use caution. The contract shows meaningful risk signals that need review."
    elif not contract.get("verified", False):
        verdict = "Source is not verified, which limits confidence in the scan and increases due-diligence risk."
    else:
        verdict = "No severe risk signal was detected in the quick scan, but this is not a substitute for a full audit."

    # ---- bounty triage status ----
    risk_level = scores["risk_level"]
    if (
        flags.get("live_eoa_admin")
        and flags.get("live_admin_snapshot_available")
        and (flags.get("upgradeable") or flags.get("role_controlled"))
        and risk_level in {"CRITICAL", "HIGH"}
    ):
        bounty_triage_status = "submission_ready"
    elif (
        risk_level in {"CRITICAL", "HIGH", "MEDIUM"}
        or flags.get("live_eoa_admin")
    ):
        bounty_triage_status = "found_candidate"
    else:
        bounty_triage_status = "likely_not_in_scope"

    return {
        "timestamp": report_data["timestamp"],
        "contract": contract,
        "bounty_triage_status": bounty_triage_status,
        "quick_verdict": verdict,
        "risk": {
            "security_score": scores["security_score"],
            "risk_level": scores["risk_level"],
            "top_vuln_score": top_vuln_score,
            "total_findings": summary["total_findings"],
            "critical": summary["critical"],
            "high": summary["high"],
            "medium": summary["medium"],
        },
        "summary_labels": summary_labels,
        "risk_badges": risk_badges,
        "flags": flags,
        "live_admin_snapshot": live_admin_snapshot or {},
        "surface": {
            "total_functions": analysis.get("functions", {}).get("total", 0),
            "external_functions": analysis.get("functions", {}).get("external", 0),
            "payable_functions": analysis.get("functions", {}).get("payable", 0),
            "admin_functions": analysis.get("functions", {}).get("admin", 0),
        },
        "prominent_warnings": prominent_warnings,
        "next_step": "Run the full /audit endpoint for detailed findings, code snippets, and export formats."
    }


# ===================================================
# AUTHENTICATION & RATE LIMITING
# ===================================================

def get_api_key():
    """Extract API key from request."""
    # Check header first
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key
    # Check query param
    return request.args.get("api_key")


def get_user_tier(api_key: Optional[str]) -> str:
    """Get user's tier based on API key."""
    # TODO: Lookup in database
    # For now, return free tier for unauthenticated, pro for any key
    if not api_key:
        return "free"
    # In production: lookup api_key in database
    return "pro"


def check_rate_limit(api_key: Optional[str], tier: str) -> tuple[bool, str]:
    """Check if request is within rate limits."""
    tier_config = TIERS.get(tier, TIERS["free"])
    limits = tier_config.rate_limits

    identifier = api_key or request.remote_addr or "anonymous"
    allowed, message, _ = usage_store.check_and_increment(
        identifier,
        limits.requests_per_minute,
        limits.requests_per_day,
    )
    return allowed, message


def require_feature(feature: str):
    """Decorator to check if user's tier has required feature."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            tier = g.get("tier", "free")
            tier_config = TIERS.get(tier, TIERS["free"])
            
            if feature not in tier_config.features:
                return jsonify({
                    "error": "Feature not available",
                    "message": f"'{feature}' requires {tier_config.name} tier or higher",
                    "upgrade_url": "/pricing"
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


@app.before_request
def before_request():
    """Run before each request - auth and rate limiting."""
    # Skip for health check
    if request.endpoint == "health":
        return
    
    api_key = get_api_key()
    tier = get_user_tier(api_key)
    
    # Store in request context
    g.api_key = api_key
    g.tier = tier
    
    # Check rate limit
    allowed, message = check_rate_limit(api_key, tier)
    if not allowed:
        return jsonify({"error": "Rate limit exceeded", "message": message}), 429


# ===================================================
# API ENDPOINTS
# ===================================================

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "service": "Smart Contract Audit Service",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "patterns": len(KNOWN_VULNERABILITIES),
        "chains": len(SUPPORTED_CHAINS),
    })


@app.route("/chains", methods=["GET"])
def list_chains():
    """List supported blockchain networks."""
    return jsonify({
        "chains": list(SUPPORTED_CHAINS.keys()),
        "details": SUPPORTED_CHAINS
    })


@app.route("/pricing", methods=["GET"])
def pricing():
    """Get pricing tiers."""
    tiers_info = {}
    for name, tier in TIERS.items():
        tiers_info[name] = {
            "name": tier.name,
            "price_monthly_usd": tier.price_monthly_usd,
            "features": tier.features,
            "rate_limits": {
                "requests_per_minute": tier.rate_limits.requests_per_minute,
                "requests_per_day": tier.rate_limits.requests_per_day
            }
        }
    return jsonify({"tiers": tiers_info})


@app.route("/usage", methods=["GET"])
def get_usage():
    """Get current usage statistics for authenticated user."""
    api_key = g.get("api_key")
    tier = g.get("tier", "free")
    
    identifier = api_key or request.remote_addr or "anonymous"
    tracker = usage_store.get_usage(identifier)
    tier_config = TIERS.get(tier, TIERS["free"])
    
    return jsonify({
        "tier": tier,
        "usage": {
            "minute": {
                "used": tracker.get("minute_count", 0),
                "limit": tier_config.rate_limits.requests_per_minute
            },
            "day": {
                "used": tracker.get("day_count", 0),
                "limit": tier_config.rate_limits.requests_per_day
            }
        },
        "counter_backend": usage_store.backend,
    })


@app.route("/audit/<address>", methods=["GET"])
@require_feature("basic_audit")
def audit_contract(address: str):
    """
    Audit a smart contract.
    
    Query params:
        chain: blockchain network (default: ethereum)
        full: include transaction analysis (default: false)
    """
    chain = request.args.get("chain", "ethereum")
    full_audit = request.args.get("full", "false").lower() == "true"
    
    # Validate address format
    if not validate_address(address):
        return jsonify({"error": "Invalid address", "message": "Must be a valid Ethereum address (0x + 40 hex chars)"}), 400
    
    # Validate chain
    if chain not in SUPPORTED_CHAINS:
        return jsonify({
            "error": "Invalid chain",
            "message": f"Supported chains: {list(SUPPORTED_CHAINS.keys())}"
        }), 400
    
    # Check if full audit is allowed
    if full_audit:
        tier = g.get("tier", "free")
        tier_config = TIERS.get(tier, TIERS["free"])
        if "transaction_analysis" not in tier_config.features:
            return jsonify({
                "error": "Feature not available",
                "message": "Full audit requires Pro tier or higher"
            }), 403
    
    try:
        # Perform audit using advanced auditor
        auditor = AdvancedAuditor(config.etherscan_api_key, chain)
        report = auditor.audit(address)
        
        # Log audit
        logger.info(f"Audit completed: {address} on {chain} (score: {report.security_score}, risk: {report.risk_level})")
        
        report_data = report.to_dict()
        
        # Support multiple output formats
        fmt = request.args.get("format", "json").lower()
        if fmt == "markdown" or fmt == "md":
            return generate_markdown_report(report_data), 200, {"Content-Type": "text/markdown; charset=utf-8"}
        elif fmt == "sarif":
            return jsonify(generate_sarif_report(report_data))
        
        return jsonify(report_data)
        
    except ValueError as e:
        return jsonify({"error": "Invalid input", "message": str(e)}), 400
    except Exception as e:
        logger.exception(f"Audit failed for {address}")
        return jsonify({"error": "Audit failed", "message": str(e)}), 500


@app.route("/triage/<address>", methods=["GET"])
@require_feature("basic_audit")
def triage_contract(address: str):
    """Fast, plain-English triage for a contract address."""
    chain = request.args.get("chain", "ethereum")

    if not validate_address(address):
        return jsonify({
            "error": "Invalid address",
            "message": "Must be a valid Ethereum address (0x + 40 hex chars)"
        }), 400

    if chain not in SUPPORTED_CHAINS:
        return jsonify({
            "error": "Invalid chain",
            "message": f"Supported chains: {list(SUPPORTED_CHAINS.keys())}"
        }), 400

    try:
        auditor = AdvancedAuditor(config.etherscan_api_key, chain)
        report = auditor.audit(address)
        triage_address = report.metadata.implementation or address.lower()
        abi = auditor.client.get_contract_abi(triage_address)
        live_admin_snapshot = _build_live_admin_snapshot(auditor.client, report, abi)
        return jsonify(_build_triage_response(report, abi, live_admin_snapshot))
    except ValueError as e:
        return jsonify({"error": "Invalid input", "message": str(e)}), 400
    except Exception as e:
        logger.exception(f"Triage failed for {address}")
        return jsonify({"error": "Triage failed", "message": str(e)}), 500


@app.route("/audit/url", methods=["GET", "POST"])
@require_feature("basic_audit")
def audit_explorer_url():
    """
    Audit a contract from a block-explorer URL.

    Accepts URLs like:
        https://bscscan.com/address/0xB562127efDC97B417B3116efF2C23A29857C0F0B
        https://etherscan.io/address/0x...
        https://arbiscan.io/token/0x...

    GET  /audit/url?url=<explorer_url>&format=json|markdown|sarif
    POST /audit/url  {"url": "<explorer_url>"}
    """
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        explorer_url = data.get("url", "")
    else:
        explorer_url = request.args.get("url", "")

    if not explorer_url:
        return jsonify({
            "error": "Missing URL",
            "message": "Provide a block-explorer URL via ?url= or JSON body {\"url\": \"...\"}",
            "examples": [
                "https://bscscan.com/address/0xB562127efDC97B417B3116efF2C23A29857C0F0B",
                "https://etherscan.io/address/0xdAC17F958D2ee523a2206206994597C13D831ec7",
                "https://arbiscan.io/address/0x...",
            ]
        }), 400

    try:
        chain, address = parse_explorer_url(explorer_url)
    except ValueError as e:
        return jsonify({"error": "Invalid explorer URL", "message": str(e)}), 400

    try:
        auditor = AdvancedAuditor(config.etherscan_api_key, chain)
        report = auditor.audit(address)

        logger.info(f"Explorer-URL audit: {chain}:{address} (score: {report.security_score})")

        report_data = report.to_dict()

        fmt = request.args.get("format", "json").lower()
        if fmt in ("markdown", "md"):
            return generate_markdown_report(report_data), 200, {"Content-Type": "text/markdown; charset=utf-8"}
        elif fmt == "sarif":
            return jsonify(generate_sarif_report(report_data))

        return jsonify(report_data)

    except ValueError as e:
        return jsonify({"error": "Invalid input", "message": str(e)}), 400
    except Exception as e:
        logger.exception(f"Explorer-URL audit failed for {explorer_url}")
        return jsonify({"error": "Audit failed", "message": str(e)}), 500


@app.route("/audit/batch", methods=["POST"])
@require_feature("batch_audits")
def batch_audit():
    """
    Audit multiple contracts (Enterprise feature).
    
    Request body:
        {
            "contracts": [
                {"address": "0x...", "chain": "ethereum"},
                {"address": "0x...", "chain": "arbitrum"}
            ]
        }
    """
    data = request.get_json()
    if not data or "contracts" not in data:
        return jsonify({"error": "Invalid request", "message": "contracts array required"}), 400
    
    contracts = data["contracts"]
    if len(contracts) > 10:
        return jsonify({"error": "Too many contracts", "message": "Max 10 contracts per batch"}), 400
    
    results = []
    for contract in contracts:
        address = contract.get("address")
        chain = contract.get("chain", "ethereum")
        
        try:
            auditor = AdvancedAuditor(config.etherscan_api_key, chain)
            report = auditor.audit(address)
            results.append({
                "address": address,
                "chain": chain,
                "status": "success",
                "report": report.to_dict()
            })
        except Exception as e:
            results.append({
                "address": address,
                "chain": chain,
                "status": "error",
                "error": str(e)
            })
    
    return jsonify({
        "batch_id": f"batch_{int(time.time())}",
        "total": len(contracts),
        "successful": sum(1 for r in results if r["status"] == "success"),
        "results": results
    })


@app.route("/compare", methods=["POST"])
@require_feature("source_analysis")
def compare_contracts():
    """
    Compare two contracts.
    
    Request body:
        {
            "contract1": {"address": "0x...", "chain": "ethereum"},
            "contract2": {"address": "0x...", "chain": "arbitrum"}
        }
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request"}), 400
    
    c1 = data.get("contract1", {})
    c2 = data.get("contract2", {})
    
    try:
        auditor1 = AdvancedAuditor(config.etherscan_api_key, c1.get("chain", "ethereum"))
        auditor2 = AdvancedAuditor(config.etherscan_api_key, c2.get("chain", "ethereum"))
        
        report1 = auditor1.audit(c1["address"])
        report2 = auditor2.audit(c2["address"])
        
        # Compare findings
        comparison = {
            "contract1": {
                "address": c1["address"],
                "name": report1.metadata.name,
                "security_score": report1.security_score,
                "risk_level": report1.risk_level,
                "findings_count": len(report1.findings)
            },
            "contract2": {
                "address": c2["address"],
                "name": report2.metadata.name,
                "security_score": report2.security_score,
                "risk_level": report2.risk_level,
                "findings_count": len(report2.findings)
            },
            "score_difference": abs(report1.security_score - report2.security_score),
            "safer_contract": c1["address"] if report1.security_score > report2.security_score else c2["address"]
        }
        
        return jsonify(comparison)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ===================================================
# SCANNER ENDPOINTS — Repo & Source Scanning
# ===================================================

@app.route("/scan/repo", methods=["POST"])
@require_feature("source_analysis")
def scan_repo():
    """
    Scan a GitHub repository for Solidity vulnerabilities.

    Request body:
        {
            "url": "https://github.com/owner/repo",
            "branch": "main",
            "scope_paths": ["contracts/"],
            "include_tests": false
        }
    """
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    repo_url = data["url"]
    branch = data.get("branch", "main")
    scope_paths = data.get("scope_paths")
    include_tests = data.get("include_tests", False)

    # Validate URL to prevent SSRF
    if not validate_repo_url(repo_url):
        return jsonify({"error": "Invalid URL", "message": "Only https://github.com/<owner>/<repo> URLs are accepted"}), 400

    try:
        result = scanner.scan_repo(
            repo_url, branch=branch,
            include_tests=include_tests,
            scope_paths=scope_paths
        )
        logger.info(
            f"Repo scan completed: {repo_url} "
            f"({result.files_scanned} files, {len(result.findings)} findings)"
        )
        return jsonify(result.to_dict())

    except Exception as e:
        logger.exception(f"Repo scan failed: {repo_url}")
        return jsonify({"error": "Scan failed", "message": str(e)}), 500


@app.route("/scan/local", methods=["POST"])
@require_feature("source_analysis")
def scan_local():
    """
    Scan a local directory for Solidity vulnerabilities.

    Request body:
        {
            "path": "/path/to/project",
            "scope_paths": ["contracts/"],
            "include_tests": false
        }
    """
    data = request.get_json()
    if not data or "path" not in data:
        return jsonify({"error": "Missing 'path' in request body"}), 400

    local_path = data["path"]
    if not os.path.isdir(local_path):
        return jsonify({"error": f"Directory not found: {local_path}"}), 400

    # Prevent directory traversal
    real_path = os.path.realpath(local_path)
    if ".." in local_path:
        return jsonify({"error": "Directory traversal not allowed"}), 400
        return jsonify({"error": f"Directory not found: {local_path}"}), 400

    try:
        result = scanner.scan_local(
            local_path,
            include_tests=data.get("include_tests", False),
            scope_paths=data.get("scope_paths")
        )
        return jsonify(result.to_dict())

    except Exception as e:
        logger.exception(f"Local scan failed: {local_path}")
        return jsonify({"error": "Scan failed", "message": str(e)}), 500


# ===================================================
# SCHEDULER ENDPOINTS — Target Management & History
# ===================================================

@app.route("/targets", methods=["GET"])
@require_feature("api_access")
def list_targets():
    """List all scan targets."""
    targets = scheduler.list_targets(enabled_only=False)
    return jsonify({
        "count": len(targets),
        "targets": [
            {
                "id": t.id,
                "type": t.target_type,
                "url": t.url,
                "chain": t.chain,
                "branch": t.branch,
                "interval_hours": t.interval_hours,
                "priority": t.priority,
                "enabled": t.enabled,
                "last_scanned": t.last_scanned,
                "last_findings": t.last_findings,
            }
            for t in targets
        ]
    })


@app.route("/targets", methods=["POST"])
@require_feature("api_access")
def add_target():
    """
    Add a scan target.

    Request body:
        {
            "url": "https://github.com/owner/repo",
            "type": "repo",
            "branch": "main",
            "chain": "ethereum",
            "scope_paths": ["contracts/"],
            "interval_hours": 24,
            "priority": 0
        }
    """
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url'"}), 400

    url = data["url"]
    target_type = data.get("type")

    # Auto-detect type
    if not target_type:
        if url.startswith("0x") and len(url) == 42:
            target_type = "address"
        else:
            target_type = "repo"

    target = ScanTarget(
        id="",
        target_type=target_type,
        url=url,
        chain=data.get("chain"),
        branch=data.get("branch", "main"),
        scope_paths=data.get("scope_paths"),
        priority=data.get("priority", 0),
        interval_hours=data.get("interval_hours", 0),
    )

    target_id = scheduler.add_target(target)
    return jsonify({"id": target_id, "status": "added"}), 201


@app.route("/targets/<target_id>", methods=["DELETE"])
@require_feature("api_access")
def remove_target(target_id: str):
    """Remove a scan target."""
    scheduler.remove_target(target_id)
    return jsonify({"status": "removed"})


@app.route("/targets/<target_id>/scan", methods=["POST"])
@require_feature("source_analysis")
def trigger_scan(target_id: str):
    """Trigger an immediate scan for a target."""
    target = scheduler.get_target(target_id)
    if not target:
        return jsonify({"error": "Target not found"}), 404

    result = scheduler.run_scan(target)
    return jsonify(result)


@app.route("/targets/<target_id>/history", methods=["GET"])
@require_feature("api_access")
def scan_history(target_id: str):
    """Get scan history for a target."""
    limit = request.args.get("limit", 10, type=int)
    history = scheduler.get_scan_history(target_id, limit=limit)
    alerts = scheduler.get_scan_alerts(target_id, limit=limit)
    return jsonify({
        "target_id": target_id,
        "scans": [
            {
                "scan_id": h.scan_id,
                "started_at": h.started_at,
                "completed_at": h.completed_at,
                "status": h.status,
                "findings_count": h.findings_count,
                "critical": h.critical_count,
                "high": h.high_count,
                "commit_hash": h.commit_hash,
            }
            for h in history
        ],
        "alerts": alerts,
    })


@app.route("/scan/results/<scan_id>", methods=["GET"])
@require_feature("api_access")
def get_scan_result(scan_id: str):
    """Retrieve full results for a specific scan."""
    # Sanitize scan_id to prevent path traversal
    safe_id = os.path.basename(scan_id)
    result_path = os.path.join(scheduler.results_dir, f"{safe_id}.json")
    if not os.path.exists(result_path):
        return jsonify({"error": "Scan result not found"}), 404

    with open(result_path) as f:
        return jsonify(json.load(f))


@app.route("/alerts", methods=["GET"])
@require_feature("api_access")
def list_alert_events():
    """List alert delivery events, optionally filtered by target/status."""
    target_id = request.args.get("target_id")
    status = request.args.get("status")
    limit = request.args.get("limit", 50, type=int)
    events = scheduler.list_alert_events(target_id=target_id, status=status, limit=limit)
    return jsonify({
        "count": len(events),
        "alerts": events,
    })


@app.route("/alerts/<alert_key>/retry", methods=["POST"])
@require_feature("api_access")
def retry_alert_event(alert_key: str):
    """Retry one alert webhook delivery by alert key."""
    result = scheduler.retry_alert_event(alert_key)
    if result.get("status") == "not_found":
        return jsonify(result), 404
    return jsonify(result)


@app.route("/alerts/retry-failed", methods=["POST"])
@require_feature("api_access")
def retry_failed_alerts():
    """Retry failed alert deliveries in batch."""
    data = request.get_json(silent=True) or {}
    limit = int(data.get("limit", 20))
    result = scheduler.retry_failed_alerts(limit=limit)
    return jsonify(result)


# ===================================================
# ERROR HANDLERS
# ===================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found", "message": "Endpoint does not exist"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Server error", "message": "Internal server error"}), 500


# ===================================================
# MAIN
# ===================================================

def main():
    """Run the API server."""
    if not config.etherscan_api_key:
        print("WARNING: ETHERSCAN_API_KEY not set")
    
    logger.info(f"Starting Audit Service on {config.host}:{config.port}")
    logger.info(f"Environment: {config.env.value}")
    
    app.run(
        host=config.host,
        port=config.port,
        debug=config.debug
    )


if __name__ == "__main__":
    main()
