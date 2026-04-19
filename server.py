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
from typing import Dict, Optional, Any

# Flask
try:
    from flask import Flask, jsonify, request, g
    from flask_cors import CORS
except ImportError:
    print("Installing Flask dependencies...")
    os.system(f"{sys.executable} -m pip install flask flask-cors")
    from flask import Flask, jsonify, request, g
    from flask_cors import CORS

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

# In-memory usage tracking (replace with Redis/DB in production)
usage_tracker: Dict[str, Dict[str, Any]] = {}

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
    
    # Use IP for anonymous users
    identifier = api_key or request.remote_addr
    
    now = datetime.now()
    if identifier not in usage_tracker:
        usage_tracker[identifier] = {
            "minute_count": 0,
            "minute_start": now,
            "day_count": 0,
            "day_start": now.date()
        }
    
    tracker = usage_tracker[identifier]
    
    # Reset minute counter
    if (now - tracker["minute_start"]).seconds >= 60:
        tracker["minute_count"] = 0
        tracker["minute_start"] = now
    
    # Reset day counter
    if tracker["day_start"] != now.date():
        tracker["day_count"] = 0
        tracker["day_start"] = now.date()
    
    # Check limits
    if tracker["minute_count"] >= limits.requests_per_minute:
        return False, f"Rate limit exceeded: {limits.requests_per_minute}/minute"
    
    if tracker["day_count"] >= limits.requests_per_day:
        return False, f"Daily limit exceeded: {limits.requests_per_day}/day"
    
    # Increment counters
    tracker["minute_count"] += 1
    tracker["day_count"] += 1
    
    return True, ""


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
    
    identifier = api_key or request.remote_addr
    tracker = usage_tracker.get(identifier, {})
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
        }
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
        ]
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
