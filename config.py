"""
Audit Service Configuration
"""
import os
from dataclasses import dataclass, field
from typing import Dict, Optional
from enum import Enum

from env_loader import load_local_env_files

load_local_env_files()


class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class RateLimits:
    """Rate limiting configuration per tier."""
    requests_per_minute: int = 10
    requests_per_day: int = 100
    max_concurrent: int = 2


@dataclass
class TierConfig:
    """Pricing tier configuration."""
    name: str
    rate_limits: RateLimits
    features: list = field(default_factory=list)
    price_monthly_usd: float = 0.0


# Pricing tiers
TIERS: Dict[str, TierConfig] = {
    "free": TierConfig(
        name="Free",
        rate_limits=RateLimits(
            requests_per_minute=5,
            requests_per_day=10,
            max_concurrent=1
        ),
        features=["basic_audit", "abi_analysis"],
        price_monthly_usd=0.0
    ),
    "pro": TierConfig(
        name="Pro",
        rate_limits=RateLimits(
            requests_per_minute=30,
            requests_per_day=100,
            max_concurrent=5
        ),
        features=[
            "basic_audit",
            "abi_analysis",
            "source_analysis",
            "transaction_analysis",
            "api_access",
            "json_reports"
        ],
        price_monthly_usd=49.0
    ),
    "enterprise": TierConfig(
        name="Enterprise",
        rate_limits=RateLimits(
            requests_per_minute=120,
            requests_per_day=10000,
            max_concurrent=20
        ),
        features=[
            "basic_audit",
            "abi_analysis",
            "source_analysis",
            "transaction_analysis",
            "api_access",
            "json_reports",
            "custom_rules",
            "priority_support",
            "webhook_notifications",
            "batch_audits"
        ],
        price_monthly_usd=299.0
    )
}


@dataclass
class Config:
    """Main configuration."""
    
    # Environment
    env: Environment = Environment.DEVELOPMENT
    debug: bool = True
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8080
    
    # API Keys
    etherscan_api_key: str = ""
    
    # Database
    database_url: str = "sqlite:///audit_service.db"
    
    # Redis (for rate limiting and caching)
    redis_url: str = "redis://localhost:6379/0"
    
    # JWT Authentication
    jwt_secret: str = ""
    jwt_expiry_hours: int = 24
    
    # Caching
    cache_ttl_seconds: int = 3600  # 1 hour
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "audit_service.log"

    # Alerting
    alert_webhook_url: str = ""
    alert_webhook_timeout: float = 5.0
    alert_webhook_retries: int = 2
    alert_high_delta_threshold: int = 1
    
    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        return cls(
            env=Environment(os.getenv("AUDIT_ENV", "development")),
            debug=os.getenv("AUDIT_DEBUG", "true").lower() == "true",
            host=os.getenv("AUDIT_HOST", "0.0.0.0"),
            port=int(os.getenv("AUDIT_PORT", "8080")),
            etherscan_api_key=os.getenv("ETHERSCAN_API_KEY", ""),
            database_url=os.getenv("DATABASE_URL", "sqlite:///audit_service.db"),
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            jwt_secret=os.getenv("JWT_SECRET", ""),
            jwt_expiry_hours=int(os.getenv("JWT_EXPIRY_HOURS", "24")),
            cache_ttl_seconds=int(os.getenv("CACHE_TTL", "3600")),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_file=os.getenv("LOG_FILE", "audit_service.log"),
            alert_webhook_url=os.getenv("ALERT_WEBHOOK_URL", ""),
            alert_webhook_timeout=float(os.getenv("ALERT_WEBHOOK_TIMEOUT", "5")),
            alert_webhook_retries=int(os.getenv("ALERT_WEBHOOK_RETRIES", "2")),
            alert_high_delta_threshold=int(os.getenv("ALERT_HIGH_DELTA_THRESHOLD", "1"))
        )


# Chain configurations
SUPPORTED_CHAINS = {
    "ethereum": {"chain_id": 1, "name": "Ethereum Mainnet"},
    "arbitrum": {"chain_id": 42161, "name": "Arbitrum One"},
    "polygon": {"chain_id": 137, "name": "Polygon"},
    "bsc": {"chain_id": 56, "name": "BNB Smart Chain"},
    "optimism": {"chain_id": 10, "name": "Optimism"},
    "base": {"chain_id": 8453, "name": "Base"},
    "avalanche": {"chain_id": 43114, "name": "Avalanche C-Chain"},
    "fantom":    {"chain_id": 250,   "name": "Fantom Opera"},
    "gnosis":    {"chain_id": 100,   "name": "Gnosis Chain"},
    "moonbeam":  {"chain_id": 1284,  "name": "Moonbeam"},
    "etc":       {"chain_id": 61,    "name": "Ethereum Classic"},
}

# ===================================================
# BLOCK EXPLORER URL PARSER
# ===================================================

import re as _re
from urllib.parse import urlparse as _urlparse

# Map explorer hostnames → chain name (matches SUPPORTED_CHAINS keys)
EXPLORER_HOST_MAP = {
    # Ethereum
    "etherscan.io": "ethereum",
    "www.etherscan.io": "ethereum",
    # BSC / BNB Chain
    "bscscan.com": "bsc",
    "www.bscscan.com": "bsc",
    # Polygon
    "polygonscan.com": "polygon",
    "www.polygonscan.com": "polygon",
    # Arbitrum
    "arbiscan.io": "arbitrum",
    "www.arbiscan.io": "arbitrum",
    # Optimism
    "optimistic.etherscan.io": "optimism",
    # Base
    "basescan.org": "base",
    "www.basescan.org": "base",
    # Avalanche
    "snowtrace.io": "avalanche",
    "www.snowtrace.io": "avalanche",
    "snowscan.xyz": "avalanche",
    "www.snowscan.xyz": "avalanche",
    # Fantom
    "ftmscan.com": "fantom",
    "www.ftmscan.com": "fantom",
    # Gnosis
    "gnosisscan.io": "gnosis",
    "www.gnosisscan.io": "gnosis",
    # Moonbeam
    "moonscan.io": "moonbeam",
    "www.moonscan.io": "moonbeam",
}

_EXPLORER_ADDRESS_RE = _re.compile(r"^/(?:address|token|contract)/+(0x[0-9a-fA-F]{40})(?:[/?#]|$)")


def parse_explorer_url(url: str) -> tuple:
    """Parse a block-explorer URL into (chain, address).

    Accepts URLs like:
        https://bscscan.com/address/0xB562127efDC97B417B3116efF2C23A29857C0F0B
        https://etherscan.io/token/0xdAC17F958D2ee523a2206206994597C13D831ec7
        https://arbiscan.io/address/0x...#code

    Returns:
        (chain_name, address) on success, e.g. ("bsc", "0xB562...")
    Raises:
        ValueError if the URL is not a recognised explorer link.
    """
    parsed = _urlparse(url)
    host = parsed.hostname or ""

    chain = EXPLORER_HOST_MAP.get(host)
    if chain is None:
        raise ValueError(
            f"Unrecognised block-explorer host: {host}. "
            f"Supported: {', '.join(sorted(set(EXPLORER_HOST_MAP.values())))}"
        )

    m = _EXPLORER_ADDRESS_RE.match(parsed.path)
    if not m:
        raise ValueError(
            f"Could not extract address from URL path: {parsed.path}. "
            "Expected /address/0x… or /token/0x…"
        )

    return chain, m.group(1)
