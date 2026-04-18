# Solidity Audit Service

Autonomous smart contract security scanner. Audits on-chain contracts via Etherscan APIs, clones and scans GitHub repos, schedules continuous monitoring — all through a REST API or CLI.

## Features

- **On-chain audit** — Fetch source from 7 block explorer APIs, run 80+ vulnerability patterns
- **Repo scanning** — Clone public/private GitHub repos, discover Solidity files, analyze
- **Pattern engine** — Protection-first: checks for guards before flagging (reentrancy, access control, oracle, flash loan, MEV, front-running, arithmetic)
- **Scheduler** — SQLite-backed target management with continuous re-scan loop
- **CLI** — One-shot scans, target management, watch mode
- **REST API** — 15 endpoints with tiered rate limiting

## Quick Start

```bash
# Clone
git clone https://github.com/yourorg/solidity-audit-service.git
cd solidity-audit-service

# Install
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env — set ETHERSCAN_API_KEY at minimum

# Run server
python server.py

# Or scan a repo directly via CLI
python scanner_scheduler.py scan https://github.com/owner/repo --scope contracts/
```

## Docker

```bash
docker compose up -d
# API available at http://localhost:8080
```

## API Reference

### Core Audit

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/chains` | Supported chains (ethereum, arbitrum, polygon, bsc, optimism, base, avalanche) |
| `GET` | `/pricing` | Tier information |
| `GET` | `/usage` | Current rate limit usage |
| `GET` | `/audit/<address>?chain=ethereum&full=false` | Audit on-chain contract |
| `POST` | `/audit/batch` | Batch audit (enterprise) |
| `POST` | `/compare` | Compare two contracts |

### Scanner

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan/repo` | Scan GitHub repository |
| `POST` | `/scan/local` | Scan local directory |
| `GET` | `/scan/results/<scan_id>` | Full scan results JSON |

### Scheduler

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/targets` | List all scan targets |
| `POST` | `/targets` | Add target (auto-detects repo vs address) |
| `DELETE` | `/targets/<id>` | Remove target |
| `POST` | `/targets/<id>/scan` | Trigger immediate scan |
| `GET` | `/targets/<id>/history` | Scan history |

### Examples

```bash
# Audit an on-chain contract
curl http://localhost:8080/audit/0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984?chain=ethereum

# Scan a GitHub repo
curl -X POST http://localhost:8080/scan/repo \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/aave/aave-v3-core", "scope_paths": ["contracts/"]}'

# Add a scheduled target
curl -X POST http://localhost:8080/targets \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/owner/repo", "interval_hours": 24}'
```

## CLI

```bash
# One-shot scan (local directory)
python scanner_scheduler.py scan /path/to/contracts --scope contracts/

# One-shot scan (GitHub)
python scanner_scheduler.py scan https://github.com/owner/repo

# Manage targets
python scanner_scheduler.py add https://github.com/owner/repo --interval 24
python scanner_scheduler.py list

# Continuous watch loop
python scanner_scheduler.py run --interval 300
```

## Architecture

```
server.py               Flask API — 15 endpoints, rate limiting, tiered access
config.py               Environment config, 7 chains, 3 pricing tiers
advanced_auditor.py     Core engine — 80+ vuln patterns, multi-chain Etherscan
repo_scanner.py         Git clone → file discovery → pattern analysis
source_analyzer.py      solc/forge compilation, AST extraction, call graphs
scanner_scheduler.py    SQLite targets/history, continuous poll loop, CLI
```

## Vulnerability Patterns

The pattern engine covers:

| Category | Examples |
|----------|----------|
| Reentrancy | State after external call, cross-function, read-only |
| Access Control | Missing modifiers, unprotected selfdestruct, tx.origin |
| Oracle | Price manipulation, stale data, single-source dependency |
| Flash Loan | Unchecked callback, price in same block |
| MEV | Sandwich vectors, front-running exposure |
| Arithmetic | Unchecked math, precision loss, rounding |
| DeFi-specific | Slippage, donation attacks, fee-on-transfer |

Each pattern checks for known protections (ReentrancyGuard, access modifiers, oracle guards) before flagging — reducing false positives.

## Configuration

All settings via environment variables (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `ETHERSCAN_API_KEY` | — | Required for on-chain audits |
| `AUDIT_PORT` | 8080 | Server port |
| `GITHUB_TOKEN` | — | For private repo scanning |
| `SCANNER_WORKSPACE` | `./scanner_workspace` | Clone directory |
| `SCANNER_DB` | `scan_history.db` | SQLite path |
| `LOG_LEVEL` | INFO | Logging verbosity |

## Requirements

- Python 3.10+
- `requests`, `flask`, `flask-cors`
- Optional: `solc` or `forge` in PATH for AST analysis
- Optional: `redis` for production rate limiting

## License

MIT
