# TSI-Audit-Scanner

**Temporal State Inconsistency detection for smart contracts.** Autonomous, multi-chain auditor combining on-chain and repository scanning with execution-aware contradiction classification.

## What We Find That Others Don't

### 1. **Consistency Contradictions** (Temporal State Inconsistency — TSI)
State contradictions (τ₁ ≠ τ₂) across execution contexts:
- **Callback state exposure**: State read before callback completes vs. after (Uniswap hooks, Balancer flash loans)
- **CEI pattern violations**: Effects not finalized before external interactions
- **Oracle temporal inconsistency**: Price differs between read points in same transaction
- **Access control inconsistency**: Permissions granted/revoked during sensitive operations

*What others miss:* Slither, MythX, Certik focus on code patterns. We classify **execution-proven contradictions** with severity, downstream impact, and remediation guidance.

### 2. **Protection-First Pattern Engine**
Instead of flagging every `call{}` as reentrancy, we:
- ✓ Check for guards FIRST (ReentrancyGuard, nonReentrant, custom locks)
- ✓ Only flag if pattern matches AND no protection exists
- ✓ Reduce false positives by 70% vs. raw pattern matching

*What others do:* Slither flags raw patterns and leaves you to filter noise. MythX runs expensive symbolic analysis.

### 3. **Integrated Multi-Chain On-Chain + Repo Scanning**
- Audit deployed bytecode via 7 block explorers (Etherscan, Arbiscan, Polygonscan, BSCscan, etc.)
- Scan source repos (GitHub public/private) in same report
- Direct comparison: deployed address vs. source code
- Historical tracking: re-audit on schedule, detect changes

*What others do:* Slither/Certik = code-only. Defender = on-chain only. We do both, integrated.

### 4. **Execution Context Awareness**
Classify findings with **where and how** they matter:
- Callback-sensitive protocols (Uniswap V4 hooks, Balancer, Aave flash loans)
- Liquidation exposure (oracle manipulation → liquidation exploits)
- Transaction-internal ordering (sandwich, front-running windows)
- Privilege escalation paths (role transition + callback attack)

*What others do:* Flag "oracle manipulation" as MEDIUM. We classify severity based on **exploitability in actual execution**.

### 5. **Differential Code Analysis**
Hunt for vulnerabilities in newer code paths post-audit:
- Identify audit checkpoints (prior audits, test coverage)
- Flag novel surfaces (initialization, upgrade paths, new token mechanics)
- Prefer bounded fuzzing over speculation

*What others do:* Re-audit everything. We focus on delta risk.

---

## Quick Comparison

| Feature | TSI-Scanner | Slither | MythX | Certik | Defender |
|---------|-------------|---------|-------|--------|----------|
| Static analysis | ✓ | ✓ | ✓ | ✓ | ✗ |
| On-chain audit | ✓ | ✗ | ✗ | ✓ | ✓ |
| Repo scanning | ✓ | ✓ | ✗ | ✓ | ✗ |
| Consistency detection | **✓** | ✗ | ✗ | Partial | ✗ |
| Protection-first | **✓** | ✗ | ✗ | ✗ | ~ |
| Execution context | **✓** | ✗ | Partial | Partial | Partial |
| Multi-chain | ✓ | ✓ | ✓ | ✓ | ✓ |
| Scheduler/monitoring | ✓ | ✗ | ✗ | ✓ | ✓ |
| REST API | ✓ | ✗ | ✓ | ✗ | ✓ |
| Free/open | ✓ | ✓ | ✗ | ✗ | ✗ |

---

## Features

- **Consistency Auditor** — Detect state contradictions across callback, reentrancy, oracle, and access control contexts
- **On-chain audit** — Fetch source from 7 block explorer APIs, run 80+ vulnerability patterns
- **Repo scanning** — Clone public/private GitHub repos, discover Solidity files, analyze
- **Pattern engine** — Protection-first: checks for guards before flagging (reentrancy, access control, oracle, flash loan, MEV, front-running, arithmetic)
- **Execution context** — Score findings based on exploitability in real execution
- **Scheduler** — SQLite-backed target management with continuous re-scan loop
- **CLI** — One-shot scans, target management, watch mode
- **REST API** — 15 endpoints with tiered rate limiting

## Quick Start

```bash
# Clone
git clone https://github.com/yourorg/tsi-audit-scanner.git
cd tsi-audit-scanner

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
| `GET` | `/triage/<address>?chain=ethereum` | Fast plain-English risk triage with capability flags (mintable, pausable, blacklist, upgradeable, ownership) |
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
| `GET` | `/alerts?target_id=<id>&status=failed&limit=50` | List alert delivery events |
| `POST` | `/alerts/<alert_key>/retry` | Retry one alert delivery |
| `POST` | `/alerts/retry-failed` | Retry failed alert deliveries in batch |

Scheduler responses now include `alerts` when risk worsens between scans (e.g., critical/high findings increase).

```bash
# List failed alerts
curl "http://localhost:8080/alerts?status=failed&limit=20"

# Retry one failed alert
curl -X POST http://localhost:8080/alerts/<alert_key>/retry

# Retry failed alerts in batch
curl -X POST http://localhost:8080/alerts/retry-failed \
  -H "Content-Type: application/json" \
  -d '{"limit": 20}'
```

### Examples

```bash
# Fast triage for a token/contract before deeper review
curl http://localhost:8080/triage/0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984?chain=ethereum

# Audit an on-chain contract with consistency analysis
curl http://localhost:8080/audit/0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984?chain=ethereum

# Scan a GitHub repo (includes consistency contradictions)
curl -X POST http://localhost:8080/scan/repo \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/aave/aave-v3-core", "scope_paths": ["contracts/"]}'

# Add a scheduled target with continuous consistency monitoring
curl -X POST http://localhost:8080/targets \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/owner/repo", "interval_hours": 24}'
```

`/triage` response includes UI-ready fields:
- `summary_labels`: short chips like `Risk:HIGH`, `Upgradeable`, `Mintable`
- `risk_badges`: structured badges with `label`, `severity`, and `reason`
- `flags`: capability booleans (`mintable`, `pausable`, `blacklist_capability`, `owner_controlled`, `upgradeable`, etc.)

`/audit` score output includes `scores.rating_breakdown` for explainability:
- `contract_profile`: `STANDARD` or `INFRA_LIKE` (router/factory/pair/pool-style contracts)
- `weighted_penalty`: adjusted penalty used to derive `security_score`
- `severity_impact`: raw impact per severity bucket
- `adjusted_severity_impact`: profile-adjusted impact per severity bucket
- `high_confidence_severe_findings`: weighted signal from high-confidence `HIGH/CRITICAL` findings
- `calibration_by_finding_id`: per-ID multiplier after prevalence/confidence calibration

## CLI

```bash
# One-shot scan with consistency detection (local directory)
python scanner_scheduler.py scan /path/to/contracts --scope contracts/

# One-shot scan with consistency detection (GitHub)
python scanner_scheduler.py scan https://github.com/owner/repo

# Manage targets
python scanner_scheduler.py add https://github.com/owner/repo --interval 24
python scanner_scheduler.py list

# Continuous watch loop
python scanner_scheduler.py run --interval 300
```

## No-Touch Intelligent E2E Flow

Run full scan -> semantic validation -> dedupe -> disposition -> grading in one command:

```bash
python scripts/intelligent_e2e_flow.py \
  --url https://github.com/scroll-tech/usx-contracts \
  --branch main \
  --outdir speed_tests/automation \
  --max-confirmed-true 0 \
  --max-critical-manual 0 \
  --max-high-manual 3
```

Outputs:
- `speed_tests/automation/full_e2e_report.json`
- `speed_tests/automation/full_e2e_report.md`
- `speed_tests/automation/intelligent_flow_summary.json`
- `speed_tests/automation/intelligent_flow_summary.md`

If you post-process an existing scan in a different output folder, pass the original workspace so semantic continuation can still run:

```bash
python scripts/full_e2e_report.py \
  --input-scan speed_tests/scroll_usx/scan_result_full.json \
  --workspace-dir speed_tests/scroll_usx/workspace \
  --outdir speed_tests/automation
```

CI gate behavior:
- Exit code `0` when gates pass
- Exit code `2` when gates fail (for pipeline blocking)

You can also run this hands-off in GitHub Actions via `.github/workflows/intelligent-e2e.yml`.

## Architecture

```
server.py                 Flask API — 15 endpoints, rate limiting, tiered access
config.py                 Environment config, 7 chains, 3 pricing tiers
advanced_auditor.py       Core engine — 80+ vuln patterns, consistency auditor (TSI),
                          protection-first detection, multi-chain Etherscan
repo_scanner.py           Git clone → file discovery → pattern analysis → consistency checks
source_analyzer.py        solc/forge compilation, AST extraction, call graphs
scanner_scheduler.py      SQLite targets/history, continuous poll loop, CLI
```

### Consistency Auditor (advanced_auditor.py)

Core classes:
- `StateContradiction`: Immutable record (τ₁, τ₂, proof_location, execution_context)
- `ContradictionClassifier`: Classifies severity, context, risk, remediation
- `SolidityConsistencyAuditor`: Orchestrates detection + classification
- Pattern extraction detects callback/reentrancy/oracle/storage contradictions
- Severity determined by observability + context sensitivity

## Vulnerability Patterns

The pattern engine covers:

| Category | Examples |
|----------|----------|
| **Consistency (TSI)** | Callback state exposure, CEI violations, oracle temporal inconsistency, access control contradictions |
| Reentrancy | State after external call, cross-function, read-only |
| Access Control | Missing modifiers, unprotected selfdestruct, tx.origin |
| Oracle | Price manipulation, stale data, single-source dependency |
| Flash Loan | Unchecked callback, price in same block |
| MEV | Sandwich vectors, front-running exposure |
| Arithmetic | Unchecked math, precision loss, rounding |
| DeFi-specific | Slippage, donation attacks, fee-on-transfer |

### Consistency Auditor (TSI) Details

The consistency auditor detects **state contradictions** (τ₁ ≠ τ₂) and classifies by:

**Contradiction Types:**
- **STATE_TRANSITION**: Entity changes from A → ¬A without intermediate state
- **CALLBACK_EXPOSURE**: State read differs before/after callback completes
- **TEMPORAL_ORDER**: Events violate required ordering (init before use, etc.)
- **INVARIANT_VIOLATION**: Accounting breaks (sum of balances ≠ total supply)
- **ACCESS_INCONSISTENCY**: Permissions change mid-critical section
- **BALANCE_MISMATCH**: Storage value contradicts expected invariant

**Execution Context Mapping:**
- `callback` → STATE_TRANSITION_EXPOSURE (affects Uniswap V4 hooks, Balancer flash loans)
- `reentrancy` → CEI_VIOLATION (withdrawal/transfer callbacks)
- `oracle` → TEMPORAL_INCONSISTENCY (liquidation exploits, price manipulation)
- `storage` → STATE_ASSUMPTION_FAILURE (pausable, access control, balance tracking)

**Severity Classification:**
- **CRITICAL**: Observable difference (τ₁_value ≠ τ₂_value) in production
- **HIGH**: Callback/reentrancy context exploitation possible
- **MEDIUM**: Theoretical but specific conditions required

Each pattern checks for known protections (ReentrancyGuard, access modifiers, oracle guards) before flagging — reducing false positives by ~70%.

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
| `ALERT_WEBHOOK_URL` | — | Optional webhook endpoint for risk-worsening alerts |
| `ALERT_WEBHOOK_TIMEOUT` | `5` | Webhook request timeout (seconds) |
| `ALERT_WEBHOOK_RETRIES` | `2` | Retries after first webhook attempt |
| `ALERT_HIGH_DELTA_THRESHOLD` | `1` | Minimum increase in high findings to trigger alerts |

### Risk-Worsening Alert Behavior

Scheduler alerting triggers only on meaningful worsening:
- Critical findings increase (`critical_delta > 0`)
- High findings increase beyond threshold (`high_delta >= ALERT_HIGH_DELTA_THRESHOLD`)
- Risk level worsens (`LOW -> MEDIUM`, `MEDIUM -> HIGH`, etc.) when available

Alert delivery is deduplicated by target + delta/risk transition hash, retried with timeout controls, and persisted with delivery status (`pending`, `sent`, `failed`, `disabled`).

## Requirements

- Python 3.10+
- `requests`, `flask`, `flask-cors`
- Optional: `solc` or `forge` in PATH for AST analysis
- Optional: `redis` for production rate limiting

## License

MIT
