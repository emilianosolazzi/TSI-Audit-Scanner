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

### 5. **Spec-Implementation Contradiction (SIC)**
Detect contradictions across administrative and operational paths where `D(spec) ≠ D(impl)`:
- Parse documentation for explicit capability claims (e.g., `address(0)` disables X, `deactivate()` stops Y)
- Trace the corresponding implementation path and reachability
- Flag where the documented path is structurally unreachable or contradicts the codebase

*What others do:* Rely entirely on humans to read the spec and compare it to the code. We begin bridging NLP documentation extraction with reachability analysis.

### 6. **Differential Code Analysis**
Hunt for vulnerabilities in newer code paths post-audit:
- Identify audit checkpoints (prior audits, test coverage)
- Flag novel surfaces (initialization, upgrade paths, new token mechanics)
- Prefer bounded fuzzing over speculation

*What others do:* Re-audit everything. We focus on delta risk.

### 7. **Dead Code Reachability Validator (DCR)**
Flag defensive checks, modifiers, or guards that can never be reached given the current setter/initializer logic:
- `DCR: code_path(P) is reachable ↔ ∃ execution_trace T such that T reaches P`
- Catches entire classes of "designed but impossible" safety mechanisms (like `_checkWhitelist` bypassing on `address(0)` while `_setWhitelist` reverts).

### 8. **Emergency Path Coverage (EPC) pass**
A specialized audit pass isolating emergency and recovery functions:
- Explicit checks for `pause()`, `unpause()`, `deactivate()`, `emergencyWithdraw()`, and `setX(address(0))`.
- Verifies realistic execution paths against the current environment state.
- *Why:* Emergency functions are disproportionately likely to be broken since they are rarely tested and often bolted on late.

### 9. **Governance Timelock Gap Analysis (GTGA)**
Directly feeds into severity scoring by quantifying the time delta introduced by a broken emergency path:
- `impact_window = recovery_time(with_bug) - recovery_time(without_bug)`
- Without a native escape hatch, recovery might require an arbitrary proxy upgrade through a 48-hour timelock, functionally elevating the exploit window by 48 hours.

### 10. **Documentation Coverage Score (DCS)**
Heuristic calculation mapping `DCS = |documented_capabilities| / |verified_reachable_capabilities|`.
A ratio below 1.0 flags the protocol for high-priority manual review, as certain documented capabilities are structurally unimplementable.

### 11. **Initializer State Assumption Validator (ISAV)**
Validates that every state assumption made in modifiers and guards is actually established somewhere in the initialization path:
- `ISAV: ∀ state_assumption A in modifier M, ∃ initializer I such that I guarantees A`
- Catches cases where a modifier assumes a condition (like `whitelist != address(0)`), but nothing in the contract lifecycle ever guarantees it was properly set up.

---

## Quick Comparison

| Feature | TSI-Scanner | Slither | MythX | Certik | Defender |
|---------|-------------|---------|-------|--------|----------|
| Static analysis | ✓ | ✓ | ✓ | ✓ | ✗ |
| On-chain audit | ✓ | ✗ | ✗ | ✓ | ✓ |
| Repo scanning | ✓ | ✓ | ✗ | ✓ | ✗ |
| Consistency detection | **✓** | ✗ | ✗ | Partial | ✗ |
| Spec-Impl Contradiction (SIC) | **✓** | ✗ | ✗ | ✗ | ✗ |
| Protection-first | **✓** | ✗ | ✗ | ✗ | ~ |
| Execution context | **✓** | ✗ | Partial | Partial | Partial |
| Multi-chain | ✓ | ✓ | ✓ | ✓ | ✓ |
| Scheduler/monitoring | ✓ | ✗ | ✗ | ✓ | ✓ |
| REST API | ✓ | ✗ | ✓ | ✗ | ✓ |
| Free/open | ✓ | ✓ | ✗ | ✗ | ✗ |

---

## Features

- **Consistency Auditor** — Detect state contradictions across callback, reentrancy, oracle, and access control contexts
- **Spec-Implementation Contradiction (SIC)** — Verify `D(spec) = D(impl)` across documented administrative workflows and code reachability
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

# Configure (only needed for the on-chain auditor / REST API)
cp .env.example .env
# Edit .env — set ETHERSCAN_API_KEY at minimum
```

### Option A — One-click full scan (recommended)

Runs all seven pipeline phases (clone → discover → analyze → validate →
verify → forge plugin) in a single process and emits JSON / SARIF /
Markdown side-by-side. See [SCANNER.md](SCANNER.md) for the full guide.

```bash
# Local repo
python scan.py path/to/repo

# Public GitHub repo, multi-format output
python scan.py https://github.com/owner/repo \
    --out scan_results/run.json \
    --format json sarif markdown

# Skip Phase 7 (Foundry plugin) when forge isn't installed
python scan.py path/to/repo --no-forge
```

### False-positive benchmark gate

The scanner includes a known-safe Solidity corpus for tracking false-positive
drift across common audited patterns. Phase 7 Forge runtime findings are
disabled by default so the gate measures source-level precision.

```bash
python scripts/run_benchmark.py \
  --corpus tests/fp_benchmark_corpus \
  --output benchmarks/results/fp_latest.json \
  --min-precision 1 \
  --min-recall 1 \
  --max-safe-fp-rate 0
```

Use `--with-forge-plugin` only when you explicitly want runtime adapter
findings included in the benchmark output.

### Option B — REST API + scheduler

```bash
# Run server
python server.py

# Or scan a repo via the legacy CLI scheduler
python scanner_scheduler.py scan https://github.com/owner/repo --scope contracts/
```

## Repository Layout (Canonical)

- Core Python service (runtime + API): `server.py`, `advanced_auditor.py`, `repo_scanner.py`, `scanner_scheduler.py`, `source_analyzer.py`, `config.py`, `report_generator.py`, `finding_validator.py`, `exploit_verifier.py`
- Canonical Foundry plugin package: `forge/`
- Core automation and validation: `scripts/`, `tests/`
- Non-core protocol research and historical workspaces: `research/`
- Generated artifacts: `scan_results/`, `reports/`, `speed_tests/automation/`, `scanner_workspace/`

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
- `speed_tests/automation/tsi_plugin_result.json`
- `speed_tests/automation/tsi_plugin_test_output.log`

TSI plugin integration options:

```bash
python scripts/intelligent_e2e_flow.py \
  --input-scan speed_tests/scroll_usx/scan_result_full.json \
  --outdir speed_tests/automation \
  --tsi-plugin-dir forge \
  --tsi-match-contract TSI_Aave_FlashLoan_Oracle \
  --tsi-findings-contract TSI_Aave_FlashLoan_Oracle \
  --tsi-fork-url "$ETH_RPC_URL" \
  --tsi-enforce-pass
```

- By default, structured findings are read from the same contract provided to `--tsi-match-contract`.
- Set `--tsi-findings-contract TSI_Findings_Report` to keep legacy generic adapter findings.
- Set `--tsi-findings-artifact <relative/path.json>` if your custom harness writes findings to a non-default artifact path.
- Without `--tsi-fork-url`, the plugin runs in local mode and safely reports `skipped` when fork-only tests cannot execute.
- With `--tsi-enforce-pass`, the pipeline fails unless the TSI plugin status is `pass`.
- Intelligent E2E now runs the plugin in a dedicated post-report step, so scanner-side Phase 7 findings are not double-counted in `full_e2e_report.json`.

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
scan.py                   One-click CLI — runs the full 7-phase pipeline
server.py                 Flask API — 15 endpoints, rate limiting, tiered access
config.py                 Environment config, 7 chains, 3 pricing tiers
advanced_auditor.py       Core engine — 80+ vuln patterns, consistency auditor (TSI),
                          protection-first detection, multi-chain Etherscan
repo_scanner.py           Phase 1-7 orchestrator: clone, discover, analyze (parallel),
                          validate, verify, forge plugin
novel_analyzers.py        CryptoAccessControlAnalyzer (CRYPTO-IDM/MAL/CTX/RPL),
                          guard-dominance, selector / storage-slot collisions
finding_validator.py      Triage findings into confirm_first / needs_context / likely_noise
exploit_verifier.py       Algebraic verifiers per VERIFIER_MAP entry; emits CONFIRMED /
                          LIKELY / CONDITIONAL / INCONCLUSIVE / DISPROVEN dispositions
report_generator.py       JSON / SARIF v2.1.0 / Markdown emitters
source_analyzer.py        solc/forge compilation, AST extraction, call graphs
scanner_scheduler.py      SQLite targets/history, continuous poll loop, CLI
forge/                    Foundry TSI plugin harness (Phase 7 adapters)
tests/                    Pytest regression suite (one fixture per VERIFIER_MAP entry)
```

### Seven-phase pipeline (`scan.py` / `RepoScanner.scan_repo`)

| # | Phase | What it does |
|---|-------|--------------|
| 1 | Clone / locate | git clone the URL or use the local path as-is |
| 2 | Detect framework | foundry / hardhat / brownie / truffle, plus remappings |
| 3 | Discover sources | recursive walk; skips `node_modules`, `.git`, `cache`, `out`, `artifacts`, `lib`; strips test/script files unless `--include-tests` |
| 4 | Analyze (parallel) | 80+ pattern detectors + `CryptoAccessControlAnalyzer` + project-wide novel passes (selector / storage-slot collisions) |
| 5 | Validate | `FindingValidator` triages every raw finding and dedupes |
| 6 | Verify | `ExploitVerifier` runs the algebraic check defined in `VERIFIER_MAP` and assigns CONFIRMED / LIKELY / CONDITIONAL / INCONCLUSIVE / DISPROVEN |
| 7 | Foundry plugin | (optional) invokes `./forge` `TSI_Findings_Report` test and merges runtime adapter findings |

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
| **Cryptographic access control** | `CRYPTO-IDM-001` (truncated identity hash), `CRYPTO-MAL-001` (ECDSA s-malleability), `CRYPTO-CTX-001` (missing chainId / verifyingContract domain), `CRYPTO-RPL-001` (signature replay / missing nonce), `CRYPTO-DSM-001` (domain-separator mutability / semantic mismatch) |
| **Intent / Permit (ERC-7683 / Permit2)** | `INTENT-RDR-001` (intent redirection / unbound `orderData` field — implicit parameter injection), `INTENT-PMT-001` (ghost-permit bypass — `permit()` + `transferFrom` without try/catch or allowance recheck) |
| Reentrancy | State after external call, cross-function, read-only |
| Access Control | Missing modifiers, unprotected selfdestruct, tx.origin |
| Oracle | Price manipulation, stale data, single-source dependency |
| Flash Loan | Unchecked callback, price in same block |
| MEV | Sandwich vectors, front-running exposure |
| Arithmetic | Unchecked math, precision loss, rounding |
| DeFi-specific | Slippage, donation attacks, fee-on-transfer |

### Verifier dispositions

The Phase 6 `ExploitVerifier` doesn't just keep or drop findings — it
assigns each candidate an `exploit_class` so the consumer can gate on
algebraically-confirmed bugs:

| Class | Meaning |
|-------|---------|
| `CONFIRMED` | Algebraically guaranteed exploit conditions met. Triage first. |
| `LIKELY` | High probability, one minor assumption open. Manual review. |
| `CONDITIONAL` | Exploitable only under specific preconditions (off-chain integration, market state, caller). |
| `INCONCLUSIVE` | Verifier could not decide. Treat as a normal severity-tiered finding. |
| `DISPROVEN` | Verifier proved the candidate is not exploitable in this code shape. Auto-noise. |

The verifier is **self-calibrating** — known false-positive shapes are
encoded as protection checks (e.g., `permit` style malleability is
auto-downgraded to `CONDITIONAL` when the function consumes an
in-contract nonce in the same body; reentrancy on stateless
Multicall-style forwarders is auto-classified `DISPROVEN`).
All calibrations are covered by `tests/test_verifier_regression.py`.

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
