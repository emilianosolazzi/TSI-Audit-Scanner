# TSI-Audit-Scanner — Project Guidelines

Autonomous smart contract security scanner. Audits on-chain contracts via block explorer APIs and scans GitHub repos for Solidity vulnerabilities. Exposes a Flask REST API, a CLI scheduler, and Docker deployment.

## Architecture

```
server.py            → Flask REST API (15 endpoints, entry point)
advanced_auditor.py  → On-chain auditing: fetches source from 7 chain explorers, runs 80+ vuln patterns
repo_scanner.py      → Git repo scanning: clone, detect framework, discover .sol files, analyze
source_analyzer.py   → Compilation (solc/forge), AST extraction, call graph analysis
scanner_scheduler.py → SQLite-backed scheduler + CLI (add/list/scan/run targets)
config.py            → Dataclass-based config, tiers (free/pro/enterprise), chain definitions
```

**Data flow:** API request → `AdvancedAuditor.audit()` or `RepoScanner.scan_repo()` → pattern matching against `KNOWN_VULNERABILITIES` with protection-first checks → JSON result.

## Build and Run

```bash
pip install -r requirements.txt       # Install deps
python server.py                      # REST API on :8080
python scanner_scheduler.py scan <url> # One-shot scan
python scanner_scheduler.py run --poll 300  # Continuous scheduler
docker compose up -d                  # Docker deployment
```

Required env var: `ETHERSCAN_API_KEY`. Optional: `GITHUB_TOKEN`, `JWT_SECRET`, `REDIS_URL`. All config via env vars — see `config.py` `Config.from_env()`.

No test suite exists yet.

## Conventions

- **Dataclasses everywhere** — `SolidityFile`, `RepoMetadata`, `ScanResult`, `AuditReport`, `Finding`, `ScanTarget`. Each has a manual `.to_dict()` for JSON serialization.
- **Protection-first pattern engine** — Check for known protections (ReentrancyGuard, access modifiers, oracle guards) BEFORE flagging a vulnerability. Only flag if pattern matches AND no protection exists. See `PROTECTION_PATTERNS` and `SAFE_PATTERNS` dicts in `advanced_auditor.py`.
- **Vulnerability IDs follow prefixes** — `SWC-*` (standard), `TSI-*` (temporal state inconsistency), `DEFI-*` (DeFi-specific), `INIT-*` (initialization), `ACCESS-*`, `GAS-*`.
- **Error handling** — Try-catch at critical paths (git ops, API calls, scanning). Return errors in result dicts rather than raising. Log with `logger.exception()`. No custom exception classes.
- **Thread safety** — `ScanScheduler` uses `threading.Lock()` around all SQLite access (`check_same_thread=False`).
- **IDs** — 16-char truncated SHA256 hex. Timestamps are ISO 8601 with "Z" suffix (UTC).
- **File discovery** — Recursive walk, skip `node_modules`, `.git`, `cache`, `out`, `artifacts`. Classify by naming: `.t.sol` = test, `.s.sol` = script.

## Pitfalls

- `server.py` rate limiting uses an in-memory dict — resets on restart, not shared across workers.
- SQLite DB files (`audit_service.db`, `scan_history.db`) are created at CWD by default — watch for path issues in Docker.
- `SCANNER_WORKSPACE` dir accumulates cloned repos; no automatic cleanup beyond per-scan cleanup.
- The `JWT_SECRET` default is `"change-me-in-production"` — must override in prod.
- No async — all scanning is synchronous. Long scans block the Flask request thread.

## Audit Workflow Learnings

- **Run scope checks before calling something a submission** — verify the exact contract or deployed address is in bounty scope, not just the protocol name.
- **Run prior-audit checks before claiming novelty** — grep public audit reports for the contract name and bug keywords first. If a prior audit already reported the issue and the team acknowledged or accepted the risk, treat it as out of scope.
- **Graph-specific known issue** — `AllocationExchange` cross-chain voucher replay is already known from the 2023 staking/vesting L2 audit. Do not spend more time re-reporting it.
- **Prefer differential hunting on newer code** — older `packages/contracts` surfaces are heavily audited. Better yield comes from newer Horizon, issuance, or post-audit changes.
- **Protection-first still applies to real-world audits** — bespoke guards like `onlyImpl` can be functionally equivalent to OpenZeppelin modifiers even when regexes miss them.
- **PoC discipline** — when a candidate survives code review, prove exploitability with Foundry before escalating severity. Keep one file that proves what works and what is neutralized.
- **Fuzz before speculation** — once obvious auth/signature bugs are exhausted, switch to invariant and stateful fuzzing around accounting, transitions, pause/unpause, and legacy migration paths.
