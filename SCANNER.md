# SCANNER.md — One-Click Audit Scanner

End-to-end Solidity / Vyper auditor. One command, seven phases, CI-ready
output (JSON / SARIF / Markdown).

## Install

```powershell
pip install -r requirements.txt
# Optional (only required for Phase 7 — Foundry plugin):
#   https://book.getfoundry.sh/getting-started/installation
forge --version
```

Optional environment variables:

| Variable            | Purpose                                               |
| ------------------- | ----------------------------------------------------- |
| `GITHUB_TOKEN`      | Clone private repos.                                  |
| `ETHERSCAN_API_KEY` | Required only for the on-chain auditor (`server.py`). |
| `JWT_SECRET`        | Override the default Flask JWT secret in production.  |

## One-click usage

```powershell
# Local repo, default JSON output
python scan.py path\to\repo

# Public GitHub repo
python scan.py https://github.com/org/repo --branch main

# Limit scope to specific subpaths
python scan.py path\to\repo --scope contracts/core contracts/lending

# Include test/script files
python scan.py path\to\repo --include-tests

# Skip Phase 7 (Foundry plugin) when forge isn't installed
python scan.py path\to\repo --no-forge

# Emit JSON + SARIF + Markdown sibling files
python scan.py path\to\repo --out scan_results/run.json `
    --format json sarif markdown
```

## What runs (the seven phases)

1. **Clone / locate** — git clone the URL or use the local path as-is.
2. **Detect framework** — foundry / hardhat / brownie / truffle, plus
   remappings and dependency graph.
3. **Discover sources** — recursive walk, skips `node_modules`, `.git`,
   `cache`, `out`, `artifacts`, `lib`, etc. Test/script files stripped
   unless `--include-tests` is set.
4. **Analyze** — runs in parallel across all source files:
   - 80+ pattern-based detectors (SWC, DEFI, ACCESS, GAS, INIT, TSI…)
   - `CryptoAccessControlAnalyzer` (CRYPTO-IDM / MAL / CTX / RPL)
   - Project-wide novel passes (selector / storage-slot collisions).
5. **Validate** — `FindingValidator` triages every raw finding into
   `confirm_first` / `needs_context` / `likely_noise` and dedupes.
6. **Verify** — `ExploitVerifier` runs the algebraic checks defined in
   `VERIFIER_MAP` (reentrancy, oracle manipulation, share inflation,
   crypto access control, MMR bounds, …) and assigns each candidate an
   `exploit_class`: **CONFIRMED**, LIKELY, CONDITIONAL, INCONCLUSIVE,
   or **DISPROVEN**.
7. **Foundry TSI plugin** *(optional)* — invokes `./forge` harness
   (`TSI_Findings_Report` test) and merges any runtime adapter findings
   back into the result.

## Sample output

```text
========================================================================
  Pipeline result
========================================================================
  status:                complete
  duration:              4.5s
  files scanned:         78
  total findings:        344
  forge plugin status:   pass
  forge plugin findings: 7

========================================================================
  Findings by severity
========================================================================
  CRITICAL 134
  HIGH     15
  MEDIUM   36
  LOW      16
  INFO     124
  GAS      19

========================================================================
  Verifier-CONFIRMED (2)
========================================================================
  CRYPTO-MAL-001       ecrecover_signature_malleability    adj=upgrade_to_HIGH
    -> contracts/lending/tokenization/AToken.sol:328  conf=0.90
  SWC-107              reentrancy_cei_violation            adj=upgrade_to_CRITICAL
    -> contracts/radiant/accessories/Multicall3.sol:158  conf=0.75
```

## Disposition reference

| Class          | Meaning                                                                            |
| -------------- | ---------------------------------------------------------------------------------- |
| `CONFIRMED`    | Algebraically guaranteed exploit conditions met. Triage first.                     |
| `LIKELY`       | High probability, one minor assumption open. Manual review.                        |
| `CONDITIONAL`  | Exploitable only under specific preconditions (caller, market state).              |
| `INCONCLUSIVE` | Verifier could not decide. Treat as a normal severity-tiered finding.              |
| `DISPROVEN`    | Verifier proved the candidate is not exploitable in this code shape. Auto-noise.   |

`severity_adjustment` (`upgrade_to_CRITICAL`, `downgrade_to_INFO`, etc.)
overrides the pattern-database severity when verifier confidence warrants.

## Output formats

| Format     | When to use                                            |
| ---------- | ------------------------------------------------------ |
| `json`     | Default. Full ScanResult — every finding + verifier verdict + triage. |
| `sarif`    | CI / GitHub Code Scanning. Per-finding `physicalLocation` points at the real source path. |
| `markdown` | Human-readable triage handoff.                         |

## Exit codes

| Code | Meaning                                       |
| ---- | --------------------------------------------- |
| `0`  | Scan completed (regardless of findings).      |
| `2`  | Scan failed (`ScanStatus.FAILED`).            |

> The CLI deliberately does **not** fail the build on findings — gating
> is the consumer's job (parse the SARIF / JSON in CI and threshold on
> CONFIRMED / CRITICAL counts).

## Tests

```powershell
python -m pytest tests/test_verifier_regression.py -q
python scripts/run_benchmark.py --corpus tests/fp_benchmark_corpus --output benchmarks/results/fp_latest.json --min-precision 1 --min-recall 1 --max-safe-fp-rate 0
```

Each test in `tests/test_verifier_regression.py` exercises a single
`VERIFIER_MAP` branch with both a vulnerable and a properly guarded
fixture. Add a paired test whenever you add a new verifier branch.

The false-positive benchmark corpus in `tests/fp_benchmark_corpus` tracks
known-safe audited patterns. Unexpected findings fail the gate; retained
informational signals should be listed as `allowed_findings` in the corpus
manifest so they stay visible without counting as false positives.
