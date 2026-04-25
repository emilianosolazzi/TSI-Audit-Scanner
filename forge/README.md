## TSI Forge Plugin

Canonical Foundry package for temporal-state and oracle-composition findings used by the Python pipeline.

### Package Scope

- Concrete adapters live under `src/adapters/`
- Shared scoring and contradiction primitives live under `src/core/`, `src/interfaces/`, and `src/lib/`
- Structured findings are emitted by `test/TSI_Findings_Report.t.sol`
- Runtime adapter coverage includes oracle lag, TWAP skew, ERC-4626 donation previews, read-only reentrancy, governance snapshots, replay claims, SSV state, and fork-aware Aave flash-loan/oracle checks.

### Commands

```shell
forge build
forge test -vv
forge test --match-contract TSI_Findings_Report -vv
forge fmt
```

### Output Artifacts

- `artifacts/tsi_adapter_findings.json`: structured adapter findings emitted from Forge
- `out/`: compiled artifacts
- `cache/`: Foundry cache

### Notes

- The Aave flash-loan adapter is fork-aware and emits a `skipped` finding when no mainnet fork RPC is configured.
- The Python runner copies `artifacts/tsi_adapter_findings.json` into the automation output directory and merges it into `native_merged_findings.json`.
