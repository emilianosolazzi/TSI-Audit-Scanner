# False-Positive Benchmark Corpus

This corpus is the seed for roadmap item 2: known-safe false-positive benchmarking.

Every case in `manifest.json` is classified as `safe`, so any scanner finding that is not listed in `allowed_findings` is counted as a false positive. The current fixtures are compact representative shapes modeled after audited contract families; the manifest also names the external projects that should be mirrored or checked out to grow this into a 50-100 contract production corpus.

Run it with:

```shell
python scripts/run_benchmark.py --corpus tests/fp_benchmark_corpus --output benchmarks/results/fp_latest.json --min-precision 1 --min-recall 1 --max-safe-fp-rate 0
```

The benchmark runner disables the Forge runtime plugin by default so source-level false-positive rates are not polluted by adapter findings.