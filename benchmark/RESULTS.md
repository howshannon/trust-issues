# Benchmark results

Generated 2026-07-15 from commit `26eb7e4`. Regenerate after any ruleset change with `bash benchmark/run_benchmark.sh --results`.

| Metric | Value |
| --- | --- |
| Malicious recall (all) | 0 / 0 |
| — correct category | 0 / 0 |
| — evasive, missed by design | 0 |
| Missed entirely |  none |
| Wrong category |  none |
| False positives (benign flagged) | 4 / 8 (50%) |
| Precision (flags that are truly malicious) | 0.0% |
| Community evasions caught | 0 / 0 |

**Recall** is how many known-malicious techniques are flagged in the *right* category. **Precision** and the **false-positive** count measure how often benign code gets surfaced for review — a scanner tuned only for recall is unusable if it blocks common benign install hooks, so both are reported. **Community evasions** are post-release samples submitted via PR into `benchmark/fixtures/community/`. A clean scan is never proof of safety.
