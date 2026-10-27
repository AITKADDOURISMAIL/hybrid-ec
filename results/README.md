# Results

All files were produced on an Intel Core i5-1035G1 laptop, Windows, native build, clock not locked. The CSV files were transcribed from the console output of the harness; the original raw files can be added here.

- `run4_summary.csv`: single-operation campaign (harness v13). Command: `cargo run --release -p hec-bench --features baselines --bin hec-bench -- --label i5-1035G1 --out run4.csv`.
- `run5_batch_summary.csv`: Ed25519 batch verification (second campaign).
- `run6_block_summary.csv`: block validation and block failure scenarios (third campaign).
- `run7_ct_summary.csv`: dudect-style constant-time test, shipped code and the `naive-select` build.
- `run8_diff2_output.txt`: output of the differential test against the libraries on Wycheproof vectors and random mutations. The project-vector comparison is the output of `cargo run --release -p hec-bench --features baselines --bin diff` on `validation/tests/validation.txt` (456 Ed25519 cases, including 28 mixed-order-key cases added by `reference/gen_vectors_mixed_order.py`).

Timing columns: each sample is normalized by a calibration loop run immediately before and after it, so `units` is the time of one operation expressed in calibration steps (batch ns per operation divided by the mean calibration ns per step), not a time in nanoseconds. `cycles_est` = units x 0.5 (empirical constant, see the paper for its uncertainty). `range_pct` is the run-to-run range, and `clean_pct_min` the minimum fraction of clean samples.
The Ed25519 doubling row of `run4_summary.csv` (range 38%) is unreliable and is not reported in the paper's table.
