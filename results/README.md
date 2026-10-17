# Results

`run4_summary.csv`: results of the full benchmark campaign (harness v13) on an Intel Core i5-1035G1 laptop, Windows, native build, clock not locked.
Command: `cargo run --release -p hec-bench --features baselines --bin hec-bench -- --label i5-1035G1 --out run4.csv`.
`units` are nanoseconds per calibration step, `cycles_est` = units x 0.5 (empirical estimate), `range_pct` is the run-to-run range, `clean_pct_min` the minimum fraction of clean samples.
The Ed25519 doubling row (range 38%) is unreliable and excluded from the paper. Transcribed from the console output; the original `run4.csv` can be added here.
