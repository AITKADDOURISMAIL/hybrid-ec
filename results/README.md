# Results

All files were produced on an Intel Core i5-1035G1 laptop, Windows, native build, clock not locked. The CSV files were transcribed from the console output of the harness; the original raw files can be added here.

- `run4_summary.csv`: single-operation campaign (harness v13). Command: `cargo run --release -p hec-bench --features baselines --bin hec-bench -- --label i5-1035G1 --out run4.csv`.
- `run5_batch_summary.csv`: Ed25519 batch verification (second campaign).
- `run6_block_summary.csv`: block validation and block failure scenarios (third campaign).
- `run7_ct_summary.csv`: dudect-style constant-time test, shipped code and the `naive-select` build.
- `run8_diff2_output.txt`: output of the differential test against the libraries on Wycheproof vectors and random mutations. The project-vector comparison is the output of `cargo run --release -p hec-bench --features baselines --bin diff` on `validation/tests/validation.txt` (456 Ed25519 cases, including 28 mixed-order-key cases added by `reference/gen_vectors_mixed_order.py`).

Timing columns: each sample is normalized by a calibration loop run immediately before and after it, so `units` is the time of one operation expressed in calibration steps (batch ns per operation divided by the mean calibration ns per step), not a time in nanoseconds. `cycles_est` = units x 0.5 (empirical constant, see the paper for its uncertainty). `range_pct` is the run-to-run range, and `clean_pct_min` the minimum fraction of clean samples.
The Ed25519 doubling row of `run4_summary.csv` (range 38%) is unreliable and is not reported in the paper's table.

## run11 (constant-time evidence, 2026-10-31)
- `run11_ct_shipped_all_laptop_pinned.csv`, `run11_ct_naive_all_laptop_pinned.csv`: dudect-style test of all routines (Windows laptop, turbo off, maximum processor state 99 %), shipped build and `--features naive-select`.
- `run11_ctgrind.txt`: ctgrind-style check with valgrind (`bench/ctgrind.sh`): 0 findings for the shipped build; for the naive build no conditional branch but secret-dependent addresses in all five routines.
- `asm_*_Point_select.s`: x86-64 assembly (rustc 1.x, Linux container) of `ed25519::Point::select`: masked and/xor in the shipped build, `test; cmovne` on the operand pointers followed by loads through the selected pointer in the naive build.

## Official BIP-340 vectors
`validation/tests/bip340_official.csv` is the unchanged `bip-0340/test-vectors.csv` of the BIP repository (19 cases); `validation/tests/bip340_official.rs` runs it through the unified verifier, the single-curve counterpart and the batch verifier.

## run12 (second processor)
Intel Core 3 100U (6 cores / 8 threads as reported by Windows), Windows 11 10.0.26200, rustc 1.99.1, tag v1.2.1.
Thread pinned with `start /affinity 1` (assumed to be a performance core, not verified); frequency not locked and not read from a counter
(calibration step 0.156-0.558 ns during the benchmark). The 0.5 cycle/unit constant of the first machine does not apply: use ratios only.
- `run12_cpu2_ct_shipped.csv`, `run12_cpu2_ct_naive.csv`: dudect-style test, 5 campaigns x 10^5 measurements, shipped and `naive-select` builds.
- `run12_cpu2_bench.csv`: `verify/` benchmarks (unified, dedicated arithmetic only, dedicated).
- `run12_cpu2_cpu_name.txt`: processor model.
