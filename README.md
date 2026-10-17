# hybrid-ec — research prototype (NOT audited, do not use in production)

Companion code for the paper on hybrid Weierstrass/Edwards/Montgomery arithmetic.

- `core/`       Layer A: GF(2^255-19) 5x51 and GF(secp256k1 p) 5x52 (done, tested vs big-int). TODO: safegcd inversion.
- `curves/`     Layer B: secp256k1 (RCB), Ed25519 extended, X25519, fixed-base signed-digit, vartime wNAF, GLV (constants verified in Python: lambda^3=1, beta^3=1, lambda*G=(beta*x,y), lattice basis det=n), 256-bit helpers (bn). `pippenger.rs`: variable-time multi-scalar multiplication.
- `validation/` Layer C: SHA-256/512, Ed25519 P_c/P_s (+fast), BIP-340 and ECDSA verify (GLV; ECDSA accepts high-S), differential-tested vs Python oracles.
- `bench/`      TODO: Section 5 protocol harness (N=10,000 reps, R=5 runs, median of medians).
- `reference/`  Python big-int oracles: `gen_vectors.py`, `gen_vectors_k1.py` (fields), `gen_vectors_secp256k1.py`, `gen_vectors_ed25519.py` (points, decode, X25519), `gen_vectors_validation.py`, `secp_sigs.py` (BIP-340 vector 0 reproduced), `vp_ed25519.py` (V_P, RFC 8032 checked).

Run: `cargo test --release` ; `python3 -I reference/vp_ed25519.py`.
Benchmarks must be run on your own frequency-locked i5-1035G1; none were run here.

## Benchmarking (run on your own machine, not in the cloud)
Release build only. Plug in the laptop and fix the frequency as far as Windows allows (High
performance plan, turbo off), e.g. in an elevated PowerShell:
    powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 0
    powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100
    powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
    powercfg /setactive SCHEME_CURRENT
Close other programs, then:
    cargo run --release -p hec-bench -- --label i5-1035G1 --filter field   # quick check
    cargo run --release -p hec-bench -- --label i5-1035G1                  # full: N=10000, R=5
Results are printed and appended to bench_results.csv (send that file back).

## Baselines and differential check against real libraries (needs internet for crates.io)
    cargo run --release -p hec-bench --features baselines --bin diff      # verdict agreement report
    cargo run --release -p hec-bench --features baselines -- --label i5-1035G1 --filter baseline/
Libraries: ed25519-dalek 2 (verify, verify_strict), ed25519-zebra 4 (ZIP-215), secp256k1 0.29
(libsecp256k1 C), k256 0.13. The first build compiles libsecp256k1 and needs the MSVC tools.

## Timing method (clock-state independent)
Laptop cores switch clock state several times per second; on the i5-1035G1 every operation changed by
the same factor (2.97, sd 1.3%) between two states, so time is proportional to frequency. Every sample
is normalized individually: a short fixed-work calibration runs right before and after the timed batch,
units = batch ns per op / mean calibration ns per step. A sample whose two calibrations differ by more
than --tol % (default 25) is dirty and excluded; each of the R passes reports the median of its clean
samples, and the report gives the median of the pass medians, the range, and the minimum clean fraction.
Cycle estimates use an empirical constant (0.5 cycles per calibration step, consistent with 3.6 GHz and
1.0 GHz) and are estimates. One complete file per session:
    cargo run --release -p hec-bench --features baselines --bin hec-bench -- --label i5-1035G1 --out run4.csv

## Batch verification benchmark
    cargo run --release -p hec-bench --features baselines --bin hec-bench -- --label i5-1035G1 --filter batch/ --out run5.csv
Measures Ed25519 P_c batch verification (Pippenger, 2u+1 points) for u = 1, 4, 16, 64, 256, 1024 distinct signatures, individual
verification of the same items (u <= 256), and ed25519-dalek `verify_batch` and ed25519-zebra batch. Values are per batch; divide by u.

## Block validation campaign
    cargo run --release -p hec-bench --features baselines --bin hec-bench -- --label i5-1035G1 --filter block/ --runs 3 --out run6.csv
Verifies blocks of N = 500, 1000, 3000, 10000 distinct Ed25519 signatures (individual and batch; ours, dalek, zebra) and, for N = 3000,
finds k = 0, 1, 10 corrupted signatures by batch check plus bisection (leaf 8) versus verifying all individually. The run checks that
the set found equals the set corrupted. Takes 15 to 30 minutes; generating 10,000 signatures at start takes a few seconds.

## Constant-time test (dudect-style)
    cargo run --release -p hec-bench --bin ct -- --out ct_fixed.csv
    cargo run --release -p hec-bench --bin ct --features naive-select -- --filter "control A/A,control positive,fixed-base,x25519" --out ct_naive.csv
First command: routines as shipped (mask hidden from the optimizer with black_box). Second: the original select idiom, which dudect flagged
on the fixed-base multiplications and the X25519 ladder (the compiler can turn the mask idiom into a branch on the secret).
Fixed class = scalar of Hamming weight 2, random class = uniform scalars, random interleaving, |t| > 4.5 means leakage; controls: A/A (must pass),
leaky double-and-add (must fail), field multiplication chain (must pass). Defaults: 100,000 measurements per campaign, 5 campaigns.
The test detects leakage; it cannot prove its absence.

## Differential tests on Wycheproof vectors and random mutations
    cargo run --release -p hec-bench --features baselines --bin diff2 -- 1000000
Vectors: `validation/tests/wycheproof_*.txt` (converted from C2SP/wycheproof testvectors_v1; ECDSA signatures are strict-DER decoded by the converter). Output of the run reported in the paper: `results/run8_diff2_output.txt`.
