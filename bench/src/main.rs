//! Benchmark harness following the paper's Section 5 protocol:
//! N repetitions per run (default 10,000), R independent runs (default 5), report the median
//! of the R per-run medians and the run-to-run range. Operations too short for the clock are
//! batched (`inner` calls per sample) and reported per operation. Inputs rotate through a pool
//! so that no single input is favoured by caches or branch predictors.
//! Usage: hec-bench [--n 10000] [--runs 5] [--filter text] [--label text] [--quick] [--tol 25] [--out file.csv]
use hec_core::{fe25519, fe256k1};
use hec_curves::{bn::*, ed25519, fixed_base::FixedBase, secp256k1, x25519::x25519};
use hec_validation::{secp_sig, sign_for_tests, verify, verify_batch_fast, verify_fast, Policy};
use std::hint::black_box;
use std::io::Write;
use std::time::Instant;
#[cfg(feature = "baselines")]
mod baselines;

fn hx(s: &str) -> Vec<u8> {
    if s == "-" { return vec![]; }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn a32(s: &str) -> [u8; 32] { hx(s).try_into().unwrap() }

/// Fixed-work dependent integer chain; its duration is inversely proportional to the core clock,
/// so it exposes frequency changes between and during benchmarks.
fn calib() -> f64 {
    let mut ts = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        let mut x = black_box(1u64);
        for _ in 0..4_000_000u32 { x = x.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1); }
        black_box(x);
        ts.push(t.elapsed().as_nanos() as f64);
    }
    ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
    ts[2] / 4_000_000.0
}

fn median(v: &mut Vec<f64>) -> f64 { v.sort_by(|a, b| a.partial_cmp(b).unwrap()); v[v.len() / 2] }

struct Cfg { n: usize, runs: usize, filter: String, label: String, out: std::fs::File, ref_calib: f64, tol: f64 }

/// Empirical cycles per calibration step (0.139 ns at 3.6 GHz and 0.505 ns at 1.0 GHz on the
/// i5-1035G1 both give about 0.50). Used only to turn normalized units into an estimated cycle count.
const KAPPA: f64 = 0.50;

/// Short calibration: fixed-work dependent chain of CAL_STEPS steps; returns ns per step.
const CAL_STEPS: u32 = 50_000;
fn mini_calib() -> f64 {
    let t = Instant::now();
    let mut x = black_box(1u64);
    for _ in 0..CAL_STEPS { x = x.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1); }
    black_box(x);
    t.elapsed().as_nanos() as f64 / CAL_STEPS as f64
}

/// `op(i)` performs one operation using pool element i.
/// Laptop cores switch clock state several times per second, and time scales exactly with frequency
/// (checked: all operations changed by the same factor between two states, sd 1.3%). Every sample
/// is therefore normalized individually: a short fixed-work calibration runs immediately before and
/// after the timed batch, and units = (batch ns per op) / (mean calibration ns per step). A sample is
/// dirty, and excluded from the median, when the two calibrations differ by more than `tol` percent
/// (the clock changed while the batch ran). Each of the R passes reports the median of its clean samples.
fn bench<F: FnMut(usize)>(cfg: &mut Cfg, name: &str, mut op: F) {
    if !cfg.filter.is_empty() && !name.contains(&cfg.filter) { return; }
    // choose the batch size so one sample lasts at least ~50 microseconds
    let mut inner = 1usize;
    loop {
        let t = Instant::now();
        for i in 0..inner { op(i); }
        if t.elapsed().as_nanos() >= 50_000 || inner >= 1 << 14 { break; }
        inner *= 2;
    }
    for i in 0..(cfg.n / 10).max(20).min(cfg.n.max(3)) { op(i); } // warm-up, discarded
    let (mut pass_units, mut pass_ns) = (Vec::new(), Vec::new());
    let (mut worst_clean, mut cmin, mut cmax) = (100.0f64, f64::MAX, 0f64);
    for r in 0..cfg.runs {
        let (mut units, mut raws, mut dirty) = (Vec::with_capacity(cfg.n), Vec::with_capacity(cfg.n), 0usize);
        let mut c0 = mini_calib();
        for s in 0..cfg.n {
            let t = Instant::now();
            for i in 0..inner { op(s * inner + i + r); }
            let ns = t.elapsed().as_nanos() as f64 / inner as f64;
            let c1 = mini_calib();
            if 100.0 * (c1 - c0).abs() / c0.min(c1) <= cfg.tol {
                let c = (c0 + c1) / 2.0;
                units.push(ns / c); raws.push(ns); cmin = cmin.min(c); cmax = cmax.max(c);
            } else { dirty += 1; }
            c0 = c1;
        }
        worst_clean = worst_clean.min(100.0 * units.len() as f64 / cfg.n as f64);
        if units.len() >= cfg.n / 10 { pass_units.push(median(&mut units)); pass_ns.push(median(&mut raws)); }
        let _ = dirty;
    }
    if pass_units.is_empty() { println!("{:<44} NO CLEAN SAMPLES  <-- UNSTABLE", name); return; }
    let (mut u, mut ns) = (pass_units.clone(), pass_ns.clone());
    let (um, nm) = (median(&mut u), median(&mut ns));
    let range = 100.0 * (u[u.len() - 1] - u[0]) / um;
    let cyc = um * KAPPA;
    let unstable = worst_clean < 50.0 || pass_units.len() < cfg.runs;
    println!("{:<44} {:>9.0} units  ~{:>9.0} cycles  raw {:>11.1} ns  range {:>5.2}%  clean>={:.0}%  calib {:.3}..{:.3}{}",
        name, um, cyc, nm, range, worst_clean, cmin, cmax, if unstable { "  <-- UNSTABLE" } else { "" });
    writeln!(cfg.out, "{},{},{},{},{},{:.2},{:.1},{:.1},{:.3},{:.1},{:.4},{:.4},{}", cfg.label, name, cfg.n, cfg.runs, inner, um, cyc, nm, range, worst_clean, cmin, cmax, unstable as u8).unwrap();
}

type Item = ([u8; 32], Vec<u8>, [u8; 64]);

/// Identify the invalid items of a block: batch check, then bisection; ranges of at most `leaf` items
/// are verified individually. `batch_ok` must be sound (a passing batch contains no invalid item).
fn locate<B: Fn(&[Item], &[[u8; 16]]) -> bool, S: Fn(&Item) -> bool>(items: &[Item], z: &[[u8; 16]], base: usize, batch_ok: &B, single_ok: &S, leaf: usize, out: &mut Vec<usize>) {
    if batch_ok(items, z) { return; }
    if items.len() <= leaf {
        for (i, it) in items.iter().enumerate() { if !single_ok(it) { out.push(base + i); } }
        return;
    }
    let mid = items.len() / 2;
    locate(&items[..mid], &z[..mid], base, batch_ok, single_ok, leaf, out);
    locate(&items[mid..], &z[mid..], base + mid, batch_ok, single_ok, leaf, out);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let quick = args.iter().any(|a| a == "--quick");
    let n = get("--n").map(|s| s.parse().unwrap()).unwrap_or(if quick { 300 } else { 10_000 });
    let runs = get("--runs").map(|s| s.parse().unwrap()).unwrap_or(5);
    let label = get("--label").unwrap_or_else(|| "unlabeled".into());
    let out_path = get("--out").unwrap_or_else(|| "bench_results.csv".into());
    let new = !std::path::Path::new(&out_path).exists();
    let mut out = std::fs::OpenOptions::new().create(true).append(true).open(&out_path).unwrap();
    if new { writeln!(out, "label,benchmark,N,R,inner,units_median,cycles_est,raw_ns_median,range_units_pct,clean_pct_min,calib_min_ns,calib_max_ns,unstable").unwrap(); }
    let ref_calib = (0..20).map(|_| calib()).fold(f64::MAX, f64::min);
    let tol: f64 = get("--tol").map(|s| s.parse().unwrap()).unwrap_or(25.0);
    let mut cfg = Cfg { n, runs, filter: get("--filter").unwrap_or_default(), label, out, ref_calib, tol };
    println!("N={} R={} label={} dirty-sample tol={}% start calib={:.4} ns (results appended to {})\nunits = ns per calibration step; cycles ~ units x {} (empirical, see source)", n, runs, cfg.label, cfg.tol, cfg.ref_calib, out_path, KAPPA);

    // ---- field arithmetic
    let (fa, fb) = (fe25519::Fe::from_bytes(&[7u8; 32]), fe25519::Fe::from_bytes(&[9u8; 32]));
    bench(&mut cfg, "field/25519/mul", |_| { black_box(black_box(&fa).mul(black_box(&fb))); });
    bench(&mut cfg, "field/25519/square", |_| { black_box(black_box(&fa).square()); });
    bench(&mut cfg, "field/25519/invert", |_| { black_box(black_box(&fa).invert()); });
    let (ka, kb) = (fe256k1::Fe::from_bytes(&[7u8; 32]), fe256k1::Fe::from_bytes(&[9u8; 32]));
    bench(&mut cfg, "field/k1/mul", |_| { black_box(black_box(&ka).mul(black_box(&kb))); });
    bench(&mut cfg, "field/k1/square", |_| { black_box(black_box(&ka).square()); });
    bench(&mut cfg, "field/k1/invert", |_| { black_box(black_box(&ka).invert()); });

    // ---- point operations
    let g = secp256k1::generator();
    let g2 = g.double();
    bench(&mut cfg, "point/k1/add (RCB complete)", |_| { black_box(black_box(&g).add(black_box(&g2))); });
    bench(&mut cfg, "point/k1/double (RCB complete)", |_| { black_box(black_box(&g).double()); });
    let b = ed25519::Point::base();
    let b2 = b.double();
    bench(&mut cfg, "point/ed25519/add (unified)", |_| { black_box(black_box(&b).add(black_box(&b2))); });
    bench(&mut cfg, "point/ed25519/double", |_| { black_box(black_box(&b).double()); });

    // ---- scalar multiplication
    let scal: Vec<[u8; 32]> = (0..64u64).map(|i| { let mut k = [0u8; 32]; let mut x = 0x9E3779B97F4A7C15u64.wrapping_mul(i + 1); for c in k.iter_mut() { x ^= x << 13; x ^= x >> 7; x ^= x << 17; *c = x as u8; } k[31] &= 0x7F; k }).collect();
    bench(&mut cfg, "scalar/k1/naive-CT double-and-add", |i| { black_box(g.scalar_mul(black_box(&scal[i % 64]))); });
    bench(&mut cfg, "scalar/ed25519/naive-CT double-and-add", |i| { black_box(b.scalar_mul(black_box(&scal[i % 64]))); });
    for c in [4usize, 5, 6, 7, 8] {
        let fb = FixedBase::new(g, c);
        let name = format!("scalar/k1/fixed-base c={} (table {} pts)", c, fb.table_len());
        bench(&mut cfg, &name, |i| { black_box(fb.mul(black_box(&scal[i % 64]))); });
    }
    for c in [3usize, 4, 5, 6, 7, 8] {
        let fb = FixedBase::new(b, c);
        let name = format!("scalar/ed25519/fixed-base c={} (table {} pts)", c, fb.table_len());
        bench(&mut cfg, &name, |i| { black_box(fb.mul(black_box(&scal[i % 64]))); });
    }
    let (xk, xu) = ([5u8; 32], { let mut u = [0u8; 32]; u[0] = 9; u });
    bench(&mut cfg, "scalar/x25519 ladder", |_| { black_box(x25519(black_box(&xk), black_box(&xu))); });

    // ---- signature verification (valid inputs taken from the test vectors)
    let ed: Vec<([u8; 32], Vec<u8>, [u8; 64])> = include_str!("../../validation/tests/validation.txt").lines()
        .filter_map(|l| { let f: Vec<&str> = l.split(' ').collect(); if f[3] == "1" && f[4] == "1" { Some((a32(f[0]), hx(f[1]), hx(f[2]).try_into().unwrap())) } else { None } }).collect();
    assert!(!ed.is_empty());
    bench(&mut cfg, "verify/ed25519/P_c reference (naive)", |i| { let c = &ed[i % ed.len()]; black_box(verify(&c.0, &c.1, &c.2, Policy::Cofactored)); });
    bench(&mut cfg, "verify/ed25519/P_c fast (wNAF)", |i| { let c = &ed[i % ed.len()]; black_box(verify_fast(&c.0, &c.1, &c.2, Policy::Cofactored)); });
    bench(&mut cfg, "verify/ed25519/P_s fast (wNAF)", |i| { let c = &ed[i % ed.len()]; black_box(verify_fast(&c.0, &c.1, &c.2, Policy::Strict)); });
    let bp: Vec<([u8; 32], Vec<u8>, [u8; 64])> = include_str!("../../validation/tests/bip340.txt").lines()
        .filter_map(|l| { let f: Vec<&str> = l.split(' ').collect(); if f[3] == "1" { Some((a32(f[0]), hx(f[1]), hx(f[2]).try_into().unwrap())) } else { None } }).collect();
    bench(&mut cfg, "verify/bip340 (GLV + wNAF)", |i| { let c = &bp[i % bp.len()]; black_box(secp_sig::bip340_verify(&c.0, &c.1, &c.2)); });
    let ec: Vec<[[u8; 32]; 5]> = include_str!("../../validation/tests/ecdsa.txt").lines()
        .filter_map(|l| { let f: Vec<&str> = l.split(' ').collect(); if f[5] == "1" { Some([a32(f[0]), a32(f[1]), a32(f[2]), a32(f[3]), a32(f[4])]) } else { None } }).collect();
    bench(&mut cfg, "verify/ecdsa (GLV + wNAF)", |i| { let c = &ec[i % ec.len()]; black_box(secp_sig::ecdsa_verify(&c[0], &c[1], &c[2], &c[3], &c[4])); });

    // ---- batch verification (Ed25519, policy P_c): one batch of u signatures per call.
    // Items are drawn with repetition from the pool of valid vectors; Pippenger does not exploit repetition.
    // Reported values are per batch; divide by u for the per-signature cost. Sample counts shrink with u.
    // 1024 distinct keys and signatures, so that no implementation can profit from repeated public keys
    let pool_size: u32 = if cfg.filter.is_empty() || cfg.filter.contains("block") { 10_000 } else { 1024 };
    let pool: Vec<([u8; 32], Vec<u8>, [u8; 64])> = if cfg.filter.is_empty() || "batch/".contains(&cfg.filter) || cfg.filter.starts_with("batch") || cfg.filter.starts_with("block") {
        (0..pool_size).map(|i| { let mut seed = [0u8; 32]; seed[..4].copy_from_slice(&i.to_le_bytes()); seed[4] = 0xA5;
            let msg: Vec<u8> = (0..32u8).map(|j| j ^ (i as u8)).collect();
            let (pk, sig) = sign_for_tests(&seed, &msg); (pk, msg, sig) }).collect()
    } else { Vec::new() };
    if !pool.is_empty() { assert!(pool.iter().all(|c| verify_fast(&c.0, &c.1, &c.2, Policy::Cofactored))); }
    let zs: Vec<[u8; 16]> = (0..10_000).map(|i: u64| { let mut z = [0u8; 16]; let mut x = 0xD1B54A32D192ED03u64.wrapping_mul(i + 1); for c in z.iter_mut() { x ^= x << 13; x ^= x >> 7; x ^= x << 17; *c = x as u8; } z[0] |= 1; z }).collect();
    let saved_n = cfg.n;
    for u in if pool.is_empty() { vec![] } else { vec![1usize, 4, 16, 64, 256, 1024] } {
    // [1usize, 4, 16, 64, 256, 1024] {
        cfg.n = (saved_n / u).max(20);
        let items: Vec<_> = (0..u).map(|i| pool[i % pool.len()].clone()).collect();
        let name = format!("batch/ed25519 P_c batch u={}", u);
        bench(&mut cfg, &name, |_| { black_box(verify_batch_fast(black_box(&items), black_box(&zs[..u]))); });
        if u <= 256 {
            let name = format!("batch/ed25519 P_c individual x{}", u);
            bench(&mut cfg, &name, |_| { for it in black_box(&items) { black_box(verify_fast(&it.0, &it.1, &it.2, Policy::Cofactored)); } });
        }
        #[cfg(feature = "baselines")]
        {
            if cfg.filter.is_empty() || "batch/baseline".contains(&cfg.filter) || cfg.filter.starts_with("batch") { assert!(baselines::dalek_batch(&items) && baselines::zebra_batch(&items), "baseline rejects generated signatures"); }
            let name = format!("batch/baseline dalek verify_batch u={}", u);
            bench(&mut cfg, &name, |_| { black_box(baselines::dalek_batch(black_box(&items))); });
            let name = format!("batch/baseline zebra batch u={}", u);
            bench(&mut cfg, &name, |_| { black_box(baselines::zebra_batch(black_box(&items))); });
        }
    }
    cfg.n = saved_n;

    // ---- block validation: all signatures of a block, then the failure scenario
    if !pool.is_empty() && pool.len() >= 10_000 && (cfg.filter.is_empty() || cfg.filter.starts_with("block")) {
        let saved_n = cfg.n;
        cfg.n = 5; // each sample is one whole block (hundreds of ms to seconds); R passes of 5 samples
        for nt in [500usize, 1000, 3000, 10_000] {
            let items = &pool[..nt];
            let name = format!("block/N={} ours individual", nt);
            bench(&mut cfg, &name, |_| { for it in black_box(items) { black_box(verify_fast(&it.0, &it.1, &it.2, Policy::Cofactored)); } });
            let name = format!("block/N={} ours batch", nt);
            bench(&mut cfg, &name, |_| { black_box(verify_batch_fast(black_box(items), black_box(&zs[..nt]))); });
            #[cfg(feature = "baselines")]
            {
                let name = format!("block/N={} dalek individual", nt);
                bench(&mut cfg, &name, |_| { for it in black_box(items) { black_box(baselines::dalek_verify(&it.0, &it.1, &it.2, false)); } });
                let name = format!("block/N={} dalek batch", nt);
                bench(&mut cfg, &name, |_| { black_box(baselines::dalek_batch(black_box(items))); });
                let name = format!("block/N={} zebra individual", nt);
                bench(&mut cfg, &name, |_| { for it in black_box(items) { black_box(baselines::zebra_verify(&it.0, &it.1, &it.2)); } });
                let name = format!("block/N={} zebra batch", nt);
                bench(&mut cfg, &name, |_| { black_box(baselines::zebra_batch(black_box(items))); });
            }
        }
        // failure scenario: N = 3000 with k invalid signatures at pseudo-random positions
        let nt = 3000usize;
        for k in [0usize, 1, 10] {
            let mut block: Vec<Item> = pool[..nt].to_vec();
            let mut pos: Vec<usize> = Vec::new();
            let mut x = 0x2545F4914F6CDD1Du64.wrapping_add(k as u64);
            while pos.len() < k { x ^= x << 13; x ^= x >> 7; x ^= x << 17; let p = (x % nt as u64) as usize; if !pos.contains(&p) { pos.push(p); } }
            for &p in &pos { block[p].1[0] ^= 1; }
            pos.sort();
            let ours_b = |it: &[Item], z: &[[u8; 16]]| verify_batch_fast(it, z);
            let ours_s = |it: &Item| verify_fast(&it.0, &it.1, &it.2, Policy::Cofactored);
            let mut found = Vec::new(); locate(&block, &zs[..nt], 0, &ours_b, &ours_s, 8, &mut found);
            assert_eq!(found, pos, "ours: wrong set of invalid signatures");
            let name = format!("block/fail N=3000 k={} ours individual (verify all)", k);
            bench(&mut cfg, &name, |_| { let mut f = Vec::new(); for (i, it) in black_box(&block).iter().enumerate() { if !ours_s(it) { f.push(i); } } black_box(f); });
            let name = format!("block/fail N=3000 k={} ours batch + bisection", k);
            bench(&mut cfg, &name, |_| { let mut f = Vec::new(); locate(black_box(&block), &zs[..nt], 0, &ours_b, &ours_s, 8, &mut f); black_box(f); });
            #[cfg(feature = "baselines")]
            {
                let db = |it: &[Item], _z: &[[u8; 16]]| baselines::dalek_batch(it);
                let ds = |it: &Item| baselines::dalek_verify(&it.0, &it.1, &it.2, false);
                let mut found = Vec::new(); locate(&block, &zs[..nt], 0, &db, &ds, 8, &mut found);
                assert_eq!(found, pos, "dalek: wrong set of invalid signatures");
                let name = format!("block/fail N=3000 k={} dalek batch + bisection", k);
                bench(&mut cfg, &name, |_| { let mut f = Vec::new(); locate(black_box(&block), &zs[..nt], 0, &db, &ds, 8, &mut f); black_box(f); });
                let zb = |it: &[Item], _z: &[[u8; 16]]| baselines::zebra_batch(it);
                let zsg = |it: &Item| baselines::zebra_verify(&it.0, &it.1, &it.2);
                let name = format!("block/fail N=3000 k={} zebra batch + bisection", k);
                bench(&mut cfg, &name, |_| { let mut f = Vec::new(); locate(black_box(&block), &zs[..nt], 0, &zb, &zsg, 8, &mut f); black_box(f); });
            }
        }
        cfg.n = saved_n;
    }
    // GLV ablation: same double multiplication without the endomorphism
    let q = g.scalar_mul(&scal[3]);
    let us: Vec<(U256, U256)> = (0..32).map(|i| (from_le(&scal[i]), from_le(&scal[i + 32]))).collect();
    bench(&mut cfg, "dsm/k1 u1*G+u2*Q GLV", |i| { let u = &us[i % 32]; black_box(hec_curves::glv::double_mul_glv(&u.0, &u.1, &q)); });
    let (tg, tq) = (hec_curves::wnaf::odd_multiples(&g, 7), hec_curves::wnaf::odd_multiples(&q, 5));
    bench(&mut cfg, "dsm/k1 u1*G+u2*Q plain wNAF (no GLV)", |i| { let u = &us[i % 32]; black_box(hec_curves::wnaf::double_scalar_vartime(&to_le(&u.0), &tg, 7, &to_le(&u.1), &tq, 5)); });

    #[cfg(feature = "baselines")]
    {
        use baselines::*;
        bench(&mut cfg, "baseline/ed25519-dalek verify (cofactorless)", |i| { let c = &ed[i % ed.len()]; black_box(dalek_verify(&c.0, &c.1, &c.2, false)); });
        bench(&mut cfg, "baseline/ed25519-dalek verify_strict", |i| { let c = &ed[i % ed.len()]; black_box(dalek_verify(&c.0, &c.1, &c.2, true)); });
        bench(&mut cfg, "baseline/ed25519-zebra (ZIP-215)", |i| { let c = &ed[i % ed.len()]; black_box(zebra_verify(&c.0, &c.1, &c.2)); });
        let bp32: Vec<_> = bp.iter().filter(|c| c.1.len() == 32).collect();
        bench(&mut cfg, "baseline/libsecp256k1 schnorr verify", |i| { let c = bp32[i % bp32.len()]; black_box(libsecp_schnorr(&c.0, &c.1, &c.2)); });
        bench(&mut cfg, "baseline/k256 schnorr verify", |i| { let c = &bp[i % bp.len()]; black_box(k256_schnorr(&c.0, &c.1, &c.2)); });
        let ec_low: Vec<_> = ec.iter().filter(|c| k256_ecdsa(&c[0], &c[1], &c[2], &c[3], &c[4])).cloned().collect();
        assert!(!ec_low.is_empty());
        bench(&mut cfg, "baseline/libsecp256k1 ecdsa verify", |i| { let c = &ec_low[i % ec_low.len()]; black_box(libsecp_ecdsa(&c[0], &c[1], &c[2], &c[3], &c[4], false)); });
        bench(&mut cfg, "baseline/k256 ecdsa verify", |i| { let c = &ec_low[i % ec_low.len()]; black_box(k256_ecdsa(&c[0], &c[1], &c[2], &c[3], &c[4])); });
    }
}
