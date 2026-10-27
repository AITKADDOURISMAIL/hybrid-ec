//! Measures how much each kind of work changes between the two clock states of the laptop
//! (about 3.6 GHz and about 1.0 GHz), to settle the factor reported in the paper (2.97 or 3.6).
//! Every sample records, at nearly the same instant: the calibration step (ns per step of the
//! multiply-add chain used by the benchmark) and several fixed workloads. The samples are split into
//! a fast and a slow cluster using the calibration time, and the slow/fast ratio is printed for the
//! calibration and for each workload.
//! Usage: cargo run --release --bin clockstates [-- --secs 60 --out clockstates.csv]
//! Run it on the measurement laptop, on battery or on mains as in the campaign, with nothing else running.
use hec_core::{fe25519, fe256k1};
use std::hint::black_box;
use std::io::Write;
use std::time::Instant;

const CAL_STEPS: u32 = 50_000;
fn calib() -> f64 {
    let t = Instant::now();
    let mut x = black_box(1u64);
    for _ in 0..CAL_STEPS { x = x.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1); }
    black_box(x);
    t.elapsed().as_nanos() as f64 / CAL_STEPS as f64
}
fn chain_25519(n: usize) -> f64 {
    let (mut a, b) = (fe25519::Fe::from_bytes(&[7u8; 32]), fe25519::Fe::from_bytes(&[9u8; 32]));
    let t = Instant::now();
    for _ in 0..n { a = black_box(a.mul(black_box(&b))); }
    black_box(&a);
    t.elapsed().as_nanos() as f64 / n as f64
}
fn chain_256k1(n: usize) -> f64 {
    let (mut a, b) = (fe256k1::Fe::from_bytes(&[7u8; 32]), fe256k1::Fe::from_bytes(&[9u8; 32]));
    let t = Instant::now();
    for _ in 0..n { a = black_box(a.mul(black_box(&b))); }
    black_box(&a);
    t.elapsed().as_nanos() as f64 / n as f64
}
fn chain_add(n: usize) -> f64 {
    let (mut a, b) = (fe25519::Fe::from_bytes(&[7u8; 32]), fe25519::Fe::from_bytes(&[9u8; 32]));
    let t = Instant::now();
    for _ in 0..n { a = black_box(a.add(black_box(&b))); }
    black_box(&a);
    t.elapsed().as_nanos() as f64 / n as f64
}
fn median(v: &mut Vec<f64>) -> f64 { v.sort_by(|a, b| a.partial_cmp(b).unwrap()); v[v.len() / 2] }

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let secs: f64 = get("--secs").map(|s| s.parse().unwrap()).unwrap_or(60.0);
    let out_path = get("--out").unwrap_or_else(|| "clockstates.csv".into());
    let mut out = std::fs::File::create(&out_path).unwrap();
    writeln!(out, "calib_before_ns,calib_after_ns,mul25519_ns,mul256k1_ns,add25519_ns").unwrap();
    let names = ["calibration step", "field mul 25519", "field mul secp256k1", "field add 25519"];
    let mut rows: Vec<[f64; 4]> = Vec::new();
    let start = Instant::now();
    let _ = (chain_25519(1000), chain_256k1(1000), chain_add(1000)); // warm-up
    while start.elapsed().as_secs_f64() < secs {
        let c0 = calib();
        let m1 = chain_25519(2000);
        let m2 = chain_256k1(2000);
        let m3 = chain_add(20000);
        let c1 = calib();
        // keep only samples where the clock did not change during the sample
        if 100.0 * (c1 - c0).abs() / c0.min(c1) <= 10.0 {
            writeln!(out, "{c0},{c1},{m1},{m2},{m3}").unwrap();
            rows.push([(c0 + c1) / 2.0, m1, m2, m3]);
        }
    }
    println!("{} clean samples in {:.0} s (raw data in {})", rows.len(), secs, out_path);
    if rows.len() < 20 { println!("Too few samples: rerun with a larger --secs."); return; }
    let mut cs: Vec<f64> = rows.iter().map(|r| r[0]).collect();
    cs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let (lo, hi) = (cs[cs.len() / 20], cs[cs.len() - 1 - cs.len() / 20]);
    println!("calibration step: 5th percentile {lo:.4} ns, 95th percentile {hi:.4} ns (ratio {:.3})", hi / lo);
    if hi / lo < 1.3 {
        println!("Only one clock state seen in this run. Medians of this run (copy them, then run again in another power mode):");
        for k in 0..4 {
            let m = median(&mut rows.iter().map(|r| r[k]).collect());
            println!("  {:<22} median {:.4} ns", names[k], m);
        }
        return;
    }
    let thr = (lo * hi).sqrt();
    let (mut fast, mut slow): (Vec<[f64; 4]>, Vec<[f64; 4]>) = (vec![], vec![]);
    for r in &rows { if r[0] < thr { fast.push(*r) } else { slow.push(*r) } }
    println!("fast state: {} samples, slow state: {} samples (threshold {thr:.4} ns)\n", fast.len(), slow.len());
    println!("{:<22} {:>12} {:>12} {:>10}", "workload", "fast (ns)", "slow (ns)", "slow/fast");
    for k in 0..4 {
        let mf = median(&mut fast.iter().map(|r| r[k]).collect());
        let ms = median(&mut slow.iter().map(|r| r[k]).collect());
        println!("{:<22} {:>12.4} {:>12.4} {:>10.3}", names[k], mf, ms, ms / mf);
    }
    println!("\nIf all ratios are close to each other (about 3.6 or about 3.0), the normalization is valid and");
    println!("the ratio is the true factor between the states. If calibration and field operations differ, send all of this output.");
}
