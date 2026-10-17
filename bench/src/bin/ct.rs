//! dudect-style timing leakage test (Reparaz, Balasch, Verbauwhede, 2017) for the secret-dependent
//! routines of the prototype. Two classes of secret inputs, "fixed" and "random", are measured in
//! random interleaving; Welch's t-test is applied to the raw measurements and to measurements cropped
//! at several percentiles. |t| > 4.5 is interpreted as evidence of leakage.
//! Each measurement is normalized by a calibration loop to cope with clock-state changes of laptops.
//! Controls: A/A (both classes random) must stay below the threshold; a deliberately leaky
//! double-and-add (branch on secret bits) must exceed it.
//! Usage: ct [--n 100000] [--campaigns 5] [--filter a,b,c] [--out ct.csv] [--tol 25]
use hec_curves::{ed25519, fixed_base::FixedBase, group::Group, secp256k1, x25519::x25519};
use std::hint::black_box;
use std::io::Write;
use std::time::Instant;

const CAL_STEPS: u32 = 50_000;
fn mini_calib() -> f64 {
    let t = Instant::now();
    let mut x = black_box(1u64);
    for _ in 0..CAL_STEPS { x = x.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1); }
    black_box(x);
    t.elapsed().as_nanos() as f64 / CAL_STEPS as f64
}
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
    fn scalar(&mut self) -> [u8; 32] { let mut k = [0u8; 32]; for c in k.iter_mut() { *c = self.next() as u8; } k[31] &= 0x7F; k }
}
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let stat = |v: &[f64]| { let n = v.len() as f64; let m = v.iter().sum::<f64>() / n; let var = v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (n - 1.0); (m, var, n) };
    let (ma, va, na) = stat(a); let (mb, vb, nb) = stat(b);
    (ma - mb) / (va / na + vb / nb).sqrt()
}
/// (raw |t|, max |t| over cropped sets, number of measurements used)
fn analyze(c0: &[f64], c1: &[f64]) -> (f64, f64) {
    let raw = welch_t(c0, c1).abs();
    let mut all: Vec<f64> = c0.iter().chain(c1.iter()).copied().collect();
    all.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mut best = raw;
    for q in [0.5, 0.7, 0.8, 0.9, 0.95, 0.99] {
        let thr = all[((all.len() as f64 * q) as usize).min(all.len() - 1)];
        let a: Vec<f64> = c0.iter().copied().filter(|&x| x <= thr).collect();
        let b: Vec<f64> = c1.iter().copied().filter(|&x| x <= thr).collect();
        if a.len() > 100 && b.len() > 100 { best = best.max(welch_t(&a, &b).abs()); }
    }
    (raw, best)
}
fn leaky_mul<P: Group>(p: &P, k: &[u8; 32]) -> P {
    let mut acc = P::identity();
    for i in (0..256).rev() { acc = acc.double(); if (k[i / 8] >> (i % 8)) & 1 == 1 { acc = acc.add(p); } }
    acc
}

/// One campaign: `op(secret)` is measured on `n` interleaved inputs; class 0 uses `fixed`, class 1 random.
/// With `aa` set, class 0 also uses random inputs (A/A control).
fn campaign<F: FnMut(&[u8; 32])>(n: usize, tol: f64, fixed: [u8; 32], aa: bool, seed: u64, mut op: F) -> (f64, f64, usize, f64) {
    const POOL: usize = 4096;
    let mut rng = Rng(seed);
    let pool0: Vec<[u8; 32]> = (0..POOL).map(|_| if aa { rng.scalar() } else { fixed }).collect();
    let pool1: Vec<[u8; 32]> = (0..POOL).map(|_| rng.scalar()).collect();
    let (mut c0, mut c1) = (Vec::with_capacity(n / 2 + 1000), Vec::with_capacity(n / 2 + 1000));
    let mut dirty = 0usize;
    for i in 0..2000 { black_box(op(&pool1[i % POOL])); } // warm-up
    let mut cal0 = mini_calib();
    for i in 0..n {
        let class = rng.next() & 1;
        let input = if class == 0 { &pool0[i % POOL] } else { &pool1[i % POOL] };
        let t = Instant::now();
        op(black_box(input));
        let ns = t.elapsed().as_nanos() as f64;
        let cal1 = mini_calib();
        if 100.0 * (cal1 - cal0).abs() / cal0.min(cal1) <= tol {
            let v = ns / ((cal0 + cal1) / 2.0);
            if class == 0 { c0.push(v) } else { c1.push(v) }
        } else { dirty += 1; }
        cal0 = cal1;
    }
    let (raw, best) = analyze(&c0, &c1);
    (raw, best, c0.len() + c1.len(), 100.0 * dirty as f64 / n as f64)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let n: usize = get("--n").map(|s| s.parse().unwrap()).unwrap_or(100_000);
    let campaigns: usize = get("--campaigns").map(|s| s.parse().unwrap()).unwrap_or(5);
    let tol: f64 = get("--tol").map(|s| s.parse().unwrap()).unwrap_or(25.0);
    let filter = get("--filter").unwrap_or_default();
    let out_path = get("--out").unwrap_or_else(|| "ct_results.csv".into());
    let new = !std::path::Path::new(&out_path).exists();
    let mut out = std::fs::OpenOptions::new().create(true).append(true).open(&out_path).unwrap();
    if new { writeln!(out, "routine,campaign,n_used,t_raw,t_max_cropped,dirty_pct,leak").unwrap(); }
    println!("dudect-style test: n={} measurements per campaign, {} campaigns, threshold |t|>4.5, dirty-sample tol {}%", n, campaigns, tol);
    println!("fixed class: scalar with a single set bit pattern (low Hamming weight); random class: uniform 255-bit scalars\n");

    let g = secp256k1::generator();
    let b = ed25519::Point::base();
    let fb_k1 = FixedBase::new(g, 5);
    let fb_ed = FixedBase::new(b, 4);
    let mut fixed = [0u8; 32]; fixed[0] = 1; fixed[17] = 0x80; // Hamming weight 2
    let q_k1 = g.scalar_mul(&Rng(7).scalar());
    let q_ed = b.scalar_mul(&Rng(8).scalar());
    let xu = { let mut u = [0u8; 32]; u[0] = 9; u };

    type Case<'a> = (&'a str, bool, bool, Box<dyn FnMut(&[u8; 32]) + 'a>); // name, aa, expect_leak, op
    let mut cases: Vec<Case> = vec![
        ("control A/A (ed25519 fixed-base, both classes random)", true, false, Box::new(|k| { black_box(fb_ed.mul(k)); })),
        ("control field-chain (400 field multiplications of the secret, constant time by construction)", false, false, Box::new(|k| { use hec_core::fe25519::Fe; let a = Fe::from_bytes(k); let mut x = a; for _ in 0..400 { x = x.mul(&a).add(&x); } black_box(x); })),
        ("control positive (leaky double-and-add, ed25519)", false, true, Box::new(|k| { black_box(leaky_mul(&b, k)); })),
        ("secp256k1 fixed-base c=5 (keygen/signing path)", false, false, Box::new(|k| { black_box(fb_k1.mul(k)); })),
        ("ed25519 fixed-base c=4 (keygen/signing path)", false, false, Box::new(|k| { black_box(fb_ed.mul(k)); })),
        ("secp256k1 variable-base regular double-and-add", false, false, Box::new(|k| { black_box(q_k1.scalar_mul(k)); })),
        ("ed25519 variable-base regular double-and-add", false, false, Box::new(|k| { black_box(q_ed.scalar_mul(k)); })),
        ("x25519 Montgomery ladder", false, false, Box::new(|k| { black_box(x25519(k, &xu)); })),
    ];
    let mut summary = Vec::new();
    for (name, aa, expect, op) in cases.iter_mut() {
        if !filter.is_empty() && !filter.split(',').any(|f| name.contains(f)) { continue; }
        let mut leaks = 0;
        for c in 0..campaigns {
            let (raw, best, used, dirty) = campaign(n, tol, fixed, *aa, 0x1234_5678_9ABC_DEF0u64.wrapping_add(c as u64 * 7919), |k| op(k));
            let leak = best > 4.5;
            if leak { leaks += 1; }
            println!("{:<56} campaign {}: |t| raw {:>7.2}  max cropped {:>7.2}  n={} dirty {:.1}%  {}", name, c + 1, raw, best, used, dirty, if leak { "LEAK" } else { "ok" });
            writeln!(out, "\"{}\",{},{},{:.3},{:.3},{:.2},{}", name, c + 1, used, raw, best, dirty, leak as u8).unwrap();
        }
        let majority = leaks * 2 > campaigns;
        let verdict = if majority { "LEAKAGE DETECTED (majority of campaigns)" } else { "no leakage detected" };
        println!("  => {}: {}/{} campaigns above 4.5 -> {}{}\n", name, leaks, campaigns, verdict, if majority == *expect { "" } else { "   <-- UNEXPECTED for a control or a constant-time routine" });
        summary.push((name.to_string(), leaks, majority));
    }
    println!("summary:");
    for (n, l, m) in summary { println!("  {:<56} {}/{}  {}", n, l, campaigns, if m { "LEAK" } else { "ok" }); }
}
