//! Differential tests on Wycheproof vectors and on random mutations.
//! Run: cargo run --release -p hec-bench --features baselines --bin diff2 -- [mutations_per_scheme]
#[path = "../baselines.rs"]
mod baselines;
use baselines::*;
use hec_validation::{secp_sig, sign_for_tests, verify_fast, Policy};

fn hx(s: &str) -> Vec<u8> { if s == "-" { return vec![]; } (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect() }
fn a32(s: &str) -> [u8; 32] { hx(s).try_into().unwrap() }

const N: [u8; 32] = [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41];
const HALF: [u8; 32] = [0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0];
/// s -> n - s when s > n/2 (big-endian), leaving out-of-range values untouched.
fn low_s(s: &[u8; 32]) -> [u8; 32] {
    if s.as_slice() > HALF.as_slice() && s.as_slice() < N.as_slice() {
        let mut o = [0u8; 32]; let mut br = 0i16;
        for i in (0..32).rev() { let d = N[i] as i16 - s[i] as i16 - br; if d < 0 { o[i] = (d + 256) as u8; br = 1 } else { o[i] = d as u8; br = 0 } }
        o
    } else { *s }
}

struct Tally { name: String, n: usize, agree: usize, ex: Vec<String> }
impl Tally {
    fn new(n: &str) -> Self { Tally { name: n.into(), n: 0, agree: 0, ex: vec![] } }
    fn add(&mut self, a: bool, b: bool, case: impl FnOnce() -> String) {
        self.n += 1;
        if a == b { self.agree += 1 } else if self.ex.len() < 4 { self.ex.push(format!("ours={a} lib={b} {}", case())) }
    }
    fn print(&self) {
        println!("{:<58} agree {}/{}  disagree {}", self.name, self.agree, self.n, self.n - self.agree);
        for e in &self.ex { println!("    {e}"); }
    }
}
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
    fn below(&mut self, n: usize) -> usize { (self.next() % n as u64) as usize }
}
fn mutate(r: &mut Rng, fields: &mut [Vec<u8>]) {
    let k = 1 + r.below(3);
    for _ in 0..k {
        let f = r.below(fields.len());
        if fields[f].is_empty() { fields[f].push(r.next() as u8); continue; }
        let i = r.below(fields[f].len());
        match r.below(3) { 0 => fields[f][i] ^= 1 << r.below(8), 1 => fields[f][i] = r.next() as u8, _ => { if r.below(4) == 0 { fields[f].truncate(i) } else { fields[f][i] = fields[f][i].wrapping_add(1) } } }
    }
}

fn main() {
    let nmut: usize = std::env::args().nth(1).map(|s| s.parse().unwrap()).unwrap_or(1_000_000);
    // ===== Wycheproof Ed25519
    let all: Vec<&str> = include_str!("../../../validation/tests/wycheproof_ed25519.txt").lines().collect();
    let wy: Vec<([u8; 32], Vec<u8>, [u8; 64], bool, String)> = all.iter().filter_map(|l| {
        let f: Vec<&str> = l.split(' ').collect();
        Some((a32(f[0]), hx(f[1]), <[u8; 64]>::try_from(hx(f[2])).ok()?, f[3] == "1", format!("tcId {}", f[4])))
    }).collect();
    println!("Wycheproof Ed25519: {} vectors, {} with a signature of wrong length (rejected before verification)", all.len(), all.len() - wy.len());
    let mut t = [Tally::new("Wycheproof Ed25519: P_c vs expected"), Tally::new("Wycheproof Ed25519: P_s vs expected"), Tally::new("Wycheproof Ed25519: P_c vs ed25519-zebra"), Tally::new("Wycheproof Ed25519: P_s vs dalek verify_strict"), Tally::new("Wycheproof Ed25519: dalek verify vs expected"), Tally::new("Wycheproof Ed25519: zebra vs expected")];
    for c in &wy {
        let (pc, ps) = (verify_fast(&c.0, &c.1, &c.2, Policy::Cofactored), verify_fast(&c.0, &c.1, &c.2, Policy::Strict));
        let (z, ds, d) = (zebra_verify(&c.0, &c.1, &c.2), dalek_verify(&c.0, &c.1, &c.2, true), dalek_verify(&c.0, &c.1, &c.2, false));
        t[0].add(pc, c.3, || c.4.clone()); t[1].add(ps, c.3, || c.4.clone()); t[2].add(pc, z, || c.4.clone()); t[3].add(ps, ds, || c.4.clone());
        t[4].add(d, c.3, || c.4.clone()); t[5].add(z, c.3, || c.4.clone());
    }
    for x in &t { x.print(); }

    // ===== Wycheproof ECDSA (signatures with a valid strict-DER encoding are passed to all implementations)
    let mut t = [Tally::new("Wycheproof ECDSA: ours vs expected"), Tally::new("Wycheproof ECDSA: ours vs libsecp256k1 (s normalized)"), Tally::new("Wycheproof ECDSA: ours vs k256 (s normalized)"), Tally::new("Wycheproof ECDSA: libsecp256k1 (s normalized) vs expected")];
    let (mut enc_total, mut enc_exp_valid) = (0, 0);
    for l in include_str!("../../../validation/tests/wycheproof_ecdsa.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        if f[0] == "-" { enc_total += 1; if f[5] == "1" { enc_exp_valid += 1 } continue; }
        let (qx, qy, z, r, s) = (a32(f[0]), a32(f[1]), a32(f[2]), a32(f[3]), a32(f[4]));
        let exp = f[5] == "1";
        let ours = secp_sig::ecdsa_verify(&qx, &qy, &z, &r, &s);
        let ls = libsecp_ecdsa(&qx, &qy, &z, &r, &s, true);
        let k = k256_ecdsa(&qx, &qy, &z, &r, &low_s(&s));
        let id = || f[6].to_string();
        t[0].add(ours, exp, id); t[1].add(ours, ls, id); t[2].add(ours, k, id); t[3].add(ls, exp, id);
    }
    for x in &t { x.print(); }
    println!("ECDSA vectors rejected before verification by the strict DER parser: {enc_total} (of which expected valid: {enc_exp_valid})");

    // ===== Random mutations
    let mut rng = Rng(0x9E3779B97F4A7C15);
    // Ed25519
    let seeds: Vec<([u8; 32], Vec<u8>, [u8; 64])> = (0..64).map(|i| {
        let mut sd = [0u8; 32]; for b in sd.iter_mut() { *b = rng.next() as u8 }
        let msg: Vec<u8> = (0..(i % 65)).map(|_| rng.next() as u8).collect();
        let (pk, sig) = sign_for_tests(&sd, &msg); (pk, msg, sig)
    }).collect();
    let mut t = [Tally::new(&format!("Mutation Ed25519 ({nmut}): P_c vs zebra")), Tally::new("Mutation Ed25519: P_s vs dalek verify_strict"), Tally::new("Mutation Ed25519: P_c vs dalek verify")];
    let mut accepted = 0usize;
    for _ in 0..nmut {
        let s = &seeds[rng.below(seeds.len())];
        let mut f = [s.0.to_vec(), s.1.clone(), s.2.to_vec()];
        mutate(&mut rng, &mut f);
        let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(f[0].clone()), <[u8; 64]>::try_from(f[2].clone())) else { continue };
        let pc = verify_fast(&pk, &f[1], &sig, Policy::Cofactored); let ps = verify_fast(&pk, &f[1], &sig, Policy::Strict);
        if pc { accepted += 1 }
        let cs = || format!("pk={} msg={} sig={}", hex(&pk), hex(&f[1]), hex(&sig));
        t[0].add(pc, zebra_verify(&pk, &f[1], &sig), cs); t[1].add(ps, dalek_verify(&pk, &f[1], &sig, true), cs); t[2].add(pc, dalek_verify(&pk, &f[1], &sig, false), cs);
    }
    for x in &t { x.print(); } println!("    (mutants accepted by P_c: {accepted})");
    // BIP-340
    let bp: Vec<([u8; 32], Vec<u8>, [u8; 64])> = include_str!("../../../validation/tests/bip340.txt").lines().map(|l| {
        let f: Vec<&str> = l.split(' ').collect(); (a32(f[0]), hx(f[1]), <[u8; 64]>::try_from(hx(f[2])).unwrap())
    }).filter(|c| c.1.len() == 32 && secp_sig::bip340_verify(&c.0, &c.1, &c.2)).collect();
    let mut t = [Tally::new(&format!("Mutation BIP-340 ({nmut}, {} seeds): ours vs libsecp256k1", bp.len())), Tally::new("Mutation BIP-340: ours vs k256")];
    let mut accepted = 0usize;
    for _ in 0..nmut {
        let s = &bp[rng.below(bp.len())];
        let mut f = [s.0.to_vec(), s.1.clone(), s.2.to_vec()];
        mutate(&mut rng, &mut f);
        let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(f[0].clone()), <[u8; 64]>::try_from(f[2].clone())) else { continue };
        if f[1].len() != 32 { continue }
        let o = secp_sig::bip340_verify(&pk, &f[1], &sig); if o { accepted += 1 }
        let cs = || format!("pk={} msg={} sig={}", hex(&pk), hex(&f[1]), hex(&sig));
        t[0].add(o, libsecp_schnorr(&pk, &f[1], &sig), cs); t[1].add(o, k256_schnorr(&pk, &f[1], &sig), cs);
    }
    for x in &t { x.print(); } println!("    (mutants accepted by ours: {accepted})");
    // ECDSA
    let ec: Vec<[[u8; 32]; 5]> = include_str!("../../../validation/tests/ecdsa.txt").lines().filter_map(|l| {
        let f: Vec<&str> = l.split(' ').collect(); if f[5] == "1" { Some([a32(f[0]), a32(f[1]), a32(f[2]), a32(f[3]), a32(f[4])]) } else { None }
    }).collect();
    let mut t = [Tally::new(&format!("Mutation ECDSA ({nmut}, {} seeds): ours vs libsecp256k1 (s norm.)", ec.len())), Tally::new("Mutation ECDSA: ours vs k256 (s normalized)")];
    let mut accepted = 0usize;
    for _ in 0..nmut {
        let s = &ec[rng.below(ec.len())];
        let mut f: Vec<Vec<u8>> = s.iter().map(|x| x.to_vec()).collect();
        // fields are fixed-length; use bit flips and byte replacement only
        for _ in 0..(1 + rng.below(3)) { let a = rng.below(5); let i = rng.below(32); if rng.below(2) == 0 { f[a][i] ^= 1 << rng.below(8) } else { f[a][i] = rng.next() as u8 } }
        let g: Vec<[u8; 32]> = f.iter().map(|x| x.as_slice().try_into().unwrap()).collect();
        let o = secp_sig::ecdsa_verify(&g[0], &g[1], &g[2], &g[3], &g[4]); if o { accepted += 1 }
        let cs = || g.iter().map(|x| hex(x)).collect::<Vec<_>>().join(" ");
        t[0].add(o, libsecp_ecdsa(&g[0], &g[1], &g[2], &g[3], &g[4], true), cs); t[1].add(o, k256_ecdsa(&g[0], &g[1], &g[2], &g[3], &low_s(&g[4])), cs);
    }
    for x in &t { x.print(); } println!("    (mutants accepted by ours: {accepted})");
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
