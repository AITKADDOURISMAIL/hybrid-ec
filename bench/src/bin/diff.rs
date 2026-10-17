//! Differential report: our verdicts versus reference libraries on the shared test vectors.
//! Run: cargo run --release -p hec-bench --features baselines --bin diff
#[path = "../baselines.rs"]
mod baselines;
use baselines::*;
use hec_validation::{secp_sig, verify_fast, Policy};

fn hx(s: &str) -> Vec<u8> { if s == "-" { return vec![]; } (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect() }
fn a32(s: &str) -> [u8; 32] { hx(s).try_into().unwrap() }

fn report(name: &str, rows: &[(String, bool, bool)]) {
    let agree = rows.iter().filter(|r| r.1 == r.2).count();
    println!("{:<52} agree {}/{}", name, agree, rows.len());
    for r in rows.iter().filter(|r| r.1 != r.2).take(6) { println!("    MISMATCH ours={} lib={} case {}", r.1, r.2, r.0); }
}

fn main() {
    // ---- Ed25519
    let mut v: Vec<([u8; 32], Vec<u8>, [u8; 64], String)> = vec![];
    for (i, l) in include_str!("../../../validation/tests/validation.txt").lines().enumerate() {
        let f: Vec<&str> = l.split(' ').collect();
        v.push((a32(f[0]), hx(f[1]), hx(f[2]).try_into().unwrap(), format!("#{i} pk={}..", &f[0][..8])));
    }
    let row = |g: &dyn Fn(&([u8; 32], Vec<u8>, [u8; 64], String)) -> (bool, bool)| -> Vec<(String, bool, bool)> {
        v.iter().map(|c| { let (a, b) = g(c); (c.3.clone(), a, b) }).collect()
    };
    report("Ed25519 P_c  vs ed25519-zebra (ZIP-215)", &row(&|c| (verify_fast(&c.0, &c.1, &c.2, Policy::Cofactored), zebra_verify(&c.0, &c.1, &c.2))));
    report("Ed25519 P_s  vs dalek verify_strict", &row(&|c| (verify_fast(&c.0, &c.1, &c.2, Policy::Strict), dalek_verify(&c.0, &c.1, &c.2, true))));
    report("Ed25519 P_c  vs dalek verify (cofactorless)", &row(&|c| (verify_fast(&c.0, &c.1, &c.2, Policy::Cofactored), dalek_verify(&c.0, &c.1, &c.2, false))));
    report("dalek verify vs dalek verify_strict", &row(&|c| (dalek_verify(&c.0, &c.1, &c.2, false), dalek_verify(&c.0, &c.1, &c.2, true))));
    report("zebra (ZIP-215) vs dalek verify_strict", &row(&|c| (zebra_verify(&c.0, &c.1, &c.2), dalek_verify(&c.0, &c.1, &c.2, true))));

    // ---- BIP-340
    let bp: Vec<_> = include_str!("../../../validation/tests/bip340.txt").lines().enumerate().map(|(i, l)| {
        let f: Vec<&str> = l.split(' ').collect(); (a32(f[0]), hx(f[1]), <[u8; 64]>::try_from(hx(f[2])).unwrap(), format!("#{i}"))
    }).collect();
    let rows: Vec<_> = bp.iter().filter(|c| c.1.len() == 32).map(|c| (c.3.clone(), secp_sig::bip340_verify(&c.0, &c.1, &c.2), libsecp_schnorr(&c.0, &c.1, &c.2))).collect();
    report("BIP-340 vs libsecp256k1 (32-byte messages only)", &rows);
    let rows: Vec<_> = bp.iter().map(|c| (c.3.clone(), secp_sig::bip340_verify(&c.0, &c.1, &c.2), k256_schnorr(&c.0, &c.1, &c.2))).collect();
    report("BIP-340 vs k256", &rows);

    // ---- ECDSA
    let ec: Vec<_> = include_str!("../../../validation/tests/ecdsa.txt").lines().enumerate().map(|(i, l)| {
        let f: Vec<&str> = l.split(' ').collect(); ([a32(f[0]), a32(f[1]), a32(f[2]), a32(f[3]), a32(f[4])], format!("#{i}"))
    }).collect();
    let rows: Vec<_> = ec.iter().map(|c| (c.1.clone(), secp_sig::ecdsa_verify(&c.0[0], &c.0[1], &c.0[2], &c.0[3], &c.0[4]), libsecp_ecdsa(&c.0[0], &c.0[1], &c.0[2], &c.0[3], &c.0[4], false))).collect();
    report("ECDSA vs libsecp256k1 (high-S rejected by lib)", &rows);
    let rows: Vec<_> = ec.iter().map(|c| (c.1.clone(), secp_sig::ecdsa_verify(&c.0[0], &c.0[1], &c.0[2], &c.0[3], &c.0[4]), libsecp_ecdsa(&c.0[0], &c.0[1], &c.0[2], &c.0[3], &c.0[4], true))).collect();
    report("ECDSA vs libsecp256k1 (s normalized first)", &rows);
    let rows: Vec<_> = ec.iter().map(|c| (c.1.clone(), secp_sig::ecdsa_verify(&c.0[0], &c.0[1], &c.0[2], &c.0[3], &c.0[4]), k256_ecdsa(&c.0[0], &c.0[1], &c.0[2], &c.0[3], &c.0[4]))).collect();
    report("ECDSA vs k256", &rows);
}
