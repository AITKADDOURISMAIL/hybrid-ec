//! Cases signed and checked by vetted implementations (libsodium, OpenSSL, libsecp256k1), see reference/gen_vectors_vetted.py.
use hec_validation::{secp_sig::*, verify, verify_fast, Policy};
fn hx(s: &str) -> Vec<u8> {
    if s == "-" { return vec![]; }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn a32(s: &str) -> [u8; 32] { hx(s).try_into().unwrap() }
#[test]
fn ed25519_vetted() {
    let (mut ok, mut bad) = (0, 0);
    for l in include_str!("vetted_ed25519.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let (pk, msg, sig): ([u8; 32], Vec<u8>, [u8; 64]) = (a32(f[0]), hx(f[1]), hx(f[2]).try_into().unwrap());
        let (pc, ps) = (f[3] == "1", f[4] == "1");
        assert_eq!(verify(&pk, &msg, &sig, Policy::Cofactored), pc, "P_c {l}");
        assert_eq!(verify(&pk, &msg, &sig, Policy::Strict), ps, "P_s {l}");
        assert_eq!(verify_fast(&pk, &msg, &sig, Policy::Cofactored), pc, "fast P_c {l}");
        assert_eq!(verify_fast(&pk, &msg, &sig, Policy::Strict), ps, "fast P_s {l}");
        if pc { ok += 1 } else { bad += 1 }
    }
    assert_eq!((ok, bad), (120, 360));
}
#[test]
fn ecdsa_vetted() {
    let (mut ok, mut bad) = (0, 0);
    for l in include_str!("vetted_ecdsa.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let got = ecdsa_verify(&a32(f[0]), &a32(f[1]), &a32(f[2]), &a32(f[3]), &a32(f[4]));
        assert_eq!(got, f[5] == "1", "ecdsa {l}");
        if got { ok += 1 } else { bad += 1 }
    }
    assert_eq!((ok, bad), (120, 360));
}
#[test]
fn bip340_vetted() {
    let (mut ok, mut bad) = (0, 0);
    for l in include_str!("vetted_bip340.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let sig: [u8; 64] = hx(f[2]).try_into().unwrap();
        let got = bip340_verify(&a32(f[0]), &hx(f[1]), &sig);
        assert_eq!(got, f[3] == "1", "bip340 {l}");
        if got { ok += 1 } else { bad += 1 }
    }
    assert_eq!((ok, bad), (60, 180));
}

/// Batch verification of BIP-340 must equal the AND of the individual verdicts (with probability 1 - 2^-128).
#[test]
fn bip340_batch_matches_individual() {
    let cases: Vec<([u8; 32], Vec<u8>, [u8; 64], bool)> = include_str!("vetted_bip340.txt").lines().map(|l| {
        let f: Vec<&str> = l.split(' ').collect();
        (a32(f[0]), hx(f[1]), hx(f[2]).try_into().unwrap(), f[3] == "1")
    }).collect();
    let mut seed = 987654321u64;
    let mut rnd = || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };
    let (mut t, mut f) = (0, 0);
    for round in 0..400 {
        let size = 1 + (rnd() % 9) as usize;
        // half of the rounds only use valid cases so that accepted batches occur
        let pool: Vec<&_> = if round % 2 == 0 { cases.iter().filter(|c| c.3).collect() } else { cases.iter().collect() };
        let picks: Vec<&_> = (0..size).map(|_| pool[(rnd() % pool.len() as u64) as usize]).collect();
        let items: Vec<_> = picks.iter().map(|c| (c.0, c.1.clone(), c.2)).collect();
        let z: Vec<[u8; 16]> = (0..size).map(|i| { let mut b = [0u8; 16]; b[..8].copy_from_slice(&rnd().to_le_bytes()); b[8..].copy_from_slice(&rnd().to_le_bytes()); b[0] |= 1; if i == 0 && round % 3 == 0 { b = [0; 16]; b[0] = 1; } b }).collect();
        let want = picks.iter().all(|c| c.3);
        assert_eq!(bip340_verify_batch(&items, &z), want, "round {round}");
        if want { t += 1 } else { f += 1 }
    }
    assert!(t > 100 && f > 50, "{t} {f}");
    assert!(bip340_verify_batch(&[], &[]), "the empty batch is the identity check");
}
/// Whole-batch rejection of malformed items.
#[test]
fn bip340_batch_rejects_malformed() {
    let c: Vec<([u8; 32], Vec<u8>, [u8; 64])> = include_str!("vetted_bip340.txt").lines().filter_map(|l| {
        let f: Vec<&str> = l.split(' ').collect();
        if f[3] == "1" { Some((a32(f[0]), hx(f[1]), hx(f[2]).try_into().unwrap())) } else { None }
    }).take(4).collect();
    let z = vec![[7u8; 16]; 4];
    assert!(bip340_verify_batch(&c, &z));
    let mut bad = c.clone(); bad[2].2[..32].fill(0xFF);           // r >= p
    assert!(!bip340_verify_batch(&bad, &z));
    let mut bad = c.clone(); bad[1].2[32..].fill(0xFF);           // s >= n
    assert!(!bip340_verify_batch(&bad, &z));
    let mut bad = c.clone(); bad[3].0 = [0xFF; 32];               // pk >= p
    assert!(!bip340_verify_batch(&bad, &z));
}
