//! The single-curve baseline must return exactly the same verdicts as the unified layer on every vector.
use hec_validation::{secp_sig::*, verify_fast, verify_fast_dedicated, Policy};
fn hx(s: &str) -> Vec<u8> {
    if s == "-" { return vec![]; }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn a32(s: &str) -> [u8; 32] { hx(s).try_into().unwrap() }

#[test]
fn ed25519_dedicated_equals_unified() {
    let mut n = 0;
    for l in include_str!("vetted_ed25519.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let (pk, msg, sig): ([u8; 32], Vec<u8>, [u8; 64]) = (a32(f[0]), hx(f[1]), hx(f[2]).try_into().unwrap());
        assert_eq!(verify_fast_dedicated(&pk, &msg, &sig), verify_fast(&pk, &msg, &sig, Policy::Cofactored), "{l}");
        assert_eq!(verify_fast_dedicated(&pk, &msg, &sig), f[3] == "1", "{l}");
        n += 1;
    }
    assert_eq!(n, 480);
}
#[test]
fn bip340_dedicated_equals_unified() {
    let mut n = 0;
    for l in include_str!("vetted_bip340.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let sig: [u8; 64] = hx(f[2]).try_into().unwrap();
        let (pk, msg) = (a32(f[0]), hx(f[1]));
        assert_eq!(bip340_verify_dedicated(&pk, &msg, &sig), bip340_verify(&pk, &msg, &sig), "{l}");
        assert_eq!(bip340_verify_dedicated(&pk, &msg, &sig), f[3] == "1", "{l}");
        n += 1;
    }
    assert_eq!(n, 240);
}

#[test]
fn ed25519_dedicated_on_policy_and_wycheproof_vectors() {
    // 456 policy cases (non-canonical encodings, small-order and mixed-order points): the P_c column
    let mut n = 0;
    for l in include_str!("validation.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let (pk, msg, sig): ([u8; 32], Vec<u8>, [u8; 64]) = (a32(f[0]), hx(f[1]), hx(f[2]).try_into().unwrap());
        assert_eq!(verify_fast_dedicated(&pk, &msg, &sig), f[3] == "1", "{l}");
        n += 1;
    }
    assert_eq!(n, 456);
    let mut checked = 0;
    for l in include_str!("wycheproof_ed25519.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(hx(f[0])), <[u8; 64]>::try_from(hx(f[2]))) else { continue }; // wrong lengths are rejected before the verifier
        let msg = hx(f[1]);
        assert_eq!(verify_fast_dedicated(&pk, &msg, &sig), verify_fast(&pk, &msg, &sig, Policy::Cofactored), "{l}");
        checked += 1;
    }
    assert!(checked > 100, "{checked}");
}
#[test]
fn bip340_dedicated_on_extra_vectors() {
    for l in include_str!("bip340.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let (pk, msg) = (a32(f[0]), hx(f[1]));
        let Ok(sig) = <[u8; 64]>::try_from(hx(f[2])) else { continue };
        assert_eq!(bip340_verify_dedicated(&pk, &msg, &sig), bip340_verify(&pk, &msg, &sig), "{l}");
    }
}

#[test]
fn ablation_variants_agree() {
    for l in include_str!("vetted_ed25519.txt").lines().chain(include_str!("validation.txt").lines()) {
        let f: Vec<&str> = l.split(' ').collect();
        let (pk, msg, sig): ([u8; 32], Vec<u8>, [u8; 64]) = (a32(f[0]), hx(f[1]), hx(f[2]).try_into().unwrap());
        assert_eq!(hec_validation::verify_fast_dedicated_arith_only(&pk, &msg, &sig), f[3] == "1", "{l}");
    }
    for l in include_str!("vetted_bip340.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let (pk, msg, sig): ([u8; 32], Vec<u8>, [u8; 64]) = (a32(f[0]), hx(f[1]), hx(f[2]).try_into().unwrap());
        assert_eq!(bip340_verify_dedicated_arith_only(&pk, &msg, &sig), f[3] == "1", "{l}");
    }
}
