use hec_validation::{secp_sig::*, sha256::sha256};
fn hx(s: &str) -> Vec<u8> {
    if s == "-" { return vec![]; }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn a32(s: &str) -> [u8; 32] { hx(s).try_into().unwrap() }
#[test]
fn sha256_matches_hashlib() {
    for l in include_str!("sha256.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        assert_eq!(sha256(&[&hx(f[0])]).to_vec(), hx(f[1]), "{l}");
    }
}
#[test]
fn bip340_matches_oracle() {
    let (mut ok, mut bad) = (0, 0);
    for l in include_str!("bip340.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let sig: [u8; 64] = hx(f[2]).try_into().unwrap();
        let got = bip340_verify(&a32(f[0]), &hx(f[1]), &sig);
        assert_eq!(got, f[3] == "1", "bip340 {l}");
        if got { ok += 1 } else { bad += 1 }
    }
    assert!(ok > 30 && bad > 100);
}
#[test]
fn ecdsa_matches_oracle() {
    let (mut ok, mut bad) = (0, 0);
    for l in include_str!("ecdsa.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let got = ecdsa_verify(&a32(f[0]), &a32(f[1]), &a32(f[2]), &a32(f[3]), &a32(f[4]));
        assert_eq!(got, f[5] == "1", "ecdsa {l}");
        if got { ok += 1 } else { bad += 1 }
    }
    assert!(ok > 50 && bad > 100);
}
