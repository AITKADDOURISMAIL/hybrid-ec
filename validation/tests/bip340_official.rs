//! The 19 official BIP-340 test vectors (bitcoin/bips, bip-0340/test-vectors.csv, indices 0 to 18), unchanged.
use hec_validation::secp_sig::*;
fn hx(s: &str) -> Vec<u8> { (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect() }

struct V { idx: usize, pk: [u8; 32], msg: Vec<u8>, sig: [u8; 64], ok: bool, comment: String }
fn load() -> Vec<V> {
    include_str!("bip340_official.csv").lines().skip(1).map(|l| {
        let f: Vec<&str> = l.splitn(8, ',').collect();
        V { idx: f[0].parse().unwrap(), pk: hx(f[2]).try_into().unwrap(), msg: hx(f[4]),
            sig: hx(f[5]).try_into().unwrap(), ok: f[6] == "TRUE", comment: f.get(7).unwrap_or(&"").to_string() }
    }).collect()
}

#[test]
fn official_vectors_single_and_dedicated() {
    let v = load();
    assert_eq!(v.len(), 19);
    assert_eq!(v.iter().filter(|x| x.ok).count(), 9);
    for x in &v {
        assert_eq!(bip340_verify(&x.pk, &x.msg, &x.sig), x.ok, "index {} ({})", x.idx, x.comment);
        assert_eq!(bip340_verify_dedicated(&x.pk, &x.msg, &x.sig), x.ok, "dedicated, index {} ({})", x.idx, x.comment);
    }
}

/// Batch verification of one item (z = 1) must give the individual verdict; the batch of all valid vectors must pass,
/// and adding any invalid vector must make it fail.
#[test]
fn official_vectors_batch() {
    let v = load();
    for x in &v {
        let item = vec![(x.pk, x.msg.clone(), x.sig)];
        let mut z = [0u8; 16]; z[0] = 1;
        assert_eq!(bip340_verify_batch(&item, &[z]), x.ok, "batch of one, index {}", x.idx);
    }
    let valid: Vec<_> = v.iter().filter(|x| x.ok).map(|x| (x.pk, x.msg.clone(), x.sig)).collect();
    let z: Vec<[u8; 16]> = (0..valid.len() + 1).map(|i| { let mut z = [0u8; 16]; z[0] = 1 + i as u8; z[5] = 0x77; z }).collect();
    assert!(bip340_verify_batch(&valid, &z[..valid.len()]));
    for bad in v.iter().filter(|x| !x.ok) {
        let mut items = valid.clone();
        items.push((bad.pk, bad.msg.clone(), bad.sig));
        assert!(!bip340_verify_batch(&items, &z), "valid batch plus invalid index {}", bad.idx);
    }
}
