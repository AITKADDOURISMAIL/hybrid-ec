use hec_core::fe256k1::Fe;
fn hex(s: &str) -> [u8; 32] {
    let mut be = [0u8; 32];
    for i in 0..32 { be[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap(); }
    be.reverse(); be // file is big-endian hex; Fe uses little-endian
}
#[test]
fn matches_bigint_reference() {
    let data = include_str!("fe256k1_vectors.txt");
    let mut n = 0;
    for line in data.lines() {
        let f: Vec<[u8; 32]> = line.split(' ').map(hex).collect();
        let (a, b) = (Fe::from_bytes(&f[0]), Fe::from_bytes(&f[1]));
        assert_eq!(a.add(&b).to_bytes(), f[2], "add {line}");
        assert_eq!(a.sub(&b).to_bytes(), f[3], "sub {line}");
        assert_eq!(a.mul(&b).to_bytes(), f[4], "mul {line}");
        assert_eq!(a.square().to_bytes(), f[5], "sq {line}");
        assert_eq!(a.invert().to_bytes(), f[6], "inv {line}");
        // chained lazy-reduction stress
        let c = a.mul(&b).add(&a).sub(&b).mul(&a.add(&b));
        let d = c.mul(&c).sub(&a);
        let _ = d.to_bytes();
        n += 1;
    }
    assert!(n > 1000);
}
#[test]
fn select_masks() {
    let a = Fe::ONE; let b = Fe::ONE.add(&Fe::ONE);
    assert_eq!(Fe::select(&a, &b, 0).to_bytes(), a.to_bytes());
    assert_eq!(Fe::select(&a, &b, 1).to_bytes(), b.to_bytes());
}
