use hec_curves::{ed25519::Point, x25519::x25519};
fn h(s: &str) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..32 { b[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap(); }
    b
}
#[test]
fn base_point_roundtrip() {
    assert_eq!(Point::base().compress(), hec_curves::ed25519::BASE_ENC);
}
#[test]
fn add_double_match_reference() {
    let mut n = 0;
    for line in include_str!("ed_points.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let (p, q) = (Point::decompress(&h(f[0])).unwrap(), Point::decompress(&h(f[1])).unwrap());
        assert_eq!(p.add(&q).compress(), h(f[2]), "add {line}");
        assert_eq!(p.add(&p).compress(), h(f[3]), "P+P {line}");
        assert_eq!(p.double().compress(), h(f[3]), "double {line}");
        n += 1;
    }
    assert!(n > 500);
}
#[test]
fn scalar_mul_matches_reference() {
    for line in include_str!("ed_scalar.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let p = Point::decompress(&h(f[1])).unwrap();
        assert_eq!(p.scalar_mul(&h(f[0])).compress(), h(f[2]), "kB {line}");
    }
}
#[test]
fn permissive_decompression_matches_reference() {
    let (mut ok, mut none) = (0, 0);
    for line in include_str!("ed_decode.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match Point::decompress(&h(f[0])) {
            Some(p) => { assert_eq!(p.compress(), h(f[1]), "dec {line}"); ok += 1; }
            None => { assert_eq!(f[1], "none", "dec {line}"); none += 1; }
        }
    }
    assert!(ok > 50 && none > 50, "ok={ok} none={none}");
}
#[test]
fn x25519_matches_reference_and_rfc7748() {
    for line in include_str!("x25519.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!(x25519(&h(f[0]), &h(f[1])), h(f[2]), "x25519 {line}");
    }
}
