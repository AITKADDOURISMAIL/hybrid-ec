use hec_curves::secp256k1::Point;
fn hex(s: &str) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..32 { b[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap(); }
    b.reverse(); b
}
fn pt(x: &str, y: &str) -> Point {
    let (x, y) = (hex(x), hex(y));
    if x == [0u8; 32] && y == [0u8; 32] { Point::IDENTITY } else { Point::from_affine(&x, &y) }
}
fn check(p: &Point, x: &str, y: &str, what: &str) {
    let want = if hex(x) == [0u8; 32] && hex(y) == [0u8; 32] { None } else { Some((hex(x), hex(y))) };
    assert_eq!(p.to_affine(), want, "{what}");
}
#[test]
fn add_and_double_match_reference() {
    let mut n = 0;
    for line in include_str!("k1_points.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let (p, q) = (pt(f[0], f[1]), pt(f[2], f[3]));
        check(&p.add(&q), f[4], f[5], &format!("add {line}"));
        check(&p.add(&p), f[6], f[7], &format!("add(P,P) {line}"));
        check(&p.double(), f[6], f[7], &format!("double {line}"));
        n += 1;
    }
    assert!(n > 500);
}
#[test]
fn scalar_mul_matches_reference() {
    for line in include_str!("k1_scalar.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let k = hex(f[0]);
        check(&pt(f[1], f[2]).scalar_mul(&k), f[3], f[4], &format!("kP {line}"));
    }
}
