use hec_curves::{ed25519, fixed_base::{recode, FixedBase}, secp256k1, wnaf::*};
fn hx(s: &str) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..32 { b[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap(); }
    b
}
fn hx_be(s: &str) -> [u8; 32] { let mut b = hx(s); b.reverse(); b }
#[test]
fn recode_reconstructs_scalar() {
    // sum d_i 2^(ci) == k, checked with i128 chunks on small + structured scalars via Horner over bytes
    for c in 2..=10usize {
        for k0 in [[0u8; 32], [0xFF; 32], { let mut a = [0u8; 32]; a[0] = 1; a }, { let mut a = [0x55u8; 32]; a[31] = 0xA5; a }] {
            let d = recode(&k0, c);
            assert!(d.iter().all(|&x| x >= -(1 << (c - 1)) && x <= (1 << (c - 1))));
            // verify by evaluating in the group Z/2^300 via limb arithmetic: compute sum with a [i128;..] big number
            let mut acc = vec![0i128; 40]; // base 2^16 limbs, signed
            for (i, &x) in d.iter().enumerate() {
                let bit = c * i; let (limb, sh) = (bit / 16, bit % 16);
                acc[limb] += (x as i128) << sh;
            }
            let mut carry = 0i128; let mut bytes = vec![0u8; 80];
            for i in 0..40 { let v = acc[i] + carry; let lo = v.rem_euclid(1 << 16); carry = (v - lo) >> 16; bytes[2 * i] = lo as u8; bytes[2 * i + 1] = (lo >> 8) as u8; }
            assert_eq!(carry, 0);
            assert_eq!(&bytes[..32], &k0[..], "c={c}");
            assert!(bytes[32..].iter().all(|&b| b == 0));
        }
    }
}
#[test]
fn fixed_base_ed25519_matches_reference() {
    for c in [3usize, 4, 5, 6, 8] {
        let fb = FixedBase::new(ed25519::Point::base(), c);
        for line in include_str!("ed_scalar.txt").lines() {
            let f: Vec<&str> = line.split(' ').collect();
            assert_eq!(fb.mul(&hx(f[0])).compress(), hx(f[2]), "c={c} {line}");
        }
    }
}
#[test]
fn fixed_base_secp256k1_matches_reference() {
    // generator from vector file (scalar line k=1, base G)
    let first = include_str!("k1_scalar.txt").lines().nth(1).unwrap();
    let f: Vec<&str> = first.split(' ').collect();
    let g = secp256k1::Point::from_affine(&hx_be(f[1]), &hx_be(f[2]));
    for c in [4usize, 5, 8] {
        let fb = FixedBase::new(g, c);
        for line in include_str!("k1_scalar.txt").lines().filter(|l| l.split(' ').nth(1) == Some(f[1]) && l.split(' ').nth(2) == Some(f[2])) {
            let f: Vec<&str> = line.split(' ').collect();
            let want = if hx_be(f[3]) == [0u8; 32] && hx_be(f[4]) == [0u8; 32] { None } else { Some((hx_be(f[3]), hx_be(f[4]))) };
            assert_eq!(fb.mul(&hx_be(f[0])).to_affine(), want, "c={c} {line}");
        }
    }
}
#[test]
fn double_scalar_matches_two_naive_multiplications() {
    let b = ed25519::Point::base();
    let a = b.scalar_mul(&hx("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
    let (ta, tb) = (odd_multiples(&a, 5), odd_multiples(&b, 7));
    let mut x = 0x9E3779B97F4A7C15u64;
    for _ in 0..60 {
        let (mut s, mut h) = ([0u8; 32], [0u8; 32]);
        for i in 0..32 { x ^= x << 13; x ^= x >> 7; x ^= x << 17; s[i] = x as u8; x ^= x << 13; x ^= x >> 7; x ^= x << 17; h[i] = x as u8; }
        s[31] &= 0x0F; h[31] &= 0x0F; // < 2^252 < l
        let want = b.scalar_mul(&s).add(&a.scalar_mul(&h)).compress();
        assert_eq!(double_scalar_vartime(&s, &tb, 7, &h, &ta, 5).compress(), want);
    }
    assert_eq!(double_scalar_vartime(&[0; 32], &tb, 7, &[0; 32], &ta, 5).compress(), ed25519::Point::IDENTITY.compress());
}
