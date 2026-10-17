use hec_curves::{bn::*, glv::*, secp256k1::*};
fn rnd(x: &mut u64) -> U256 { let mut r = [0u64; 4]; for l in r.iter_mut() { *x ^= *x << 13; *x ^= *x >> 7; *x ^= *x << 17; *l = *x; } r }
#[test]
fn generator_and_endomorphism() {
    let g = generator();
    assert!(on_curve(&g.to_affine().unwrap().0, &g.to_affine().unwrap().1));
    let lam: [u64; 4] = [0xdf02967c1b23bd72, 0x122e22ea20816678, 0xa5261c028812645a, 0x5363ad4cc05c30e0];
    assert_eq!(endo(&g).to_affine(), g.scalar_mul(&to_le(&lam)).to_affine());
}
#[test]
fn split_is_short_and_correct() {
    let g = generator();
    let mut s = 0x1234_5678_9ABC_DEF1u64;
    let mut ks = vec![[0u64; 4], [1, 0, 0, 0], sub(&N, &[1, 0, 0, 0]).0, [u64::MAX; 4]];
    for _ in 0..40 { ks.push(reduce(&rnd(&mut s), &N)); }
    for k in ks {
        let sp = split(&k);
        for m in [&sp.k1, &sp.k2] { assert!(m[2] <= 1 && m[3] == 0, "not short: {:x?}", m); }
        let a = g.scalar_mul(&to_le(&sp.k1)); let a = if sp.neg1 { a.neg() } else { a };
        let b = endo(&g).scalar_mul(&to_le(&sp.k2)); let b = if sp.neg2 { b.neg() } else { b };
        assert_eq!(a.add(&b).to_affine(), g.scalar_mul(&to_le(&k)).to_affine(), "split k={:x?}", k);
    }
}
#[test]
fn glv_double_mul_matches_naive() {
    let g = generator();
    let mut s = 0xDEADBEEFCAFEF00Du64;
    let q = g.scalar_mul(&to_le(&rnd(&mut s)));
    for i in 0..30 {
        let (u1, u2) = if i == 0 { ([0; 4], [0; 4]) } else { (rnd(&mut s), rnd(&mut s)) };
        let want = g.scalar_mul(&to_le(&u1)).add(&q.scalar_mul(&to_le(&u2)));
        assert_eq!(double_mul_glv(&u1, &u2, &q).to_affine(), want.to_affine(), "i={i}");
    }
}
#[test]
fn bn_inverse_and_mul() {
    let mut s = 77u64;
    for _ in 0..50 {
        let a = reduce(&rnd(&mut s), &N);
        if is_zero(&a) { continue; }
        assert_eq!(mod_mul(&a, &mod_inv(&a, &N), &N), [1, 0, 0, 0]);
    }
}
