use hec_curves::{ed25519::Point, group::Group, pippenger::msm_vartime};
#[test]
fn msm_matches_naive_sum() {
    let b = Point::base();
    let mut seed = 99u64;
    let mut rnd = || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };
    for &n in &[1usize, 2, 3, 4, 7, 16, 40, 100] {
        let pts: Vec<Point> = (0..n).map(|_| { let mut k = [0u8; 32]; for c in k.iter_mut() { *c = rnd() as u8; } k[31] &= 0x0F; b.scalar_mul(&k) }).collect();
        let ks: Vec<[u8; 32]> = (0..n).map(|i| { let mut k = [0u8; 32]; for c in k.iter_mut() { *c = rnd() as u8; } if i % 3 == 0 { k[16..].fill(0); } if i % 5 == 0 { k = [0u8; 32]; } k[31] &= 0x1F; k }).collect();
        let mut want = Point::identity();
        for (p, k) in pts.iter().zip(&ks) { want = want.add(&p.scalar_mul(k)); }
        let got = msm_vartime(&pts, &ks);
        assert!(got.add(&want.neg()).is_identity(), "n={n}");
    }
}
