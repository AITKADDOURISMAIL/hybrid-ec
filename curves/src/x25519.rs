//! X25519 Montgomery ladder (RFC 7748). Research prototype.
use hec_core::fe25519::Fe;

pub fn x25519(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *k;
    k[0] &= 248; k[31] &= 127; k[31] |= 64;
    let mut ub = *u; ub[31] &= 127;
    let x1 = Fe::from_bytes(&ub);
    let a24 = Fe([121665, 0, 0, 0, 0]);
    let (mut x2, mut z2, mut x3, mut z3) = (Fe::ONE, Fe::ZERO, x1, Fe::ONE);
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let kt = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= kt;
        let (nx2, nx3) = (Fe::select(&x2, &x3, swap), Fe::select(&x3, &x2, swap));
        let (nz2, nz3) = (Fe::select(&z2, &z3, swap), Fe::select(&z3, &z2, swap));
        x2 = nx2; x3 = nx3; z2 = nz2; z3 = nz3;
        swap = kt;
        let a = x2.add(&z2); let aa = a.square();
        let b = x2.sub(&z2); let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3); let d = x3.sub(&z3);
        let da = d.mul(&a); let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&a24.mul(&e)));
    }
    let (nx2, _nx3) = (Fe::select(&x2, &x3, swap), Fe::select(&x3, &x2, swap));
    let nz2 = Fe::select(&z2, &z3, swap);
    nx2.mul(&nz2.invert()).to_bytes()
}
