//! Dedicated (non-unified) single-curve baseline, used only to measure what the unified layer costs
//! (paper, section on the cost of unification). Verification only: variable time, public data.
//! Ed25519: dedicated squaring, lazy additions and subtractions, cached additions (8 multiplications),
//! doubling without the T coordinate when no addition follows.
//! secp256k1: Jacobian coordinates with incomplete formulas (exceptional cases handled by branches, which is
//! acceptable on public data), dedicated squaring, mixed additions with affine tables, addition-chain inversion.
//! Every function returns the same group element as the unified code; the tests compare both.
use crate::group::Group;
use hec_core::{fe25519, fe256k1};

pub mod ed {
    use super::*;
    use crate::ed25519::{Point, D, D2, SQRT_M1};
    use fe25519::Fe;

    /// Extended coordinates, as in the unified layer. Invariant: every limb is carried (below 2^52).
    #[derive(Clone, Copy, Debug)]
    pub struct Ext { pub x: Fe, pub y: Fe, pub z: Fe, pub t: Fe }
    /// (Y+X, Y-X, 2dT, 2Z): lets a general addition cost 8 multiplications. Limbs below 2^53.
    #[derive(Clone, Copy, Debug)]
    pub struct Cached { ypx: Fe, ymx: Fe, t2d: Fe, z2: Fe }

    impl Ext {
        pub fn from_point(p: &Point) -> Ext { Ext { x: p.x, y: p.y, z: p.z, t: p.t } }
        pub fn to_point(&self) -> Point { Point { x: self.x, y: self.y, z: self.z, t: self.t } }
        pub fn neg(&self) -> Ext { Ext { x: Fe::ZERO.sub(&self.x), y: self.y, z: self.z, t: Fe::ZERO.sub(&self.t) } }

        pub fn to_cached(&self) -> Cached {
            let d2 = Fe::from_bytes(&D2);
            Cached { ypx: self.y.add(&self.x), ymx: self.y.sub(&self.x), t2d: self.t.mul(&d2), z2: self.z.add(&self.z) }
        }

        /// dbl-2008-hwcd (a = -1) with squarings and lazy reductions; `with_t` = false leaves T unspecified.
        pub fn dbl(&self, with_t: bool) -> Ext {
            let a = self.x.square_fast();
            let b = self.y.square_fast();
            let zz = self.z.square_fast();
            let c = zz.add_lazy(&zz);                       // 2 Z^2
            let ab = a.add_lazy(&b);                        // A + B
            let e = self.x.add_lazy(&self.y).square_fast().sub_lazy(&ab); // (X+Y)^2 - A - B
            let g = b.sub_lazy(&a);                         // B - A      (= D + B with D = -A)
            let f = b.sub_lazy(&a.add_lazy(&c));            // B - A - C  (= G - C)
            let h = Fe::ZERO.sub_lazy(&ab);                 // -(A + B)   (= D - B)
            Ext { x: e.mul(&f), y: g.mul(&h), z: f.mul(&g), t: if with_t { e.mul(&h) } else { Fe::ZERO } }
        }

        /// add-2008-hwcd-3 with a cached second operand: 8 multiplications.
        pub fn add_cached(&self, q: &Cached) -> Ext {
            let pp = self.y.add_lazy(&self.x).mul(&q.ypx);
            let mm = self.y.sub_lazy(&self.x).mul(&q.ymx);
            let tt = self.t.mul(&q.t2d);
            let zz = self.z.mul(&q.z2);
            let e = pp.sub_lazy(&mm);
            let h = pp.add_lazy(&mm);
            let g = zz.add_lazy(&tt);
            let f = zz.sub_lazy(&tt);
            Ext { x: e.mul(&f), y: g.mul(&h), z: f.mul(&g), t: e.mul(&h) }
        }
    }
    impl Cached {
        pub fn neg(&self) -> Cached { Cached { ypx: self.ymx, ymx: self.ypx, t2d: Fe::ZERO.sub(&self.t2d), z2: self.z2 } }
    }

    /// a^(2^250 - 1) and a^11 by the usual chain (250 squarings, 11 multiplications).
    fn pow250(a: &Fe) -> (Fe, Fe) {
        let sqn = |x: &Fe, n: u32| { let mut r = *x; for _ in 0..n { r = r.square_fast(); } r };
        let z2 = a.square_fast();
        let z9 = sqn(&z2, 2).mul(a);
        let z11 = z9.mul(&z2);
        let z_5_0 = z11.square_fast().mul(&z9);
        let z_10_0 = sqn(&z_5_0, 5).mul(&z_5_0);
        let z_20_0 = sqn(&z_10_0, 10).mul(&z_10_0);
        let z_40_0 = sqn(&z_20_0, 20).mul(&z_20_0);
        let z_50_0 = sqn(&z_40_0, 10).mul(&z_10_0);
        let z_100_0 = sqn(&z_50_0, 50).mul(&z_50_0);
        let z_200_0 = sqn(&z_100_0, 100).mul(&z_100_0);
        (sqn(&z_200_0, 50).mul(&z_50_0), z11)
    }

    /// Permissive decoding as `Point::decompress` (ZIP-215 style), with one exponentiation by chain
    /// (the combined inversion and square root of RFC 8032, section 5.1.3) instead of an inversion and a binary square root.
    pub fn decompress_chain(b: &[u8; 32]) -> Option<Point> {
        let sign = (b[31] >> 7) as u64;
        let mut yb = *b; yb[31] &= 0x7F;
        let y = Fe::from_bytes(&yb);
        let yy = y.square_fast();
        let u = yy.sub(&Fe::ONE);
        let v = Fe::from_bytes(&D).mul(&yy).add(&Fe::ONE);
        let v3 = v.square_fast().mul(&v);
        let v7 = v3.square_fast().mul(&v);
        let uv7 = u.mul(&v7);
        let (z250, _) = pow250(&uv7);
        let pw = z250.square_fast().square_fast().mul(&uv7);        // (u v^7)^(2^252 - 3)
        let mut x = u.mul(&v3).mul(&pw);
        let vxx = v.mul(&x.square_fast());
        if vxx.sub(&u).to_bytes() != [0u8; 32] {
            if vxx.add(&u).to_bytes() != [0u8; 32] { return None; }
            x = x.mul(&Fe::from_bytes(&SQRT_M1));
        }
        let par = (x.to_bytes()[0] & 1) as u64;
        let neg = Fe::ZERO.sub(&x);
        x = Fe::select(&x, &neg, par ^ sign);
        Some(Point { x, y, z: Fe::ONE, t: x.mul(&y) })
    }

    /// Odd multiples [1P, 3P, ..., (2^(w-1)-1)P] in cached form.
    pub fn odd_multiples_cached(p: &Ext, w: usize) -> Vec<Cached> {
        let n = 1usize << (w - 2);
        let p2 = p.dbl(true).to_cached();
        let mut cur = *p;
        let mut t = Vec::with_capacity(n);
        t.push(cur.to_cached());
        for _ in 1..n { cur = cur.add_cached(&p2); t.push(cur.to_cached()); }
        t
    }

    /// a*P + b*Q by interleaved wNAF, as `wnaf::double_scalar_vartime`, with the dedicated arithmetic.
    pub fn double_scalar_vartime(a: &[u8; 32], ta: &[Cached], wa: usize, b: &[u8; 32], tb: &[Cached], wb: usize) -> Ext {
        let (da, db) = (crate::wnaf::wnaf(a, wa), crate::wnaf::wnaf(b, wb));
        let mut acc = Ext::from_point(&Point::IDENTITY);
        let len = da.len().max(db.len());
        for i in (0..len).rev() {
            let (xa, xb) = (da.get(i).copied().unwrap_or(0), db.get(i).copied().unwrap_or(0));
            acc = acc.dbl(i == 0 || xa != 0 || xb != 0);
            for (d, t) in [(xa, ta), (xb, tb)] {
                if d > 0 { acc = acc.add_cached(&t[(d as usize) >> 1]); }
                else if d < 0 { acc = acc.add_cached(&t[((-d) as usize) >> 1].neg()); }
            }
        }
        acc
    }
}

pub mod k1 {
    use super::*;
    use crate::secp256k1::Point;
    use fe256k1::Fe;

    /// Jacobian coordinates (x/z^2, y/z^3); `inf` marks the point at infinity.
    #[derive(Clone, Copy, Debug)]
    pub struct Jac { pub x: Fe, pub y: Fe, pub z: Fe, pub inf: bool }

    fn is_zero(a: &Fe) -> bool { a.to_bytes() == [0u8; 32] }
    fn is_one(a: &Fe) -> bool { a.0 == [1, 0, 0, 0, 0] }
    fn dbl_fe(a: &Fe) -> Fe { a.add(a) }

    impl Jac {
        pub const INF: Jac = Jac { x: Fe::ZERO, y: Fe::ONE, z: Fe::ZERO, inf: true };
        pub fn from_point(p: &Point) -> Jac { Jac { x: p.x, y: p.y, z: p.z, inf: false } } // projective z = 1 only
        pub fn from_affine(x: Fe, y: Fe) -> Jac { Jac { x, y, z: Fe::ONE, inf: false } }
        pub fn endo(&self, beta: &Fe) -> Jac { Jac { x: self.x.mul(beta), ..*self } }

        /// dbl-2009-l (a = 0): 2M + 5S.
        pub fn dbl(&self) -> Jac {
            if self.inf { return *self; }
            let a = self.x.square_fast();
            let b = self.y.square_fast();
            let c = b.square_fast();
            let d = self.x.add(&b).square_fast().sub(&a).sub(&c);
            let d = dbl_fe(&d);
            let e = dbl_fe(&a).add(&a);                       // 3A
            let f = e.square_fast();
            let x3 = f.sub(&dbl_fe(&d));
            let c8 = dbl_fe(&dbl_fe(&dbl_fe(&c)));
            let y3 = e.mul(&d.sub(&x3)).sub(&c8);
            let z3 = dbl_fe(&self.y.mul(&self.z));
            Jac { x: x3, y: y3, z: z3, inf: false }
        }

        pub fn neg(&self) -> Jac { Jac { y: Fe::ZERO.sub(&self.y), ..*self } }

        /// Addition with the exceptional cases handled by branches (public data only).
        pub fn add(&self, o: &Jac) -> Jac {
            if self.inf { return *o; }
            if o.inf { return *self; }
            let z1z1 = self.z.square_fast();
            let (u1, s1, u2, s2);
            let mixed = is_one(&o.z);
            if mixed {                                          // madd-2007-bl: 7M + 4S
                u1 = self.x; s1 = self.y;
                u2 = o.x.mul(&z1z1); s2 = o.y.mul(&self.z).mul(&z1z1);
            } else {                                             // add-2007-bl: 11M + 5S
                let z2z2 = o.z.square_fast();
                u1 = self.x.mul(&z2z2); s1 = self.y.mul(&o.z).mul(&z2z2);
                u2 = o.x.mul(&z1z1); s2 = o.y.mul(&self.z).mul(&z1z1);
            }
            let h = u2.sub(&u1);
            let r0 = s2.sub(&s1);
            if is_zero(&h) { return if is_zero(&r0) { self.dbl() } else { Jac::INF }; }
            let r = dbl_fe(&r0);
            let hh = h.square_fast();
            let i = dbl_fe(&dbl_fe(&hh));
            let j = h.mul(&i);
            let v = u1.mul(&i);
            let x3 = r.square_fast().sub(&j).sub(&dbl_fe(&v));
            let y3 = r.mul(&v.sub(&x3)).sub(&dbl_fe(&s1.mul(&j)));
            let z3 = if mixed { self.z.add(&h).square_fast().sub(&z1z1).sub(&hh) }
                     else { let z2z2 = o.z.square_fast(); self.z.add(&o.z).square_fast().sub(&z1z1).sub(&z2z2).mul(&h) };
            Jac { x: x3, y: y3, z: z3, inf: false }
        }

        /// Normalize to z = 1 (one inversion).
        pub fn to_affine_jac(&self, chain: bool) -> Option<Jac> {
            if self.inf { return None; }
            let zi = if chain { invert_chain(&self.z) } else { self.z.invert() };
            let zi2 = zi.square_fast();
            Some(Jac::from_affine(self.x.mul(&zi2), self.y.mul(&zi2).mul(&zi)))
        }
        /// Affine coordinates (x, y) as 32-byte little-endian strings.
        pub fn to_affine_bytes(&self, chain: bool) -> Option<([u8; 32], [u8; 32])> {
            let a = self.to_affine_jac(chain)?;
            Some((a.x.to_bytes(), a.y.to_bytes()))
        }
    }

    impl Group for Jac {
        fn identity() -> Self { Jac::INF }
        fn add(&self, o: &Self) -> Self { Jac::add(self, o) }
        fn double(&self) -> Self { self.dbl() }
        fn neg(&self) -> Self { Jac::neg(self) }
        fn select(a: &Self, b: &Self, c: u64) -> Self { if c & 1 == 1 { *b } else { *a } }
    }

    /// x^(p-2) by the addition chain of libsecp256k1 (255 squarings, 15 multiplications).
    pub fn invert_chain(a: &Fe) -> Fe {
        let sqn = |x: &Fe, n: u32| { let mut r = *x; for _ in 0..n { r = r.square_fast(); } r };
        let x2 = a.square_fast().mul(a);
        let x3 = x2.square_fast().mul(a);
        let x6 = sqn(&x3, 3).mul(&x3);
        let x9 = sqn(&x6, 3).mul(&x3);
        let x11 = sqn(&x9, 2).mul(&x2);
        let x22 = sqn(&x11, 11).mul(&x11);
        let x44 = sqn(&x22, 22).mul(&x22);
        let x88 = sqn(&x44, 44).mul(&x44);
        let x176 = sqn(&x88, 88).mul(&x88);
        let x220 = sqn(&x176, 44).mul(&x44);
        let x223 = sqn(&x220, 3).mul(&x3);
        let t = sqn(&x223, 23).mul(&x22);
        let t = sqn(&t, 5).mul(a);
        let t = sqn(&t, 3).mul(&x2);
        sqn(&t, 2).mul(a)
    }

    /// x^((p+1)/4) by an addition chain (255 squarings, 14 multiplications): square root of a quadratic residue.
    pub fn sqrt_chain(a: &Fe) -> Fe {
        let sqn = |x: &Fe, n: u32| { let mut r = *x; for _ in 0..n { r = r.square_fast(); } r };
        let x2 = a.square_fast().mul(a);
        let x3 = x2.square_fast().mul(a);
        let x6 = sqn(&x3, 3).mul(&x3);
        let x9 = sqn(&x6, 3).mul(&x3);
        let x11 = sqn(&x9, 2).mul(&x2);
        let x22 = sqn(&x11, 11).mul(&x11);
        let x44 = sqn(&x22, 22).mul(&x22);
        let x88 = sqn(&x44, 44).mul(&x44);
        let x176 = sqn(&x88, 88).mul(&x88);
        let x220 = sqn(&x176, 44).mul(&x44);
        let x223 = sqn(&x220, 3).mul(&x3);
        let t = sqn(&x223, 23).mul(&x22);
        sqn(&sqn(&t, 6).mul(&x2), 2)
    }

    /// BIP-340 lift_x with the dedicated field operations: affine point with the given x (little-endian) and even y.
    pub fn lift_x_even(x_le: &[u8; 32]) -> Option<Jac> {
        let x = Fe::from_bytes(x_le);
        if x.to_bytes() != *x_le { return None; }
        let rhs = x.square_fast().mul(&x).add(&Fe([7, 0, 0, 0, 0]));
        let mut y = sqrt_chain(&rhs);
        if y.square_fast().sub(&rhs).to_bytes() != [0u8; 32] { return None; }
        if y.to_bytes()[0] & 1 == 1 { y = Fe::ZERO.sub(&y); }
        Some(Jac::from_affine(x, y))
    }

    const WG: usize = 7;
    const WQ: usize = 5;
    /// Odd multiples of G in affine form (z = 1, so that additions are mixed) and of phi(G).
    fn gen_tables() -> &'static (Vec<Jac>, Vec<Jac>) {
        use std::sync::OnceLock;
        static T: OnceLock<(Vec<Jac>, Vec<Jac>)> = OnceLock::new();
        T.get_or_init(|| {
            let g = Jac::from_point(&crate::secp256k1::generator());
            let t: Vec<Jac> = crate::wnaf::odd_multiples(&g, WG).iter().map(|p| p.to_affine_jac(true).unwrap()).collect();
            let beta = Fe::from_bytes(&crate::glv::BETA_LE);
            let p = t.iter().map(|p| p.endo(&beta)).collect();
            (t, p)
        })
    }

    /// u1*G + u2*Q with GLV and the dedicated arithmetic (the counterpart of `glv::double_mul_glv`).
    pub fn double_mul_glv(u1: &crate::bn::U256, u2: &crate::bn::U256, q: &Jac) -> Jac {
        use crate::{bn::to_le, glv::split, wnaf::{multi_scalar_vartime, odd_multiples, wnaf}};
        let (tg, tpg) = gen_tables();
        let beta = Fe::from_bytes(&crate::glv::BETA_LE);
        let tq = odd_multiples(q, WQ);
        let tpq: Vec<Jac> = tq.iter().map(|p| p.endo(&beta)).collect();
        let (s1, s2) = (split(u1), split(u2));
        let d = |m: &crate::bn::U256, w| wnaf(&to_le(m), w);
        multi_scalar_vartime(&[
            (d(&s1.k1, WG), &tg[..], s1.neg1), (d(&s1.k2, WG), &tpg[..], s1.neg2),
            (d(&s2.k1, WQ), &tq[..], s2.neg1), (d(&s2.k2, WQ), &tpq[..], s2.neg2),
        ])
    }
}
