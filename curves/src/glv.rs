//! GLV endomorphism for secp256k1: phi(x,y) = (beta x, y) = [lambda] P, and the scalar split
//! k = k1 + k2 lambda (mod n), |k1|,|k2| < 2^129. Constants verified in Python (see README).
use crate::bn::*;
use crate::secp256k1::{generator, Point};
use crate::wnaf::{multi_scalar_vartime, odd_multiples, wnaf};
use hec_core::fe256k1::Fe;
use std::sync::OnceLock;

pub const N: U256 = [0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff];
pub const P: U256 = [0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff];
const A1: U256 = [0xe86c90e49284eb15, 0x3086d221a7d46bcd, 0, 0];
const A2: U256 = [0x57c1108d9d44cfd8, 0x14ca50f7a8e2f3f6, 1, 0];
const B1ABS: U256 = [0x6f547fa90abfe4c3, 0xe4437ed6010e8828, 0, 0];
const G1: U256 = [0xe893209a45dbb031, 0x3daa8a1471e8ca7f, 0xe86c90e49284eb15, 0x3086d221a7d46bcd];
const G2: U256 = [0x1571b4ae8ac47f71, 0x221208ac9df506c6, 0x6f547fa90abfe4c4, 0xe4437ed6010e8828];
const BETA_LE: [u8; 32] = [238,1,149,113,40,108,57,193,149,137,245,18,117,73,240,156,233,52,52,172,158,71,100,110,16,7,124,101,43,106,233,122];

pub fn endo(p: &Point) -> Point { Point { x: p.x.mul(&Fe::from_bytes(&BETA_LE)), y: p.y, z: p.z } }

pub struct Split { pub neg1: bool, pub k1: U256, pub neg2: bool, pub k2: U256 }

/// round(k * g / 2^384)
fn round_shift384(k: &U256, g: &U256) -> U256 {
    let mut w = wide_mul(k, g);
    let mut carry = 1u64 << 63; // + 2^383
    for i in 5..8 { let (v, c) = w[i].overflowing_add(carry); w[i] = v; carry = c as u64; }
    [w[6], w[7], 0, 0]
}
fn signed_mag(x: U256) -> (bool, U256) { if x[3] >> 63 == 1 { (true, neg_wrapping(&x)) } else { (false, x) } }

pub fn split(k: &U256) -> Split {
    let (c1, c2) = (round_shift384(k, &G1), round_shift384(k, &G2));
    // exact values are small, so wrapping 256-bit two's complement arithmetic is exact
    let k1 = sub(&sub(k, &mul_low(&c1, &A1)).0, &mul_low(&c2, &A2)).0;
    let k2 = sub(&mul_low(&c1, &B1ABS), &mul_low(&c2, &A1)).0; // b2 = a1
    let ((neg1, k1), (neg2, k2)) = (signed_mag(k1), signed_mag(k2));
    Split { neg1, k1, neg2, k2 }
}

const WG: usize = 7;
const WQ: usize = 5;
fn gen_tables() -> &'static (Vec<Point>, Vec<Point>) {
    static T: OnceLock<(Vec<Point>, Vec<Point>)> = OnceLock::new();
    T.get_or_init(|| { let t = odd_multiples(&generator(), WG); let p = t.iter().map(endo).collect(); (t, p) })
}

/// u1*G + u2*Q with GLV (four ~128-bit streams interleaved). Variable time: public scalars only.
pub fn double_mul_glv(u1: &U256, u2: &U256, q: &Point) -> Point {
    let (tg, tpg) = gen_tables();
    let tq = odd_multiples(q, WQ);
    let tpq: Vec<Point> = tq.iter().map(endo).collect();
    let (s1, s2) = (split(u1), split(u2));
    let d = |m: &U256, w| wnaf(&to_le(m), w);
    multi_scalar_vartime(&[
        (d(&s1.k1, WG), &tg[..], s1.neg1), (d(&s1.k2, WG), &tpg[..], s1.neg2),
        (d(&s2.k1, WQ), &tq[..], s2.neg1), (d(&s2.k2, WQ), &tpq[..], s2.neg2),
    ])
}
