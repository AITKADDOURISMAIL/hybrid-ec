//! Layer C: validation policies for Ed25519 (Section 4 of the paper). Research prototype.
//!  P_c : permissive decoding, S < l, cofactored equation [8]([S]B - R - [h]A) = O.
//!  P_s : P_c plus canonical encodings of A and R and rejection of small-order A and R.
//! The hash is always computed over the received bytes. h is used unreduced: since [8l]X = O
//! for every curve point X, [8][h]A = [8][h mod l]A, so reduction is not needed here.
#![forbid(unsafe_code)]
pub mod sha512;
pub mod sha256;
pub mod secp_sig;
use hec_curves::{ed25519::Point, wnaf::{double_scalar_vartime, odd_multiples}};
use std::sync::OnceLock;
use sha512::sha512;

const L: [u8; 32] = [0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Policy { Cofactored, Strict }

/// s < l, little-endian (public data, variable time is fine).
pub fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    for i in (0..32).rev() { if s[i] != L[i] { return s[i] < L[i]; } }
    false
}

fn small_order(p: &Point) -> bool { p.mul_by_cofactor().is_identity() }

struct Parsed { a: Point, r: Point, s: [u8; 32], h: [u8; 64] }

fn parse(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64], policy: Policy) -> Option<Parsed> {
    let a = Point::decompress(pk)?;
    let rb: [u8; 32] = sig[..32].try_into().unwrap();
    let r = Point::decompress(&rb)?;
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    if !scalar_is_canonical(&s) { return None; }
    if policy == Policy::Strict {
        if a.compress() != *pk || r.compress() != rb { return None; }
        if small_order(&a) || small_order(&r) { return None; }
    }
    let h = sha512(&[&rb, pk, msg]);
    Some(Parsed { a, r, s, h })
}

/// T = [S]B - R - [h]A (before the cofactor).
fn residual(p: &Parsed) -> Point {
    Point::base().scalar_mul(&p.s)
        .add(&p.r.neg())
        .add(&p.a.neg().scalar_mul_bytes(&p.h))
}

pub fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64], policy: Policy) -> bool {
    match parse(pk, msg, sig, policy) {
        Some(p) => residual(&p).mul_by_cofactor().is_identity(),
        None => false,
    }
}

/// Reference cofactored batch check: [8] sum_i [z_i] T_i = O, with 128-bit coefficients z_i
/// (little-endian, must be fresh uniformly random in deployment). This is a correctness
/// oracle (one scalar multiplication per signature); the optimized multi-scalar version is
/// a separate task. Policy P_c only. Returns false if any item fails parsing.
pub fn verify_batch(items: &[([u8; 32], Vec<u8>, [u8; 64])], z: &[[u8; 16]]) -> bool {
    assert_eq!(items.len(), z.len());
    let mut acc = Point::IDENTITY;
    for ((pk, msg, sig), zi) in items.iter().zip(z) {
        let Some(p) = parse(pk, msg, sig, Policy::Cofactored) else { return false };
        acc = acc.add(&residual(&p).scalar_mul_bytes(zi));
    }
    acc.mul_by_cofactor().is_identity()
}

/// 512-bit little-endian value reduced modulo l (public data; variable time).
pub fn reduce_mod_l(h: &[u8; 64]) -> [u8; 32] {
    let l: [u64; 4] = core::array::from_fn(|i| u64::from_le_bytes(L[8 * i..8 * i + 8].try_into().unwrap()));
    let mut r = [0u64; 4];
    for bit in (0..512).rev() {
        let top = r[3] >> 63;
        for i in (0..4).rev() { r[i] = (r[i] << 1) | if i > 0 { r[i - 1] >> 63 } else { ((h[bit / 8] >> (bit % 8)) & 1) as u64 }; }
        // r < 2l < 2^254, so no overflow out of 256 bits (top is always 0)
        debug_assert_eq!(top, 0);
        let mut t = [0u64; 4]; let mut borrow = 0u64;
        for i in 0..4 { let (v1, b1) = r[i].overflowing_sub(l[i]); let (v2, b2) = v1.overflowing_sub(borrow); t[i] = v2; borrow = (b1 | b2) as u64; }
        if borrow == 0 { r = t; }
    }
    let mut out = [0u8; 32];
    for i in 0..4 { out[8 * i..8 * i + 8].copy_from_slice(&r[i].to_le_bytes()); }
    out
}

const WB: usize = 7; // static base table width
const WA: usize = 5; // per-key table width
fn base_table() -> &'static Vec<Point> {
    static T: OnceLock<Vec<Point>> = OnceLock::new();
    T.get_or_init(|| odd_multiples(&Point::base(), WB))
}

/// Optimized verification: interleaved wNAF for [S]B + [h mod l](-A), then -R and cofactor.
/// Same predicate as `verify`; variable time is acceptable because every input is public.
pub fn verify_fast(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64], policy: Policy) -> bool {
    let Some(p) = parse(pk, msg, sig, policy) else { return false };
    let h = reduce_mod_l(&p.h);
    let ta = odd_multiples(&p.a.neg(), WA);
    let t = double_scalar_vartime(&p.s, base_table(), WB, &h, &ta, WA).add(&p.r.neg());
    t.mul_by_cofactor().is_identity()
}
