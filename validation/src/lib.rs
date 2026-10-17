//! Layer C: validation policies for Ed25519 (Section 4 of the paper). Research prototype.
//!  P_c : permissive decoding, S < l, cofactored equation [8]([S]B - R - [h]A) = O.
//!  P_s : P_c plus canonical encodings of A and R and rejection of small-order A and R.
//! The hash is always computed over the received bytes. h is used unreduced: since [8l]X = O
//! for every curve point X, [8][h]A = [8][h mod l]A, so reduction is not needed here.
#![forbid(unsafe_code)]
pub mod sha512;
pub mod sha256;
pub mod secp_sig;
use hec_curves::{ed25519::Point, pippenger::msm_vartime, wnaf::{double_scalar_vartime, odd_multiples}};
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

/// 256x256 -> 512-bit schoolbook product of little-endian integers (public data).
fn mul_wide(a: &[u8; 32], b: &[u8; 32]) -> [u64; 8] {
    let al: [u64; 4] = core::array::from_fn(|i| u64::from_le_bytes(a[8 * i..8 * i + 8].try_into().unwrap()));
    let bl: [u64; 4] = core::array::from_fn(|i| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap()));
    let mut out = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = al[i] as u128 * bl[j] as u128 + out[i + j] as u128 + carry;
            out[i + j] = t as u64; carry = t >> 64;
        }
        out[i + 4] = carry as u64;
    }
    out
}
fn wide_bytes(w: &[u64; 8]) -> [u8; 64] {
    let mut o = [0u8; 64];
    for i in 0..8 { o[8 * i..8 * i + 8].copy_from_slice(&w[i].to_le_bytes()); }
    o
}

/// Optimized cofactored batch check for policy P_c: the same equation as `verify_batch`,
/// evaluated as ONE multi-scalar multiplication of size 2u+1 (Pippenger):
///   [8]( [sum z_i S_i]B - sum [z_i]R_i - sum [z_i h_i mod l]A_i ) = O.
/// z_i are 128-bit coefficients (fresh uniformly random in deployment; the caller supplies them
/// so that the function is deterministic and testable). Returns false if any item fails parsing.
pub fn verify_batch_fast(items: &[([u8; 32], Vec<u8>, [u8; 64])], z: &[[u8; 16]]) -> bool {
    assert_eq!(items.len(), z.len());
    let mut points = Vec::with_capacity(2 * items.len() + 1);
    let mut scalars = Vec::with_capacity(2 * items.len() + 1);
    let mut sacc = [0u64; 8]; // sum z_i S_i, at most 2^128 * 2^253 * u < 2^512 for u < 2^130
    for ((pk, msg, sig), zi) in items.iter().zip(z) {
        let Some(p) = parse(pk, msg, sig, Policy::Cofactored) else { return false };
        let mut zf = [0u8; 32]; zf[..16].copy_from_slice(zi);
        let w = mul_wide(&zf, &p.s);
        let mut carry = 0u64;
        for k in 0..8 { let (v1, c1) = sacc[k].overflowing_add(w[k]); let (v2, c2) = v1.overflowing_add(carry); sacc[k] = v2; carry = (c1 | c2) as u64; }
        let h = reduce_mod_l(&p.h);
        let zh = reduce_mod_l(&wide_bytes(&mul_wide(&zf, &h)));
        points.push(p.r.neg()); scalars.push(zf);
        points.push(p.a.neg()); scalars.push(zh);
    }
    points.push(Point::base());
    scalars.push(reduce_mod_l(&wide_bytes(&sacc)));
    msm_vartime(&points, &scalars).mul_by_cofactor().is_identity()
}

/// Ed25519 signing (RFC 8032) used ONLY to generate distinct valid workloads for tests and benchmarks.
/// It is not a hardened signing routine: it is not evaluated for constant time and clamping
/// and nonce derivation are the only protections. Returns (public key, signature).
pub fn sign_for_tests(seed: &[u8; 32], msg: &[u8]) -> ([u8; 32], [u8; 64]) {
    let h = sha512(&[seed]);
    let mut a: [u8; 32] = h[..32].try_into().unwrap();
    a[0] &= 248; a[31] &= 127; a[31] |= 64;
    let pk = Point::base().scalar_mul(&a).compress();
    let r = reduce_mod_l(&sha512(&[&h[32..], msg]));
    let rb = Point::base().scalar_mul(&r).compress();
    let k = reduce_mod_l(&sha512(&[&rb, &pk, msg]));
    let mut w = mul_wide(&k, &a);
    let mut rw = [0u64; 8];
    for i in 0..4 { rw[i] = u64::from_le_bytes(r[8 * i..8 * i + 8].try_into().unwrap()); }
    let mut carry = 0u64;
    for i in 0..8 { let (v1, c1) = w[i].overflowing_add(rw[i]); let (v2, c2) = v1.overflowing_add(carry); w[i] = v2; carry = (c1 | c2) as u64; }
    let sb = reduce_mod_l(&wide_bytes(&w));
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&rb); sig[32..].copy_from_slice(&sb);
    (pk, sig)
}
