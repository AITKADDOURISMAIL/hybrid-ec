//! secp256k1 signature verification: BIP-340 Schnorr and ECDSA, using GLV double multiplication.
//! Variable time (public inputs only). ECDSA accepts high-S (no low-S policy applied).
use crate::sha256::sha256;
use hec_curves::bn::*;
use hec_curves::glv::{double_mul_glv, N, P};
use hec_curves::pippenger::msm_vartime;
use hec_curves::secp256k1::{generator, lift_x_even, on_curve, Point};

fn be_rev(b: &[u8; 32]) -> [u8; 32] { let mut r = *b; r.reverse(); r }

fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let th = sha256(&[tag.as_bytes()]);
    let mut v: Vec<&[u8]> = vec![&th, &th];
    v.extend_from_slice(parts);
    sha256(&v)
}

pub fn bip340_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Some(p) = lift_x_even(&be_rev(pk)) else { return false };
    let r: [u8; 32] = sig[..32].try_into().unwrap();
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    if cmp(&from_be(&r), &P) != core::cmp::Ordering::Less { return false; }
    let s = from_be(&s);
    if cmp(&s, &N) != core::cmp::Ordering::Less { return false; }
    let e = reduce(&from_be(&tagged_hash("BIP0340/challenge", &[&r, pk, msg])), &N);
    let ne = mod_neg(&e, &N);
    let big_r = double_mul_glv(&s, &ne, &p);
    match big_r.to_affine() {
        Some((x, y)) => y[0] & 1 == 0 && be_rev(&x) == r,
        None => false,
    }
}

/// BIP-340 batch verification as one multi-scalar multiplication (Pippenger) of size 2u+1:
///   [sum z_i s_i]G - sum [z_i]R_i - sum [z_i e_i]P_i = O,   with R_i = lift_x(r_i) and P_i = lift_x(pk_i).
/// Policy: the whole batch is rejected if any item fails parsing (x >= p, no square root, r >= p or s >= n).
/// z_i are nonzero 128-bit coefficients, fresh and uniformly random in deployment (the first may be 1); the caller
/// supplies them so that the function is deterministic and testable. Variable time (public inputs only).
/// A passing batch means every signature is valid except with probability at most 2^-128.
pub fn bip340_verify_batch(items: &[([u8; 32], Vec<u8>, [u8; 64])], z: &[[u8; 16]]) -> bool {
    assert_eq!(items.len(), z.len());
    let mut points = Vec::with_capacity(2 * items.len() + 1);
    let mut scalars = Vec::with_capacity(2 * items.len() + 1);
    let mut sacc: U256 = [0; 4];
    for ((pk, msg, sig), zi) in items.iter().zip(z) {
        let Some(p) = lift_x_even(&be_rev(pk)) else { return false };
        let r: [u8; 32] = sig[..32].try_into().unwrap();
        let Some(rp) = lift_x_even(&be_rev(&r)) else { return false }; // also rejects r >= p
        let s = from_be(&sig[32..].try_into().unwrap());
        if cmp(&s, &N) != core::cmp::Ordering::Less { return false; }
        let e = reduce(&from_be(&tagged_hash("BIP0340/challenge", &[&r, pk, msg])), &N);
        let mut zf = [0u8; 32]; zf[..16].copy_from_slice(zi);
        let zn = from_le(&zf);
        sacc = mod_add(&sacc, &mod_mul(&zn, &s, &N), &N);
        points.push(rp.neg()); scalars.push(zf);
        points.push(p.neg()); scalars.push(to_le(&mod_mul(&zn, &e, &N)));
    }
    points.push(generator()); scalars.push(to_le(&sacc));
    msm_vartime(&points, &scalars).z.to_bytes() == [0u8; 32]
}

/// ECDSA verification; z is the (already hashed) message digest, big-endian.
pub fn ecdsa_verify(qx: &[u8; 32], qy: &[u8; 32], z: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> bool {
    let (qxl, qyl) = (be_rev(qx), be_rev(qy));
    let lt = |a: &U256, m: &U256| cmp(a, m) == core::cmp::Ordering::Less;
    if !lt(&from_le(&qxl), &P) || !lt(&from_le(&qyl), &P) || !on_curve(&qxl, &qyl) { return false; }
    let (r, s) = (from_be(r), from_be(s));
    if is_zero(&r) || is_zero(&s) || !lt(&r, &N) || !lt(&s, &N) { return false; }
    let z = reduce(&from_be(z), &N);
    let w = mod_inv(&s, &N);
    let (u1, u2) = (mod_mul(&z, &w, &N), mod_mul(&r, &w, &N));
    let q = Point::from_affine(&qxl, &qyl);
    match double_mul_glv(&u1, &u2, &q).to_affine() {
        Some((x, _)) => reduce(&from_le(&x), &N) == r,
        None => false,
    }
}
#[allow(dead_code)]
fn _use(_: Point) { let _ = generator(); }

/// Single-curve baseline: the same predicate as `bip340_verify` with the dedicated secp256k1 arithmetic
/// (dedicated squaring, Jacobian coordinates with mixed addition, addition-chain inversion and square root).
pub fn bip340_verify_dedicated(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool { bip340_dedicated_impl(pk, msg, sig, true) }
/// Ablation: dedicated point arithmetic only, with the unified square root and inversion (binary exponentiation).
pub fn bip340_verify_dedicated_arith_only(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool { bip340_dedicated_impl(pk, msg, sig, false) }
fn bip340_dedicated_impl(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64], chain: bool) -> bool {
    use hec_curves::dedicated::k1;
    let pj = if chain { k1::lift_x_even(&be_rev(pk)) } else { lift_x_even(&be_rev(pk)).map(|q| k1::Jac::from_point(&q)) };
    let Some(p) = pj else { return false };
    let r: [u8; 32] = sig[..32].try_into().unwrap();
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    if cmp(&from_be(&r), &P) != core::cmp::Ordering::Less { return false; }
    let s = from_be(&s);
    if cmp(&s, &N) != core::cmp::Ordering::Less { return false; }
    let e = reduce(&from_be(&tagged_hash("BIP0340/challenge", &[&r, pk, msg])), &N);
    let ne = mod_neg(&e, &N);
    let big_r = k1::double_mul_glv(&s, &ne, &p);
    match big_r.to_affine_bytes(chain) {
        Some((x, y)) => y[0] & 1 == 0 && be_rev(&x) == r,
        None => false,
    }
}
