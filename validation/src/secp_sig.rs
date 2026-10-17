//! secp256k1 signature verification: BIP-340 Schnorr and ECDSA, using GLV double multiplication.
//! Variable time (public inputs only). ECDSA accepts high-S (no low-S policy applied).
use crate::sha256::sha256;
use hec_curves::bn::*;
use hec_curves::glv::{double_mul_glv, N, P};
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
