//! Tiny variable-time 256-bit integer helpers (little-endian u64 limbs).
//! Used ONLY on public data (signature verification scalars); never on secrets.
use core::cmp::Ordering;
pub type U256 = [u64; 4];

pub fn from_be(b: &[u8; 32]) -> U256 { core::array::from_fn(|i| u64::from_be_bytes(b[24 - 8 * i..32 - 8 * i].try_into().unwrap())) }
pub fn to_be(a: &U256) -> [u8; 32] { let mut o = [0u8; 32]; for i in 0..4 { o[24 - 8 * i..32 - 8 * i].copy_from_slice(&a[i].to_be_bytes()); } o }
pub fn from_le(b: &[u8; 32]) -> U256 { core::array::from_fn(|i| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap())) }
pub fn to_le(a: &U256) -> [u8; 32] { let mut o = [0u8; 32]; for i in 0..4 { o[8 * i..8 * i + 8].copy_from_slice(&a[i].to_le_bytes()); } o }

pub fn cmp(a: &U256, b: &U256) -> Ordering {
    for i in (0..4).rev() { if a[i] != b[i] { return a[i].cmp(&b[i]); } }
    Ordering::Equal
}
pub fn is_zero(a: &U256) -> bool { a.iter().all(|&x| x == 0) }
pub fn add(a: &U256, b: &U256) -> (U256, bool) {
    let (mut r, mut c) = ([0u64; 4], false);
    for i in 0..4 { let (v1, c1) = a[i].overflowing_add(b[i]); let (v2, c2) = v1.overflowing_add(c as u64); r[i] = v2; c = c1 | c2; }
    (r, c)
}
pub fn sub(a: &U256, b: &U256) -> (U256, bool) {
    let (mut r, mut br) = ([0u64; 4], false);
    for i in 0..4 { let (v1, b1) = a[i].overflowing_sub(b[i]); let (v2, b2) = v1.overflowing_sub(br as u64); r[i] = v2; br = b1 | b2; }
    (r, br)
}
pub fn wide_mul(a: &U256, b: &U256) -> [u64; 8] {
    let mut r = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let v = (a[i] as u128) * (b[j] as u128) + r[i + j] as u128 + carry;
            r[i + j] = v as u64; carry = v >> 64;
        }
        r[i + 4] = carry as u64;
    }
    r
}
pub fn mul_low(a: &U256, b: &U256) -> U256 { let w = wide_mul(a, b); [w[0], w[1], w[2], w[3]] }
pub fn neg_wrapping(a: &U256) -> U256 { sub(&[0; 4], a).0 }

/// a reduced into [0, m) (repeated subtraction; fine when a < 2^256 and m > 2^255).
pub fn reduce(a: &U256, m: &U256) -> U256 {
    let mut r = *a;
    while cmp(&r, m) != Ordering::Less { r = sub(&r, m).0; }
    r
}
pub fn mod_add(a: &U256, b: &U256, m: &U256) -> U256 {
    let (s, c) = add(a, b);
    if c || cmp(&s, m) != Ordering::Less { sub(&s, m).0 } else { s }
}
pub fn mod_sub(a: &U256, b: &U256, m: &U256) -> U256 {
    let (d, br) = sub(a, b);
    if br { add(&d, m).0 } else { d }
}
pub fn mod_neg(a: &U256, m: &U256) -> U256 { if is_zero(a) { *a } else { sub(m, a).0 } }

pub fn reduce_wide(w: &[u64; 8], m: &U256) -> U256 {
    let mut r = [0u64; 4];
    for bit in (0..512).rev() {
        let carry = r[3] >> 63;
        for i in (0..4).rev() { r[i] = (r[i] << 1) | if i > 0 { r[i - 1] >> 63 } else { (w[bit / 64] >> (bit % 64)) & 1 }; }
        if carry == 1 || cmp(&r, m) != Ordering::Less { r = sub(&r, m).0; }
    }
    r
}
pub fn mod_mul(a: &U256, b: &U256, m: &U256) -> U256 { reduce_wide(&wide_mul(a, b), m) }

fn shr1(a: &U256, top: u64) -> U256 {
    let mut r = [0u64; 4];
    for i in 0..4 { r[i] = (a[i] >> 1) | if i < 3 { a[i + 1] << 63 } else { top << 63 }; }
    r
}
/// Modular inverse for odd modulus m and 0 < a < m (binary extended Euclid, variable time).
pub fn mod_inv(a: &U256, m: &U256) -> U256 {
    let (mut u, mut v, mut x1, mut x2) = (*a, *m, [1u64, 0, 0, 0], [0u64; 4]);
    let one = [1u64, 0, 0, 0];
    while u != one && v != one {
        while u[0] & 1 == 0 {
            u = shr1(&u, 0);
            if x1[0] & 1 == 0 { x1 = shr1(&x1, 0); } else { let (s, c) = add(&x1, m); x1 = shr1(&s, c as u64); }
        }
        while v[0] & 1 == 0 {
            v = shr1(&v, 0);
            if x2[0] & 1 == 0 { x2 = shr1(&x2, 0); } else { let (s, c) = add(&x2, m); x2 = shr1(&s, c as u64); }
        }
        if cmp(&u, &v) != Ordering::Less { u = sub(&u, &v).0; x1 = mod_sub(&x1, &x2, m); }
        else { v = sub(&v, &u).0; x2 = mod_sub(&x2, &x1, m); }
    }
    if u == one { x1 } else { x2 }
}
