//! Fixed-base multiplication with signed-digit recoding (paper, Section 3, Layer B):
//! k = sum_i d_i 2^(c i), d_i in [-2^(c-1), 2^(c-1)], m = ceil(256/c) + 1 digits.
//! Table T[i][j] = j * 2^(c i) * B, j = 1..2^(c-1). Evaluation uses only additions,
//! a full-table scan per digit (no secret-dependent index) and a masked negation.
use crate::group::Group;

pub struct FixedBase<P: Group> { c: usize, half: usize, m: usize, table: Vec<P> }

/// bits [pos, pos+c) of a 256-bit little-endian scalar (zeros beyond bit 255).
fn window(k: &[u8; 32], pos: usize, c: usize) -> i64 {
    let mut v = 0i64;
    for b in 0..c { let p = pos + b; if p < 256 { v |= (((k[p / 8] >> (p % 8)) & 1) as i64) << b; } }
    v
}

/// Constant-time signed recoding; returns m = ceil(256/c)+1 digits with sum d_i 2^(ci) = k.
pub fn recode(k: &[u8; 32], c: usize) -> Vec<i64> {
    let w = (256 + c - 1) / c;
    let (mut carry, mut out) = (0i64, Vec::with_capacity(w + 1));
    for i in 0..w {
        let v = window(k, i * c, c) + carry;
        carry = (v + (1 << (c - 1)) - 1) >> c; // digits in [-2^(c-1)+1, 2^(c-1)]
        out.push(v - (carry << c));
    }
    out.push(carry);
    out
}

impl<P: Group> FixedBase<P> {
    pub fn new(base: P, c: usize) -> Self {
        assert!((2..=10).contains(&c));
        let (half, m) = (1usize << (c - 1), (256 + c - 1) / c + 1);
        let mut table = Vec::with_capacity(m * half);
        let mut cur = base;
        for _ in 0..m {
            let mut acc = cur;
            for _ in 0..half { table.push(acc); acc = acc.add(&cur); }
            for _ in 0..c { cur = cur.double(); }
        }
        FixedBase { c, half, m, table }
    }
    pub fn table_len(&self) -> usize { self.table.len() }

    pub fn mul(&self, k: &[u8; 32]) -> P {
        let digits = recode(k, self.c);
        debug_assert_eq!(digits.len(), self.m);
        let mut acc = P::identity();
        for (i, &d) in digits.iter().enumerate() {
            let neg = ((d >> 63) & 1) as u64;
            let abs = ((d ^ (d >> 63)) - (d >> 63)) as u64; // branch-free |d|
            let mut sel = P::identity();
            for j in 1..=self.half as u64 {
                let eq = ((abs ^ j).wrapping_sub(1) >> 63) & 1; // 1 iff abs == j
                sel = P::select(&sel, &self.table[i * self.half + (j as usize - 1)], eq);
            }
            sel = P::select(&sel, &sel.neg(), neg);
            acc = acc.add(&sel);
        }
        acc
    }
}
