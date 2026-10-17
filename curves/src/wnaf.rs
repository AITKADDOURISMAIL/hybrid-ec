//! Variable-time interleaved wNAF double-scalar multiplication a*P + b*Q.
//! ONLY for public data (signature verification): digit pattern leaks the scalars.
use crate::group::Group;

/// wNAF of a little-endian 256-bit scalar (width w, digits odd in (-2^(w-1), 2^(w-1))).
pub fn wnaf(k: &[u8; 32], w: usize) -> Vec<i8> {
    let mut l = [0u64; 5];
    for i in 0..4 { l[i] = u64::from_le_bytes(k[8 * i..8 * i + 8].try_into().unwrap()); }
    let (mask, half) = ((1u64 << w) - 1, 1i64 << (w - 1));
    let mut out = Vec::with_capacity(260);
    while l.iter().any(|&x| x != 0) {
        let mut d = 0i64;
        if l[0] & 1 == 1 {
            d = (l[0] & mask) as i64;
            if d >= half { d -= 1 << w; }
            // l -= d  (d may be negative => add)
            if d >= 0 {
                let mut borrow = d as u64;
                for x in l.iter_mut() { let (v, b) = x.overflowing_sub(borrow); *x = v; borrow = b as u64; }
            } else {
                let mut carry = (-d) as u64;
                for x in l.iter_mut() { let (v, c) = x.overflowing_add(carry); *x = v; carry = c as u64; }
            }
        }
        out.push(d as i8);
        for i in 0..5 { l[i] = (l[i] >> 1) | if i + 1 < 5 { l[i + 1] << 63 } else { 0 }; }
    }
    out
}

/// Odd multiples [1P, 3P, ..., (2^(w-1)-1)P].
pub fn odd_multiples<P: Group>(p: &P, w: usize) -> Vec<P> {
    let n = 1usize << (w - 2);
    let p2 = p.double();
    let mut t = Vec::with_capacity(n);
    t.push(*p);
    for i in 1..n { let next = t[i - 1].add(&p2); t.push(next); }
    t
}

pub fn double_scalar_vartime<P: Group>(a: &[u8; 32], ta: &[P], wa: usize, b: &[u8; 32], tb: &[P], wb: usize) -> P {
    let (da, db) = (wnaf(a, wa), wnaf(b, wb));
    let mut acc = P::identity();
    for i in (0..da.len().max(db.len())).rev() {
        acc = acc.double();
        for (d, t) in [(da.get(i).copied().unwrap_or(0), ta), (db.get(i).copied().unwrap_or(0), tb)] {
            if d > 0 { acc = acc.add(&t[(d as usize) >> 1]); }
            else if d < 0 { acc = acc.add(&t[((-d) as usize) >> 1].neg()); }
        }
    }
    acc
}

/// Interleaved evaluation of sum_i (+/-) digits_i . table_i ; the bool flips the sign of a term.
pub fn multi_scalar_vartime<P: Group>(terms: &[(Vec<i8>, &[P], bool)]) -> P {
    let len = terms.iter().map(|t| t.0.len()).max().unwrap_or(0);
    let mut acc = P::identity();
    for i in (0..len).rev() {
        acc = acc.double();
        for (digits, table, neg) in terms {
            let mut d = digits.get(i).copied().unwrap_or(0) as i32;
            if *neg { d = -d; }
            if d > 0 { acc = acc.add(&table[(d as usize) >> 1]); }
            else if d < 0 { acc = acc.add(&table[((-d) as usize) >> 1].neg()); }
        }
    }
    acc
}
