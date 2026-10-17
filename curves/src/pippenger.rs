//! Variable-time multi-scalar multiplication sum_i [k_i] P_i by Pippenger's bucket method.
//! ONLY for public data (batch signature verification): digits, window and bucket accesses
//! depend on the scalars.
use crate::group::Group;

fn bit_len(k: &[u8; 32]) -> usize {
    for i in (0..32).rev() { if k[i] != 0 { return 8 * i + 8 - k[i].leading_zeros() as usize; } }
    0
}
fn digit(k: &[u8; 32], pos: usize, c: usize) -> usize {
    let mut v = 0usize;
    for b in 0..c { let bit = pos + b; if bit < 256 { v |= (((k[bit / 8] >> (bit % 8)) & 1) as usize) << b; } }
    v
}
fn add_opt<P: Group>(acc: &mut Option<P>, p: &P) { *acc = Some(match acc { Some(a) => a.add(p), None => *p }); }

/// Window width heuristic (about 2/3 log2 n + 2, at most 12).
pub fn window_for(n: usize) -> usize { if n < 4 { 2 } else { ((n.ilog2() as usize) * 2 / 3 + 2).min(12) } }

pub fn msm_vartime<P: Group>(points: &[P], scalars: &[[u8; 32]]) -> P {
    assert_eq!(points.len(), scalars.len());
    if points.is_empty() { return P::identity(); }
    let c = window_for(points.len());
    let maxbits = scalars.iter().map(bit_len).max().unwrap();
    let nw = (maxbits + c - 1) / c;
    let mut acc = P::identity();
    for w in (0..nw).rev() {
        for _ in 0..c { acc = acc.double(); }
        let mut buckets: Vec<Option<P>> = vec![None; (1 << c) - 1];
        for (p, k) in points.iter().zip(scalars) {
            let d = digit(k, w * c, c);
            if d != 0 { add_opt(&mut buckets[d - 1], p); }
        }
        let (mut running, mut sum): (Option<P>, Option<P>) = (None, None);
        for b in buckets.iter().rev() {
            if let Some(p) = b { add_opt(&mut running, p); }
            if let Some(r) = &running { add_opt(&mut sum, r); }
        }
        if let Some(s) = sum { acc = acc.add(&s); }
    }
    acc
}
