//! ctgrind-style check (Langley, 2010) with valgrind/memcheck: the secret scalar is marked "undefined", the routine runs,
//! and memcheck reports every conditional branch and every memory address that depends on it.
//! Usage (x86-64 Linux):  valgrind --error-exitcode=9 ./ctgrind <routine>
//! routines: fixed-base-ed25519, fixed-base-secp256k1, var-base-ed25519, var-base-secp256k1, x25519, control-leaky, control-clean
use hec_curves::{ed25519, fixed_base::FixedBase, group::Group, secp256k1, x25519::x25519};
use std::hint::black_box;

/// VALGRIND_MAKE_MEM_UNDEFINED(addr, len) by the client-request sequence of valgrind.h (x86-64).
#[cfg(target_arch = "x86_64")]
fn make_undefined(p: *const u8, len: usize) {
    let args: [u64; 6] = [0x4d43_0001, p as u64, len as u64, 0, 0, 0];
    let mut res: u64 = 0;
    // SAFETY: the sequence is a no-op outside valgrind (rotations of rdi and an xchg of rbx with itself).
    unsafe {
        core::arch::asm!(
            "rol rdi, 3", "rol rdi, 13", "rol rdi, 61", "rol rdi, 51", "xchg rbx, rbx",
            inout("rdx") res, in("rax") args.as_ptr(), options(nostack),
        );
    }
    black_box(res);
}
#[cfg(not(target_arch = "x86_64"))]
fn make_undefined(_: *const u8, _: usize) { panic!("x86-64 only"); }

fn leaky_mul<P: Group>(p: &P, k: &[u8; 32]) -> P {
    let mut acc = P::identity();
    for i in (0..256).rev() { acc = acc.double(); if (k[i / 8] >> (i % 8)) & 1 == 1 { acc = acc.add(p); } }
    acc
}

fn main() {
    let which = std::env::args().nth(1).unwrap_or_default();
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(37).wrapping_add(11); }
    k[31] &= 0x7f;
    let g = secp256k1::generator();
    let b = ed25519::Point::base();
    // public setup first (tables, public points), then the secret becomes undefined
    let fb_k1 = FixedBase::new(g, 5);
    let fb_ed = FixedBase::new(b, 4);
    let q_k1 = g.scalar_mul(&[3u8; 32]);
    let q_ed = b.scalar_mul(&[5u8; 32]);
    let mut xu = [0u8; 32]; xu[0] = 9;
    make_undefined(k.as_ptr(), 32);
    match which.as_str() {
        "fixed-base-ed25519" => { black_box(fb_ed.mul(&k)); }
        "fixed-base-secp256k1" => { black_box(fb_k1.mul(&k)); }
        "var-base-ed25519" => { black_box(q_ed.scalar_mul(&k)); }
        "var-base-secp256k1" => { black_box(q_k1.scalar_mul(&k)); }
        "x25519" => { black_box(x25519(&k, &xu)); }
        "control-leaky" => { black_box(leaky_mul(&b, &k)); }
        "control-clean" => { black_box(k[0] ^ k[1]); }
        _ => { eprintln!("unknown routine"); std::process::exit(2); }
    }
}
