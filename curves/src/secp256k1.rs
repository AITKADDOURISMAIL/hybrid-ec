//! secp256k1 (y^2 = x^3 + 7) with the complete projective formulas of
//! Renes-Costello-Batina 2016 (Alg. 7 addition, Alg. 9 doubling, a = 0, b3 = 21).
//! Complete: valid for all inputs incl. P = Q, P = -Q and the identity (0:1:0).
use hec_core::fe256k1::Fe;

const B3: Fe = Fe([21, 0, 0, 0, 0]);

#[derive(Clone, Copy, Debug)]
pub struct Point { pub x: Fe, pub y: Fe, pub z: Fe }

impl Point {
    pub const IDENTITY: Point = Point { x: Fe::ZERO, y: Fe::ONE, z: Fe::ZERO };

    pub fn from_affine(x: &[u8; 32], y: &[u8; 32]) -> Point {
        Point { x: Fe::from_bytes(x), y: Fe::from_bytes(y), z: Fe::ONE }
    }

    /// Returns None for the identity. Not constant time in that public outcome.
    pub fn to_affine(&self) -> Option<([u8; 32], [u8; 32])> {
        if self.z.to_bytes() == [0u8; 32] { return None; }
        let zi = self.z.invert();
        Some((self.x.mul(&zi).to_bytes(), self.y.mul(&zi).to_bytes()))
    }

    pub fn add(&self, q: &Point) -> Point {
        let (x1, y1, z1, x2, y2, z2) = (&self.x, &self.y, &self.z, &q.x, &q.y, &q.z);
        let mut t0 = x1.mul(x2);
        let mut t1 = y1.mul(y2);
        let mut t2 = z1.mul(z2);
        let mut t3 = x1.add(y1);
        let mut t4 = x2.add(y2);
        t3 = t3.mul(&t4);
        t4 = t0.add(&t1);
        t3 = t3.sub(&t4);
        t4 = y1.add(z1);
        let mut x3 = y2.add(z2);
        t4 = t4.mul(&x3);
        x3 = t1.add(&t2);
        t4 = t4.sub(&x3);
        x3 = x1.add(z1);
        let mut y3 = x2.add(z2);
        x3 = x3.mul(&y3);
        y3 = t0.add(&t2);
        y3 = x3.sub(&y3);
        x3 = t0.add(&t0);
        t0 = x3.add(&t0);
        t2 = B3.mul(&t2);
        let mut z3 = t1.add(&t2);
        t1 = t1.sub(&t2);
        y3 = B3.mul(&y3);
        x3 = t4.mul(&y3);
        t2 = t3.mul(&t1);
        x3 = t2.sub(&x3);
        y3 = y3.mul(&t0);
        t1 = t1.mul(&z3);
        y3 = t1.add(&y3);
        t0 = t0.mul(&t3);
        z3 = z3.mul(&t4);
        z3 = z3.add(&t0);
        Point { x: x3, y: y3, z: z3 }
    }

    pub fn double(&self) -> Point {
        let (x, y, z) = (&self.x, &self.y, &self.z);
        let mut t0 = y.square();
        let mut z3 = t0.add(&t0);
        z3 = z3.add(&z3);
        z3 = z3.add(&z3);
        let mut t1 = y.mul(z);
        let mut t2 = z.square();
        t2 = B3.mul(&t2);
        let mut x3 = t2.mul(&z3);
        let mut y3 = t0.add(&t2);
        z3 = t1.mul(&z3);
        t1 = t2.add(&t2);
        t2 = t1.add(&t2);
        t0 = t0.sub(&t2);
        y3 = t0.mul(&y3);
        y3 = x3.add(&y3);
        t1 = x.mul(y);
        x3 = t0.mul(&t1);
        x3 = x3.add(&x3);
        Point { x: x3, y: y3, z: z3 }
    }

    pub fn select(a: &Point, b: &Point, choice: u64) -> Point {
        Point { x: Fe::select(&a.x, &b.x, choice), y: Fe::select(&a.y, &b.y, choice), z: Fe::select(&a.z, &b.z, choice) }
    }

    /// Naive constant-time double-and-always-add, scalar = 32 bytes little-endian.
    /// Baseline only; the paper's fixed-base / GLV routines replace it.
    pub fn scalar_mul(&self, k: &[u8; 32]) -> Point {
        let mut acc = Point::IDENTITY;
        for i in (0..256).rev() {
            acc = acc.double();
            let sum = acc.add(self);
            let bit = ((k[i / 8] >> (i % 8)) & 1) as u64;
            acc = Point::select(&acc, &sum, bit);
        }
        acc
    }

    pub fn neg(&self) -> Point { Point { x: self.x, y: Fe::ZERO.sub(&self.y), z: self.z } }

}

const GX_LE: [u8; 32] = [0x98,0x17,0xf8,0x16,0x5b,0x81,0xf2,0x59,0xd9,0x28,0xce,0x2d,0xdb,0xfc,0x9b,0x02,0x07,0x0b,0x87,0xce,0x95,0x62,0xa0,0x55,0xac,0xbb,0xdc,0xf9,0x7e,0x66,0xbe,0x79];
const GY_LE: [u8; 32] = [0xb8,0xd4,0x10,0xfb,0x8f,0xd0,0x47,0x9c,0x19,0x54,0x85,0xa6,0x48,0xb4,0x17,0xfd,0xa8,0x08,0x11,0x0e,0xfc,0xfb,0xa4,0x5d,0x65,0xc4,0xa3,0x26,0x77,0xda,0x3a,0x48];
/// (p+1)/4 big-endian: square-root exponent since p = 3 mod 4.
const SQRT_EXP_BE: [u8; 32] = [63,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,191,255,255,12];

pub fn generator() -> Point { Point::from_affine(&GX_LE, &GY_LE) }

/// y^2 == x^3 + 7 for affine little-endian coordinates (both must already be < p).
pub fn on_curve(x: &[u8; 32], y: &[u8; 32]) -> bool {
    let (x, y) = (Fe::from_bytes(x), Fe::from_bytes(y));
    y.square().sub(&x.square().mul(&x).add(&Fe([7, 0, 0, 0, 0]))).to_bytes() == [0u8; 32]
}

/// BIP-340 lift_x: the point with the given x (little-endian) and even y; None if x >= p or no root.
pub fn lift_x_even(x_le: &[u8; 32]) -> Option<Point> {
    if hec_core::fe256k1::Fe::from_bytes(x_le).to_bytes() != *x_le { return None; } // x >= p
    let x = Fe::from_bytes(x_le);
    let rhs = x.square().mul(&x).add(&Fe([7, 0, 0, 0, 0]));
    let mut y = Fe::ONE;
    for byte in SQRT_EXP_BE { for bit in (0..8).rev() { y = y.square(); if (byte >> bit) & 1 == 1 { y = y.mul(&rhs); } } }
    if y.square().sub(&rhs).to_bytes() != [0u8; 32] { return None; }
    if y.to_bytes()[0] & 1 == 1 { y = Fe::ZERO.sub(&y); }
    Some(Point { x, y, z: Fe::ONE })
}
