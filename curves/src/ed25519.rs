//! Twisted Edwards -x^2 + y^2 = 1 + d x^2 y^2 (Ed25519), extended coordinates.
//! Unified addition (HWCD 2008, a = -1) is complete on this curve. Research prototype.
use hec_core::fe25519::Fe;

const D: [u8; 32] = [163,120,89,19,202,77,235,117,171,216,65,65,77,10,112,0,152,232,121,119,121,64,199,140,115,254,111,43,238,108,3,82];
const D2: [u8; 32] = [89,241,178,38,148,155,214,235,86,177,131,130,154,20,224,0,48,209,243,238,242,128,142,25,231,252,223,86,220,217,6,36];
const SQRT_M1: [u8; 32] = [176,160,14,74,39,27,238,196,120,228,47,173,6,24,67,47,167,215,251,61,153,0,77,43,11,223,193,79,128,36,131,43];
/// Compressed base point (y = 4/5, x even).
pub const BASE_ENC: [u8; 32] = [0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66];

#[derive(Clone, Copy, Debug)]
pub struct Point { pub x: Fe, pub y: Fe, pub z: Fe, pub t: Fe }

/// x^(2^252 - 2) = x^((p+3)/8); the exponent is public.
fn pow_p3_8(x: &Fe) -> Fe {
    let mut e = [0xFFu8; 32];
    e[0] = 0x0F; e[31] = 0xFE;
    let mut r = Fe::ONE;
    for byte in e { for bit in (0..8).rev() {
        r = r.square();
        if (byte >> bit) & 1 == 1 { r = r.mul(x); }
    } }
    r
}

impl Point {
    pub const IDENTITY: Point = Point { x: Fe::ZERO, y: Fe::ONE, z: Fe::ONE, t: Fe::ZERO };

    pub fn base() -> Point { Point::decompress(&BASE_ENC).expect("base point") }

    /// Permissive decoding (ZIP-215 style): y need not be < p; (x=0, sign=1) accepted.
    /// Returns None iff x^2 has no square root.
    pub fn decompress(b: &[u8; 32]) -> Option<Point> {
        let sign = (b[31] >> 7) as u64;
        let mut yb = *b; yb[31] &= 0x7F;
        let y = Fe::from_bytes(&yb);
        let yy = y.square();
        let u = yy.sub(&Fe::ONE);
        let v = Fe::from_bytes(&D).mul(&yy).add(&Fe::ONE);
        let x2 = u.mul(&v.invert());
        let mut x = pow_p3_8(&x2);
        if x.square().sub(&x2).to_bytes() != [0u8; 32] { x = x.mul(&Fe::from_bytes(&SQRT_M1)); }
        if x.square().sub(&x2).to_bytes() != [0u8; 32] { return None; }
        let par = (x.to_bytes()[0] & 1) as u64;
        let neg = Fe::ZERO.sub(&x);
        x = Fe::select(&x, &neg, par ^ sign);
        Some(Point { x, y, z: Fe::ONE, t: x.mul(&y) })
    }

    pub fn compress(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x.mul(&zi).to_bytes();
        let mut y = self.y.mul(&zi).to_bytes();
        y[31] |= (x[0] & 1) << 7;
        y
    }

    pub fn add(&self, q: &Point) -> Point {
        let d2 = Fe::from_bytes(&D2);
        let a = self.y.sub(&self.x).mul(&q.y.sub(&q.x));
        let b = self.y.add(&self.x).mul(&q.y.add(&q.x));
        let c = self.t.mul(&d2).mul(&q.t);
        let d = self.z.mul(&q.z); let d = d.add(&d);
        let (e, f, g, h) = (b.sub(&a), d.sub(&c), d.add(&c), b.add(&a));
        Point { x: e.mul(&f), y: g.mul(&h), t: e.mul(&h), z: f.mul(&g) }
    }

    pub fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square(); let c = c.add(&c);
        let d = Fe::ZERO.sub(&a);
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = d.add(&b);
        let f = g.sub(&c);
        let h = d.sub(&b);
        Point { x: e.mul(&f), y: g.mul(&h), t: e.mul(&h), z: f.mul(&g) }
    }

    pub fn select(a: &Point, b: &Point, c: u64) -> Point {
        Point { x: Fe::select(&a.x, &b.x, c), y: Fe::select(&a.y, &b.y, c), z: Fe::select(&a.z, &b.z, c), t: Fe::select(&a.t, &b.t, c) }
    }

    /// Naive constant-time double-and-always-add; k is 32 bytes little-endian.
    pub fn scalar_mul(&self, k: &[u8; 32]) -> Point {
        let mut acc = Point::IDENTITY;
        for i in (0..256).rev() {
            acc = acc.double();
            let s = acc.add(self);
            acc = Point::select(&acc, &s, ((k[i / 8] >> (i % 8)) & 1) as u64);
        }
        acc
    }

    /// Naive constant-time double-and-always-add over an arbitrary-length little-endian scalar.
    pub fn scalar_mul_bytes(&self, k: &[u8]) -> Point {
        let mut acc = Point::IDENTITY;
        for i in (0..8 * k.len()).rev() {
            acc = acc.double();
            let s = acc.add(self);
            acc = Point::select(&acc, &s, ((k[i / 8] >> (i % 8)) & 1) as u64);
        }
        acc
    }

    pub fn neg(&self) -> Point {
        Point { x: Fe::ZERO.sub(&self.x), y: self.y, z: self.z, t: Fe::ZERO.sub(&self.t) }
    }

    /// True iff this is the neutral element (projective test; public outcome).
    pub fn is_identity(&self) -> bool {
        self.x.to_bytes() == [0u8; 32] && self.y.sub(&self.z).to_bytes() == [0u8; 32]
    }

    /// [8]P by three doublings.
    pub fn mul_by_cofactor(&self) -> Point { self.double().double().double() }
}
