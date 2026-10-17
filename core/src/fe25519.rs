//! GF(2^255-19), 5x51-bit limbs, lazy reduction, no secret-dependent branches.
const M51: u64 = (1u64 << 51) - 1;

#[derive(Clone, Copy, Debug)]
pub struct Fe(pub [u64; 5]);

impl Fe {
    pub const ZERO: Fe = Fe([0; 5]);
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn carry(mut l: [u64; 5]) -> Fe {
        for _ in 0..2 {
            let c0 = l[0] >> 51; l[0] &= M51; l[1] += c0;
            let c1 = l[1] >> 51; l[1] &= M51; l[2] += c1;
            let c2 = l[2] >> 51; l[2] &= M51; l[3] += c2;
            let c3 = l[3] >> 51; l[3] &= M51; l[4] += c3;
            let c4 = l[4] >> 51; l[4] &= M51; l[0] += c4 * 19;
        }
        Fe(l)
    }

    pub fn add(&self, o: &Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 { r[i] = self.0[i] + o.0[i]; }
        Fe::carry(r)
    }

    pub fn sub(&self, o: &Fe) -> Fe {
        // add 16p so limbs never underflow (inputs are carried, < 2^52)
        const P0: u64 = 0x7ffffffffffed * 16;
        const PN: u64 = 0x7ffffffffffff * 16;
        let r = [
            self.0[0] + P0 - o.0[0],
            self.0[1] + PN - o.0[1],
            self.0[2] + PN - o.0[2],
            self.0[3] + PN - o.0[3],
            self.0[4] + PN - o.0[4],
        ];
        Fe::carry(r)
    }

    pub fn mul(&self, o: &Fe) -> Fe {
        let a = &self.0;
        let b = &o.0;
        let b19 = [b[0], b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];
        let m = |x: u64, y: u64| (x as u128) * (y as u128);
        let c0 = m(a[0], b[0]) + m(a[1], b19[4]) + m(a[2], b19[3]) + m(a[3], b19[2]) + m(a[4], b19[1]);
        let c1 = m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b19[4]) + m(a[3], b19[3]) + m(a[4], b19[2]);
        let c2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b19[4]) + m(a[4], b19[3]);
        let c3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b19[4]);
        let c4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
        let mut r = [0u64; 5];
        let mut c = c0; r[0] = (c as u64) & M51; c >>= 51;
        let c1 = c1 + c; c = c1; r[1] = (c as u64) & M51; c >>= 51;
        let c2 = c2 + c; c = c2; r[2] = (c as u64) & M51; c >>= 51;
        let c3 = c3 + c; c = c3; r[3] = (c as u64) & M51; c >>= 51;
        let c4 = c4 + c; c = c4; r[4] = (c as u64) & M51; c >>= 51;
        r[0] += (c as u64) * 19;
        Fe::carry(r)
    }

    pub fn square(&self) -> Fe { self.mul(self) }

    /// Masked select: returns b if choice==1, a if choice==0.
    pub fn select(a: &Fe, b: &Fe, choice: u64) -> Fe {
        let mask = 0u64.wrapping_sub(choice & 1);
        let mut r = [0u64; 5];
        for i in 0..5 { r[i] = a.0[i] ^ (mask & (a.0[i] ^ b.0[i])); }
        Fe(r)
    }

    /// Fully reduce and serialize little-endian.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut l = Fe::carry(self.0).0;
        // compute q = floor((h+19)/2^255) then h += 19q, drop bit 255
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        for i in 0..4 { let c = l[i] >> 51; l[i] &= M51; l[i + 1] += c; }
        l[4] &= M51;
        let mut out = [0u8; 32];
        let mut acc: u128 = 0; let mut bits = 0; let mut idx = 0;
        for i in 0..5 {
            acc |= (l[i] as u128) << bits; bits += 51;
            while bits >= 8 && idx < 32 { out[idx] = acc as u8; acc >>= 8; bits -= 8; idx += 1; }
        }
        if idx < 32 { out[idx] = acc as u8; }
        out
    }

    /// Parse 32 LE bytes (bit 255 ignored); result is not necessarily canonical (value < 2^255).
    pub fn from_bytes(b: &[u8; 32]) -> Fe {
        let ld = |i: usize| -> u64 {
            let mut v = 0u64;
            for k in 0..8 { if i + k < 32 { v |= (b[i + k] as u64) << (8 * k); } }
            v
        };
        Fe([
            ld(0) & M51,
            (ld(6) >> 3) & M51,
            (ld(12) >> 6) & M51,
            (ld(19) >> 1) & M51,
            (ld(24) >> 12) & M51,
        ])
    }

    /// Inversion via x^(p-2) (fixed addition chain; constant time). safegcd comes later.
    pub fn invert(&self) -> Fe {
        let sqn = |x: &Fe, n: u32| { let mut r = *x; for _ in 0..n { r = r.square(); } r };
        let z2 = self.square();
        let z9 = sqn(&z2, 2).mul(self);
        let z11 = z9.mul(&z2);
        let z_5_0 = z11.square().mul(&z9);
        let z_10_0 = sqn(&z_5_0, 5).mul(&z_5_0);
        let z_20_0 = sqn(&z_10_0, 10).mul(&z_10_0);
        let z_40_0 = sqn(&z_20_0, 20).mul(&z_20_0);
        let z_50_0 = sqn(&z_40_0, 10).mul(&z_10_0);
        let z_100_0 = sqn(&z_50_0, 50).mul(&z_50_0);
        let z_200_0 = sqn(&z_100_0, 100).mul(&z_100_0);
        let z_250_0 = sqn(&z_200_0, 50).mul(&z_50_0);
        sqn(&z_250_0, 5).mul(&z11)
    }
}
