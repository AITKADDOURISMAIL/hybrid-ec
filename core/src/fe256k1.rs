//! GF(p), p = 2^256 - 2^32 - 977 (secp256k1), 5x52-bit limbs, lazy reduction.
//! 2^260 = R (mod p) with R = 2^4 * 0x1000003D1 = 0x1000003D10.
const M52: u64 = (1u64 << 52) - 1;
const M48: u64 = (1u64 << 48) - 1;
const C: u64 = 0x1000003D1; // 2^256 mod p
const R: u64 = 0x1000003D10; // 2^260 mod p

#[derive(Clone, Copy, Debug)]
pub struct Fe(pub [u64; 5]);

impl Fe {
    pub const ZERO: Fe = Fe([0; 5]);
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// Propagate carries; the carry out of limb 4 is folded back with factor R.
    fn carry(mut l: [u64; 5]) -> Fe {
        for _ in 0..2 {
            for i in 0..4 { let c = l[i] >> 52; l[i] &= M52; l[i + 1] += c; }
            let c = l[4] >> 52; l[4] &= M52; l[0] += c * R;
        }
        Fe(l)
    }

    pub fn add(&self, o: &Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 { r[i] = self.0[i] + o.0[i]; }
        Fe::carry(r)
    }

    pub fn sub(&self, o: &Fe) -> Fe {
        // add 32p (limbs of p: 0xFFFFEFFFFFC2F, 0xFFFFFFFFFFFFF x3, 0xFFFFFFFFFFFF)
        const P0: u64 = 0xFFFFEFFFFFC2F * 32;
        const PM: u64 = 0xFFFFFFFFFFFFF * 32;
        const P4: u64 = 0x0FFFFFFFFFFFF * 32;
        let r = [
            self.0[0] + P0 - o.0[0],
            self.0[1] + PM - o.0[1],
            self.0[2] + PM - o.0[2],
            self.0[3] + PM - o.0[3],
            self.0[4] + P4 - o.0[4],
        ];
        Fe::carry(r)
    }

    pub fn mul(&self, o: &Fe) -> Fe {
        let (a, b) = (&self.0, &o.0);
        let mut t = [0u128; 9];
        for i in 0..5 { for j in 0..5 { t[i + j] += (a[i] as u128) * (b[j] as u128); } }
        // 10 limbs of 52 bits
        let mut r = [0u64; 10];
        let mut c: u128 = 0;
        for k in 0..9 { let v = t[k] + c; r[k] = (v as u64) & M52; c = v >> 52; }
        r[9] = c as u64;
        // fold high half: 2^(260+52j) = R * 2^(52j)
        let mut s = [0u128; 5];
        for j in 0..5 { s[j] = r[j] as u128 + (r[j + 5] as u128) * (R as u128); }
        for _ in 0..2 {
            for j in 0..4 { let cc = s[j] >> 52; s[j] &= M52 as u128; s[j + 1] += cc; }
            let cc = s[4] >> 52; s[4] &= M52 as u128; s[0] += cc * (R as u128);
        }
        Fe::carry([s[0] as u64, s[1] as u64, s[2] as u64, s[3] as u64, s[4] as u64])
    }

    pub fn square(&self) -> Fe { self.mul(self) }

    pub fn select(a: &Fe, b: &Fe, choice: u64) -> Fe {
        let mask = 0u64.wrapping_sub(choice & 1);
        let mut r = [0u64; 5];
        for i in 0..5 { r[i] = a.0[i] ^ (mask & (a.0[i] ^ b.0[i])); }
        Fe(r)
    }

    /// Fully reduce mod p, little-endian bytes. Branch-free.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut l = Fe::carry(self.0).0;
        for _ in 0..3 {
            let h = l[4] >> 48; l[4] &= M48;
            l[0] += h * C;
            for i in 0..4 { let c = l[i] >> 52; l[i] &= M52; l[i + 1] += c; }
        }
        // now value < 2^256 + small; conditional subtract of p via +C and bit 256
        let mut t = l;
        t[0] += C;
        for i in 0..4 { let c = t[i] >> 52; t[i] &= M52; t[i + 1] += c; }
        let ge = t[4] >> 48; // 1 iff value >= p
        t[4] &= M48;
        let sel = Fe::select(&Fe(l), &Fe(t), ge).0;
        let mut out = [0u8; 32];
        let mut acc: u128 = 0; let mut bits = 0; let mut idx = 0;
        for i in 0..5 {
            acc |= (sel[i] as u128) << bits; bits += 52;
            while bits >= 8 && idx < 32 { out[idx] = acc as u8; acc >>= 8; bits -= 8; idx += 1; }
        }
        out
    }

    /// Parse 32 LE bytes (any 256-bit value; not necessarily < p).
    pub fn from_bytes(b: &[u8; 32]) -> Fe {
        let mut l = [0u64; 5];
        for i in 0..5 {
            let start = 52 * i;
            let mut v: u128 = 0;
            for k in 0..16 { let idx = start / 8 + k; if idx < 32 { v |= (b[idx] as u128) << (8 * k); } }
            l[i] = ((v >> (start % 8)) as u64) & M52;
        }
        Fe(l)
    }

    /// x^(p-2); the exponent is public so the bit branches are not secret-dependent.
    pub fn invert(&self) -> Fe {
        let mut e = [0xFFu8; 32];
        e[27] = 0xFE; e[28] = 0xFF; e[29] = 0xFF; e[30] = 0xFC; e[31] = 0x2D; // p-2, big-endian
        let mut r = Fe::ONE;
        for byte in e { for bit in (0..8).rev() {
            r = r.square();
            if (byte >> bit) & 1 == 1 { r = r.mul(self); }
        } }
        r
    }
}
