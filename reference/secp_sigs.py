#!/usr/bin/env python3
"""BIP-340 Schnorr and ECDSA oracle for secp256k1 + vector generator. Usage: secp_sigs.py <outdir>"""
import sys, os, random, hashlib
p = 2**256 - 2**32 - 977
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    l = 3*x1*x1*pow(2*y1, p-2, p) % p if P == Q else (y2-y1)*pow(x2-x1, p-2, p) % p
    x3 = (l*l - x1 - x2) % p
    return (x3, (l*(x1-x3) - y1) % p)
def mul(k, P):
    R = None
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R
def th(tag, *parts):
    t = hashlib.sha256(tag.encode()).digest(); return hashlib.sha256(t + t + b"".join(parts)).digest()
b32 = lambda x: x.to_bytes(32, 'big')
def lift_x(x):
    if x >= p: return None
    y2 = (pow(x, 3, p) + 7) % p; y = pow(y2, (p+1)//4, p)
    if pow(y, 2, p) != y2: return None
    return (x, y if y % 2 == 0 else p - y)
def schnorr_pk(sk): P = mul(sk, G); return b32(P[0])
def schnorr_sign(sk, msg, aux=bytes(32)):
    P = mul(sk, G); d = sk if P[1] % 2 == 0 else n - sk
    t = (d ^ int.from_bytes(th("BIP0340/aux", aux), 'big')).to_bytes(32, 'big')
    k0 = int.from_bytes(th("BIP0340/nonce", t, b32(P[0]), msg), 'big') % n
    R = mul(k0, G); k = k0 if R[1] % 2 == 0 else n - k0
    e = int.from_bytes(th("BIP0340/challenge", b32(R[0]), b32(P[0]), msg), 'big') % n
    return b32(R[0]) + b32((k + e * d) % n)
def schnorr_verify(pk, msg, sig):
    P = lift_x(int.from_bytes(pk, 'big'))
    r = int.from_bytes(sig[:32], 'big'); s = int.from_bytes(sig[32:], 'big')
    if P is None or r >= p or s >= n: return False
    e = int.from_bytes(th("BIP0340/challenge", sig[:32], pk, msg), 'big') % n
    R = add(mul(s, G), mul(n - e, P))
    return R is not None and R[1] % 2 == 0 and R[0] == r
def ecdsa_sign(sk, z, k):
    R = mul(k, G); r = R[0] % n
    s = pow(k, n-2, n) * (z % n + r * sk) % n
    return r, s
def ecdsa_verify(Q, z, r, s):
    if Q[0] >= p or Q[1] >= p or (Q[1]**2 - Q[0]**3 - 7) % p: return False
    if not (0 < r < n and 0 < s < n): return False
    w = pow(s, n-2, n); R = add(mul(z % n * w % n, G), mul(r * w % n, Q))
    return R is not None and R[0] % n == r

if __name__ == "__main__":
    # BIP-340 official test vector 0
    sig0 = schnorr_sign(3, bytes(32))
    assert schnorr_pk(3).hex().upper() == "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    assert sig0.hex().upper() == "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    random.seed(8)
    out = os.path.join(sys.argv[1] if len(sys.argv) > 1 else ".", "")
    rows = []
    def addrow(pk, msg, sig): rows.append(" ".join([pk.hex(), msg.hex() or "-", sig.hex(), str(int(schnorr_verify(pk, msg, sig)))]))
    for _ in range(25):
        sk = random.randrange(1, n); msg = random.randbytes(random.choice([0, 32, 77]))
        pk = schnorr_pk(sk); sig = schnorr_sign(sk, msg, random.randbytes(32)); addrow(pk, msg, sig)
        for _ in range(6):
            w = random.choice("pmrs")
            if w == "p": b = bytearray(pk); b[random.randrange(32)] ^= 1 << random.randrange(8); addrow(bytes(b), msg, sig)
            elif w == "m": addrow(pk, msg + b"!", sig)
            elif w == "r": b = bytearray(sig); b[random.randrange(32)] ^= 1 << random.randrange(8); addrow(pk, msg, bytes(b))
            else: b = bytearray(sig); b[32 + random.randrange(32)] ^= 1 << random.randrange(8); addrow(pk, msg, bytes(b))
        S = int.from_bytes(sig[32:], 'big')
        addrow(pk, msg, sig[:32] + b32(S + n if S + n < 2**256 else S))     # s >= n
        addrow(pk, msg, b32(p) + sig[32:]); addrow(pk, msg, b32(p + int.from_bytes(sig[:32], 'big') % 1000) + sig[32:])  # r >= p
    for _ in range(40): addrow(random.randbytes(32), b"x", random.randbytes(64))
    addrow(b32(p), b"x", sig0); addrow(b32(p + 1), b"x", sig0); addrow(bytes(32), b"", sig0)
    addrow(schnorr_pk(3), bytes(32), sig0)
    open(out + "bip340.txt", "w").write("\n".join(rows) + "\n")
    rows = []
    def adde(Q, z, r, s): rows.append(" ".join([b32(Q[0]).hex(), b32(Q[1]).hex(), b32(z).hex(), b32(r).hex(), b32(s).hex(), str(int(ecdsa_verify(Q, z, r, s)))]))
    for _ in range(40):
        sk = random.randrange(1, n); Q = mul(sk, G); z = random.getrandbits(256); k = random.randrange(1, n)
        r, s = ecdsa_sign(sk, z, k); adde(Q, z, r, s); adde(Q, z, r, n - s)   # high-S variant valid in plain ECDSA
        adde(Q, z ^ 1, r, s); adde(Q, z, r ^ 1, s); adde(Q, z, r, s ^ (1 << random.randrange(256)))
        adde(Q, z, 0, s); adde(Q, z, r, 0); adde(Q, z, n, s); adde(Q, z, r, n)
        adde((Q[0], (Q[1] + 1) % p), z, r, s); adde((Q[0] + p if Q[0] + p < 2**256 else Q[0], Q[1]), z, r, s)
    open(out + "ecdsa.txt", "w").write("\n".join(rows) + "\n")
    with open(out + "sha256.txt", "w") as f:
        for ln in list(range(0, 200, 5)) + [55, 56, 57, 63, 64, 65, 119, 120, 121]:
            m = bytes((i * 7 + ln) % 256 for i in range(ln)); f.write((m.hex() or "-") + " " + hashlib.sha256(m).hexdigest() + "\n")
    print("ok: BIP-340 vector 0 reproduced;", len(open(out + "bip340.txt").readlines()), "schnorr,", len(open(out + "ecdsa.txt").readlines()), "ecdsa cases")
