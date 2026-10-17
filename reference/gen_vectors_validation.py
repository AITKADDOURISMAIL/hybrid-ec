#!/usr/bin/env python3
"""Validation-layer vectors from the Python oracle V_P. Usage: gen_vectors_validation.py <outdir>"""
import sys, os, random, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vp_ed25519 as V
p, l = V.p, V.l
random.seed(6)
enc = lambda P: (P[1] | ((P[0] & 1) << 255)).to_bytes(32, 'little')
def keygen(sk):
    h = bytearray(hashlib.sha512(sk).digest()[:32]); h[0] &= 248; h[31] &= 127; h[31] |= 64
    a = int.from_bytes(h, 'little'); return a, enc(V.mul(a, V.B))
def sign(sk, msg):
    a, pk = keygen(sk); hh = hashlib.sha512(sk).digest()
    r = int.from_bytes(hashlib.sha512(hh[32:] + msg).digest(), 'little') % l
    R = enc(V.mul(r, V.B)); hv = int.from_bytes(hashlib.sha512(R + pk + msg).digest(), 'little') % l
    return pk, R + ((r + hv * a) % l).to_bytes(32, 'little')
cases = []
def add(pk, msg, sig): cases.append((pk, msg, sig))
for i in range(25):
    sk = random.randbytes(32); msg = random.randbytes(random.choice([0, 1, 32, 100, 200]))
    pk, sig = sign(sk, msg); add(pk, msg, sig)
    # mutations
    for _ in range(8):
        m = random.choice("pmsr")
        if m == "p": b = bytearray(pk); b[random.randrange(32)] ^= 1 << random.randrange(8); add(bytes(b), msg, sig)
        elif m == "m": add(pk, msg + b"x", sig)
        elif m == "s": b = bytearray(sig); b[32 + random.randrange(32)] ^= 1 << random.randrange(8); add(pk, msg, bytes(b))
        else: b = bytearray(sig); b[random.randrange(32)] ^= 1 << random.randrange(8); add(pk, msg, bytes(b))
    S = int.from_bytes(sig[32:], 'little')
    add(pk, msg, sig[:32] + (S + l).to_bytes(32, 'little'))          # non-canonical S
    add(pk, msg, sig[:32] + (S + 8 * l).to_bytes(32, 'little'))
# small-order / non-canonical edge cases
ident = (1).to_bytes(32, 'little'); ident_nc = (p + 1).to_bytes(32, 'little')
neg_zero = (1 | 1 << 255).to_bytes(32, 'little')
order2 = (p - 1).to_bytes(32, 'little'); order4 = (0).to_bytes(32, 'little')
zero32 = bytes(32)
for A in (ident, ident_nc, neg_zero, order2, order4):
    for R in (ident, ident_nc, neg_zero, order2, order4):
        for m in (b"", b"msg"): add(A, m, R + zero32)
# honest key but small-order R
sk = random.randbytes(32); pk, sig = sign(sk, b"hello")
for R in (ident, order2, order4): add(pk, b"hello", R + sig[32:])
# non-canonical pk encoding of a real key is not possible unless y < 19; try y>=p encodings of random points
for _ in range(100):
    c = random.getrandbits(256).to_bytes(32, 'little'); add(c, b"q", c + zero32)
with open(os.path.join(sys.argv[1], "validation.txt"), "w") as f:
    for pk, msg, sig in cases:
        f.write(" ".join([pk.hex(), msg.hex() or "-", sig.hex(), str(int(V.verify(pk, msg, sig))), str(int(V.verify(pk, msg, sig, strict=True)))]) + "\n")
# sha512 vectors
with open(os.path.join(sys.argv[1], "sha512.txt"), "w") as f:
    for n in list(range(0, 300, 7)) + [111, 112, 113, 127, 128, 129, 239, 240, 255, 256]:
        m = bytes((i * 31 + n) % 256 for i in range(n))
        f.write((m.hex() or "-") + " " + hashlib.sha512(m).hexdigest() + "\n")
with open(os.path.join(sys.argv[1], "modl.txt"), "w") as f:
    for v in [0, 1, l - 1, l, l + 1, 2**512 - 1, 2**256, 2**252, 8 * l, 2**511] + [random.getrandbits(512) for _ in range(200)]:
        f.write(v.to_bytes(64, 'little').hex() + " " + (v % l).to_bytes(32, 'little').hex() + "\n")
print(len(cases), "cases")
