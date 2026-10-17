#!/usr/bin/env python3
"""Ed25519 + X25519 reference vectors. Usage: gen_vectors_ed25519.py <outdir>"""
import sys, os, random, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vp_ed25519 as V
p, l = V.p, V.l
def enc(P): return (P[1] | ((P[0] & 1) << 255)).to_bytes(32, 'little')
O = (0, 1)
neg = lambda P: ((-P[0]) % p, P[1])
random.seed(5)
pts = [O, V.B, V.mul(2, V.B), neg(V.B), V.mul(l - 1, V.B)] + [V.mul(random.randrange(1, l), V.B) for _ in range(100)]
# small-order and torsion points
tors = []
for y in (0, p - 1, 1):
    x = V.recover_x(y, 0)
    if x is not None: tors.append((x, y))
I = V.I
tors.append((I, 0)) if (I*I+1) % p == 0 else None
pts += [t for t in tors if (-t[0]*t[0] + t[1]*t[1] - 1 - V.d*t[0]*t[0]*t[1]*t[1]) % p == 0]
out = []
for i, P in enumerate(pts):
    for Q in (P, neg(P), pts[(i*5+1) % len(pts)], pts[(i*11+2) % len(pts)], O):
        out.append(" ".join(x.hex() for x in (enc(P), enc(Q), enc(V.add(P, Q)), enc(V.add(P, P)))))
open(os.path.join(sys.argv[1], "ed_points.txt"), "w").write("\n".join(out) + "\n")
# scalar mults, incl. RFC 8032 test 1 key
sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
h = bytearray(hashlib.sha512(sk).digest()[:32]); h[0] &= 248; h[31] &= 127; h[31] |= 64
a = int.from_bytes(h, 'little')
assert enc(V.mul(a, V.B)).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
ks = [0, 1, 2, 8, l - 1, l, l + 1, 2**255, 2**256 - 1, a] + [random.getrandbits(256) for _ in range(40)]
out = []
for k in ks:
    out.append(" ".join([k.to_bytes(32, 'little').hex(), enc(V.B).hex(), enc(V.mul(k, V.B)).hex()]))
open(os.path.join(sys.argv[1], "ed_scalar.txt"), "w").write("\n".join(out) + "\n")
# decompression, incl. non-canonical y and (x=0, sign=1)
cases = [bytes([1] + [0]*31), bytes([1] + [0]*30 + [0x80])]
for y in range(0, 25): cases.append((p + y).to_bytes(32, 'little'))      # y >= p, non-canonical
for y in range(0, 25): cases.append((p + y | (1 << 255)).to_bytes(32, 'little'))
cases += [random.getrandbits(256).to_bytes(32, 'little') for _ in range(300)] + [enc(P) for P in pts[:30]]
out = []
for c in cases:
    r = V.decode(c)
    out.append(c.hex() + " " + (enc(r).hex() if r is not None else "none"))
open(os.path.join(sys.argv[1], "ed_decode.txt"), "w").write("\n".join(out) + "\n")
# X25519 reference (RFC 7748) cross-checked against the RFC vectors
def x25519(k, u):
    k = bytearray(k); k[0] &= 248; k[31] &= 127; k[31] |= 64
    kk = int.from_bytes(k, 'little'); x1 = int.from_bytes(u, 'little') & (2**255 - 1)
    x2, z2, x3, z3, sw = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (kk >> t) & 1; sw ^= kt
        if sw: x2, x3, z2, z3 = x3, x2, z3, z2
        sw = kt
        A = (x2+z2) % p; AA = A*A % p; B = (x2-z2) % p; BB = B*B % p; E = (AA-BB) % p
        C = (x3+z3) % p; D = (x3-z3) % p; DA = D*A % p; CB = C*B % p
        x3 = (DA+CB)**2 % p; z3 = x1*(DA-CB)**2 % p; x2 = AA*BB % p; z2 = E*(AA+121665*E) % p
    if sw: x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, p-2, p) % p).to_bytes(32, 'little')
H = bytes.fromhex
assert x25519(H("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"), H("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
assert x25519(H("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"), H("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")).hex() == "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
nine = bytes([9] + [0]*31)
assert x25519(nine, nine).hex() == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
out = []
for _ in range(60):
    k = random.getrandbits(256).to_bytes(32, 'little'); u = random.getrandbits(256).to_bytes(32, 'little')
    out.append(" ".join(x.hex() for x in (k, u, x25519(k, u))))
for k, u in ((nine, nine), (H("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"), H("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))):
    out.append(" ".join(x.hex() for x in (k, u, x25519(k, u))))
open(os.path.join(sys.argv[1], "x25519.txt"), "w").write("\n".join(out) + "\n")
print("ok: RFC 7748 + RFC 8032 key asserts passed")
