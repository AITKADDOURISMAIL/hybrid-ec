#!/usr/bin/env python3
"""Appends mixed-order-key cases to validation/tests/validation.txt (the file is rewritten in place).
Usage: gen_vectors_mixed_order.py <path-to-validation.txt>
Key A = A0 + T with A0 in <B> and T a nonzero point of order dividing 8. The nonce R is honest. S = r + h*a (mod l)
with h = SHA-512(R || enc(A) || M) mod l, so that [S]B = R + [h]A0. Then [8]([S]B - R - [h]A) = O (accepted under P_c and P_s),
while the cofactorless equation [S]B = R + [h]A fails exactly when [h]T != O (rejected by dalek verify / verify_strict)."""
import sys, os, random, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vp_ed25519 as V
p, l = V.p, V.l
rng = random.Random(77)
enc = lambda P: (P[1] | ((P[0] & 1) << 255)).to_bytes(32, 'little')
# nonzero torsion points: T = [l]Q for random points Q
tors = {}
while len(tors) < 7:
    y = rng.randrange(2, p); x = V.recover_x(y, 0)
    if x is None: continue
    T = V.mul(l, (x, y))
    if T != (0, 1): tors[T] = None
tors = sorted(tors)
lines = []
for T in tors:
    for msg in (b"", b"mixed", b"mixed-order key", b"x" * 100):
        a = rng.randrange(1, l); A = V.add(V.mul(a, V.B), T); pk = enc(A)
        r = rng.randrange(1, l); R = enc(V.mul(r, V.B))
        h = int.from_bytes(hashlib.sha512(R + pk + msg).digest(), 'little') % l
        S = (r + h * a) % l; sig = R + S.to_bytes(32, 'little')
        lines.append(" ".join([pk.hex(), msg.hex() or "-", sig.hex(), str(int(V.verify(pk, msg, sig))), str(int(V.verify(pk, msg, sig, strict=True)))]))
with open(sys.argv[1], "a") as f: f.write("\n".join(lines) + "\n")
print(len(lines), "mixed-order cases appended")
