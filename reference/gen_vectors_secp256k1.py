#!/usr/bin/env python3
"""Big-int affine reference for secp256k1 point ops. Identity encoded as x=y=0."""
import random, sys
p = 2**256 - 2**32 - 977
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
INF = None
def add(P, Q):
    if P is INF: return Q
    if Q is INF: return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0: return INF
    if P == Q: l = 3*x1*x1 * pow(2*y1, p-2, p) % p
    else: l = (y2-y1) * pow(x2-x1, p-2, p) % p
    x3 = (l*l - x1 - x2) % p
    return (x3, (l*(x1-x3) - y1) % p)
def mul(k, P):
    R = INF
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R
assert (G[1]**2 - G[0]**3 - 7) % p == 0 and mul(n, G) is INF
h = lambda x: "%064x" % x
enc = lambda P: (h(0)+" "+h(0)) if P is INF else (h(P[0])+" "+h(P[1]))
neg = lambda P: INF if P is INF else (P[0], (-P[1]) % p)
if sys.argv[1] == "points":
    random.seed(3)
    pts = [INF, G, mul(2, G), mul(n-1, G)] + [mul(random.randrange(1, n), G) for _ in range(120)]
    lines = []
    for i, P in enumerate(pts):
        for Q in (P, neg(P), pts[(i*5+1) % len(pts)], pts[(i*11+2) % len(pts)], INF):
            lines.append(" ".join([enc(P), enc(Q), enc(add(P, Q)), enc(add(P, P))]))
    open(sys.argv[2], "w").write("\n".join(lines) + "\n")
else:
    random.seed(4)
    ks = [0, 1, 2, 3, n-1, n, n+1, 2**255, 2**256-1, 2**128] + [random.getrandbits(256) for _ in range(60)]
    base = [G, mul(7, G)]
    lines = []
    for k in ks:
        for B in base:
            lines.append(" ".join([h(k), enc(B), enc(mul(k, B))]))
    open(sys.argv[2], "w").write("\n".join(lines) + "\n")
