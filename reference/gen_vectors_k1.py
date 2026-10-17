#!/usr/bin/env python3
"""Big-int reference vectors for GF(secp256k1 p). Output: hex a b add sub mul sq inv."""
import random, sys
p = 2**256 - 2**32 - 977
random.seed(2)
edge = [0, 1, 2, p-1, p, p+1, p+2**32, 2**256-1, 2**255, 2**52-1, 2**52, 2**208, 2**256-2**32, 977, 0x1000003D1]
vals = edge + [random.getrandbits(256) for _ in range(500)] + [random.randrange(p) for _ in range(500)]
h = lambda x: "%064x" % x
out = []
for i, a in enumerate(vals):
    b = vals[(i * 7 + 3) % len(vals)]
    am, bm = a % p, b % p
    out.append(" ".join(h(x) for x in (a, b, (am+bm)%p, (am-bm)%p, am*bm%p, am*am%p, pow(am, p-2, p))))
open(sys.argv[1], "w").write("\n".join(out) + "\n")
