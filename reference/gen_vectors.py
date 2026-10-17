#!/usr/bin/env python3
"""Big-int reference vectors for GF(2^255-19). Output: hex lines a b add sub mul sq inv."""
import random, sys
p = 2**255 - 19
random.seed(1)
edge = [0, 1, 2, 18, 19, p-1, p-2, p-19, 2**255-1, 2**254, 2**51-1, 2**51, 2**204]
vals = edge + [random.getrandbits(255) for _ in range(500)] + [random.randrange(p) for _ in range(500)]
def h(x): return "%064x" % x
out = []
for i, a in enumerate(vals):
    b = vals[(i * 7 + 3) % len(vals)]
    am, bm = a % p, b % p
    inv = pow(am, p-2, p)  # 0 -> 0
    out.append(" ".join(h(x) for x in (a, b, (am+bm)%p, (am-bm)%p, am*bm%p, am*am%p, inv)))
open(sys.argv[1], "w").write("\n".join(out) + "\n")
