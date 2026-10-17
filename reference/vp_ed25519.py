#!/usr/bin/env python3
"""Big-int reference of validation predicate V_P for Ed25519. Slow, variable-time: oracle only.
Policy 'cofactored' (P_c): permissive decoding, S<l, [8]([S]B-R-[h]A)=O, hash over received bytes.
Policy 'strict'  (P_s): additionally canonical encodings and A,R not small order.
"""
import hashlib
p = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, p-2, p)) % p
I = pow(2, (p-1)//4, p)

def inv(x): return pow(x, p-2, p)
def add(P, Q):
    x1,y1=P; x2,y2=Q
    t = d*x1*x2*y1*y2 % p
    return ((x1*y2+x2*y1)*inv(1+t) % p, (y1*y2+x1*x2)*inv(1-t) % p)  # a=-1
def mul(k, P):
    R = (0, 1)
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R
def recover_x(y, sign):
    """Permissive: accepts y>=p (reduced) ; returns None if not on curve."""
    y %= p
    x2 = (y*y-1) * inv(d*y*y+1) % p
    x = pow(x2, (p+3)//8, p)
    if (x*x - x2) % p: x = x*I % p
    if (x*x - x2) % p: return None
    if x == 0 and sign: return None if False else 0  # ZIP-215 style: accepted
    if (x & 1) != sign: x = p - x
    return x % p
def decode(b, strict=False):
    v = int.from_bytes(b, 'little'); sign = v >> 255; y = v & (2**255-1)
    if strict and y >= p: return None
    x = recover_x(y, sign)
    if x is None: return None
    if strict and x == 0 and sign: return None
    return (x, y % p)
By = 4 * inv(5) % p
B = (recover_x(By, 0), By)
def small_order(P): return mul(8, P) == (0, 1)
def verify(pk, msg, sig, strict=False):
    if len(pk) != 32 or len(sig) != 64: return False
    A = decode(pk, strict); R = decode(sig[:32], strict)
    if A is None or R is None: return False
    S = int.from_bytes(sig[32:], 'little')
    if S >= l: return False
    if strict and (small_order(A) or small_order(R)): return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), 'little') % l
    lhs = add(mul(S, B), add(mul(h, ((-A[0]) % p, A[1])), ((-R[0]) % p, R[1])))
    return mul(8, lhs) == (0, 1)

if __name__ == "__main__":
    # RFC 8032 section 7.1 test 1 (empty message) and test 2
    t = [("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
          "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
         ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
          "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")]
    for pk, m, s in t:
        pk, m, s = map(bytes.fromhex, (pk, m, s))
        assert verify(pk, m, s) and verify(pk, m, s, strict=True)
        bad = bytearray(s); bad[40] ^= 1
        assert not verify(pk, m, bytes(bad))
    # small-order A with identity R and S=0: accepted by P_c, rejected by P_s
    ident = (1).to_bytes(32, 'little'); sig = ident + bytes(32)
    assert verify(ident, b"x", sig) and not verify(ident, b"x", sig, strict=True)
    print("V_P reference: RFC 8032 vectors + P_c/P_s divergence OK")
