#!/usr/bin/env python3
"""Vectors signed by vetted implementations (not by the prototype and not by the project's Python oracle):
  Ed25519: libsodium (PyNaCl) and OpenSSL (cryptography), both must give the same deterministic signature.
  ECDSA/secp256k1: libsecp256k1 (coincurve, RFC 6979, low-s), checked with OpenSSL.
  BIP-340: libsecp256k1 (coincurve).
Every expected verdict is that of a vetted verifier: libsodium crypto_sign_open and OpenSSL for Ed25519, OpenSSL for ECDSA,
libsecp256k1 for BIP-340. Mutated cases are made by flipping one bit of the public key, message, or signature.
Usage: gen_vectors_vetted.py <outdir>   (writes vetted_ed25519.txt, vetted_ecdsa.txt, vetted_bip340.txt)
Formats: ed25519 "pk msg sig pc ps", ecdsa "qx qy z r s ok", bip340 "pk msg sig ok" (msg "-" means empty).
Requires: pip install cryptography pynacl coincurve"""
import sys, os, random, hashlib
import nacl.signing, nacl.exceptions
from cryptography.hazmat.primitives.asymmetric import ed25519 as oed, ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import coincurve

out = sys.argv[1] if len(sys.argv) > 1 else "."
rng = random.Random(20261031)
H = lambda b: b.hex() or "-"
flip = lambda b, i: bytes(x ^ (1 << (i % 8)) if j == i // 8 else x for j, x in enumerate(b))
n_secp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MSGLENS = [0, 1, 32, 33, 64, 77, 255, 1000]

# ---------------- Ed25519
def ed_verify_vetted(pk, msg, sig):
    ok_nacl = ok_ossl = True
    try: nacl.signing.VerifyKey(pk).verify(msg, sig)
    except Exception: ok_nacl = False
    try: oed.Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
    except Exception: ok_ossl = False
    return ok_nacl, ok_ossl
lines = []
for i in range(120):
    seed = rng.randbytes(32); msg = rng.randbytes(MSGLENS[i % len(MSGLENS)])
    sk = nacl.signing.SigningKey(seed); pk = bytes(sk.verify_key); sig = sk.sign(msg).signature
    osig = oed.Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
    assert sig == osig, "libsodium and OpenSSL disagree on a signature"
    assert ed_verify_vetted(pk, msg, sig) == (True, True)
    lines.append(f"{pk.hex()} {H(msg)} {sig.hex()} 1 1")
    for k in range(3):
        which = rng.choice("pms")
        if which == "p": cp, cm, cs = flip(pk, rng.randrange(256)), msg, sig
        elif which == "m": cp, cm, cs = pk, (flip(msg, rng.randrange(8 * len(msg))) if msg else b"!"), sig
        else: cp, cm, cs = pk, msg, flip(sig, rng.randrange(512))
        a, b = ed_verify_vetted(cp, cm, cs)
        assert a == b == False, "a one-bit mutation was accepted by a vetted verifier"
        lines.append(f"{cp.hex()} {H(cm)} {cs.hex()} 0 0")
open(os.path.join(out, "vetted_ed25519.txt"), "w").write("\n".join(lines) + "\n")
print(len(lines), "Ed25519 cases")

# ---------------- ECDSA secp256k1 (libsecp256k1 signer, OpenSSL verifier)
def ossl_ecdsa_verify(qx, qy, z, r, s):
    pub = ec.EllipticCurvePublicNumbers(int.from_bytes(qx, 'big'), int.from_bytes(qy, 'big'), ec.SECP256K1())
    try: key = pub.public_key()
    except Exception: return False
    try:
        key.verify(utils.encode_dss_signature(int.from_bytes(r, 'big'), int.from_bytes(s, 'big')), z, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError): return False
lines = []
for i in range(120):
    d = rng.randrange(1, n_secp); sk = coincurve.PrivateKey(d.to_bytes(32, 'big'))
    msg = rng.randbytes(MSGLENS[i % len(MSGLENS)]); z = hashlib.sha256(msg).digest()
    der = sk.sign(msg)                              # libsecp256k1: SHA-256 of msg, RFC 6979, low-s
    r, s = utils.decode_dss_signature(der)
    pt = sk.public_key.point(); qx, qy = pt[0].to_bytes(32, 'big'), pt[1].to_bytes(32, 'big')
    rb, sb = r.to_bytes(32, 'big'), s.to_bytes(32, 'big')
    assert sk.public_key.verify(der, msg) and ossl_ecdsa_verify(qx, qy, z, rb, sb)
    lines.append(f"{qx.hex()} {qy.hex()} {z.hex()} {rb.hex()} {sb.hex()} 1")
    for k in range(3):
        which = rng.choice("zrs")
        zz, rr, ss = z, rb, sb
        if which == "z": zz = flip(z, rng.randrange(256))
        elif which == "r": rr = flip(rb, rng.randrange(256))
        else: ss = flip(sb, rng.randrange(256))
        assert not ossl_ecdsa_verify(qx, qy, zz, rr, ss)
        lines.append(f"{qx.hex()} {qy.hex()} {zz.hex()} {rr.hex()} {ss.hex()} 0")
open(os.path.join(out, "vetted_ecdsa.txt"), "w").write("\n".join(lines) + "\n")
print(len(lines), "ECDSA cases")

# ---------------- BIP-340 (libsecp256k1); messages of 32 bytes (the API of the signer)
lines = []
for i in range(60):
    sk = coincurve.PrivateKey(rng.randbytes(32)); msg = rng.randbytes(32)
    sig = sk.sign_schnorr(msg, rng.randbytes(32)); pk = sk.public_key_xonly.format()
    assert coincurve.PublicKeyXOnly(pk).verify(sig, msg)
    lines.append(f"{pk.hex()} {H(msg)} {sig.hex()} 1")
    for k in range(3):
        which = rng.choice("pms")
        if which == "p": cp, cm, cs = flip(pk, rng.randrange(256)), msg, sig
        elif which == "m": cp, cm, cs = pk, flip(msg, rng.randrange(256)), sig
        else: cp, cm, cs = pk, msg, flip(sig, rng.randrange(512))
        try: ok = coincurve.PublicKeyXOnly(cp).verify(cs, cm)
        except Exception: ok = False
        assert not ok
        lines.append(f"{cp.hex()} {H(cm)} {cs.hex()} 0")
open(os.path.join(out, "vetted_bip340.txt"), "w").write("\n".join(lines) + "\n")
print(len(lines), "BIP-340 cases")

# ---------------- pool of 1024 valid BIP-340 signatures (libsecp256k1) with distinct keys and messages, for the batch benchmark
lines = []
for i in range(1024):
    sk = coincurve.PrivateKey(rng.randbytes(32)); msg = rng.randbytes(32)
    sig = sk.sign_schnorr(msg, rng.randbytes(32)); pk = sk.public_key_xonly.format()
    assert coincurve.PublicKeyXOnly(pk).verify(sig, msg)
    lines.append(f"{pk.hex()} {H(msg)} {sig.hex()} 1")
open(os.path.join(out, "vetted_bip340_pool.txt"), "w").write("\n".join(lines) + "\n")
print(len(lines), "BIP-340 pool cases")
