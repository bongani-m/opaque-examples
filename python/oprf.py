"""Code A: a teaching OPRF over ristretto255.

For learning, not production. RFC 9497 hashes to the group with
expand_message_xmd and a domain-separation tag; this file uses plain SHA-512
so every step stays visible. Use a real library (see opaque_flow.py).

Usage: python oprf.py [password] [--r HEX] [--k HEX]
"""
import argparse
import hashlib

import pysodium as s


def hash_to_group(x: bytes) -> bytes:
    # H'(x): map 64 uniform bytes onto the group (Elligator 2 inside libsodium).
    return s.crypto_core_ristretto255_from_hash(hashlib.sha512(x).digest())


def blind(x: bytes, r: bytes) -> bytes:
    return s.crypto_scalarmult_ristretto255(r, hash_to_group(x))  # a = H'(x)^r


def evaluate(k: bytes, a: bytes) -> bytes:
    return s.crypto_scalarmult_ristretto255(k, a)  # b = a^k


def finalize(x: bytes, r: bytes, b: bytes) -> bytes:
    r_inv = s.crypto_core_ristretto255_scalar_invert(r)
    unblinded = s.crypto_scalarmult_ristretto255(r_inv, b)  # b^(1/r) = H'(x)^k
    return hashlib.sha512(x + unblinded).digest()  # F(k, x) = H(x, H'(x)^k)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("password", nargs="?", default="correct horse battery staple")
    p.add_argument("--r", help="client blind (32-byte scalar, hex)")
    p.add_argument("--k", help="server key (32-byte scalar, hex)")
    args = p.parse_args()

    x = args.password.encode()
    r = bytes.fromhex(args.r) if args.r else s.crypto_core_ristretto255_scalar_random()
    k = bytes.fromhex(args.k) if args.k else s.crypto_core_ristretto255_scalar_random()

    a = blind(x, r)            # client -> server: a
    b = evaluate(k, a)         # server -> client: b
    out = finalize(x, r, b)    # client: F(k, x)

    # Check: the same as evaluating without a blind, which only someone
    # holding both x and k could do.
    direct = hashlib.sha512(x + s.crypto_scalarmult_ristretto255(k, hash_to_group(x))).digest()
    print("server saw a =", a.hex())
    print("F(k, x)      =", out.hex())
    print("matches unblinded evaluation:", out == direct)
    assert out == direct


if __name__ == "__main__":
    main()
