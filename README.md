# opaque-examples

Small, runnable examples of the [OPAQUE](https://www.rfc-editor.org/rfc/rfc9807) augmented PAKE in
Python, C++ and Rust, written for the post
[OPAQUE: logging in without ever sending your password](https://bonganimbigi.com/archives/opaque).

| | Python | C++ | Rust |
| --- | --- | --- | --- |
| **A** teaching OPRF (not OPAQUE) | [`python/oprf.py`](python/oprf.py) (pysodium) | [`cpp/oprf.cpp`](cpp/oprf.cpp) (libsodium) | [`rust/src/bin/oprf.rs`](rust/src/bin/oprf.rs) (curve25519-dalek) |
| **B + C** registration and login | [`python/opaque_flow.py`](python/opaque_flow.py) (libopaque) | [`cpp/opaque_flow.cpp`](cpp/opaque_flow.cpp) (libopaque) | [`rust/src/bin/opaque_flow.rs`](rust/src/bin/opaque_flow.rs) (opaque-ke) |
| **D** across the network | [`python/server.py`](python/server.py) | [`cpp/client.cpp`](cpp/client.cpp) | [`rust/src/bin/client.rs`](rust/src/bin/client.rs) |

Every B/C/D example tries the right password and a wrong one. The wrong one fails inside the
protocol (the server MAC in KE2 doesn't verify on the client), not on a string comparison.

## Run

Needs libsodium ≥ 1.0.19, pkg-config, CMake, Python 3.10+ and a Rust toolchain.

```sh
make test
```

That builds liboprf and libopaque at pinned commits into `third_party/`, then runs:

1. Code A in all three languages with a fixed blind and key, and checks that the outputs match.
2. Codes B and C in all three languages.
3. Code D: the Python server (libopaque) against the C++ client (libopaque) and the Rust client
   (opaque-ke).

## Interop notes

libopaque and opaque-ke are separate implementations that both follow the CFRG OPAQUE spec. They
interoperate here because every parameter matches:

- ristretto255 for the OPRF and 3DH, SHA-512.
- The same context string and the same client and server identities on both sides.
- KSF: Argon2id, 64 MiB, 2 passes, 1 lane, all-zero salt. That is libsodium's `crypto_pwhash`
  INTERACTIVE setting, which libopaque hard-codes; [`rust/src/lib.rs`](rust/src/lib.rs) sets the
  same on the opaque-ke side.

The KSF is the subtle one. It runs only on the client, so the server never notices which
parameters a client used. It matters once two client implementations share one record. The last
interop step registers a user from C++ and logs in from Rust: with matching Argon2 parameters it
works, and with opaque-ke's defaults (`--default-ksf`) the right password is rejected.

## Not production code

The OPRF in Code A uses plain SHA-512 where RFC 9497 uses `expand_message_xmd` with a
domain-separation tag. The server in Code D has no TLS, no rate limiting and no fake records for
unknown users. The post's "footguns" section explains why a real one needs all three.

MIT licensed.
