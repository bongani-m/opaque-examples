//! Code A: a teaching OPRF over ristretto255 with curve25519-dalek.
//! For learning, not production: RFC 9497 hashes to the group with expand_message_xmd and a
//! domain-separation tag; this uses plain SHA-512.
//!
//! Usage: oprf [password] [r_hex k_hex]
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use opaque_examples::{hex, unhex};
use rand_core::OsRng;
use sha2::{Digest, Sha512};

fn hash_to_group(x: &[u8]) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(x) // H'(x): SHA-512, then Elligator 2
}

fn blind(x: &[u8], r: &Scalar) -> RistrettoPoint {
    hash_to_group(x) * r // a = H'(x)^r
}

fn evaluate(k: &Scalar, a: &RistrettoPoint) -> RistrettoPoint {
    a * k // b = a^k
}

fn finalize(x: &[u8], r: &Scalar, b: &RistrettoPoint) -> Vec<u8> {
    let unblinded = b * r.invert(); // b^(1/r) = H'(x)^k
    Sha512::new().chain_update(x).chain_update(unblinded.compress().as_bytes()).finalize().to_vec()
}

fn scalar(arg: Option<String>) -> Scalar {
    match arg.and_then(|s| unhex(&s)).and_then(|b| <[u8; 32]>::try_from(b).ok()) {
        Some(b) => Scalar::from_canonical_bytes(b).expect("scalar must be canonical"),
        None => Scalar::random(&mut OsRng),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let x = args.next().unwrap_or_else(|| "correct horse battery staple".into()).into_bytes();
    let (r, k) = (scalar(args.next()), scalar(args.next()));

    let a = blind(&x, &r); // client -> server
    let b = evaluate(&k, &a); // server -> client
    let out = finalize(&x, &r, &b); // client

    let direct = Sha512::new()
        .chain_update(&x)
        .chain_update((hash_to_group(&x) * k).compress().as_bytes())
        .finalize()
        .to_vec();
    println!("server saw a = {}", hex(a.compress().as_bytes()));
    println!("F(k, x)      = {}", hex(&out));
    println!("matches unblinded evaluation: {}", if out == direct { "True" } else { "False" });
    assert_eq!(out, direct);
}
