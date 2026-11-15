//! Shared OPAQUE configuration for the examples.
use argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::{CipherSuite, Ristretto255, TripleDh};

/// ristretto255 for the OPRF and the 3DH key exchange, SHA-512, Argon2id as the KSF.
pub struct Suite;
impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

/// Argon2id with libsodium's crypto_pwhash INTERACTIVE limits (64 MiB, 2 passes, 1 lane), the
/// setting libopaque hard-codes. Matching it is what lets this client log in to a libopaque server.
pub fn ksf() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(65536, 2, 1, None).unwrap())
}

pub const CONTEXT: &[u8] = b"opaque-examples-v1";

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}
