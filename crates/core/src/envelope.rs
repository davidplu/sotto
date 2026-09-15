//! Versioned, self-describing ciphertext envelope.
//!
//! Wire layout:
//! `[ scheme: u8 ][ alg: u8 ][ nonce: 24 ][ ciphertext ‖ Poly1305 tag ]`
//!
//! Fixed layout per scheme (no algorithm negotiation - avoids downgrade attacks). New schemes
//! append; algorithm ids are never reused.

use crate::error::Error;

/// Current envelope scheme.
pub const SCHEME_V1: u8 = 1;

/// XChaCha20-Poly1305 nonce length, in bytes (192-bit; random nonces are collision-safe).
pub const NONCE_LEN: usize = 24;

/// Algorithms in the scheme registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Alg {
    /// XChaCha20-Poly1305 one-shot AEAD with a 192-bit random nonce (scheme 1).
    XChaCha20Poly1305 = 1,
}

impl Alg {
    /// Parse an algorithm id from its on-the-wire byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Alg::XChaCha20Poly1305),
            _ => None,
        }
    }
}

/// Validate the structural header and borrow its nonce and ciphertext.
/// Authentication, including the tag length, remains the AEAD implementation's job.
pub(crate) fn parse(bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if bytes.len() < 2 + NONCE_LEN {
        return Err(Error::Malformed("envelope too short"));
    }
    let scheme = bytes[0];
    let alg = bytes[1];
    if scheme != SCHEME_V1 || Alg::from_u8(alg) != Some(Alg::XChaCha20Poly1305) {
        return Err(Error::UnsupportedScheme { scheme, alg });
    }
    Ok((&bytes[2..2 + NONCE_LEN], &bytes[2 + NONCE_LEN..]))
}

#[cfg(kani)]
mod verification {
    use super::*;

    /// Every byte combination at lengths 0..=64, including every pair of registry ids.
    #[kani::proof]
    #[kani::unwind(65)]
    fn header_validation_and_slicing() {
        let bytes: [u8; 64] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let result = parse(&bytes[..len]);
        // Literal wire values make registry/layout drift visible to the proof.
        if len < 26 {
            assert!(matches!(
                result,
                Err(Error::Malformed("envelope too short"))
            ));
        } else if bytes[0] != 1 || bytes[1] != 1 {
            assert!(
                matches!(result, Err(Error::UnsupportedScheme { scheme, alg })
                if scheme == bytes[0] && alg == bytes[1])
            );
        } else {
            let (nonce, ciphertext) = result.expect("valid header");
            assert_eq!(nonce, &bytes[2..26]);
            assert_eq!(ciphertext, &bytes[26..len]);
        }
    }
}
