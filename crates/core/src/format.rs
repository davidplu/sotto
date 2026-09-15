//! Human-facing key encoding: Crockford base32, versioned + checksummed.
//!
//! Used for the secret key (`SK1-…`) and the Emergency Kit recovery key (`RK1-…`). Crockford
//! base32 omits ambiguous letters and is case-insensitive; a Fletcher-16 checksum catches
//! transcription typos before they reach the (irreversible) recovery path.

use crate::error::Error;

/// Crockford base32 alphabet - excludes the ambiguous letters I, L, O, and U.
pub const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encode bytes as Crockford base32 (uppercase, no padding).
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;
    for &b in data {
        acc = (acc << 8) | b as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((acc >> bits) & 0x1f) as usize;
            out.push(CROCKFORD_ALPHABET[idx] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        let idx = ((acc << (5 - bits)) & 0x1f) as usize;
        out.push(CROCKFORD_ALPHABET[idx] as char);
    }
    out
}

/// Decode a Crockford base32 string (case-insensitive; hyphens ignored).
pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8 + 1);
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;
    for byte in s.bytes() {
        let c = char::from(byte);
        if c == '-' {
            continue;
        }
        let v = decode_symbol(c).ok_or(Error::Malformed("invalid base32 symbol"))?;
        acc = (acc << 5) | v as u16;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn decode_symbol(c: char) -> Option<u8> {
    let u = c.to_ascii_uppercase();
    match u {
        'O' => Some(0),
        'I' | 'L' => Some(1),
        '0'..='9' => Some(u as u8 - b'0'),
        'A'..='H' => Some(u as u8 - b'A' + 10),
        'J'..='K' => Some(u as u8 - b'J' + 18),
        'M'..='N' => Some(u as u8 - b'M' + 20),
        'P'..='T' => Some(u as u8 - b'P' + 22),
        'V'..='Z' => Some(u as u8 - b'V' + 27),
        _ => None,
    }
}

/// Encode a versioned, checksummed key string, e.g. `SK1-9F8K2-7HJX4-…`.
///
/// `prefix` is a short tag like `"SK"` or `"RK"`; `version` is folded into both the visible
/// header and the checksum so a wrong prefix/version is rejected.
pub fn encode_key(prefix: &str, version: u8, payload: &[u8]) -> String {
    let check = fletcher16(&tagged(prefix, version, payload));
    let mut body = Vec::with_capacity(payload.len() + 2);
    body.extend_from_slice(payload);
    body.extend_from_slice(&check);
    format!("{prefix}{version}-{}", group(&encode(&body), 5))
}

/// Decode and verify a versioned key string, returning the payload bytes.
pub fn decode_key(prefix: &str, version: u8, s: &str) -> Result<Vec<u8>, Error> {
    let head = format!("{prefix}{version}-");
    let rest = s.strip_prefix(&head).ok_or(Error::KeyPrefix)?;
    let body = decode(rest)?;
    if body.len() < 2 {
        return Err(Error::Malformed("key too short"));
    }
    let (payload, check) = body.split_at(body.len() - 2);
    if fletcher16(&tagged(prefix, version, payload)) != check {
        return Err(Error::Checksum);
    }
    Ok(payload.to_vec())
}

fn tagged(prefix: &str, version: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(prefix.len() + 1 + payload.len());
    t.extend_from_slice(prefix.as_bytes());
    t.push(version);
    t.extend_from_slice(payload);
    t
}

/// Fletcher-16 checksum (two bytes, each < 255). Typo detection, not security.
fn fletcher16(data: &[u8]) -> [u8; 2] {
    let (mut a, mut b) = (0u16, 0u16);
    for &x in data {
        a = (a + x as u16) % 255;
        b = (b + a) % 255;
    }
    [a as u8, b as u8]
}

fn group(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    chars
        .chunks(n)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(kani)]
mod verification {
    use super::*;

    /// Every Unicode scalar gets the documented Crockford symbol mapping or rejection.
    #[kani::proof]
    fn decode_symbol_total_and_compatible() {
        let c: char = kani::any();
        let upper = c.to_ascii_uppercase();
        let expected = match upper {
            'O' => Some(0),
            'I' | 'L' => Some(1),
            _ => CROCKFORD_ALPHABET
                .iter()
                .position(|&b| char::from(b) == upper)
                .map(|p| p as u8),
        };
        kani::cover!(expected.is_some());
        kani::cover!(expected.is_none());
        assert_eq!(decode_symbol(c), expected);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_decoder_matches_alphabet_for_every_unicode_scalar() {
        for c in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            let upper = c.to_ascii_uppercase();
            let expected = match upper {
                'O' => Some(0),
                'I' | 'L' => Some(1),
                _ => CROCKFORD_ALPHABET
                    .iter()
                    .position(|&b| char::from(b) == upper)
                    .map(|p| p as u8),
            };
            assert_eq!(decode_symbol(c), expected, "{c:?}");
            if !c.is_ascii() {
                assert!(matches!(
                    decode(&c.to_string()),
                    Err(Error::Malformed("invalid base32 symbol"))
                ));
            }
        }
    }

    #[test]
    fn alphabet_has_32_symbols_and_no_ambiguous_letters() {
        assert_eq!(CROCKFORD_ALPHABET.len(), 32);
        for ambiguous in *b"ILOU" {
            assert!(!CROCKFORD_ALPHABET.contains(&ambiguous));
        }
    }

    #[test]
    fn encode_decode_round_trips() {
        for len in [0usize, 1, 2, 5, 16, 32] {
            let data = crate::random::bytes::<32>()[..len].to_vec();
            let s = encode(&data);
            assert_eq!(decode(&s).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn decode_is_case_insensitive_and_ignores_hyphens_and_aliases() {
        let canonical = decode("ZW").unwrap();
        assert_eq!(decode("z-w").unwrap(), canonical);
        // O -> 0, I/L -> 1
        assert_eq!(decode("O").unwrap(), decode("0").unwrap());
        assert_eq!(decode("I").unwrap(), decode("1").unwrap());
        assert_eq!(decode("L").unwrap(), decode("1").unwrap());
    }

    #[test]
    fn key_round_trips() {
        let payload = crate::random::bytes::<16>();
        let s = encode_key("SK", 1, &payload);
        assert!(s.starts_with("SK1-"));
        assert_eq!(decode_key("SK", 1, &s).unwrap(), payload);
    }

    #[test]
    fn checksum_catches_single_char_typo() {
        let payload = [0xABu8; 16];
        let s = encode_key("SK", 1, &payload);
        // Flip one character in the encoded body (after the "SK1-" head).
        let mut chars: Vec<char> = s.chars().collect();
        let pos = chars
            .iter()
            .position(|&c| c != '-' && c != 'S' && c != 'K' && c != '1')
            .unwrap();
        chars[pos] = if chars[pos] == 'Z' { 'Y' } else { 'Z' };
        let typo: String = chars.into_iter().collect();
        assert!(matches!(
            decode_key("SK", 1, &typo),
            Err(Error::Checksum) | Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let s = encode_key("SK", 1, &[1u8; 16]);
        assert!(matches!(decode_key("RK", 1, &s), Err(Error::KeyPrefix)));
        assert!(matches!(decode_key("SK", 2, &s), Err(Error::KeyPrefix)));
    }

    #[test]
    fn key_decoder_rejects_each_validation_stage() {
        assert!(matches!(
            decode_key("SK", 1, "RK1-0"),
            Err(Error::KeyPrefix)
        ));
        assert!(matches!(
            decode_key("SK", 1, "SK1-#"),
            Err(Error::Malformed("invalid base32 symbol"))
        ));
        assert!(matches!(
            decode_key("SK", 1, "SK1-0"),
            Err(Error::Malformed("key too short"))
        ));
        let mut encoded = encode_key("SK", 1, &[0x11; 16]);
        let last = encoded.pop().expect("encoded key has a body");
        encoded.push(if last == '0' { '1' } else { '0' });
        assert!(matches!(
            decode_key("SK", 1, &encoded),
            Err(Error::Checksum)
        ));
    }
}
