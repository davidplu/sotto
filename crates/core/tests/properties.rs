//! Property tests: invariants the crypto core guarantees, over randomised inputs.
//!
//! Argon2id master-key derivation is intentionally excluded - at 256 MiB it's ~seconds per
//! call, so hundreds of cases would take minutes. It's deterministic and covered by a
//! known-answer test in `vectors.rs`.

use proptest::prelude::*;
use sotto_core::{aead, format, kdf, vault, wrap, Error};

const FORMAT_FIXTURES: &str = include_str!("fixtures/format.txt");

fn key() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max)
}

fn unicode_string(max_chars: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..max_chars).prop_map(|chars| chars.into_iter().collect())
}

fn weighted_codec_string(max_chars: usize) -> impl Strategy<Value = String> {
    let character = prop_oneof![
        Just('0'),
        Just('A'),
        Just('Z'),
        Just('-'),
        Just('o'),
        Just('i'),
        Just('l'),
        Just('U'),
        Just('#'),
        any::<char>(),
    ];
    prop::collection::vec(character, 0..max_chars).prop_map(|chars| chars.into_iter().collect())
}

fn reference_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let output_len = (data.len() * 8).div_ceil(5);
    (0..output_len)
        .map(|index| {
            let mut value = 0u8;
            for offset in 0..5 {
                let bit = index * 5 + offset;
                value <<= 1;
                if bit < data.len() * 8 {
                    value |= (data[bit / 8] >> (7 - bit % 8)) & 1;
                }
            }
            char::from(ALPHABET[value as usize])
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
enum ReferenceDecodeError {
    InvalidSymbol,
}

fn reference_decode(input: &str) -> Result<Vec<u8>, ReferenceDecodeError> {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut values = Vec::with_capacity(input.len());
    for character in input.chars() {
        if character == '-' {
            continue;
        }
        let upper = character.to_ascii_uppercase();
        let value = match upper {
            'O' => 0,
            'I' | 'L' => 1,
            _ => ALPHABET
                .iter()
                .position(|&symbol| char::from(symbol) == upper)
                .ok_or(ReferenceDecodeError::InvalidSymbol)? as u8,
        };
        values.push(value);
    }
    let output_len = values.len() * 5 / 8;
    Ok((0..output_len)
        .map(|index| {
            (0..8).fold(0u8, |byte, offset| {
                let bit = index * 8 + offset;
                let value = if bit < values.len() * 5 {
                    (values[bit / 5] >> (4 - bit % 5)) & 1
                } else {
                    0
                };
                (byte << 1) | value
            })
        })
        .collect())
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("fixture hex"))
        .collect()
}

proptest! {
    /// AEAD: decrypting what we encrypted (with the same aad) returns the plaintext.
    #[test]
    fn aead_round_trip(k in key(), pt in bytes(512), aad in bytes(128)) {
        let env = aead::seal(&k, &pt, &aad);
        prop_assert_eq!(aead::open(&k, &env, &aad).expect("open"), pt);
    }

    /// AEAD: a different aad must fail (context binding).
    #[test]
    fn aead_wrong_aad_fails(k in key(), pt in bytes(256), aad1 in bytes(64), aad2 in bytes(64)) {
        prop_assume!(aad1 != aad2);
        let env = aead::seal(&k, &pt, &aad1);
        prop_assert!(aead::open(&k, &env, &aad2).is_err());
    }

    /// AEAD: a different key must fail (confidentiality).
    #[test]
    fn aead_wrong_key_fails(k1 in key(), k2 in key(), pt in bytes(256), aad in bytes(64)) {
        prop_assume!(k1 != k2);
        let env = aead::seal(&k1, &pt, &aad);
        prop_assert!(aead::open(&k2, &env, &aad).is_err());
    }

    /// AEAD: flipping any single byte of the envelope breaks decryption (integrity).
    #[test]
    fn aead_tamper_fails(k in key(), pt in bytes(256), aad in bytes(64), idx_seed in any::<usize>(), mask in 1u8..=255) {
        let mut env = aead::seal(&k, &pt, &aad);
        let idx = idx_seed % env.len();
        env[idx] ^= mask;
        prop_assert!(aead::open(&k, &env, &aad).is_err());
    }

    /// Crockford base32 round-trips over arbitrary byte lengths (bit-packing correctness).
    #[test]
    fn crockford_round_trip(data in bytes(4097)) {
        prop_assert_eq!(format::decode(&format::encode(&data)).expect("decode"), data);
    }

    /// Compare production encoding against an independent bit-indexed oracle.
    #[test]
    fn crockford_encode_matches_reference(data in bytes(4097)) {
        prop_assert_eq!(format::encode(&data), reference_encode(&data));
    }

    /// Compare the production byte walk with the independent character-based decoder.
    #[test]
    fn crockford_decode_matches_reference(input in weighted_codec_string(4096)) {
        let expected = reference_decode(&input);
        let actual = format::decode(&input).map_err(|_| ReferenceDecodeError::InvalidSymbol);
        prop_assert_eq!(actual, expected);
    }

    /// Bounded byte-derived strings are either decoded or rejected, never panicked on.
    #[test]
    fn malformed_decode_inputs_do_not_panic(data in bytes(4097)) {
        let input: String = data.into_iter().map(char::from).collect();
        let _ = format::decode(&input);
        let _ = format::decode_key("SK", 1, &input);
    }

    /// Full-Unicode strings are either decoded or rejected, never panicked on.
    #[test]
    fn malformed_unicode_decode_inputs_do_not_panic(input in unicode_string(4096)) {
        let _ = format::decode(&input);
        let _ = format::decode_key("SK", 1, &input);
    }

    /// A valid key header forces generated malformed bodies through key validation.
    #[test]
    fn malformed_key_bodies_do_not_panic(body in unicode_string(4096)) {
        let input = format!("SK1-{body}");
        let _ = format::decode_key("SK", 1, &input);
    }

    /// Versioned, checksummed key strings round-trip for any prefix/version/payload.
    #[test]
    fn key_string_round_trip(payload in prop::collection::vec(any::<u8>(), 1..=4096), version in any::<u8>()) {
        let s = format::encode_key("SK", version, &payload);
        prop_assert_eq!(format::decode_key("SK", version, &s).expect("decode_key"), payload);
    }

    /// Supported key prefixes retain their versioned round-trip behaviour.
    #[test]
    fn key_string_round_trip_for_supported_prefixes(
        prefix in prop_oneof![Just("SK".to_owned()), Just("RK".to_owned()), Just("MT".to_owned())],
        payload in prop::collection::vec(any::<u8>(), 1..=4096),
        version in any::<u8>(),
    ) {
        let encoded = format::encode_key(&prefix, version, &payload);
        prop_assert_eq!(format::decode_key(&prefix, version, &encoded).expect("decode_key"), payload);
    }

    /// Body-only case, separator and Crockford alias changes preserve a valid key payload.
    #[test]
    fn key_body_spelling_variations_preserve_payload(
        prefix in prop_oneof![Just("SK".to_owned()), Just("RK".to_owned()), Just("MT".to_owned())],
        payload in prop::collection::vec(any::<u8>(), 1..=256),
    ) {
        let encoded = format::encode_key(&prefix, 1, &payload);
        let (head, body) = encoded.split_once('-').expect("key body");
        let lower = format!("{head}-{}", body.to_ascii_lowercase());
        let lower_payload = format::decode_key(&prefix, 1, &lower).expect("lowercase body");
        prop_assert_eq!(lower_payload.as_slice(), payload.as_slice());

        let aliases = body.replace('0', "o").replace('1', "i");
        let alias_key = format!("{head}-{aliases}");
        let alias_payload = format::decode_key(&prefix, 1, &alias_key).expect("alias body");
        prop_assert_eq!(alias_payload.as_slice(), payload.as_slice());

        let separated = body.chars().map(|c| format!("{c}-")).collect::<String>();
        let separated_key = format!("{head}-{separated}");
        let separated_payload = format::decode_key(&prefix, 1, &separated_key).expect("separated body");
        prop_assert_eq!(separated_payload.as_slice(), payload.as_slice());
    }

    /// The generic key API round-trips arbitrary bounded UTF-8 prefixes as well as named ones.
    #[test]
    fn arbitrary_prefix_round_trip(
        prefix in unicode_string(32),
        payload in prop::collection::vec(any::<u8>(), 0..=256),
        version in any::<u8>(),
    ) {
        let encoded = format::encode_key(&prefix, version, &payload);
        prop_assert_eq!(format::decode_key(&prefix, version, &encoded).expect("prefix round trip"), payload);
    }

    /// Symmetric key wrapping round-trips.
    #[test]
    fn wrap_round_trip(kek in key(), k in key(), aad in bytes(64)) {
        let wrapped = wrap::wrap_key(&kek, &k, &aad);
        prop_assert_eq!(wrap::unwrap_key(&kek, &wrapped, &aad).expect("unwrap"), k);
    }

    /// X25519 sealed-box wrapping round-trips for the addressed keypair.
    #[test]
    fn sealed_box_round_trip(secret in key(), pt in bytes(256)) {
        // Derive the recipient keypair from proptest-driven bytes (not OS randomness) so a
        // failing case is reproducible from the persisted seed. Any 32 bytes is a valid X25519
        // secret, and the public is derived consistently for both seal and open.
        let kp = wrap::keypair_from_secret(&secret);
        let sealed = wrap::seal_to_public(&kp.public, &pt).expect("seal");
        prop_assert_eq!(wrap::open_sealed(&kp, &sealed).expect("unseal"), pt);
    }

    /// Distinct subkey ids yield distinct subkeys (domain separation).
    #[test]
    fn subkeys_separated(master in key(), id1 in any::<u64>(), id2 in any::<u64>()) {
        prop_assume!(id1 != id2);
        let a = kdf::derive_subkey(&master, b"vaultkey", id1).expect("subkey");
        let b = kdf::derive_subkey(&master, b"vaultkey", id2).expect("subkey");
        prop_assert_ne!(a, b);
    }

    /// Rotation: rewrapping a data key moves a secret from the old vault key to the new one - the
    /// unchanged name/value ciphertext decrypts under the new key, and the old key is locked out.
    #[test]
    fn rewrap_moves_secret_between_vault_keys(
        old in key(),
        new in key(),
        version in 1i64..1_000_000,
        name in bytes(64),
        value in bytes(256),
    ) {
        prop_assume!(old != new);
        let enc = vault::encrypt_secret(&old, "env", "secret", version, &name, &value);
        let rewrapped = vault::rewrap_data_key(&old, &new, "env", "secret", version, &enc.enc_data_key)
            .expect("rewrap");

        // The untouched ciphertext opens under the new vault key via the rewrapped data key…
        let (got_name, got_value) =
            vault::decrypt_secret(&new, "env", "secret", version, &enc.enc_name, &enc.enc_value, &rewrapped)
                .expect("decrypt under new key");
        prop_assert_eq!(got_name, name);
        prop_assert_eq!(got_value, value);
        // …and neither key opens the other's wrap.
        prop_assert!(vault::decrypt_value(&old, "env", "secret", version, &enc.enc_value, &rewrapped).is_err());
        prop_assert!(vault::decrypt_value(&new, "env", "secret", version, &enc.enc_value, &enc.enc_data_key).is_err());
    }
}

#[test]
fn crockford_reference_handles_max_payload() {
    let data = vec![0xa5; 4096];
    assert_eq!(format::encode(&data), reference_encode(&data));
}

#[test]
fn crockford_reference_matches_fixed_vectors() {
    assert_eq!(
        reference_decode("NENTQ-AXBNE-NTQAX-BNENT-QAXBN-DDBW"),
        Ok(vec![0xAB; 16].into_iter().chain([0x5A, 0xBE]).collect())
    );
    assert_eq!(reference_decode(""), Ok(Vec::new()));
}

#[test]
fn crockford_payload_boundaries_and_patterns_round_trip() {
    let lengths = [
        0, 1, 2, 3, 4, 5, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 4096,
    ];
    for length in lengths {
        for data in [
            vec![0; length],
            vec![0xFF; length],
            (0..length).map(|index| (index % 2) as u8).collect(),
            (0..length).map(|index| index as u8).collect(),
        ] {
            let encoded = format::encode(&data);
            assert_eq!(format::decode(&encoded).expect("boundary decode"), data);
            assert_eq!(encoded, reference_encode(&data));
        }
    }
}

#[test]
fn shared_format_fixtures_cover_success_and_rejection_stages() {
    for line in FORMAT_FIXTURES
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
    {
        let [kind, prefix, version, input, expected] = line
            .split('|')
            .collect::<Vec<_>>()
            .try_into()
            .expect("fixture columns");
        let version = version.parse().expect("fixture version");
        let result = format::decode_key(prefix, version, input);
        if kind == "valid" {
            assert_eq!(result.expect("valid fixture"), hex_bytes(expected));
        } else {
            let error = result.expect_err("rejected fixture");
            let expected = match expected {
                "key_prefix" => Error::KeyPrefix,
                "invalid_symbol" => Error::Malformed("invalid base32 symbol"),
                "key_short" => Error::Malformed("key too short"),
                "checksum" => Error::Checksum,
                other => panic!("unknown fixture expectation {other}"),
            };
            assert_eq!(error.to_string(), expected.to_string());
        }
    }
}
