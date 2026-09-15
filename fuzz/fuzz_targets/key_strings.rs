#![no_main]

use libfuzzer_sys::fuzz_target;
use sotto_core::{format, Error};

const MAX_PAYLOAD: usize = 4096;
const MAX_TEXT: usize = 16384;
const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn bounded(data: &[u8], max: usize) -> &[u8] {
    let end = data.len().min(max);
    &data[..end]
}

fn body_text(data: &[u8]) -> String {
    data.iter()
        .map(|byte| match byte % 40 {
            value if value < 32 => ALPHABET[value as usize] as char,
            32 => '-',
            33 => 'o',
            34 => 'i',
            35 => 'l',
            36 => 'U',
            _ => '#',
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        let _ = format::decode_key("SK", 1, "");
        return;
    };
    match mode % 6 {
        0 => {
            let payload = bounded(rest, MAX_PAYLOAD);
            let encoded = format::encode_key("SK", 1, payload);
            assert_eq!(
                format::decode_key("SK", 1, &encoded).expect("key output is valid"),
                payload
            );
        }
        1 => {
            let input = format!("X{}", body_text(bounded(rest, MAX_TEXT)));
            assert!(
                format::decode_key("SK", 1, &input).is_err(),
                "missing key header must reject"
            );
        }
        2 => {
            let prefixes = ["SK", "RK", "MT"];
            let prefix = prefixes[(rest.first().copied().unwrap_or(0) % 3) as usize];
            let input = format!("{prefix}1-0");
            assert!(matches!(
                format::decode_key(prefix, 1, &input),
                Err(Error::Malformed("key too short"))
            ));
        }
        3 => {
            let prefixes = ["SK", "RK", "MT"];
            let prefix = prefixes[(rest.first().copied().unwrap_or(0) % 3) as usize];
            let input = format!("{prefix}1-#");
            assert!(matches!(
                format::decode_key(prefix, 1, &input),
                Err(Error::Malformed("invalid base32 symbol"))
            ));
        }
        4 => {
            let payload = bounded(rest, MAX_PAYLOAD);
            let prefixes = ["SK", "RK", "MT"];
            let prefix = prefixes[(payload.first().copied().unwrap_or(0) % 3) as usize];
            let encoded = format::encode_key(prefix, 1, payload);
            let (head, body) = encoded.split_once('-').expect("encoded key body");
            let mut chars: Vec<char> = body.chars().collect();
            let index = chars
                .iter()
                .position(|character| *character != '-')
                .expect("nonempty body");
            chars[index] = if chars[index] == '0' { '1' } else { '0' };
            let mutated = format!("{head}-{}", chars.into_iter().collect::<String>());
            assert!(
                format::decode_key(prefix, 1, &mutated).is_err(),
                "mutated checksum must reject"
            );
        }
        _ => {
            let payload = bounded(rest, MAX_PAYLOAD);
            let prefixes = ["SK", "RK", "MT"];
            let prefix = prefixes[(payload.first().copied().unwrap_or(0) % 3) as usize];
            let encoded = format::encode_key(prefix, 1, payload);
            let wrong = format!(
                "{prefix}2-{}",
                encoded.split_once('-').map_or("", |(_, body)| body)
            );
            assert!(matches!(
                format::decode_key(prefix, 1, &wrong),
                Err(Error::KeyPrefix)
            ));
            assert!(
                matches!(format::decode_key("SK", 1, &encoded), Err(Error::KeyPrefix))
                    || prefix == "SK"
            );
        }
    }
});
