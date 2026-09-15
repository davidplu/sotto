#![no_main]

use libfuzzer_sys::fuzz_target;
use sotto_core::format;

const MAX_PAYLOAD: usize = 4096;
const MAX_TEXT: usize = 16384;
const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn bounded(data: &[u8], max: usize) -> &[u8] {
    let end = data.len().min(max);
    &data[..end]
}

fn structured_ascii(data: &[u8]) -> String {
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
        let _ = format::decode("");
        return;
    };
    match mode % 3 {
        0 => {
            let input = bounded(rest, MAX_PAYLOAD);
            let encoded = format::encode(input);
            assert_eq!(
                format::decode(&encoded).expect("encoder output is valid"),
                input
            );
        }
        1 => {
            let input = bounded(rest, MAX_TEXT);
            if let Ok(text) = std::str::from_utf8(input) {
                let _ = format::decode(text);
            }
        }
        _ => {
            let mut text = structured_ascii(bounded(rest, MAX_TEXT));
            text.push('#');
            assert!(
                format::decode(&text).is_err(),
                "a deliberately invalid symbol must reject"
            );
        }
    }
});
