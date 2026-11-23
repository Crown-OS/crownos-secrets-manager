//! The byte strings that give a value away: the value itself and its common encodings.

use base64::Engine as _;
use base64::engine::GeneralPurpose;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use crate::util::hex::{HexCase, hex_encode};
use crate::util::json_escape::{JsonEscapeStyle, json_escape};
use crate::util::percent::{PercentStyle, percent_encode};

/// Encoded forms shorter than this are left out: they would match ordinary text.
pub(crate) const MINIMUM_ENCODED_LENGTH: usize = 4;

/// The value first, then every encoded form that is long enough. The list can hold duplicates.
pub(crate) fn revealing_forms(value: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut forms = vec![Zeroizing::new(value.to_vec())];
    let mut encoded = Vec::new();
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        for alignment in 0..3 {
            encoded.push(base64_fragment(engine, value, alignment));
        }
    }
    for case in [HexCase::Lower, HexCase::Upper] {
        encoded.push(hex_encode(value, case));
        encoded.push(percent_encode(value, PercentStyle::Uri(case)));
    }
    encoded.push(percent_encode(value, PercentStyle::Form));
    if let Ok(text) = std::str::from_utf8(value) {
        encoded.extend(JsonEscapeStyle::ALL.map(|style| json_escape(text, style)));
    }
    forms.extend(
        encoded
            .into_iter()
            .filter(|form| form.len() >= MINIMUM_ENCODED_LENGTH),
    );
    forms
}

/// The base64 characters that depend only on `value` when `alignment` bytes (0, 1 or 2) come
/// before it in the encoded stream. Characters that share bits with neighbour bytes are cut.
fn base64_fragment(engine: &GeneralPurpose, value: &[u8], alignment: usize) -> Zeroizing<Vec<u8>> {
    let mut shifted = Zeroizing::new(Vec::with_capacity(alignment + value.len()));
    shifted.resize(alignment, 0);
    shifted.extend_from_slice(value);
    let mut encoded = Zeroizing::new(vec![0u8; shifted.len().div_ceil(3) * 4]);
    let written = engine
        .encode_slice(shifted.as_slice(), encoded.as_mut_slice())
        .unwrap_or(0);
    let first_bit = alignment * 8;
    let end_bit = (alignment + value.len()) * 8;
    let first_character = first_bit.div_ceil(6);
    let end_character = (end_bit / 6).min(written);
    Zeroizing::new(
        encoded
            .get(first_character..end_character)
            .unwrap_or_default()
            .to_vec(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn base64_fragments_appear_in_the_encoding_of_any_surrounding_stream() {
        let value = b"s3cr3t-value!";
        for alignment in 0..3 {
            let fragment = base64_fragment(&STANDARD_NO_PAD, value, alignment);
            assert!(fragment.len() >= 16, "{alignment}");
            for prefix in [[0xffu8; 3], [0x00; 3], [0x5a; 3]] {
                let mut stream = prefix[..alignment].to_vec();
                stream.extend_from_slice(value);
                stream.extend_from_slice(b"\xff\x01");
                let encoded = STANDARD_NO_PAD.encode(&stream);
                assert!(
                    encoded
                        .as_bytes()
                        .windows(fragment.len())
                        .any(|window| window == fragment.as_slice()),
                    "alignment {alignment}"
                );
            }
        }
    }

    #[test]
    fn short_encodings_are_left_out_but_the_value_stays() {
        let forms = revealing_forms(b"ab");
        assert_eq!(forms[0].as_slice(), b"ab");
        assert!(
            forms
                .iter()
                .skip(1)
                .all(|form| form.len() >= MINIMUM_ENCODED_LENGTH)
        );
    }
}
