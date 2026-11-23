//! A value planted in a stream never survives the scrubber, in any chunking.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use proptest::prelude::*;
use secrets_core::{Scrubber, SecretName};

fn scrubber_for(value: &[u8]) -> Scrubber {
    let mut scrubber = Scrubber::new();
    scrubber.add_secret(&SecretName::parse("planted").unwrap(), value);
    scrubber
}

fn scrub_in_chunks(scrubber: &Scrubber, input: &[u8], chunk_lengths: &[usize]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut stream = scrubber.stream();
    let mut rest = input;
    for &length in chunk_lengths.iter().cycle() {
        if rest.is_empty() {
            break;
        }
        let (chunk, tail) = rest.split_at(length.min(rest.len()));
        stream.push(chunk, &mut output);
        rest = tail;
    }
    stream.finish(&mut output);
    output
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn value_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 4..40),
        prop::collection::vec(prop::sample::select(vec![b'a', b'b']), 4..12),
        "[a-zA-Z0-9/+=_ -]{4,40}".prop_map(String::into_bytes),
        "\\PC{2,12}".prop_map(String::into_bytes),
    ]
}

fn noise_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..64),
        prop::collection::vec(prop::sample::select(vec![b'a', b'b']), 0..16),
    ]
}

fn chunking_strategy() -> impl Strategy<Value = Vec<usize>> {
    prop_oneof![
        Just(vec![1]),
        prop::collection::vec(1usize..17, 1..8),
        Just(vec![usize::MAX]),
    ]
}

/// The base64 characters of `stream` that only depend on `stream[start..end]`.
fn determined_base64(encoded: &str, start: usize, end: usize) -> Vec<u8> {
    let first = (start * 8).div_ceil(6);
    let last = (end * 8 / 6).min(encoded.len());
    encoded.as_bytes()[first..last].to_vec()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn a_raw_value_never_survives(
        value in value_strategy(),
        prefix in noise_strategy(),
        suffix in noise_strategy(),
        chunks in chunking_strategy(),
    ) {
        let scrubber = scrubber_for(&value);
        let input = [prefix.as_slice(), &value, &suffix].concat();
        let output = scrub_in_chunks(&scrubber, &input, &chunks);
        prop_assert!(!contains(&output, &value));
        prop_assert!(contains(&output, b"[secret:planted]"));
    }

    #[test]
    fn chunking_never_changes_the_output(
        value in value_strategy(),
        input in prop::collection::vec(any::<u8>(), 0..200),
        chunks in chunking_strategy(),
    ) {
        let scrubber = scrubber_for(&value);
        prop_assert_eq!(scrub_in_chunks(&scrubber, &input, &chunks), scrubber.scrub(&input));
    }

    #[test]
    fn a_value_inside_a_base64_stream_never_survives(
        value in prop::collection::vec(any::<u8>(), 6..40),
        prefix in prop::collection::vec(any::<u8>(), 0..9),
        suffix in prop::collection::vec(any::<u8>(), 0..9),
        url_safe in any::<bool>(),
        chunks in chunking_strategy(),
    ) {
        let scrubber = scrubber_for(&value);
        let stream = [prefix.as_slice(), &value, &suffix].concat();
        let encoded = if url_safe {
            URL_SAFE_NO_PAD.encode(&stream)
        } else {
            STANDARD_NO_PAD.encode(&stream)
        };
        let revealing = determined_base64(&encoded, prefix.len(), prefix.len() + value.len());
        let output = scrub_in_chunks(&scrubber, encoded.as_bytes(), &chunks);
        prop_assert!(revealing.len() >= 4);
        prop_assert!(!contains(&output, &revealing));
    }

    #[test]
    fn a_value_in_hex_or_percent_encoding_never_survives(
        value in value_strategy(),
        prefix in noise_strategy(),
        uppercase in any::<bool>(),
        chunks in chunking_strategy(),
    ) {
        let scrubber = scrubber_for(&value);
        let hex: String = value
            .iter()
            .map(|byte| if uppercase { format!("{byte:02X}") } else { format!("{byte:02x}") })
            .collect();
        let percent: String = value
            .iter()
            .map(|&byte| {
                if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                    char::from(byte).to_string()
                } else if uppercase {
                    format!("%{byte:02X}")
                } else {
                    format!("%{byte:02x}")
                }
            })
            .collect();
        for encoded in [hex, percent] {
            let input = [prefix.as_slice(), encoded.as_bytes(), b" end"].concat();
            let output = scrub_in_chunks(&scrubber, &input, &chunks);
            prop_assert!(!contains(&output, encoded.as_bytes()));
        }
    }

    #[test]
    fn a_value_in_a_json_string_never_survives(
        value in "\\PC{4,24}|[\"\\\\/\n\t<>&a-z]{4,24}",
        chunks in chunking_strategy(),
    ) {
        let scrubber = scrubber_for(value.as_bytes());
        let document = serde_json::json!({ "output": value, "other": 1 }).to_string();
        let quoted = serde_json::to_string(&value).unwrap();
        let escaped = &quoted[1..quoted.len() - 1];
        let output = scrub_in_chunks(&scrubber, document.as_bytes(), &chunks);
        prop_assert!(!contains(&output, escaped.as_bytes()));
        prop_assert!(contains(&output, b"[secret:planted]"));
    }
}

#[test]
fn self_overlapping_values_are_scrubbed() {
    let scrubber = scrubber_for(b"aaaa");
    for chunks in [vec![1], vec![2], vec![3], vec![usize::MAX]] {
        let output = scrub_in_chunks(&scrubber, b"aaaaaaaaab", &chunks);
        assert!(!contains(&output, b"aaaa"), "{chunks:?}");
    }
}

#[test]
fn several_secrets_are_scrubbed_together() {
    let mut scrubber = Scrubber::new();
    scrubber.add_secret(&SecretName::parse("first").unwrap(), b"alpha-secret");
    scrubber.add_secret(&SecretName::parse("second").unwrap(), b"beta-secret");
    let output = scrubber.scrub(b"x alpha-secret y beta-secret z");
    assert_eq!(output, b"x [secret:first] y [secret:second] z");
}
