use zeroize::Zeroizing;

use crate::util::hex::HexCase;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PercentStyle {
    /// RFC 3986: every byte except `A-Z a-z 0-9 - . _ ~` becomes `%XX`.
    Uri(HexCase),
    /// `application/x-www-form-urlencoded`: a space becomes `+`, other reserved bytes `%XX`.
    Form,
}

const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

pub(crate) fn percent_encode(bytes: &[u8], style: PercentStyle) -> Zeroizing<Vec<u8>> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(bytes.len() * 3));
    let case = match style {
        PercentStyle::Uri(case) => case,
        PercentStyle::Form => HexCase::Upper,
    };
    for &byte in bytes {
        if is_unreserved(byte) {
            encoded.push(byte);
        } else if byte == b' ' && style == PercentStyle::Form {
            encoded.push(b'+');
        } else {
            encoded.push(b'%');
            encoded.extend_from_slice(&case.digit_pair(byte));
        }
    }
    encoded
}
