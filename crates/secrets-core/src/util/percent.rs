use zeroize::Zeroizing;

use crate::util::hex::HexCase;

/// The bytes that an encoder leaves as they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeptBytes {
    /// RFC 3986 unreserved: `A-Z a-z 0-9 - . _ ~`.
    Unreserved,
    /// JavaScript `encodeURIComponent`: unreserved and `! * ' ( )`.
    UriComponent,
    /// Python `urllib.parse.quote` with its default `safe="/"`.
    UnreservedAndSlash,
    /// The WHATWG form encoder: `A-Z a-z 0-9 * - . _`.
    WhatwgForm,
}

impl KeptBytes {
    pub(crate) const ALL: [Self; 4] = [
        Self::Unreserved,
        Self::UriComponent,
        Self::UnreservedAndSlash,
        Self::WhatwgForm,
    ];

    const fn keeps(self, byte: u8) -> bool {
        let alphanumeric = byte.is_ascii_alphanumeric();
        match self {
            Self::Unreserved => alphanumeric || matches!(byte, b'-' | b'.' | b'_' | b'~'),
            Self::UriComponent => {
                alphanumeric
                    || matches!(
                        byte,
                        b'-' | b'.' | b'_' | b'~' | b'!' | b'*' | b'\'' | b'(' | b')'
                    )
            }
            Self::UnreservedAndSlash => {
                alphanumeric || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/')
            }
            Self::WhatwgForm => alphanumeric || matches!(byte, b'*' | b'-' | b'.' | b'_'),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PercentStyle {
    pub(crate) kept: KeptBytes,
    pub(crate) case: HexCase,
    /// A space becomes `+`, as in `application/x-www-form-urlencoded`.
    pub(crate) space_as_plus: bool,
}

impl PercentStyle {
    /// Every combination; some give the same bytes for a given value.
    pub(crate) fn all() -> impl Iterator<Item = Self> {
        KeptBytes::ALL.into_iter().flat_map(|kept| {
            [HexCase::Lower, HexCase::Upper]
                .into_iter()
                .flat_map(move |case| {
                    [false, true].map(move |space_as_plus| Self {
                        kept,
                        case,
                        space_as_plus,
                    })
                })
        })
    }
}

pub(crate) fn percent_encode(bytes: &[u8], style: PercentStyle) -> Zeroizing<Vec<u8>> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(bytes.len() * 3));
    for &byte in bytes {
        if style.kept.keeps(byte) {
            encoded.push(byte);
        } else if byte == b' ' && style.space_as_plus {
            encoded.push(b'+');
        } else {
            encoded.push(b'%');
            encoded.extend_from_slice(&style.case.digit_pair(byte));
        }
    }
    encoded
}
