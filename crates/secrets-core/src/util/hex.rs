use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HexCase {
    Lower,
    Upper,
}

impl HexCase {
    const fn digits(self) -> &'static [u8; 16] {
        match self {
            Self::Lower => b"0123456789abcdef",
            Self::Upper => b"0123456789ABCDEF",
        }
    }

    pub(crate) fn digit_pair(self, byte: u8) -> [u8; 2] {
        let digits = self.digits();
        let digit = |nibble: u8| digits.get(usize::from(nibble)).copied().unwrap_or(b'0');
        [digit(byte >> 4), digit(byte & 0x0f)]
    }
}

pub(crate) fn hex_encode(bytes: &[u8], case: HexCase) -> Zeroizing<Vec<u8>> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(bytes.len() * 2));
    for &byte in bytes {
        encoded.extend_from_slice(&case.digit_pair(byte));
    }
    encoded
}
