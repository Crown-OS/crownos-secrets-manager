use zeroize::Zeroizing;

use crate::util::hex::HexCase;

/// The escape choices that common JSON encoders make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct JsonEscapeStyle {
    /// `/` becomes `\/` (PHP, some Java encoders).
    pub(crate) escape_slash: bool,
    /// Every non-ASCII character becomes `\uXXXX` (Python `json.dumps`).
    pub(crate) ascii_only: bool,
    /// `<`, `>`, `&`, U+2028 and U+2029 become `\uXXXX` (Go `encoding/json`).
    pub(crate) html_safe: bool,
}

impl JsonEscapeStyle {
    pub(crate) const ALL: [Self; 4] = [
        Self {
            escape_slash: false,
            ascii_only: false,
            html_safe: false,
        },
        Self {
            escape_slash: true,
            ascii_only: false,
            html_safe: false,
        },
        Self {
            escape_slash: false,
            ascii_only: true,
            html_safe: false,
        },
        Self {
            escape_slash: false,
            ascii_only: false,
            html_safe: true,
        },
    ];

    fn needs_unicode_escape(self, character: char) -> bool {
        u32::from(character) < 0x20
            || (self.ascii_only && !character.is_ascii())
            || (self.html_safe && matches!(character, '<' | '>' | '&' | '\u{2028}' | '\u{2029}'))
    }
}

fn push_unicode_escape(encoded: &mut Vec<u8>, unit: u16) {
    let [high, low] = unit.to_be_bytes();
    encoded.extend_from_slice(b"\\u");
    encoded.extend_from_slice(&HexCase::Lower.digit_pair(high));
    encoded.extend_from_slice(&HexCase::Lower.digit_pair(low));
}

/// The text between the quotes of a JSON string that holds `text`.
pub(crate) fn json_escape(text: &str, style: JsonEscapeStyle) -> Zeroizing<Vec<u8>> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(text.len() * 6));
    let mut utf16_units = [0u16; 2];
    for character in text.chars() {
        match character {
            '"' => encoded.extend_from_slice(b"\\\""),
            '\\' => encoded.extend_from_slice(b"\\\\"),
            '\n' => encoded.extend_from_slice(b"\\n"),
            '\r' => encoded.extend_from_slice(b"\\r"),
            '\t' => encoded.extend_from_slice(b"\\t"),
            '\u{8}' => encoded.extend_from_slice(b"\\b"),
            '\u{c}' => encoded.extend_from_slice(b"\\f"),
            '/' if style.escape_slash => encoded.extend_from_slice(b"\\/"),
            _ if style.needs_unicode_escape(character) => {
                for &unit in character.encode_utf16(&mut utf16_units).iter() {
                    push_unicode_escape(&mut encoded, unit);
                }
            }
            _ => {
                let mut utf8 = [0u8; 4];
                encoded.extend_from_slice(character.encode_utf8(&mut utf8).as_bytes());
            }
        }
    }
    encoded
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_default_style_is_what_serde_json_writes() {
        let text = "a\"b\\c\n\u{1}é/<";
        let expected = serde_json::to_string(text).unwrap();
        let escaped = json_escape(text, JsonEscapeStyle::default());
        assert_eq!(
            format!("\"{}\"", String::from_utf8(escaped.to_vec()).unwrap()),
            expected
        );
    }

    #[test]
    fn ascii_only_uses_surrogate_pairs() {
        let style = JsonEscapeStyle {
            ascii_only: true,
            ..JsonEscapeStyle::default()
        };
        assert_eq!(
            json_escape("é😀", style).as_slice(),
            b"\\u00e9\\ud83d\\ude00"
        );
    }
}
