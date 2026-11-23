/// `bytes` as text of at most `max_bytes`, cut at a character boundary. The flag says whether
/// it was cut.
pub(crate) fn capped_text(bytes: &[u8], max_bytes: usize) -> (String, bool) {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    if text.len() <= max_bytes {
        return (text, false);
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    (text, true)
}

#[cfg(test)]
mod tests {
    use super::capped_text;

    #[test]
    fn cuts_at_a_character_boundary() {
        assert_eq!(capped_text("abc".as_bytes(), 10), ("abc".to_owned(), false));
        assert_eq!(capped_text("aé".as_bytes(), 2), ("a".to_owned(), true));
    }
}
