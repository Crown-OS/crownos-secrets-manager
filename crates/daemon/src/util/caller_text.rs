/// Caller text without control characters and at most `max_characters` long, so it cannot
/// forge audit lines or flood them.
pub(crate) fn sanitized(text: &str, max_characters: usize) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .take(max_characters)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::sanitized;

    #[test]
    fn control_characters_go_and_the_length_is_capped() {
        assert_eq!(sanitized("a\nb\u{1b}[31mc\u{7f}", 100), "ab[31mc");
        assert_eq!(sanitized("abcdef", 3), "abc");
    }
}
