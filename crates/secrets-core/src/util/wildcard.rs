/// Matches `text` against `pattern`, where `*` stands for any run of characters, including none.
pub fn wildcard_matches(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let Some(first) = parts.next() else {
        return text.is_empty();
    };
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let middle_and_last: Vec<&str> = parts.collect();
    let Some((last, middle)) = middle_and_last.split_last() else {
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(found) => rest = rest.get(found + part.len()..).unwrap_or_default(),
            None => return false,
        }
    }
    rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::wildcard_matches;

    #[test]
    fn matches_like_a_shell_glob_with_only_star() {
        assert!(wildcard_matches("abc", "abc"));
        assert!(!wildcard_matches("abc", "abcd"));
        assert!(wildcard_matches("*", ""));
        assert!(wildcard_matches("a*", "abc"));
        assert!(wildcard_matches("*c", "abc"));
        assert!(wildcard_matches("a*c", "ac"));
        assert!(wildcard_matches("a*b*c", "a-b-b-c"));
        assert!(!wildcard_matches("a*b*c", "a-c-b"));
        assert!(!wildcard_matches("ab*ba", "aba"));
        assert!(wildcard_matches(
            "https://*.github.com",
            "https://api.github.com"
        ));
        assert!(!wildcard_matches(
            "https://*.github.com",
            "https://github.com"
        ));
    }
}
