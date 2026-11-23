//! Removes secret values from text before a model can read it.
//!
//! The scrubber replaces the value and its common encodings with `[secret:<name>]`: base64
//! (standard and URL-safe, at the 3 byte alignments), hex in both cases, percent encoding and JSON
//! string escapes. It is a second line of defence: the first is that no CrownOS tool returns a
//! value.

mod patterns;
mod stream;

use zeroize::Zeroizing;

use crate::SecretName;

pub use stream::ScrubStream;

struct Pattern {
    bytes: Zeroizing<Vec<u8>>,
    line_breaks_allowed: bool,
    label_index: usize,
}

impl Pattern {
    /// The most input bytes a match can take: one CRLF between each two pattern bytes.
    fn longest_match(&self) -> usize {
        if self.line_breaks_allowed {
            self.bytes.len() * 3 - 2
        } else {
            self.bytes.len()
        }
    }

    /// How many bytes of `haystack` a match at its start takes.
    fn matched_length(&self, haystack: &[u8]) -> Option<usize> {
        if !self.line_breaks_allowed {
            return haystack
                .starts_with(&self.bytes)
                .then_some(self.bytes.len());
        }
        let mut position = 0;
        for (index, &expected) in self.bytes.iter().enumerate() {
            if index > 0 {
                position += line_break_length(haystack.get(position..)?);
            }
            if *haystack.get(position)? != expected {
                return None;
            }
            position += 1;
        }
        Some(position)
    }
}

fn line_break_length(rest: &[u8]) -> usize {
    if rest.starts_with(b"\r\n") {
        2
    } else {
        usize::from(rest.starts_with(b"\n"))
    }
}

pub struct Scrubber {
    /// Longest first, so the first match at a position is the longest one.
    patterns: Vec<Pattern>,
    labels: Vec<String>,
    first_bytes: [bool; 256],
    /// The most input bytes one match can take.
    longest_match: usize,
}

impl std::fmt::Debug for Scrubber {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Scrubber")
            .field("secrets", &self.labels.len())
            .field("patterns", &self.patterns.len())
            .finish()
    }
}

impl Default for Scrubber {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            labels: Vec::new(),
            first_bytes: [false; 256],
            longest_match: 0,
        }
    }
}

impl Scrubber {
    pub fn new() -> Self {
        Self::default()
    }

    /// Scrub `value` and its encodings from now on. An empty value is ignored.
    pub fn add_secret(&mut self, name: &SecretName, value: &[u8]) {
        if value.is_empty() {
            return;
        }
        let label_index = self.labels.len();
        self.labels.push(format!("[secret:{name}]"));
        for form in patterns::revealing_forms(value) {
            if self
                .patterns
                .iter()
                .any(|pattern| pattern.bytes == form.bytes)
            {
                continue;
            }
            if let Some(&first) = form.bytes.first()
                && let Some(seen) = self.first_bytes.get_mut(usize::from(first))
            {
                *seen = true;
            }
            let pattern = Pattern {
                bytes: form.bytes,
                line_breaks_allowed: form.line_breaks_allowed,
                label_index,
            };
            self.longest_match = self.longest_match.max(pattern.longest_match());
            self.patterns.push(pattern);
        }
        self.patterns
            .sort_by_key(|pattern| std::cmp::Reverse(pattern.bytes.len()));
    }

    pub fn stream(&self) -> ScrubStream<'_> {
        ScrubStream::new(self)
    }

    pub fn scrub(&self, input: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(input.len());
        let mut stream = self.stream();
        stream.push(input, &mut output);
        stream.finish(&mut output);
        output
    }

    fn label_matching_at(&self, haystack: &[u8], position: usize) -> Option<(&[u8], usize)> {
        let rest = haystack.get(position..)?;
        let first = *rest.first()?;
        if !self.may_start_match(first) {
            return None;
        }
        let (pattern, matched_length) = self
            .patterns
            .iter()
            .find_map(|pattern| Some((pattern, pattern.matched_length(rest)?)))?;
        let label = self.labels.get(pattern.label_index)?;
        Some((label.as_bytes(), matched_length))
    }

    fn may_start_match(&self, byte: u8) -> bool {
        self.first_bytes
            .get(usize::from(byte))
            .copied()
            .unwrap_or(false)
    }

    /// Writes the scrubbed form of `buffer[..emit_limit]` to `output` and returns how many bytes
    /// of `buffer` it consumed. A match that starts before `emit_limit` is consumed whole.
    fn scrub_prefix(&self, buffer: &[u8], emit_limit: usize, output: &mut Vec<u8>) -> usize {
        let mut position = 0;
        while position < emit_limit {
            if let Some((label, matched_length)) = self.label_matching_at(buffer, position) {
                output.extend_from_slice(label);
                position += matched_length;
                continue;
            }
            let plain_run = buffer
                .get(position + 1..emit_limit)
                .unwrap_or_default()
                .iter()
                .position(|&byte| self.may_start_match(byte))
                .map_or(emit_limit, |offset| position + 1 + offset);
            output.extend_from_slice(buffer.get(position..plain_run).unwrap_or_default());
            position = plain_run;
        }
        position
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn scrubber_for(value: &[u8]) -> Scrubber {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(&SecretName::parse("token").unwrap(), value);
        scrubber
    }

    #[test]
    fn replaces_the_value_and_its_encodings() {
        let scrubber = scrubber_for(b"hunter2/key");
        let input = b"a hunter2/key b 68756e746572322f6b6579 c hunter2%2Fkey d hunter2\\/key";
        let output = String::from_utf8(scrubber.scrub(input)).unwrap();
        assert_eq!(
            output,
            "a [secret:token] b [secret:token] c [secret:token] d [secret:token]"
        );
    }

    #[test]
    fn text_without_secrets_passes_unchanged() {
        let scrubber = scrubber_for(b"hunter2");
        assert_eq!(
            scrubber.scrub(b"hunt hunter hunter3"),
            b"hunt hunter hunter3"
        );
        assert_eq!(Scrubber::new().scrub(b"anything"), b"anything");
    }

    #[test]
    fn debug_output_shows_no_pattern() {
        let scrubber = scrubber_for(b"hunter2");
        assert!(!format!("{scrubber:?}").contains("hunter2"));
    }
}
