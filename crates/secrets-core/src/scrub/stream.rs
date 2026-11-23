use std::ops::Deref;

use zeroize::Zeroizing;

use crate::Scrubber;

/// Scrubs a stream that arrives in chunks. It holds back the last `longest match - 1` bytes of
/// each chunk, because a value can start in one chunk and end in the next. `Source` is a
/// `&Scrubber` or a shared owner such as `Arc<Scrubber>`.
pub struct ScrubStream<Source> {
    scrubber: Source,
    held_back: Zeroizing<Vec<u8>>,
}

impl<Source> std::fmt::Debug for ScrubStream<Source> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScrubStream")
            .field("held_back_bytes", &self.held_back.len())
            .finish_non_exhaustive()
    }
}

impl<Source: Deref<Target = Scrubber>> ScrubStream<Source> {
    pub fn new(scrubber: Source) -> Self {
        Self {
            scrubber,
            held_back: Zeroizing::new(Vec::new()),
        }
    }

    /// Appends the scrubbed part of `chunk` that is safe to show to `output`.
    pub fn push(&mut self, chunk: &[u8], output: &mut Vec<u8>) {
        let buffer = self.joined_with(chunk);
        let window = self.scrubber.longest_match.saturating_sub(1);
        let emit_limit = buffer.len().saturating_sub(window);
        let consumed = self.scrubber.scrub_prefix(&buffer, emit_limit, output);
        self.held_back = Zeroizing::new(buffer.get(consumed..).unwrap_or_default().to_vec());
    }

    /// Appends the scrubbed rest of the stream to `output`.
    pub fn finish(self, output: &mut Vec<u8>) {
        self.scrubber
            .scrub_prefix(&self.held_back, self.held_back.len(), output);
    }

    /// A new buffer of exactly the right size, so no reallocation leaves a copy behind.
    fn joined_with(&self, chunk: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut buffer = Zeroizing::new(Vec::with_capacity(self.held_back.len() + chunk.len()));
        buffer.extend_from_slice(&self.held_back);
        buffer.extend_from_slice(chunk);
        buffer
    }
}
