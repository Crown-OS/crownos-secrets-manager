use std::sync::Arc;
use std::time::Duration;

use secrets_core::{ScrubStream, Scrubber};
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::process::Child;
use zeroize::Zeroizing;

use crate::{SandboxError, SandboxOutput};

const READ_BUFFER_BYTES: usize = 8192;

/// One output pipe and its scrubbed text.
struct ScrubbedPipe<Pipe> {
    pipe: Option<Pipe>,
    stream: ScrubStream<Arc<Scrubber>>,
    scrubbed: Vec<u8>,
    buffer: Zeroizing<Vec<u8>>,
}

impl<Pipe: AsyncRead + Unpin> ScrubbedPipe<Pipe> {
    fn new(pipe: Option<Pipe>, scrubber: &Arc<Scrubber>) -> Self {
        Self {
            pipe,
            stream: ScrubStream::new(Arc::clone(scrubber)),
            scrubbed: Vec::new(),
            buffer: Zeroizing::new(vec![0; READ_BUFFER_BYTES]),
        }
    }

    /// Reads one chunk; returns how many raw bytes came, or `None` at the end.
    async fn read_chunk(&mut self) -> Option<usize> {
        let pipe = self.pipe.as_mut()?;
        match pipe.read(&mut self.buffer).await {
            Ok(0) | Err(_) => {
                self.pipe = None;
                None
            }
            Ok(read) => {
                let chunk = self.buffer.get(..read).unwrap_or_default();
                self.stream.push(chunk, &mut self.scrubbed);
                Some(read)
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        let mut scrubbed = self.scrubbed;
        self.stream.finish(&mut scrubbed);
        scrubbed
    }
}

pub(crate) async fn collect(
    child: &mut Child,
    scrubber: &Arc<Scrubber>,
    limit: Duration,
    max_output: usize,
) -> Result<SandboxOutput, SandboxError> {
    let mut stdout = ScrubbedPipe::new(child.stdout.take(), scrubber);
    let mut stderr = ScrubbedPipe::new(child.stderr.take(), scrubber);
    let mut truncated = false;
    let running = async {
        let mut total = 0usize;
        while stdout.pipe.is_some() || stderr.pipe.is_some() {
            let read = tokio::select! {
                read = stdout.read_chunk(), if stdout.pipe.is_some() => read,
                read = stderr.read_chunk(), if stderr.pipe.is_some() => read,
            };
            total += read.unwrap_or(0);
            if total > max_output {
                truncated = true;
                return None;
            }
        }
        child.wait().await.ok()
    };
    let finished = tokio::time::timeout(limit, running).await;
    let timed_out = finished.is_err();
    let status = finished.ok().flatten();
    if status.is_none() {
        child.kill().await?;
    }
    Ok(SandboxOutput {
        exit_code: status.and_then(|status| status.code()),
        stdout: stdout.finish(),
        stderr: stderr.finish(),
        truncated,
        timed_out,
    })
}
