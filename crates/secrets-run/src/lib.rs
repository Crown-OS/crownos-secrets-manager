//! Runs a registered command template in bubblewrap.
//!
//! The sandbox has its own pid, ipc and uts namespaces, a read-only `/usr` and `/etc`, a private
//! `/tmp`, and no network unless the template names hosts. bwrap reads its options, the secret
//! values among them, from a pipe on its standard input (`--args 0`), so no value shows in
//! `/proc/<pid>/cmdline`. A pipe, not an inherited file, keeps the values of one run away from
//! the commands of another run that starts at the same time. The command reads `/dev/null` as its
//! standard input. stdout and stderr go through the scrubber as they stream, with a time
//! limit and an output limit.

mod arguments;
mod error;
mod output;

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretSlice;
use secrets_core::{RunTemplate, Scrubber};
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

pub use error::SandboxError;

/// The installed bubblewrap.
pub const BWRAP: &str = "/usr/bin/bwrap";

pub struct SandboxRequest<'request> {
    pub bwrap: &'request Path,
    pub template: &'request RunTemplate,
    pub arguments: &'request [String],
    /// A checked, canonical directory, or `None` for an empty temporary one.
    pub cwd: Option<&'request Path>,
    /// Variable name and value, from the vault.
    pub environment: Vec<(String, SecretSlice<u8>)>,
    pub scrubber: Arc<Scrubber>,
}

impl std::fmt::Debug for SandboxRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxRequest")
            .field("command", &self.template.command)
            .field("cwd", &self.cwd)
            .finish_non_exhaustive()
    }
}

/// What the command printed, scrubbed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxOutput {
    /// `None` when a signal ended the command.
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
    pub timed_out: bool,
}

/// # Errors
///
/// [`SandboxError::SandboxMissing`] without bwrap, and an error for a bad variable name, a value
/// or argument with a NUL byte, or a failed start.
pub async fn run_in_sandbox(request: SandboxRequest<'_>) -> Result<SandboxOutput, SandboxError> {
    if !request.bwrap.is_file() {
        return Err(SandboxError::SandboxMissing);
    }
    let options = arguments::bwrap_options(request.template, request.cwd, &request.environment)?;
    let command_line = arguments::command_line(request.template, request.arguments)?;
    let mut child = Command::new(request.bwrap)
        .args(["--args", "0"])
        .args(command_line)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    if let Some(mut options_pipe) = child.stdin.take() {
        options_pipe.write_all(&options).await?;
    }
    drop(options);
    let limit = Duration::from_secs(u64::from(request.template.timeout_seconds));
    let max_output = usize::try_from(request.template.max_output_bytes).unwrap_or(usize::MAX);
    output::collect(&mut child, &request.scrubber, limit, max_output).await
}
