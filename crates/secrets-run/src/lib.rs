//! Runs a registered command template in bubblewrap, inside a transient service of the user
//! manager.
//!
//! `systemd-run --user --pipe --wait` starts the sandbox with its own memory limit and run time,
//! outside the daemon's cgroup, so the daemon keeps its strict system call filter. The sandbox
//! has its own pid, ipc, uts and cgroup namespaces, a read-only `/usr` and `/etc`, a private
//! `/tmp`, and no network unless the template names hosts. bwrap reads its options, the secret
//! values among them, from standard input (`--args 0`), which `--pipe` hands on; so no value is in
//! a command line, in the environment of `systemd-run`, or in the journal. The command reads
//! `/dev/null` as its standard input. stdout and stderr go through the scrubber as they stream,
//! with a time limit and an output limit.

mod arguments;
mod directory;
mod error;
mod launcher;
mod output;

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretSlice;
use secrets_core::{RunTemplate, Scrubber};
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

pub use directory::CheckedDirectory;
pub use error::SandboxError;
pub use launcher::{Launcher, TEST_USER_RUNTIME_VARIABLE};

pub struct SandboxRequest<'request> {
    pub launcher: &'request Launcher,
    pub template: &'request RunTemplate,
    pub arguments: &'request [String],
    /// `None` runs the command in an empty temporary directory.
    pub cwd: Option<&'request CheckedDirectory>,
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
    /// The exit code that `systemd-run` passes on; `None` when the run was stopped.
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
    pub timed_out: bool,
    /// The working directory changed after the check; the command did not run.
    pub cwd_changed: bool,
}

/// # Errors
///
/// [`SandboxError::SandboxMissing`] without bwrap or systemd-run, and an error for a bad
/// variable name, a value or argument with a NUL byte, or a failed start.
pub async fn run_in_sandbox(request: SandboxRequest<'_>) -> Result<SandboxOutput, SandboxError> {
    let launcher = request.launcher;
    if !launcher.bwrap.is_file() || !launcher.systemd_run.is_file() {
        return Err(SandboxError::SandboxMissing);
    }
    let marker = launcher::random_hex()?;
    let options = arguments::bwrap_options(
        request.template,
        request.cwd.map(CheckedDirectory::path),
        &marker,
        &request.environment,
    )?;
    let command_line = arguments::command_line(
        request.template,
        request.arguments,
        request.cwd.map(CheckedDirectory::identity),
    )?;
    let unit = launcher::unit_name()?;
    let mut child = Command::new(&launcher.systemd_run)
        .args(launcher::systemd_run_arguments(
            launcher,
            request.template,
            &unit,
        ))
        .args(command_line)
        .env_clear()
        .envs(launcher.user_manager_environment())
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
    let mut output = output::collect(&mut child, &request.scrubber, limit, max_output).await?;
    output.cwd_changed = request.cwd.is_some() && output::take_marker(&mut output.stderr, &marker);
    if output.exit_code.is_none() {
        launcher::stop(launcher, &unit).await;
    }
    Ok(output)
}
