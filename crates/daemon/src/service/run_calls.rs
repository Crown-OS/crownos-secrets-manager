//! Registered command templates in a sandbox. The checks run at once on the request loop; the
//! command runs in a task, and its reply follows when it ends. The command gets the values; the
//! caller gets only the scrubbed output.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::{ArgumentRefusal, RunTemplate, Scrubber, SecretName, TemplateName, UseOutcome};
use secrets_protocol::{RunOutput, RunReply};
use secrets_run::{
    CheckedDirectory, DIRECTORY_CHANGED_EXIT_CODE, Launcher, SandboxError, SandboxRequest,
    run_in_sandbox,
};
use tokio::sync::OwnedSemaphorePermit;

use super::{SecretsService, ServiceError};
use crate::util::caller_text::sanitized;
use crate::util::reply_text::capped_text;
use crate::{Caller, audit};

const MAX_CWD_CHARACTERS: usize = 200;
/// Scrubbed output can be larger than the raw output, because a label can be longer than the
/// value it replaces. These caps keep the reply well under the 1 MiB IPC frame.
const MAX_REPLY_STDOUT_BYTES: usize = 640 * 1024;
const MAX_REPLY_STDERR_BYTES: usize = 128 * 1024;

/// Variable name and value.
type SandboxEnvironment = Vec<(String, SecretSlice<u8>)>;

/// What the checks decided about a working directory.
enum CwdCheck {
    /// The template runs in an empty temporary directory.
    NoDirectory,
    Directory(CheckedDirectory),
    Refused,
}

/// The result of the checks of a run.
#[derive(Debug)]
pub enum RunStart {
    /// The reply, at once.
    Refused(RunReply),
    /// Everything the run needs; [`RunJob::execute`] gives the reply.
    Ready(Box<RunJob>),
}

/// A checked run with copies of its values. It holds one of the run slots until it ends.
pub struct RunJob {
    launcher: Launcher,
    template: RunTemplate,
    arguments: Vec<String>,
    cwd: Option<CheckedDirectory>,
    environment: SandboxEnvironment,
    scrubber: Arc<Scrubber>,
    caller: Caller,
    names: Vec<SecretName>,
    target: String,
    _slot: OwnedSemaphorePermit,
}

impl std::fmt::Debug for RunJob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunJob")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl SecretsService {
    /// Checks a run: the template, the binding of each of its secrets, the arguments, the
    /// working directory and a free run slot.
    ///
    /// # Errors
    ///
    /// Fails when a value of the template is missing from the vault.
    pub fn prepare_run(
        &mut self,
        caller: &Caller,
        template_name: &TemplateName,
        arguments: &[String],
        cwd: &str,
        now: Instant,
    ) -> Result<RunStart, ServiceError> {
        let target = format!("run:{template_name}");
        self.lock_if_expired(now);
        let template = match self.vault.contents(now) {
            Ok(contents) => contents.rules().run_templates.get(template_name).cloned(),
            Err(_) => return Ok(RunStart::Refused(RunReply::Refused(UseOutcome::Locked))),
        };
        let Some(template) = template else {
            audit::use_decided(caller, &[], &target, "unknown-template");
            return Ok(RunStart::Refused(RunReply::Refused(UseOutcome::Unknown)));
        };
        let names: Vec<_> = template.environment.values().cloned().collect();
        if let Some(outcome) = self.refusal_for_use(caller, &names, &target, now) {
            return Ok(RunStart::Refused(RunReply::Refused(outcome)));
        }
        if let Err(refusal) = template.check_arguments(arguments) {
            let outcome = match refusal {
                ArgumentRefusal::TooMany => "arguments-too-many",
                ArgumentRefusal::StartsWithDash => "argument-starts-with-dash",
                ArgumentRefusal::NoMatch => "argument-does-not-match",
            };
            audit::use_decided(caller, &names, &target, outcome);
            return Ok(RunStart::Refused(RunReply::ArgumentsNotAllowed));
        }
        let cwd = match self.checked_cwd(&template, cwd) {
            CwdCheck::NoDirectory => None,
            CwdCheck::Directory(directory) => Some(directory),
            CwdCheck::Refused => {
                let shown = format!("{target} cwd:{}", sanitized(cwd, MAX_CWD_CHARACTERS));
                audit::use_decided(caller, &names, &shown, "cwd-not-allowed");
                return Ok(RunStart::Refused(RunReply::CwdNotAllowed));
            }
        };
        let Ok(slot) = Arc::clone(&self.run_slots).try_acquire_owned() else {
            audit::use_decided(caller, &names, &target, "too-many-runs");
            return Ok(RunStart::Refused(RunReply::TooManyRuns));
        };
        let (environment, scrubber) = self.sandbox_inputs(&template, now)?;
        self.mark_used(&names);
        audit::use_decided(caller, &names, &target, "started");
        Ok(RunStart::Ready(Box::new(RunJob {
            launcher: self.launcher.clone(),
            template,
            arguments: arguments.to_vec(),
            cwd,
            environment,
            scrubber,
            caller: caller.clone(),
            names,
            target,
            _slot: slot,
        })))
    }

    /// The template's variables with their values, and a scrubber for every value in the vault:
    /// a command can print a stored secret that it did not get, for example from a config file.
    fn sandbox_inputs(
        &mut self,
        template: &RunTemplate,
        now: Instant,
    ) -> Result<(SandboxEnvironment, Arc<Scrubber>), ServiceError> {
        let contents = self.vault.contents(now)?;
        let mut environment = Vec::with_capacity(template.environment.len());
        for (variable, name) in &template.environment {
            let value = contents
                .value(name)
                .ok_or_else(|| ServiceError::UnknownSecret(name.clone()))?;
            environment.push((
                variable.clone(),
                SecretSlice::from(value.expose_secret().to_vec()),
            ));
        }
        let mut scrubber = Scrubber::new();
        for name in contents.rules().secrets.keys() {
            if let Some(value) = contents.value(name) {
                scrubber.add_secret(name, value.expose_secret());
            }
        }
        Ok((environment, Arc::new(scrubber)))
    }

    /// The canonical directory must match the template's pattern and must not be inside the
    /// daemon's data or runtime directory. So `..` and links cannot leave the pattern, and a
    /// command cannot reach the vault or the sockets.
    fn checked_cwd(&self, template: &RunTemplate, cwd: &str) -> CwdCheck {
        if template.cwd_glob.is_empty() {
            return if cwd.is_empty() {
                CwdCheck::NoDirectory
            } else {
                CwdCheck::Refused
            };
        }
        let path = Path::new(cwd);
        if !path.is_absolute() {
            return CwdCheck::Refused;
        }
        let Ok(directory) = CheckedDirectory::check(path) else {
            return CwdCheck::Refused;
        };
        let inside_protected = self
            .protected_directories
            .iter()
            .any(|protected| directory.path().starts_with(protected));
        let allowed = directory
            .path()
            .to_str()
            .is_some_and(|canonical| template.allows_cwd(canonical));
        if allowed && !inside_protected {
            CwdCheck::Directory(directory)
        } else {
            CwdCheck::Refused
        }
    }
}

/// Canonical forms of the directories that no run may use as its working directory.
pub(crate) fn protected_directories(data_directory: &Path) -> Vec<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let user_runtime = PathBuf::from(format!("/run/user/{}", rustix::process::getuid().as_raw()));
    [Some(data_directory.to_owned()), runtime, Some(user_runtime)]
        .into_iter()
        .flatten()
        .map(|directory| directory.canonicalize().unwrap_or(directory))
        .collect()
}

impl RunJob {
    /// Runs the command and gives the scrubbed reply.
    ///
    /// # Errors
    ///
    /// Fails when the sandbox cannot start for a reason other than a missing bwrap.
    pub async fn execute(self) -> Result<RunReply, ServiceError> {
        let request = SandboxRequest {
            launcher: &self.launcher,
            template: &self.template,
            arguments: &self.arguments,
            cwd: self.cwd.as_ref(),
            environment: self.environment,
            scrubber: self.scrubber,
        };
        match run_in_sandbox(request).await {
            Ok(output)
                if output.exit_code == Some(DIRECTORY_CHANGED_EXIT_CODE) && self.cwd.is_some() =>
            {
                audit::use_decided(&self.caller, &self.names, &self.target, "cwd-changed");
                Ok(RunReply::CwdChanged)
            }
            Ok(output) => {
                let outcome = format!(
                    "finished exit={:?} timed_out={} truncated={}",
                    output.exit_code, output.timed_out, output.truncated
                );
                audit::use_decided(&self.caller, &self.names, &self.target, &outcome);
                let (stdout, stdout_cut) = capped_text(&output.stdout, MAX_REPLY_STDOUT_BYTES);
                let (stderr, stderr_cut) = capped_text(&output.stderr, MAX_REPLY_STDERR_BYTES);
                Ok(RunReply::Finished(RunOutput {
                    exit_code: output.exit_code,
                    stdout,
                    stderr,
                    truncated: output.truncated || stdout_cut || stderr_cut,
                    timed_out: output.timed_out,
                }))
            }
            Err(SandboxError::SandboxMissing) => {
                audit::use_decided(&self.caller, &self.names, &self.target, "sandbox-missing");
                Ok(RunReply::SandboxMissing)
            }
            Err(error) => {
                audit::use_decided(&self.caller, &self.names, &self.target, "sandbox-failed");
                Err(ServiceError::Sandbox(error.to_string()))
            }
        }
    }
}
