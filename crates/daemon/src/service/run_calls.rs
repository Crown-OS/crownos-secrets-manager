//! Registered command templates in a bubblewrap sandbox. The command gets the values; the caller
//! gets only the scrubbed output.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::{RunTemplate, Scrubber, TemplateName, UseOutcome};
use secrets_protocol::{RunOutput, RunReply};
use secrets_run::{SandboxError, SandboxRequest, run_in_sandbox};

use super::{SecretsService, ServiceError};
use crate::util::caller_text::sanitized;
use crate::{Caller, audit};

const MAX_CWD_CHARACTERS: usize = 200;

/// Variable name and value.
type SandboxEnvironment = Vec<(String, SecretSlice<u8>)>;

impl SecretsService {
    /// Runs a registered template. While it runs, this call blocks the daemon's request loop, up
    /// to the template's time limit.
    ///
    /// # Errors
    ///
    /// Fails when the sandbox cannot start for a reason other than a missing bwrap.
    pub fn run(
        &mut self,
        caller: &Caller,
        template_name: &TemplateName,
        arguments: &[String],
        cwd: &str,
        now: Instant,
    ) -> Result<RunReply, ServiceError> {
        let target = format!("run:{template_name}");
        self.lock_if_expired(now);
        let template = match self.vault.contents(now) {
            Ok(contents) => contents.rules().run_templates.get(template_name).cloned(),
            Err(_) => return Ok(RunReply::Refused(UseOutcome::Locked)),
        };
        let Some(template) = template else {
            audit::use_decided(caller, &[], &target, "unknown-template");
            return Ok(RunReply::Refused(UseOutcome::Unknown));
        };
        let names: Vec<_> = template.environment.values().cloned().collect();
        if let Some(outcome) = self.refusal_for_use(caller, &names, &target, now) {
            return Ok(RunReply::Refused(outcome));
        }
        if !arguments.is_empty() && !template.allow_arguments {
            audit::use_decided(caller, &names, &target, "arguments-not-allowed");
            return Ok(RunReply::ArgumentsNotAllowed);
        }
        let Some(cwd) = checked_cwd(&template, cwd) else {
            let shown = format!("{target} cwd:{}", sanitized(cwd, MAX_CWD_CHARACTERS));
            audit::use_decided(caller, &names, &shown, "cwd-not-allowed");
            return Ok(RunReply::CwdNotAllowed);
        };
        let (environment, scrubber) = self.sandbox_inputs(&template, now)?;
        audit::use_decided(caller, &names, &target, "started");
        let request = SandboxRequest {
            bwrap: &self.bwrap,
            template: &template,
            arguments,
            cwd: cwd.as_deref(),
            environment,
            scrubber,
        };
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::block_in_place(|| handle.block_on(run_in_sandbox(request)));
        match result {
            Ok(output) => {
                self.mark_used(&names);
                let outcome = format!(
                    "finished exit={:?} timed_out={}",
                    output.exit_code, output.timed_out
                );
                audit::use_decided(caller, &names, &target, &outcome);
                Ok(RunReply::Finished(RunOutput {
                    exit_code: output.exit_code,
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                    truncated: output.truncated,
                    timed_out: output.timed_out,
                }))
            }
            Err(SandboxError::SandboxMissing) => {
                audit::use_decided(caller, &names, &target, "sandbox-missing");
                Ok(RunReply::SandboxMissing)
            }
            Err(error) => {
                audit::use_decided(caller, &names, &target, "sandbox-failed");
                Err(ServiceError::Sandbox(error.to_string()))
            }
        }
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
}

/// `Some(None)` for a template without a working directory, `Some(Some(dir))` for an allowed
/// one, `None` for a refusal. The check uses the canonical path, so `..` and links cannot leave
/// the pattern.
#[allow(clippy::option_option, reason = "the outer level is the refusal")]
fn checked_cwd(template: &RunTemplate, cwd: &str) -> Option<Option<PathBuf>> {
    if template.cwd_glob.is_empty() {
        return cwd.is_empty().then_some(None);
    }
    let path = Path::new(cwd);
    if !path.is_absolute() {
        return None;
    }
    let canonical = path
        .canonicalize()
        .ok()
        .filter(|canonical| canonical.is_dir())?;
    let allowed = canonical
        .to_str()
        .is_some_and(|canonical| template.allows_cwd(canonical));
    allowed.then_some(Some(canonical))
}
