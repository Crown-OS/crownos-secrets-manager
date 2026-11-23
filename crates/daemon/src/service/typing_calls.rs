//! Typing a secret into a window through the compositor. The checks run at once; the typing
//! waits in a task for the compositor's answer.

use std::time::Instant;

use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::{Confirm, SecretName, Target, UseOutcome};
use secrets_protocol::TypingTarget;
use tokio::sync::oneshot;

use super::{SecretsService, ServiceError};
use crate::typing::{TypingResult, TypingStep};
use crate::{Caller, audit};

/// How the secrets are typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypingShape {
    /// One secret into the focused field.
    Single,
    /// A user name, Tab, then a password into a password field.
    Login,
}

#[derive(Debug)]
pub enum TypingStart {
    Refused(UseOutcome),
    /// Waits for the compositor; gives the outcome of the last step.
    Waiting(oneshot::Receiver<TypingResult>),
}

impl SecretsService {
    /// Whether the target's app id and origin match the binding of each secret, before any
    /// dialog runs. `Some` is the refusal.
    pub(crate) fn typing_target_refusal(
        &mut self,
        names: &[SecretName],
        target: &TypingTarget,
        now: Instant,
    ) -> Option<UseOutcome> {
        let contents = self.vault.contents(now).ok()?;
        for name in names {
            let binding = &contents.rules().secrets.get(name)?.binding;
            if binding.allows_target(&target.app_id, target.origin.as_deref()) {
                continue;
            }
            let origin_bound = binding
                .targets
                .iter()
                .any(|bound| matches!(bound, Target::Origin(_)));
            return Some(if origin_bound && target.origin.is_some() {
                UseOutcome::OriginMismatch
            } else {
                UseOutcome::Denied
            });
        }
        None
    }

    /// Checks a typing request and hands it to the compositor.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Unavailable`] when the compositor offers no secret input.
    pub fn start_typing(
        &mut self,
        caller: &Caller,
        names: &[SecretName],
        target: &TypingTarget,
        shape: TypingShape,
        target_text: &str,
        now: Instant,
    ) -> Result<TypingStart, ServiceError> {
        if let Some(outcome) = self.refusal_for_use(caller, names, target_text, now) {
            return Ok(TypingStart::Refused(outcome));
        }
        if let Some(outcome) = self.typing_target_refusal(names, target, now) {
            audit::use_decided(caller, names, target_text, "target-not-bound");
            return Ok(TypingStart::Refused(outcome));
        }
        if !self.typing.is_available() {
            audit::use_decided(caller, names, target_text, "unavailable");
            return Err(ServiceError::Unavailable);
        }
        let contents = self.vault.contents(now)?;
        let rules = contents.rules();
        let mut steps = Vec::with_capacity(names.len());
        for (index, name) in names.iter().enumerate() {
            let entry = rules
                .secrets
                .get(name)
                .ok_or_else(|| ServiceError::UnknownSecret(name.clone()))?;
            let value = contents
                .value(name)
                .ok_or_else(|| ServiceError::UnknownSecret(name.clone()))?;
            let is_login_user = shape == TypingShape::Login && index == 0;
            let is_login_password = shape == TypingShape::Login && index == 1;
            steps.push(TypingStep {
                value: SecretSlice::from(value.expose_secret().to_vec()),
                window: target.window.clone(),
                require_password_field: is_login_password
                    || (!is_login_user && entry.binding.require_password_field),
                tab_after: is_login_user,
                confirmed: entry.binding.confirm_or(rules.settings.default_confirm)
                    != Confirm::Never,
                agent: caller.to_string(),
                secret_name: name.to_string(),
                origin: target.origin.clone().unwrap_or_default(),
            });
        }
        let waiting = self.typing.submit(steps).ok_or(ServiceError::Unavailable)?;
        self.mark_used(names);
        audit::use_decided(caller, names, target_text, "typing");
        Ok(TypingStart::Waiting(waiting))
    }
}

/// The reply for what the compositor answered.
pub const fn typing_outcome(result: TypingResult) -> UseOutcome {
    match result {
        TypingResult::Typed => UseOutcome::Done,
        TypingResult::FocusChanged => UseOutcome::FocusChanged,
        TypingResult::NotPasswordField => UseOutcome::NotPasswordField,
        TypingResult::Refused => UseOutcome::Denied,
        TypingResult::Cancelled | TypingResult::Lost => UseOutcome::Cancelled,
    }
}
