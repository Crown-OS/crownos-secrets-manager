//! Typing a secret into a window through the compositor. The checks run at once; the typing
//! waits in a task for the compositor's answer. The compositor's dialog is the only
//! confirmation: the binding's `confirm` and session approvals do not apply to typing.

use std::time::Instant;

use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::{SecretKind, SecretName, Target, UseOutcome};
use secrets_protocol::TypingTarget;
use tokio::sync::oneshot;

use super::agent_calls::ConfirmedBy;
use super::{SecretsService, ServiceError};
use crate::typing::{TypingRequest, TypingResult, TypingValue, ValueKind};
use crate::{Caller, audit};

/// The protocol's limit for one typed value.
const MAX_TYPED_VALUE_BYTES: usize = 4096;

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

    /// Checks a typing request and hands it to the compositor, which asks the user itself.
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
        if let Some(outcome) =
            self.refusal_for_use(caller, names, target_text, now, ConfirmedBy::Compositor)
        {
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
        let mut values = Vec::with_capacity(names.len());
        let mut require_password_field = false;
        for (index, name) in names.iter().enumerate() {
            let entry = rules
                .secrets
                .get(name)
                .ok_or_else(|| ServiceError::UnknownSecret(name.clone()))?;
            let value = contents
                .value(name)
                .ok_or_else(|| ServiceError::UnknownSecret(name.clone()))?;
            if value.expose_secret().len() > MAX_TYPED_VALUE_BYTES {
                audit::use_decided(caller, names, target_text, "value-too-large");
                return Ok(TypingStart::Refused(UseOutcome::Denied));
            }
            let is_login_user = shape == TypingShape::Login && index == 0;
            let is_secret_kind = matches!(
                entry.kind,
                SecretKind::Password | SecretKind::ApiKey | SecretKind::Token
            );
            let password =
                !is_login_user && (is_secret_kind || entry.binding.require_password_field);
            require_password_field |= password;
            values.push(TypingValue {
                value: SecretSlice::from(value.expose_secret().to_vec()),
                kind: if password {
                    ValueKind::Password
                } else {
                    ValueKind::Username
                },
                tab_after: is_login_user,
            });
        }
        let request = TypingRequest {
            window: target.window.clone(),
            app_id: target.app_id.clone(),
            require_password_field,
            agent: caller.display_name(),
            secret_names: names
                .iter()
                .map(SecretName::as_str)
                .collect::<Vec<_>>()
                .join(", "),
            origin: target.origin.clone().unwrap_or_default(),
            values,
        };
        let waiting = self
            .typing
            .submit(request)
            .ok_or(ServiceError::Unavailable)?;
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
        TypingResult::Cancelled => UseOutcome::Cancelled,
        TypingResult::UnknownWindow => UseOutcome::UnknownWindow,
        TypingResult::TimedOut => UseOutcome::TimedOut,
        TypingResult::TargetMismatch => UseOutcome::TargetMismatch,
        TypingResult::SessionLocked => UseOutcome::SessionLocked,
    }
}
