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
        if !self.typing_policy.allows_caller(caller) {
            audit::use_decided(caller, names, target_text, "not-a-typing-caller");
            return Ok(TypingStart::Refused(UseOutcome::Denied));
        }
        if let Some(outcome) =
            self.refusal_for_use(caller, names, target_text, now, ConfirmedBy::Compositor)
        {
            return Ok(TypingStart::Refused(outcome));
        }
        if let Some(outcome) = self.typing_target_refusal(names, target, now) {
            audit::use_decided(caller, names, target_text, "target-not-bound");
            return Ok(TypingStart::Refused(outcome));
        }
        let Some(expected_app_key) = self.typing_policy.expected_app_key(&target.app_id) else {
            audit::use_decided(caller, names, target_text, "no-installed-app");
            return Ok(TypingStart::Refused(UseOutcome::Denied));
        };
        if !self.typing.is_available() {
            audit::use_decided(caller, names, target_text, "unavailable");
            return Err(ServiceError::Unavailable);
        }
        let contents = self.vault.contents(now)?;
        let rules = contents.rules();
        let mut kinds = Vec::with_capacity(names.len());
        for name in names {
            let entry = rules
                .secrets
                .get(name)
                .ok_or_else(|| ServiceError::UnknownSecret(name.clone()))?;
            kinds.push(if entry.binding.require_password_field {
                SecretKind::Password
            } else {
                entry.kind
            });
        }
        let Some(value_kinds) = typed_value_kinds(shape, &kinds) else {
            audit::use_decided(caller, names, target_text, "wrong-secret-kind");
            return Ok(TypingStart::Refused(UseOutcome::Denied));
        };
        let mut values = Vec::with_capacity(names.len());
        for (name, kind) in names.iter().zip(value_kinds) {
            let value = contents
                .value(name)
                .ok_or_else(|| ServiceError::UnknownSecret(name.clone()))?;
            if value.expose_secret().len() > MAX_TYPED_VALUE_BYTES {
                audit::use_decided(caller, names, target_text, "value-too-large");
                return Ok(TypingStart::Refused(UseOutcome::Denied));
            }
            values.push(TypingValue {
                value: SecretSlice::from(value.expose_secret().to_vec()),
                kind,
                tab_after: shape == TypingShape::Login && kind == ValueKind::Username,
            });
        }
        let require_password_field = values.iter().any(|value| value.kind == ValueKind::Password);
        let request = TypingRequest {
            window: target.window.clone(),
            expected_app_key: expected_app_key.to_string(),
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

/// How each secret is typed. Only a `Username` secret goes into a field that is not a password
/// field; every other kind needs one. A login is a `Username`, then another kind. `None` when
/// the kinds do not fit the shape.
fn typed_value_kinds(shape: TypingShape, kinds: &[SecretKind]) -> Option<Vec<ValueKind>> {
    let value_kind = |kind: &SecretKind| {
        if *kind == SecretKind::Username {
            ValueKind::Username
        } else {
            ValueKind::Password
        }
    };
    match (shape, kinds) {
        (TypingShape::Single, [kind]) => Some(vec![value_kind(kind)]),
        (TypingShape::Login, [SecretKind::Username, password])
            if *password != SecretKind::Username =>
        {
            Some(vec![ValueKind::Username, ValueKind::Password])
        }
        _ => None,
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
