//! Calls that any same-user process may make. None of them returns a value.

use std::time::Instant;

use secrets_core::{Confirm, SecretKind, SecretName, UseOutcome};
use secrets_protocol::secrets::Used;
use secrets_protocol::{RequestId, SecretMeta, SecretRequest, TemplateMeta, VaultStatus};

use super::confirmations::ConfirmCheck;
use super::{MAX_PENDING_REQUESTS, MAX_PENDING_REQUESTS_PER_CALLER, SecretsService, ServiceError};
use crate::util::caller_text::sanitized;
use crate::util::rate::RateDecision;
use crate::{Caller, audit};

const MAX_PURPOSE_CHARACTERS: usize = 300;

impl SecretsService {
    /// Non-admin callers see only their own requests.
    pub fn status(&mut self, caller: &Caller, now: Instant) -> VaultStatus {
        self.lock_if_expired(now);
        let locks_in = self.vault.locks_in(now);
        let requester = caller.to_string();
        let sees_all = self.is_admin(caller);
        VaultStatus {
            vault_exists: self.vault.exists(),
            locked: locks_in.is_none(),
            locks_in_seconds: locks_in.map(|left| left.as_secs()),
            pending_requests: self
                .pending_requests
                .iter()
                .filter(|request| sees_all || request.requested_by == requester)
                .cloned()
                .collect(),
        }
    }

    /// # Errors
    ///
    /// [`ServiceError::Locked`]: the rules are sealed in the vault.
    pub fn list(&mut self, now: Instant) -> Result<Vec<SecretMeta>, ServiceError> {
        let rules = self.vault.contents(now)?.rules();
        Ok(rules
            .secrets
            .iter()
            .map(|(name, entry)| SecretMeta {
                name: name.clone(),
                kind: entry.kind,
                binding: entry.binding.clone(),
                last_used: self.last_used.get(name).copied(),
            })
            .collect())
    }

    /// # Errors
    ///
    /// [`ServiceError::Locked`]: the rules are sealed in the vault.
    pub fn templates(&mut self, now: Instant) -> Result<Vec<TemplateMeta>, ServiceError> {
        let rules = self.vault.contents(now)?.rules();
        Ok(rules
            .run_templates
            .iter()
            .map(|(name, template)| TemplateMeta {
                name: name.clone(),
                template: template.clone(),
            })
            .collect())
    }

    /// Records that an agent asks the user to add a secret. The limits apply before any log
    /// line, so a flood of requests cannot flood the audit trail.
    ///
    /// # Errors
    ///
    /// [`ServiceError::RateLimited`] after `requests_per_hour` requests from the caller, and
    /// [`ServiceError::TooManyRequests`] while too many requests are open.
    pub fn request(
        &mut self,
        caller: &Caller,
        name: SecretName,
        kind: SecretKind,
        purpose: &str,
        now: Instant,
    ) -> Result<RequestId, ServiceError> {
        let requester = caller.to_string();
        let allowed = self.rate_limit_policy(now).requests_per_hour;
        if let RateDecision::Refused { first } =
            self.request_limiter.decide(&requester, allowed, now)
        {
            if first {
                audit::secret_requested(
                    caller,
                    &name,
                    "rate-limited; further refusals are not logged",
                );
            }
            return Err(ServiceError::RateLimited);
        }
        let open_for_caller = self
            .pending_requests
            .iter()
            .filter(|request| request.requested_by == requester)
            .count();
        if open_for_caller >= MAX_PENDING_REQUESTS_PER_CALLER
            || self.pending_requests.len() >= MAX_PENDING_REQUESTS
        {
            return Err(ServiceError::TooManyRequests);
        }
        let id = RequestId(self.next_request_id);
        self.next_request_id += 1;
        audit::secret_requested(caller, &name, "recorded");
        self.pending_requests.push(SecretRequest {
            id,
            name,
            kind,
            purpose: sanitized(purpose, MAX_PURPOSE_CHARACTERS),
            requested_by: requester,
        });
        Ok(id)
    }

    /// Runs every check for a use of `names` at `target`, which the caller of this function
    /// sanitized. `None` means every check passed.
    pub(crate) fn refusal_for_use(
        &mut self,
        caller: &Caller,
        names: &[SecretName],
        target: &str,
        now: Instant,
    ) -> Option<UseOutcome> {
        self.lock_if_expired(now);
        let outcome = match self.check_use(caller, names, now) {
            UseCheck::Passed => return None,
            UseCheck::RefusedQuietly(outcome) => return Some(outcome),
            UseCheck::Refused(outcome) => outcome,
        };
        audit::use_decided(caller, names, target, outcome_name(outcome));
        self.events.extend(names.iter().map(|name| Used {
            name: name.clone(),
            actor: caller.to_string(),
            target: target.to_owned(),
            outcome,
        }));
        Some(outcome)
    }

    /// Checks a use that this milestone cannot perform yet.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Unavailable`] when every check passes.
    pub fn use_secrets(
        &mut self,
        caller: &Caller,
        names: &[SecretName],
        target: &str,
        now: Instant,
    ) -> Result<UseOutcome, ServiceError> {
        match self.refusal_for_use(caller, names, target, now) {
            Some(outcome) => Ok(outcome),
            None => {
                audit::use_decided(caller, names, target, "unavailable");
                Err(ServiceError::Unavailable)
            }
        }
    }

    fn check_use(&mut self, caller: &Caller, names: &[SecretName], now: Instant) -> UseCheck {
        let allowed = self.rate_limit_policy(now).uses_per_minute;
        if let RateDecision::Refused { first } =
            self.use_limiter.decide(&caller.to_string(), allowed, now)
        {
            return if first {
                UseCheck::Refused(UseOutcome::RateLimited)
            } else {
                UseCheck::RefusedQuietly(UseOutcome::RateLimited)
            };
        }
        let Ok(contents) = self.vault.contents(now) else {
            return UseCheck::Refused(UseOutcome::Locked);
        };
        let rules = contents.rules();
        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            let Some(entry) = rules.secrets.get(name) else {
                return UseCheck::Refused(UseOutcome::Unknown);
            };
            entries.push(entry);
        }
        let permitted = caller.app_key_text().is_some_and(|app_key| {
            entries
                .iter()
                .all(|entry| entry.binding.allows_agent(&app_key))
        });
        if !permitted || names.is_empty() {
            return UseCheck::Refused(UseOutcome::Denied);
        }
        if !names.iter().all(|name| contents.contains(name)) {
            return UseCheck::Refused(UseOutcome::Unknown);
        }
        let default_confirm = rules.settings.default_confirm;
        let confirms: Vec<Confirm> = entries
            .iter()
            .map(|entry| entry.binding.confirm_or(default_confirm))
            .collect();
        let Some(app_key) = caller.app_key_text() else {
            return UseCheck::Refused(UseOutcome::Denied);
        };
        match self.confirm_check(caller, &app_key, names, &confirms, "", now, true) {
            ConfirmCheck::Passed => {}
            ConfirmCheck::Denied => return UseCheck::Refused(UseOutcome::Denied),
            ConfirmCheck::Unreachable | ConfirmCheck::Ask(_) => {
                return UseCheck::Refused(UseOutcome::NeedsConfirmation);
            }
        }
        UseCheck::Passed
    }
}

enum UseCheck {
    Passed,
    Refused(UseOutcome),
    /// A rate-limit refusal after the first one: no audit line and no event.
    RefusedQuietly(UseOutcome),
}

const fn outcome_name(outcome: UseOutcome) -> &'static str {
    match outcome {
        UseOutcome::Done => "done",
        UseOutcome::Denied => "denied",
        UseOutcome::NotPasswordField => "not-password-field",
        UseOutcome::OriginMismatch => "origin-mismatch",
        UseOutcome::RateLimited => "rate-limited",
        UseOutcome::Locked => "locked",
        UseOutcome::Unknown => "unknown",
        UseOutcome::NeedsConfirmation => "needs-confirmation",
        UseOutcome::FocusChanged => "focus-changed",
        UseOutcome::Cancelled => "cancelled",
    }
}
