//! Calls that any same-user process may make. None of them returns a value.

use std::time::Instant;

use secrets_core::{SecretKind, SecretName, UseOutcome};
use secrets_protocol::secrets::Used;
use secrets_protocol::{RequestId, SecretMeta, SecretRequest, VaultStatus};

use super::{MAX_PENDING_REQUESTS, SecretsService, ServiceError};
use crate::{Caller, ConfigStore, audit};

const MAX_PURPOSE_CHARACTERS: usize = 500;

impl<Store: ConfigStore> SecretsService<Store> {
    pub fn status(&mut self, now: Instant) -> VaultStatus {
        self.reload_config();
        self.lock_if_expired(now);
        let locks_in = self.vault.locks_in(now);
        VaultStatus {
            vault_exists: self.vault.exists(),
            locked: locks_in.is_none(),
            locks_in_seconds: locks_in.map(|left| left.as_secs()),
            secrets: u32::try_from(self.config.secrets.len()).unwrap_or(u32::MAX),
            pending_requests: self.pending_requests.clone(),
        }
    }

    pub fn list(&mut self) -> Vec<SecretMeta> {
        self.reload_config();
        self.config
            .secrets
            .iter()
            .map(|(name, entry)| SecretMeta {
                name: name.clone(),
                kind: entry.kind,
                binding: entry.binding.clone(),
                last_used: self.last_used.get(name).copied(),
            })
            .collect()
    }

    /// Records that an agent asks the user to add a secret.
    ///
    /// # Errors
    ///
    /// [`ServiceError::RateLimited`] after `requests_per_hour` requests from the caller.
    pub fn request(
        &mut self,
        caller: &Caller,
        name: SecretName,
        kind: SecretKind,
        purpose: &str,
        now: Instant,
    ) -> Result<RequestId, ServiceError> {
        self.reload_config();
        let allowed = self.config.rate_limit.requests_per_hour;
        if !self
            .request_limiter
            .allow(&caller.to_string(), allowed, now)
        {
            audit::secret_requested(caller, &name, "rate-limited");
            return Err(ServiceError::RateLimited);
        }
        let id = RequestId(self.next_request_id);
        self.next_request_id += 1;
        audit::secret_requested(caller, &name, "recorded");
        if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
            self.pending_requests.remove(0);
        }
        self.pending_requests.push(SecretRequest {
            id,
            name,
            kind,
            purpose: purpose.chars().take(MAX_PURPOSE_CHARACTERS).collect(),
            requested_by: caller.to_string(),
        });
        Ok(id)
    }

    /// Runs every check for a use of `names` at `target`.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Unavailable`] when every check passes: this milestone does not use
    /// secrets yet.
    pub fn use_secrets(
        &mut self,
        caller: &Caller,
        names: &[SecretName],
        target: &str,
        now: Instant,
    ) -> Result<UseOutcome, ServiceError> {
        self.reload_config();
        self.lock_if_expired(now);
        let refusal = self.refusal(caller, names, now);
        let outcome_text = refusal.map_or("unavailable", outcome_name);
        audit::use_decided(caller, names, target, outcome_text);
        let Some(outcome) = refusal else {
            return Err(ServiceError::Unavailable);
        };
        self.events.extend(names.iter().map(|name| Used {
            name: name.clone(),
            actor: caller.to_string(),
            target: target.to_owned(),
            outcome,
        }));
        Ok(outcome)
    }

    /// Checks a registered command template like a use of every secret in its environment.
    ///
    /// # Errors
    ///
    /// As [`Self::use_secrets`].
    pub fn run_template(
        &mut self,
        caller: &Caller,
        template: &str,
        now: Instant,
    ) -> Result<UseOutcome, ServiceError> {
        self.reload_config();
        let Some(names) = self
            .config
            .run_templates
            .get(template)
            .map(|template| template.environment.values().cloned().collect::<Vec<_>>())
        else {
            audit::use_decided(caller, &[], &format!("run:{template}"), "unknown-template");
            return Ok(UseOutcome::Unknown);
        };
        self.use_secrets(caller, &names, &format!("run:{template}"), now)
    }

    fn refusal(
        &mut self,
        caller: &Caller,
        names: &[SecretName],
        now: Instant,
    ) -> Option<UseOutcome> {
        let allowed = self.config.rate_limit.uses_per_minute;
        if !self.use_limiter.allow(&caller.to_string(), allowed, now) {
            return Some(UseOutcome::RateLimited);
        }
        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            let Some(entry) = self.config.secrets.get(name) else {
                return Some(UseOutcome::Unknown);
            };
            entries.push(entry);
        }
        let permitted = caller.app_key().is_some_and(|app_key| {
            entries
                .iter()
                .all(|entry| entry.binding.allows_agent(app_key))
        });
        if !permitted || names.is_empty() {
            return Some(UseOutcome::Denied);
        }
        let Ok(contents) = self.vault.contents(now) else {
            return Some(UseOutcome::Locked);
        };
        if !names.iter().all(|name| contents.contains(name)) {
            return Some(UseOutcome::Unknown);
        }
        None
    }
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
    }
}
