//! The rules of the vault: who may use which secret, where, and how often. They live in the
//! sealed vault body next to the values, so only a caller with the master password can change
//! them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Binding, Confirm, SecretKind, SecretName, TemplateName};

/// Limits for each caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    pub uses_per_minute: u32,
    /// How often an agent may ask the user to add a secret.
    pub requests_per_hour: u32,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            uses_per_minute: 6,
            requests_per_hour: 10,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSettings {
    /// The vault locks itself this many minutes after an unlock.
    pub lock_after_minutes: u32,
    pub default_confirm: Confirm,
    pub rate_limit: RateLimitPolicy,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            lock_after_minutes: 15,
            default_confirm: Confirm::EveryUse,
            rate_limit: RateLimitPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEntry {
    pub kind: SecretKind,
    pub binding: Binding,
}

/// A command that may run in a sandbox with secrets in its environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTemplate {
    pub command: Vec<String>,
    /// Environment variable name to secret name.
    pub environment: BTreeMap<String, SecretName>,
    /// Hosts the command needs. Empty: the command gets no network at all.
    pub network: Vec<String>,
    /// The working directories a caller may choose; `*` matches any text. Empty: the command
    /// runs in an empty temporary directory.
    pub cwd_glob: String,
    pub cwd_writable: bool,
    /// Whether the caller may add arguments after `command`.
    pub allow_arguments: bool,
    pub timeout_seconds: u32,
    pub max_output_bytes: u32,
}

impl Default for RunTemplate {
    fn default() -> Self {
        Self {
            command: Vec::new(),
            environment: BTreeMap::new(),
            network: Vec::new(),
            cwd_glob: String::new(),
            cwd_writable: false,
            allow_arguments: false,
            timeout_seconds: 60,
            max_output_bytes: 1024 * 1024,
        }
    }
}

impl RunTemplate {
    /// # Errors
    ///
    /// Fails without a command, without a secret in the environment, or with a zero time or
    /// output limit.
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if self.command.first().is_none_or(String::is_empty)
            || self.environment.is_empty()
            || self.timeout_seconds == 0
            || self.max_output_bytes == 0
        {
            return Err(crate::CoreError::InvalidRunTemplate);
        }
        Ok(())
    }

    /// Whether `cwd` is a directory that this template permits.
    pub fn allows_cwd(&self, cwd: &str) -> bool {
        if self.cwd_glob.is_empty() {
            return cwd.is_empty();
        }
        crate::wildcard_matches(&self.cwd_glob, cwd)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SecretRules {
    pub settings: VaultSettings,
    pub secrets: BTreeMap<SecretName, SecretEntry>,
    pub run_templates: BTreeMap<TemplateName, RunTemplate>,
}
