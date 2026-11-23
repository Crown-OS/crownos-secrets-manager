//! `~/.config/crownos/secrets.ron`: the rules of the secrets manager. It holds names and rules,
//! never a value.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Binding, Confirm, SecretKind, SecretName};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnlockPolicy {
    /// The vault locks itself this many minutes after an unlock.
    pub lock_after_minutes: u32,
}

impl Default for UnlockPolicy {
    fn default() -> Self {
        Self {
            lock_after_minutes: 15,
        }
    }
}

/// Limits for each caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEntry {
    pub kind: SecretKind,
    #[serde(default)]
    pub binding: Binding,
}

/// A command that may run with secrets in its environment.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RunTemplate {
    pub command: Vec<String>,
    /// Environment variable name to secret name.
    pub environment: BTreeMap<String, SecretName>,
    /// Hosts the command may reach.
    pub network: Vec<String>,
}

crownos_config::section! {
    pub struct SecretsConfig in "secrets", keys SecretsConfigKey {
        pub unlock as Unlock: UnlockPolicy = UnlockPolicy::default(),
        pub default_confirm as DefaultConfirm: Confirm = Confirm::EveryUse,
        pub rate_limit as RateLimit: RateLimitPolicy = RateLimitPolicy::default(),
        /// Programs, by absolute path, that may add, remove and bind secrets and lock or unlock
        /// the vault. No program can read a value back.
        pub admin_executables as AdminExecutables: Vec<String> = default_admin_executables(),
        pub secrets as Secrets: BTreeMap<SecretName, SecretEntry> = BTreeMap::new(),
        pub run_templates as RunTemplates: BTreeMap<String, RunTemplate> = BTreeMap::new(),
    }
}

fn default_admin_executables() -> Vec<String> {
    ["/usr/bin/crownos-secrets", "/usr/bin/crownos-settings"]
        .map(str::to_owned)
        .to_vec()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::Target;

    #[test]
    fn a_written_config_reads_back_the_same() {
        let mut config = SecretsConfig::default();
        config.secrets.insert(
            SecretName::parse("github_token").unwrap(),
            SecretEntry {
                kind: SecretKind::Token,
                binding: Binding {
                    agents: vec!["/usr/bin/crownos-secrets-mcp".into()],
                    targets: vec![Target::Origin("https://github.com".into())],
                    confirm: Some(Confirm::PerSession(15)),
                    ..Binding::default()
                },
            },
        );
        let text = ron::ser::to_string_pretty(&config, ron::ser::PrettyConfig::default()).unwrap();
        let parsed: SecretsConfig = ron::from_str(&text).unwrap();
        assert_eq!(parsed, config);
    }

    #[test]
    fn missing_fields_take_their_defaults() {
        let parsed: SecretsConfig = ron::from_str("(rate_limit: (uses_per_minute: 2))").unwrap();
        assert_eq!(parsed.rate_limit.uses_per_minute, 2);
        assert_eq!(parsed.rate_limit.requests_per_hour, 10);
        assert_eq!(parsed.unlock.lock_after_minutes, 15);
    }
}
