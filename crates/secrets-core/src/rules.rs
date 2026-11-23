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
    /// One regular expression for each argument that a caller may add after `command`; each
    /// must match its whole argument. Empty: no extra arguments.
    pub argument_patterns: Vec<String>,
    /// Whether an extra argument may start with `-`. Off, an option such as `--output` cannot
    /// steer the command.
    pub allow_option_arguments: bool,
    pub timeout_seconds: u32,
    pub max_output_bytes: u32,
    /// The memory limit of the transient service that runs the sandbox.
    pub memory_max_megabytes: u32,
}

/// Why the extra arguments of a run were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentRefusal {
    TooMany,
    StartsWithDash,
    NoMatch,
}

impl Default for RunTemplate {
    fn default() -> Self {
        Self {
            command: Vec::new(),
            environment: BTreeMap::new(),
            network: Vec::new(),
            cwd_glob: String::new(),
            cwd_writable: false,
            argument_patterns: Vec::new(),
            allow_option_arguments: false,
            timeout_seconds: 60,
            max_output_bytes: 256 * 1024,
            memory_max_megabytes: 256,
        }
    }
}

impl RunTemplate {
    /// A run blocks the daemon's request loop, so it may last at most this long.
    pub const MAX_TIMEOUT_SECONDS: u32 = 600;
    /// The reply must fit in one IPC frame (1 MiB) after scrubbing.
    pub const MAX_OUTPUT_BYTES: u32 = 512 * 1024;
    pub const MEMORY_MEGABYTES: std::ops::RangeInclusive<u32> = 16..=4096;
    const MAX_PATTERN_LENGTH: usize = 256;

    /// # Errors
    ///
    /// Fails without a command, without a secret in the environment, or with a time or output
    /// limit of zero or above the maximum.
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if self.command.first().is_none_or(String::is_empty)
            || self.environment.is_empty()
            || !(1..=Self::MAX_TIMEOUT_SECONDS).contains(&self.timeout_seconds)
            || !(1..=Self::MAX_OUTPUT_BYTES).contains(&self.max_output_bytes)
            || !Self::MEMORY_MEGABYTES.contains(&self.memory_max_megabytes)
            || self.argument_patterns.iter().any(|pattern| {
                pattern.len() > Self::MAX_PATTERN_LENGTH || whole_match(pattern).is_err()
            })
        {
            return Err(crate::CoreError::InvalidRunTemplate);
        }
        Ok(())
    }

    /// Checks the extra arguments of a run against the patterns, position by position.
    ///
    /// # Errors
    ///
    /// The first reason to refuse them.
    pub fn check_arguments(&self, arguments: &[String]) -> Result<(), ArgumentRefusal> {
        if arguments.len() > self.argument_patterns.len() {
            return Err(ArgumentRefusal::TooMany);
        }
        for (argument, pattern) in arguments.iter().zip(&self.argument_patterns) {
            if argument.starts_with('-') && !self.allow_option_arguments {
                return Err(ArgumentRefusal::StartsWithDash);
            }
            let matches = whole_match(pattern).is_ok_and(|pattern| pattern.is_match(argument));
            if !matches {
                return Err(ArgumentRefusal::NoMatch);
            }
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

fn whole_match(pattern: &str) -> Result<regex::Regex, regex::Error> {
    regex::Regex::new(&format!("^(?:{pattern})$"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template(patterns: &[&str]) -> RunTemplate {
        RunTemplate {
            argument_patterns: patterns
                .iter()
                .map(|pattern| (*pattern).to_owned())
                .collect(),
            ..RunTemplate::default()
        }
    }

    #[test]
    fn arguments_match_their_pattern_whole_and_options_need_a_flag() {
        let template = template(&["[0-9]+", "open|closed"]);
        let arguments = |parts: &[&str]| {
            parts
                .iter()
                .map(|part| (*part).to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            template.check_arguments(&arguments(&["42", "open"])),
            Ok(())
        );
        assert_eq!(template.check_arguments(&arguments(&["42"])), Ok(()));
        assert_eq!(
            template.check_arguments(&arguments(&["42", "open", "x"])),
            Err(ArgumentRefusal::TooMany)
        );
        assert_eq!(
            template.check_arguments(&arguments(&["42x"])),
            Err(ArgumentRefusal::NoMatch)
        );
        assert_eq!(
            template.check_arguments(&arguments(&["42", "open\nclosed"])),
            Err(ArgumentRefusal::NoMatch)
        );
        let any = RunTemplate {
            argument_patterns: vec![".*".into()],
            ..RunTemplate::default()
        };
        assert_eq!(
            any.check_arguments(&arguments(&["--output=/tmp/x"])),
            Err(ArgumentRefusal::StartsWithDash)
        );
        assert_eq!(
            RunTemplate::default().check_arguments(&arguments(&["x"])),
            Err(ArgumentRefusal::TooMany)
        );
    }
}
