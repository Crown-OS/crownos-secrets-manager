use clap::Args;
use secrets_core::{RateLimitPolicy, VaultSettings};

use crate::binding_arguments::parse_confirm;

#[derive(Debug, Args)]
pub(crate) struct SettingsArguments {
    /// Minutes until the vault locks itself after an unlock.
    #[arg(long, default_value_t = 15)]
    lock_after_minutes: u32,
    /// `every-use`, `never`, or `session:<minutes>`.
    #[arg(long, default_value = "every-use", value_parser = parse_confirm)]
    default_confirm: secrets_core::Confirm,
    #[arg(long, default_value_t = 6)]
    uses_per_minute: u32,
    #[arg(long, default_value_t = 10)]
    requests_per_hour: u32,
}

impl SettingsArguments {
    pub(crate) const fn into_settings(self) -> VaultSettings {
        VaultSettings {
            lock_after_minutes: self.lock_after_minutes,
            default_confirm: self.default_confirm,
            rate_limit: RateLimitPolicy {
                uses_per_minute: self.uses_per_minute,
                requests_per_hour: self.requests_per_hour,
            },
        }
    }
}
