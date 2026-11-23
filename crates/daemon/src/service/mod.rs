//! The decisions of the daemon, without the socket: tests and the server share this code.

mod admin_calls;
mod agent_calls;
mod error;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use secrets_core::{RateLimitPolicy, SecretName};
use secrets_protocol::SecretRequest;
use secrets_protocol::secrets::Used;
use secrets_vault::Vault;

use crate::Caller;
use crate::util::rate::RateLimiter;

pub use error::ServiceError;

const MAX_PENDING_REQUESTS: usize = 64;
const MAX_PENDING_REQUESTS_PER_CALLER: usize = 4;

pub struct SecretsService {
    vault: Vault,
    admin_executables: Vec<String>,
    use_limiter: RateLimiter,
    request_limiter: RateLimiter,
    pending_requests: Vec<SecretRequest>,
    next_request_id: u64,
    last_used: HashMap<SecretName, u64>,
    events: Vec<Used>,
}

impl std::fmt::Debug for SecretsService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretsService")
            .field("vault", &self.vault)
            .field("pending_requests", &self.pending_requests.len())
            .finish_non_exhaustive()
    }
}

impl SecretsService {
    pub fn new(vault: Vault, admin_executables: Vec<String>) -> Self {
        Self {
            vault,
            admin_executables,
            use_limiter: RateLimiter::per(Duration::from_secs(60)),
            request_limiter: RateLimiter::per(Duration::from_secs(60 * 60)),
            pending_requests: Vec::new(),
            next_request_id: 1,
            last_used: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// The `Used` events since the last call, for the server to send to subscribers.
    pub fn take_events(&mut self) -> Vec<Used> {
        std::mem::take(&mut self.events)
    }

    pub fn lock_if_expired(&mut self, now: Instant) {
        if self.vault.lock_if_expired(now) {
            crate::audit::locked_after_timeout();
        }
    }

    fn is_admin(&self, caller: &Caller) -> bool {
        caller.is_any_of(&self.admin_executables)
    }

    /// The sealed limits while unlocked; the defaults while locked.
    fn rate_limit_policy(&mut self, now: Instant) -> RateLimitPolicy {
        self.vault
            .contents(now)
            .map(|contents| contents.rules().settings.rate_limit)
            .unwrap_or_default()
    }
}
