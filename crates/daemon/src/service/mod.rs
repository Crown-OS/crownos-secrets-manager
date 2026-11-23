//! The decisions of the daemon, without the socket: tests and the server share this code.

mod admin_calls;
mod agent_calls;
mod error;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use secrets_core::{SecretName, SecretsConfig};
use secrets_protocol::SecretRequest;
use secrets_protocol::secrets::Used;
use secrets_vault::Vault;

use crate::ConfigStore;
use crate::util::rate::RateLimiter;

pub use error::ServiceError;

const MAX_PENDING_REQUESTS: usize = 32;

pub struct SecretsService<Store> {
    store: Store,
    config: SecretsConfig,
    vault: Vault,
    use_limiter: RateLimiter,
    request_limiter: RateLimiter,
    pending_requests: Vec<SecretRequest>,
    next_request_id: u64,
    last_used: HashMap<SecretName, u64>,
    events: Vec<Used>,
}

impl<Store> std::fmt::Debug for SecretsService<Store> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretsService")
            .field("vault", &self.vault)
            .field("pending_requests", &self.pending_requests.len())
            .finish_non_exhaustive()
    }
}

impl<Store: ConfigStore> SecretsService<Store> {
    pub fn new(store: Store, vault: Vault) -> Self {
        let mut service = Self {
            store,
            config: SecretsConfig::default(),
            vault,
            use_limiter: RateLimiter::per(Duration::from_secs(60)),
            request_limiter: RateLimiter::per(Duration::from_secs(60 * 60)),
            pending_requests: Vec::new(),
            next_request_id: 1,
            last_used: HashMap::new(),
            events: Vec::new(),
        };
        service.reload_config();
        service
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

    /// Reads `secrets.ron` again, so a change made by hand or by Settings counts at once. On a
    /// read error the last good config stays.
    fn reload_config(&mut self) {
        match self.store.load() {
            Ok(config) => self.config = config,
            Err(error) => tracing::warn!(%error, "keeping the last good secrets.ron"),
        }
        let lock_after = u64::from(self.config.unlock.lock_after_minutes) * 60;
        self.vault.set_lock_after(Duration::from_secs(lock_after));
    }
}
