//! The decisions of the daemon, without the socket: tests and the server share this code.

mod admin_calls;
mod agent_calls;
mod error;
mod proxy_calls;
mod run_calls;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use secrets_core::{RateLimitPolicy, SecretName};
use secrets_protocol::SecretRequest;
use secrets_protocol::secrets::Used;
use secrets_proxy::Proxy;
use secrets_vault::Vault;

use crate::Caller;
use crate::admin::AdminPolicy;
use crate::util::rate::RateLimiter;

pub use error::ServiceError;
pub use run_calls::{RunJob, RunStart};

const MAX_PENDING_REQUESTS: usize = 64;
const MAX_PENDING_REQUESTS_PER_CALLER: usize = 4;
const DEFAULT_CONCURRENT_RUNS: usize = 3;

pub struct SecretsService {
    vault: Vault,
    admin: AdminPolicy,
    use_limiter: RateLimiter,
    request_limiter: RateLimiter,
    pending_requests: Vec<SecretRequest>,
    next_request_id: u64,
    last_used: HashMap<SecretName, u64>,
    events: Vec<Used>,
    data_directory: PathBuf,
    upstream_roots: Option<rustls::RootCertStore>,
    proxy: Option<Proxy>,
    /// The bound hosts that the CA of the running proxy covers.
    proxy_ca_hosts: Option<String>,
    next_session_id: u64,
    launcher: secrets_run::Launcher,
    run_slots: std::sync::Arc<tokio::sync::Semaphore>,
    protected_directories: Vec<PathBuf>,
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
    /// `data_directory` gets the CA certificate of the proxy, `secrets-ca.pem`.
    pub fn new(vault: Vault, admin: AdminPolicy, data_directory: PathBuf) -> Self {
        Self {
            vault,
            admin,
            use_limiter: RateLimiter::per(Duration::from_secs(60)),
            request_limiter: RateLimiter::per(Duration::from_secs(60 * 60)),
            pending_requests: Vec::new(),
            next_request_id: 1,
            last_used: HashMap::new(),
            events: Vec::new(),
            upstream_roots: None,
            proxy: None,
            proxy_ca_hosts: None,
            next_session_id: 1,
            launcher: secrets_run::Launcher::default(),
            run_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(DEFAULT_CONCURRENT_RUNS)),
            protected_directories: run_calls::protected_directories(&data_directory),
            data_directory,
        }
    }

    /// The programs that start runs; the installed ones when not set.
    #[must_use]
    pub fn with_launcher(mut self, launcher: secrets_run::Launcher) -> Self {
        self.launcher = launcher;
        self
    }

    /// How many runs may go on at the same time; 3 when not set.
    #[must_use]
    pub fn with_concurrent_runs(mut self, runs: usize) -> Self {
        self.run_slots = std::sync::Arc::new(tokio::sync::Semaphore::new(runs));
        self
    }

    /// The CAs that the proxy trusts for the real hosts; the system store when not set.
    #[must_use]
    pub fn with_upstream_roots(mut self, roots: rustls::RootCertStore) -> Self {
        self.upstream_roots = Some(roots);
        self
    }

    /// The `Used` events since the last call, for the server to send to subscribers.
    pub fn take_events(&mut self) -> Vec<Used> {
        std::mem::take(&mut self.events)
    }

    /// Locks an expired vault. A locked vault also stops the proxy, which drops its sessions
    /// with their values and the CA key.
    pub fn lock_if_expired(&mut self, now: Instant) {
        if self.vault.lock_if_expired(now) {
            crate::audit::locked_after_timeout();
        }
        if self.vault.locks_in(now).is_none() {
            self.proxy = None;
        } else if let Some(proxy) = &self.proxy {
            proxy.forget_expired_sessions();
        }
    }

    pub(crate) fn mark_used(&mut self, names: &[SecretName]) {
        let now = crate::util::unix_time::unix_seconds_now();
        for name in names {
            self.last_used.insert(name.clone(), now);
        }
    }

    fn is_admin(&self, caller: &Caller) -> bool {
        self.admin.allows(caller)
    }

    /// The sealed limits while unlocked; the defaults while locked.
    fn rate_limit_policy(&mut self, now: Instant) -> RateLimitPolicy {
        self.vault
            .contents(now)
            .map(|contents| contents.rules().settings.rate_limit)
            .unwrap_or_default()
    }
}
