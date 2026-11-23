//! The HTTPS proxy of `crownos-secretsd`.
//!
//! An agent gets a session: a proxy URL with a random token, and the CA certificate to trust. The
//! proxy accepts `CONNECT` only to the hosts that the session's HTTP bindings name. It ends TLS
//! with a certificate from the local CA, adds the bound header to the requests whose host, method
//! and path match, replaces `crown-secret://<name>` placeholders in headers, and sends the request
//! on to the real host over verified TLS. Each response comes back scrubbed. The agent never has
//! the key.

mod audit;
mod authority;
mod connect;
mod error;
mod forward;
mod scrubbed_body;
mod session;
mod target;
mod tunnel;
mod util;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::RootCertStore;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub use authority::CertificateAuthority;
pub use error::ProxyError;
pub use session::SessionSecret;

use crate::session::{Session, Sessions};

/// The text an agent puts in a header in place of a value.
pub const PLACEHOLDER_PREFIX: &str = "crown-secret://";

pub(crate) struct Shared {
    sessions: Sessions,
    authority: CertificateAuthority,
    upstream_tls: Arc<rustls::ClientConfig>,
}

/// The proxy listener on `127.0.0.1`. Dropping it stops the listener.
pub struct Proxy {
    address: SocketAddr,
    shared: Arc<Shared>,
    accept_loop: JoinHandle<()>,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Proxy")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.accept_loop.abort();
        self.shared.sessions.revoke_all();
    }
}

impl Proxy {
    /// Listens on a free port of `127.0.0.1`. Call it inside a tokio runtime.
    ///
    /// # Errors
    ///
    /// Fails when the port cannot be bound or TLS cannot be set up.
    pub fn start(
        authority: CertificateAuthority,
        upstream_roots: RootCertStore,
    ) -> Result<Self, ProxyError> {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;
        let address = listener.local_addr()?;
        let shared = Arc::new(Shared {
            sessions: Sessions::default(),
            authority,
            upstream_tls: Arc::new(tunnel::upstream_tls_config(upstream_roots)?),
        });
        let accept_loop = tokio::spawn(connect::accept_clients(listener, Arc::clone(&shared)));
        Ok(Self {
            address,
            shared,
            accept_loop,
        })
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn ca_certificate_pem(&self) -> String {
        self.shared.authority.certificate_pem()
    }

    /// Opens a session for `actor` and returns the proxy URL with its token.
    ///
    /// # Errors
    ///
    /// Fails when the random generator fails.
    pub fn open_session(
        &self,
        id: u64,
        actor: &str,
        secrets: Vec<SessionSecret>,
        lifetime: Duration,
    ) -> Result<String, ProxyError> {
        let token = util::token::random_token()?;
        let session = Session::new(id, actor.to_owned(), secrets, Instant::now() + lifetime);
        self.shared.sessions.insert(token.clone(), session);
        Ok(format!(
            "http://{}:{token}@{}",
            util::basic_auth::USER,
            self.address
        ))
    }

    /// Returns whether the session of `actor` was open.
    pub fn revoke_session(&self, id: u64, actor: &str) -> bool {
        self.shared.sessions.revoke(id, actor)
    }

    /// Ends every session and drops its values.
    pub fn revoke_all(&self) {
        self.shared.sessions.revoke_all();
    }

    /// Drops the sessions whose time is over.
    pub fn forget_expired_sessions(&self) {
        self.shared.sessions.forget_expired(Instant::now());
    }
}

/// The system trust store, for the TLS connections to the real hosts.
pub fn system_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    for error in &loaded.errors {
        tracing::warn!(%error, "cannot load a system CA certificate");
    }
    roots.add_parsable_certificates(loaded.certs);
    roots
}
