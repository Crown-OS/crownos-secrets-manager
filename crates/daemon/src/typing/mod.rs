//! Typing through the compositor (`crownos_secret_input_v1`). The daemon connects to Wayland at
//! start, before it turns dumpable off, so the compositor can read who it is. One worker thread
//! owns the connection and sends one request at a time, then waits for its `done` event. When the
//! connection breaks, the daemon exits so that systemd starts it again with a new connection.

mod value_fd;
mod worker;

use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Sender, channel};

use secrecy::SecretSlice;
use tokio::sync::oneshot;

/// The kind of a value, so the compositor can treat a password as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    Username,
    Password,
}

/// One value of a request.
pub struct TypingValue {
    pub value: SecretSlice<u8>,
    pub kind: ValueKind,
    pub tab_after: bool,
}

impl std::fmt::Debug for TypingValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TypingValue")
            .field("kind", &self.kind)
            .field("tab_after", &self.tab_after)
            .finish_non_exhaustive()
    }
}

/// One `crownos_secret_input_request_v1`: the compositor asks the user once for all values.
#[derive(Debug)]
pub struct TypingRequest {
    pub window: String,
    pub app_id: String,
    pub require_password_field: bool,
    /// Display text for the compositor's dialog.
    pub agent: String,
    pub secret_names: String,
    pub origin: String,
    pub values: Vec<TypingValue>,
}

/// What the compositor answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypingResult {
    Typed,
    FocusChanged,
    NotPasswordField,
    Refused,
    Cancelled,
    UnknownWindow,
    TimedOut,
    TargetMismatch,
    SessionLocked,
}

pub(crate) struct TypingJob {
    request: TypingRequest,
    answer: oneshot::Sender<TypingResult>,
}

/// The daemon's side of the protocol: available when the compositor offered the global at
/// start.
#[derive(Debug, Default)]
pub struct CompositorTyping {
    jobs: Option<Sender<TypingJob>>,
}

impl CompositorTyping {
    pub const fn unavailable() -> Self {
        Self { jobs: None }
    }

    /// Connects through `WAYLAND_DISPLAY`. Without a compositor, or without the global, typing
    /// stays unavailable until the daemon restarts.
    pub fn connect_from_environment() -> Self {
        match wayland_client::Connection::connect_to_env() {
            Ok(connection) => Self::start(&connection),
            Err(error) => {
                tracing::info!(%error, "no Wayland connection; typing secrets is unavailable");
                Self::unavailable()
            }
        }
    }

    /// Over a socket that the caller connected, for tests.
    pub fn from_socket(stream: UnixStream) -> Self {
        match wayland_client::Connection::from_socket(stream) {
            Ok(connection) => Self::start(&connection),
            Err(error) => {
                tracing::warn!(%error, "cannot use the Wayland socket");
                Self::unavailable()
            }
        }
    }

    /// The event queue keeps the connection open for the worker.
    fn start(connection: &wayland_client::Connection) -> Self {
        let Some(worker) = worker::Worker::bind(connection) else {
            tracing::info!("the compositor offers no crownos_secret_input_manager_v1");
            return Self::unavailable();
        };
        let (jobs, received) = channel();
        let spawned = std::thread::Builder::new()
            .name("secret-typing".into())
            .spawn(move || worker.run(&received));
        match spawned {
            Ok(_) => Self { jobs: Some(jobs) },
            Err(error) => {
                tracing::warn!(%error, "cannot start the typing thread");
                Self::unavailable()
            }
        }
    }

    pub const fn is_available(&self) -> bool {
        self.jobs.is_some()
    }

    /// Queues the request; the answer comes with the compositor's `done`.
    pub(crate) fn submit(&self, request: TypingRequest) -> Option<oneshot::Receiver<TypingResult>> {
        let jobs = self.jobs.as_ref()?;
        let (answer, receiver) = oneshot::channel();
        jobs.send(TypingJob { request, answer }).ok()?;
        Some(receiver)
    }
}
