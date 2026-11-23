//! Typing through the compositor (`crownos_secret_input_v1`). The daemon connects to Wayland at
//! start, before it turns dumpable off, so the compositor can read who it is. One worker thread
//! owns the connection and sends one request at a time; each step waits for its `done` event.

mod value_fd;
mod worker;

use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Sender, channel};

use secrecy::SecretSlice;
use tokio::sync::oneshot;

/// One `type_secret` request.
pub struct TypingStep {
    pub value: SecretSlice<u8>,
    pub window: String,
    pub require_password_field: bool,
    pub tab_after: bool,
    pub confirmed: bool,
    pub agent: String,
    pub secret_name: String,
    pub origin: String,
}

impl std::fmt::Debug for TypingStep {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TypingStep")
            .field("window", &self.window)
            .field("secret_name", &self.secret_name)
            .finish_non_exhaustive()
    }
}

/// What the compositor answered for the last step that ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypingResult {
    Typed,
    FocusChanged,
    NotPasswordField,
    Refused,
    Cancelled,
    /// The connection to the compositor broke.
    Lost,
}

pub(crate) struct TypingJob {
    steps: Vec<TypingStep>,
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

    /// Queues the steps; the answer comes when the last step that runs is done.
    pub(crate) fn submit(&self, steps: Vec<TypingStep>) -> Option<oneshot::Receiver<TypingResult>> {
        let jobs = self.jobs.as_ref()?;
        let (answer, receiver) = oneshot::channel();
        jobs.send(TypingJob { steps, answer }).ok()?;
        Some(receiver)
    }
}
