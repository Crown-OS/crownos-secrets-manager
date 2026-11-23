use std::collections::HashMap;
use std::os::fd::AsFd as _;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use crownos_protocols::secret_input::v1::client::crownos_secret_consent_v1::{
    self, Action, CrownosSecretConsentV1,
};
use crownos_protocols::secret_input::v1::client::crownos_secret_input_manager_v1::CrownosSecretInputManagerV1;
use crownos_protocols::secret_input::v1::client::crownos_secret_input_request_v1::{
    self, CrownosSecretInputRequestV1, Kind, Outcome,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use secrecy::ExposeSecret as _;
use wayland_client::globals::{GlobalListContents, registry_queue_init};
use wayland_client::protocol::wl_registry::WlRegistry;
use wayland_client::{Connection, Dispatch, EventQueue, QueueHandle, WEnum};

use super::value_fd::sealed_value;
use super::{ConsentRequest, Job, TypingRequest, TypingResult, ValueKind};
use crate::confirmation::UseKind;

/// The compositor answers within its own 120 s; this covers the typing after that.
const REQUEST_TIME: Duration = Duration::from_secs(150);
/// The exit code when the compositor connection breaks; systemd restarts the daemon.
const LOST_CONNECTION_EXIT_CODE: i32 = 75;

#[derive(Debug, Default)]
struct WorkerState {
    done: HashMap<u32, u32>,
    consents: HashMap<u32, u32>,
}

impl Dispatch<CrownosSecretConsentV1, u32> for WorkerState {
    fn event(
        state: &mut Self,
        _: &CrownosSecretConsentV1,
        event: crownos_secret_consent_v1::Event,
        id: &u32,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let crownos_secret_consent_v1::Event::Consent { granted } = event {
            state.consents.insert(*id, granted);
        }
    }
}

impl Dispatch<WlRegistry, GlobalListContents> for WorkerState {
    fn event(
        _: &mut Self,
        _: &WlRegistry,
        _: wayland_client::protocol::wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<CrownosSecretInputManagerV1, ()> for WorkerState {
    fn event(
        _: &mut Self,
        _: &CrownosSecretInputManagerV1,
        _: <CrownosSecretInputManagerV1 as wayland_client::Proxy>::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<CrownosSecretInputRequestV1, u32> for WorkerState {
    fn event(
        state: &mut Self,
        _: &CrownosSecretInputRequestV1,
        event: crownos_secret_input_request_v1::Event,
        id: &u32,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let crownos_secret_input_request_v1::Event::Done { outcome } = event {
            let outcome = match outcome {
                WEnum::Value(outcome) => outcome as u32,
                WEnum::Unknown(value) => value,
            };
            state.done.insert(*id, outcome);
        }
    }
}

pub(super) struct Worker {
    queue: EventQueue<WorkerState>,
    manager: CrownosSecretInputManagerV1,
    state: WorkerState,
    next_id: u32,
}

impl Worker {
    /// Binds the global, or `None` when the compositor does not offer it.
    pub(super) fn bind(connection: &Connection) -> Option<Self> {
        let (globals, queue) = registry_queue_init::<WorkerState>(connection).ok()?;
        let manager = globals
            .bind::<CrownosSecretInputManagerV1, _, _>(&queue.handle(), 1..=1, ())
            .ok()?;
        Some(Self {
            queue,
            manager,
            state: WorkerState::default(),
            next_id: 1,
        })
    }

    /// One job at a time, so the user sees one consent dialog at a time.
    pub(super) fn run(mut self, jobs: &Receiver<Job>) {
        while let Ok(job) = jobs.recv() {
            let delivered = match job {
                Job::Typing { request, answer } => {
                    let result = self.type_request(&request);
                    drop(request);
                    result.map(|result| {
                        let _ = answer.send(result);
                    })
                }
                Job::Consent { request, answer } => self.ask_consent(&request).map(|granted| {
                    let _ = answer.send(granted);
                }),
            };
            if delivered.is_none() {
                tracing::error!(
                    "the compositor connection broke; exiting so systemd restarts the daemon"
                );
                std::process::exit(LOST_CONNECTION_EXIT_CODE);
            }
        }
    }

    /// `None` when the connection broke. No answer in time is a deny.
    fn ask_consent(&mut self, request: &ConsentRequest) -> Option<bool> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let action = match request.kind {
            UseKind::Run => Action::Run,
            UseKind::Proxy => Action::Proxy,
        };
        let proxy = self.manager.ask_consent(
            request.agent_app_key.clone(),
            request.secret_names.clone(),
            action,
            request.detail.clone(),
            &self.queue.handle(),
            id,
        );
        let answered = self.wait_until(|state| state.consents.remove(&id));
        proxy.destroy();
        let _ = self.queue.flush();
        match answered {
            Waited::Done(granted) => Some(granted == 1),
            Waited::TimedOut => Some(false),
            Waited::Lost => None,
        }
    }

    /// `None` when the connection broke.
    fn type_request(&mut self, request: &TypingRequest) -> Option<TypingResult> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let proxy = self.manager.create_request(
            request.window.clone(),
            request.expected_app_key.clone(),
            u32::from(request.require_password_field),
            request.agent.clone(),
            request.secret_names.clone(),
            request.origin.clone(),
            &self.queue.handle(),
            id,
        );
        for value in &request.values {
            let Ok(descriptor) = sealed_value(value.value.expose_secret()) else {
                proxy.destroy();
                return Some(TypingResult::Refused);
            };
            let kind = match value.kind {
                ValueKind::Username => Kind::Username,
                ValueKind::Password => Kind::Password,
            };
            proxy.add_value(descriptor.as_fd(), kind, u32::from(value.tab_after));
        }
        proxy.commit();
        let outcome = self.wait_until(|state| state.done.remove(&id));
        proxy.destroy();
        let _ = self.queue.flush();
        match outcome {
            Waited::Done(outcome) => Some(result_of(outcome)),
            Waited::TimedOut => Some(TypingResult::TimedOut),
            Waited::Lost => None,
        }
    }

    fn wait_until(&mut self, mut answer: impl FnMut(&mut WorkerState) -> Option<u32>) -> Waited {
        let deadline = Instant::now() + REQUEST_TIME;
        loop {
            if self.queue.flush().is_err() || self.queue.dispatch_pending(&mut self.state).is_err()
            {
                return Waited::Lost;
            }
            if let Some(outcome) = answer(&mut self.state) {
                return Waited::Done(outcome);
            }
            let Some(guard) = self.queue.prepare_read() else {
                continue;
            };
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return Waited::TimedOut;
            };
            let timeout = Timespec {
                tv_sec: i64::try_from(left.as_secs()).unwrap_or(i64::MAX),
                tv_nsec: i64::from(left.subsec_nanos()),
            };
            let polled = {
                let descriptor = guard.connection_fd();
                let mut descriptors = [PollFd::new(&descriptor, PollFlags::IN)];
                poll(&mut descriptors, Some(&timeout))
            };
            match polled {
                Ok(0) => return Waited::TimedOut,
                Ok(_) => {
                    if guard.read().is_err() {
                        return Waited::Lost;
                    }
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(_) => return Waited::Lost,
            }
        }
    }
}

enum Waited {
    Done(u32),
    TimedOut,
    Lost,
}

fn result_of(outcome: u32) -> TypingResult {
    [
        (Outcome::Typed, TypingResult::Typed),
        (Outcome::FocusChanged, TypingResult::FocusChanged),
        (Outcome::NotPasswordField, TypingResult::NotPasswordField),
        (Outcome::Cancelled, TypingResult::Cancelled),
        (Outcome::UnknownWindow, TypingResult::UnknownWindow),
        (Outcome::TimedOut, TypingResult::TimedOut),
        (Outcome::TargetMismatch, TypingResult::TargetMismatch),
        (Outcome::SessionLocked, TypingResult::SessionLocked),
    ]
    .into_iter()
    .find(|(known, _)| *known as u32 == outcome)
    .map_or(TypingResult::Refused, |(_, result)| result)
}
