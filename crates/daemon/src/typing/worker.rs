use std::collections::HashMap;
use std::os::fd::AsFd as _;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use crownos_protocols::secret_input::v1::client::crownos_secret_input_manager_v1::{
    self, CrownosSecretInputManagerV1, Flags, Outcome,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use secrecy::ExposeSecret as _;
use wayland_client::globals::{GlobalListContents, registry_queue_init};
use wayland_client::protocol::wl_registry::WlRegistry;
use wayland_client::{Connection, Dispatch, EventQueue, QueueHandle, WEnum};

use super::value_fd::sealed_value;
use super::{TypingJob, TypingResult, TypingStep};

/// The compositor's own confirmation and the typing must end within this time.
const STEP_TIME: Duration = Duration::from_secs(150);

#[derive(Debug, Default)]
struct WorkerState {
    done: HashMap<u32, u32>,
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
        state: &mut Self,
        _: &CrownosSecretInputManagerV1,
        event: crownos_secret_input_manager_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let crownos_secret_input_manager_v1::Event::Done { id, outcome } = event {
            let outcome = match outcome {
                WEnum::Value(outcome) => outcome as u32,
                WEnum::Unknown(value) => value,
            };
            state.done.insert(id, outcome);
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

    pub(super) fn run(mut self, jobs: &Receiver<TypingJob>) {
        while let Ok(job) = jobs.recv() {
            let mut result = TypingResult::Typed;
            for step in &job.steps {
                result = self.type_one(step);
                if result != TypingResult::Typed {
                    break;
                }
            }
            drop(job.steps);
            let _ = job.answer.send(result);
            if result == TypingResult::Lost {
                break;
            }
        }
    }

    fn type_one(&mut self, step: &TypingStep) -> TypingResult {
        let Ok(value) = sealed_value(step.value.expose_secret()) else {
            return TypingResult::Refused;
        };
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let mut flags = Flags::None;
        if step.tab_after {
            flags |= Flags::TabAfter;
        }
        if step.confirmed {
            flags |= Flags::Confirmed;
        }
        self.manager.type_secret(
            id,
            step.window.clone(),
            u32::from(step.require_password_field),
            flags,
            step.agent.clone(),
            step.secret_name.clone(),
            step.origin.clone(),
            value.as_fd(),
        );
        drop(value);
        match self.wait_for(id) {
            Some(outcome) => result_of(outcome),
            None => TypingResult::Lost,
        }
    }

    /// Reads events until `done(id)`; `None` when the connection broke or the time ran out.
    fn wait_for(&mut self, id: u32) -> Option<u32> {
        let deadline = Instant::now() + STEP_TIME;
        loop {
            self.queue.flush().ok()?;
            self.queue.dispatch_pending(&mut self.state).ok()?;
            if let Some(outcome) = self.state.done.remove(&id) {
                return Some(outcome);
            }
            let Some(guard) = self.queue.prepare_read() else {
                continue;
            };
            let left = deadline.checked_duration_since(Instant::now())?;
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
                Ok(0) => return None,
                Ok(_) => {
                    guard.read().ok()?;
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(_) => return None,
            }
        }
    }
}

const fn result_of(outcome: u32) -> TypingResult {
    match outcome {
        value if value == Outcome::Typed as u32 => TypingResult::Typed,
        value if value == Outcome::FocusChanged as u32 => TypingResult::FocusChanged,
        value if value == Outcome::NotPasswordField as u32 => TypingResult::NotPasswordField,
        value if value == Outcome::Cancelled as u32 => TypingResult::Cancelled,
        _ => TypingResult::Refused,
    }
}
