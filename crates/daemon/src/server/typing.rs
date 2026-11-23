//! `type_into` and `fill_login`: one decoder, then checks at once and the compositor's answer
//! from a task. The compositor's own dialog is the only confirmation for typing.

use std::time::Instant;

use crownos_ipc::{Message, MethodMsg, PeerId, Server};
use secrets_core::{SecretName, UseOutcome};
use secrets_protocol::{TypingTarget, secrets};
use tokio::sync::mpsc::UnboundedSender;

use super::replies::{encoded, send_reply};
use super::{MAX_WINDOW_CHARACTERS, Outgoing};
use crate::service::{TypingShape, TypingStart, typing_outcome};
use crate::util::caller_text::sanitized;
use crate::{Caller, SecretsService};

/// A decoded `type_into` or `fill_login` request.
pub(super) struct TypingRequest {
    pub(super) names: Vec<SecretName>,
    pub(super) target: TypingTarget,
    pub(super) shape: TypingShape,
}

impl TypingRequest {
    pub(super) fn decode(message: &Message) -> Option<Self> {
        let payload = &message.payload;
        if message.selector == <secrets::type_into as MethodMsg>::SELECTOR {
            let request: secrets::type_into = crownos_ipc::postcard::from_bytes(payload).ok()?;
            return Some(Self {
                names: vec![request.name],
                target: request.target,
                shape: TypingShape::Single,
            });
        }
        if message.selector == <secrets::fill_login as MethodMsg>::SELECTOR {
            let request: secrets::fill_login = crownos_ipc::postcard::from_bytes(payload).ok()?;
            return Some(Self {
                names: vec![request.username, request.password],
                target: request.target,
                shape: TypingShape::Login,
            });
        }
        None
    }
}

/// Who asked, and where the answer goes.
pub(super) struct TypingContext<'context> {
    pub(super) service: &'context mut SecretsService,
    pub(super) caller: &'context Caller,
    pub(super) server: &'context mut Server,
    pub(super) peer: PeerId,
    pub(super) request_id: u32,
    pub(super) outgoing: &'context UnboundedSender<Outgoing>,
}

/// Checks a typing request at once; the compositor's answer comes from a task.
pub(super) fn start_typing(context: TypingContext<'_>, request: &TypingRequest) {
    let TypingContext {
        service,
        caller,
        server,
        peer,
        request_id,
        outgoing,
    } = context;
    let text = typing_target_text(&request.target);
    let started = service.start_typing(
        caller,
        &request.names,
        &request.target,
        request.shape,
        &text,
        Instant::now(),
    );
    match started {
        Ok(TypingStart::Refused(outcome)) => send_reply(server, peer, request_id, &Ok(outcome)),
        Err(error) => send_reply::<UseOutcome>(server, peer, request_id, &Err(error.into())),
        Ok(TypingStart::Waiting(answer)) => {
            let outgoing = outgoing.clone();
            tokio::spawn(async move {
                let outcome = answer.await.map_or(UseOutcome::Cancelled, typing_outcome);
                let _ = outgoing.send(Outgoing::Reply {
                    peer,
                    request: request_id,
                    reply: encoded(Ok(outcome)),
                });
            });
        }
    }
}

fn typing_target_text(target: &TypingTarget) -> String {
    let window = sanitized(&target.window, MAX_WINDOW_CHARACTERS);
    let app_id = sanitized(&target.app_id, MAX_WINDOW_CHARACTERS);
    match &target.origin {
        Some(origin) => format!(
            "typing into {app_id} (window {window}) at {}",
            sanitized(origin, MAX_WINDOW_CHARACTERS)
        ),
        None => format!("typing into {app_id} (window {window})"),
    }
}
