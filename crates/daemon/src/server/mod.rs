//! The crownos-ipc side: every request runs with the identity of its caller, and the `Used`
//! events of a request go to subscribers after its reply. Runs, typing and dialogs answer from
//! tasks through the outbox, so the request loop never waits.

mod dialog;
mod replies;
mod requests;
mod runs;
mod typing;

use std::cell::RefCell;
use std::path::Path;
use std::task::Poll;
use std::time::{Duration, Instant};

use crownos_ipc::adapter::tokio::serve_with_outbox;
use crownos_ipc::{Kind, Message, MethodMsg, PeerId, RemoteError, Server, ServiceBuilder};
use secrets_protocol::secrets;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

use crate::confirmation::{DialogRequest, Verdict};
use crate::service::Confirmation;
use crate::{Caller, IdentifyCaller, SecretsService};

const LOCK_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const MAX_WINDOW_CHARACTERS: usize = 128;

/// What the rest of the daemon sends to the request loop.
enum Outgoing {
    LockCheck,
    /// The encoded reply of a request that a task finished.
    Reply {
        peer: PeerId,
        request: u32,
        reply: Result<Vec<u8>, RemoteError>,
    },
    /// The user answered the dialog for this message, which now goes through dispatch again.
    Answered {
        peer: PeerId,
        message: Message,
        request: DialogRequest,
        verdict: Verdict,
    },
}

/// Binds the socket with a check of the sender of every frame, so a child that inherited a
/// caller's socket cannot speak as that caller. Without pidfs or `SO_PASSPIDFD` a release build
/// refuses to start; a debug build binds without the check and warns.
///
/// # Errors
///
/// Fails when the socket cannot be bound.
pub fn bind_socket(directory: Option<&Path>) -> Result<Server, crownos_ipc::Error> {
    let builder = |verify| {
        let builder = ServiceBuilder::new(secrets::SERVICE).verify_sender_per_frame(verify);
        match directory {
            Some(directory) => builder.directory(directory),
            None => builder,
        }
    };
    builder(true).build().or_else(|error| {
        if !cfg!(debug_assertions) {
            return Err(error);
        }
        tracing::warn!(%error, "no per-frame sender check on this kernel; a debug build goes on");
        builder(false).build()
    })
}

/// Serves until the socket fails. A run answers from a task when it ends, so it never holds up
/// the request loop.
///
/// # Errors
///
/// Fails when the listening socket fails.
pub async fn serve<Identity: IdentifyCaller>(
    server: &mut Server,
    service: SecretsService,
    identity: Identity,
) -> Result<(), crownos_ipc::Error> {
    let service = RefCell::new(service);
    let mut lock_checks = tokio::time::interval(LOCK_CHECK_INTERVAL);
    let (finished_runs, mut finished_run_receiver) = unbounded_channel();
    serve_with_outbox(
        server,
        |server, peer, message| {
            let mut service = service.try_borrow_mut().map_err(|_| {
                crownos_ipc::Error::Io(std::io::Error::other(
                    "a request arrived while the service was busy; stopping instead of dropping it",
                ))
            })?;
            dispatch(
                &mut service,
                &identity,
                server,
                peer,
                message,
                &finished_runs,
            )?;
            Ok(true)
        },
        |context| match finished_run_receiver.poll_recv(context) {
            Poll::Ready(Some(finished)) => Poll::Ready(Some(finished)),
            _ => lock_checks
                .poll_tick(context)
                .map(|_| Some(Outgoing::LockCheck)),
        },
        |server, outgoing| {
            let Ok(mut service) = service.try_borrow_mut() else {
                return;
            };
            match outgoing {
                Outgoing::LockCheck => service.lock_if_expired(Instant::now()),
                Outgoing::Reply {
                    peer,
                    request,
                    reply,
                } => replies::send_encoded_reply(server, peer, request, reply),
                Outgoing::Answered {
                    peer,
                    message,
                    request,
                    verdict,
                } => {
                    service.dialog_answered(&request, verdict, Instant::now());
                    if let Err(error) = dispatch(
                        &mut service,
                        &identity,
                        server,
                        peer,
                        message,
                        &finished_runs,
                    ) {
                        tracing::warn!(%error, "cannot answer a request after its dialog");
                    }
                }
            }
        },
    )
    .await
}

fn dispatch<Identity: IdentifyCaller>(
    service: &mut SecretsService,
    identity: &Identity,
    server: &mut Server,
    peer: PeerId,
    message: Message,
    finished_runs: &UnboundedSender<Outgoing>,
) -> Result<(), crownos_ipc::Error> {
    let caller = server
        .credentials(peer)
        .map_or_else(Caller::unidentified, |credentials| {
            identity.identify(credentials)
        });
    if message.kind == Kind::Request
        && let Some(request) = typing::TypingRequest::decode(&message)
    {
        typing::start_typing(
            typing::TypingContext {
                service,
                caller: &caller,
                server,
                peer,
                request_id: message.req_id,
                outgoing: finished_runs,
            },
            &request,
        );
        return Ok(());
    }
    if message.kind == Kind::Request
        && let Some((names, target)) = dialog::use_request(service, &message)
    {
        match service.confirmation_for(&caller, &names, &target, Instant::now()) {
            Confirmation::Ask(request) => {
                dialog::ask_first(service, peer, message, request, finished_runs);
                return Ok(());
            }
            Confirmation::Refuse => service.decide_denied(&caller, &names),
            Confirmation::NotNeeded => {}
        }
    }
    let dispatched = dispatch_now(
        service,
        identity,
        &caller,
        server,
        peer,
        message,
        finished_runs,
    );
    service.forget_decision();
    for event in service.take_events() {
        if let Err(error) = server.emit(&event) {
            tracing::debug!(%error, "cannot send a Used event");
        }
    }
    dispatched
}

fn dispatch_now<Identity: IdentifyCaller>(
    service: &mut SecretsService,
    identity: &Identity,
    caller: &Caller,
    server: &mut Server,
    peer: PeerId,
    message: Message,
    finished_runs: &UnboundedSender<Outgoing>,
) -> Result<(), crownos_ipc::Error> {
    if message.kind == Kind::Request && message.selector == <secrets::run as MethodMsg>::SELECTOR {
        runs::start_run(service, caller, server, peer, &message, finished_runs);
        return Ok(());
    }
    let mut requests = requests::PeerRequests {
        service: &mut *service,
        identity,
    };
    secrets::dispatch_with_peer(&mut requests, server, peer, message)
}
