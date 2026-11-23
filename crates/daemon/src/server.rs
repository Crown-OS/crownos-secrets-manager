//! The crownos-ipc side: every request runs with the identity of its caller, and the `Used`
//! events of a request go to subscribers after its reply.

use std::cell::RefCell;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::task::Poll;
use std::time::{Duration, Instant};

use crownos_ipc::adapter::tokio::serve_with_outbox;
use crownos_ipc::{Kind, Message, MethodMsg, PeerId, RemoteError, Server, ServiceBuilder};
use secrets_core::{
    Binding, RunTemplate, SecretKind, SecretName, TemplateName, UseOutcome, VaultSettings,
};
use secrets_protocol::secrets::{self, PeerHandler};
use secrets_protocol::transfer::read_value;
use secrets_protocol::{
    ProxySessionReply, RequestId, RunReply, SecretMeta, TemplateMeta, TypingTarget, VaultStatus,
};

use crate::util::caller_text::sanitized;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

use crate::confirmation::{DialogRequest, Verdict};
use crate::service::{Confirmation, RunStart, TypingShape, TypingStart, typing_outcome};
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
/// caller's socket cannot speak as that caller. Without pidfs or `SO_PASSPIDFD` it binds without
/// the check and warns.
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
        tracing::warn!(%error, "no per-frame sender check on this kernel");
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
                } => send_encoded_reply(server, peer, request, reply),
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

fn send_encoded_reply(
    server: &mut Server,
    peer: PeerId,
    request: u32,
    reply: Result<Vec<u8>, RemoteError>,
) {
    let sent = match reply {
        Ok(payload) => server.reply(peer, request, &payload, Vec::new()),
        Err(error) => server.reply_err(peer, request, &error),
    };
    if let Err(error) = sent {
        tracing::debug!(%error, "cannot send a reply; the caller may have gone");
    }
}

/// The encoded form of a reply for [`Outgoing::Reply`].
fn encoded<Reply: serde::Serialize>(
    reply: Result<Reply, RemoteError>,
) -> Result<Vec<u8>, RemoteError> {
    reply.and_then(|reply| {
        crownos_ipc::postcard::to_stdvec(&reply)
            .map_err(|_| RemoteError::handler("reply encoding failed"))
    })
}

fn send_reply<Reply: serde::Serialize>(
    server: &mut Server,
    peer: PeerId,
    request: u32,
    reply: &Result<Reply, RemoteError>,
) {
    let sent = match reply {
        Ok(reply) => match crownos_ipc::postcard::to_stdvec(reply) {
            Ok(payload) => server.reply(peer, request, &payload, Vec::new()),
            Err(_) => server.reply_err(
                peer,
                request,
                &RemoteError::handler("reply encoding failed"),
            ),
        },
        Err(error) => server.reply_err(peer, request, error),
    };
    if let Err(error) = sent {
        tracing::debug!(%error, "cannot send a reply; the caller may have gone");
    }
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
        && let Some((names, target)) = use_request(service, &message)
        && !typing_target_refused(service, &message, &names)
    {
        match service.confirmation_for(&caller, &names, &target, Instant::now()) {
            Confirmation::Ask(request) => {
                ask_first(service, peer, message, request, finished_runs);
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

/// A typing request whose target the bindings refuse gets no dialog; dispatch refuses it.
fn typing_target_refused(
    service: &mut SecretsService,
    message: &Message,
    names: &[SecretName],
) -> bool {
    typing_request(message).is_some_and(|(_, target, _)| {
        service
            .typing_target_refusal(names, &target, Instant::now())
            .is_some()
    })
}

/// The secrets, target and shape of a `type_into` or `fill_login` request.
fn typing_request(message: &Message) -> Option<(Vec<SecretName>, TypingTarget, TypingShape)> {
    let payload = &message.payload;
    if message.selector == <secrets::type_into as MethodMsg>::SELECTOR {
        let request: secrets::type_into = crownos_ipc::postcard::from_bytes(payload).ok()?;
        return Some((vec![request.name], request.target, TypingShape::Single));
    }
    if message.selector == <secrets::fill_login as MethodMsg>::SELECTOR {
        let request: secrets::fill_login = crownos_ipc::postcard::from_bytes(payload).ok()?;
        return Some((
            vec![request.username, request.password],
            request.target,
            TypingShape::Login,
        ));
    }
    None
}

/// Checks a typing request at once; the compositor's answer comes from a task.
#[allow(clippy::too_many_arguments)]
fn start_typing(
    service: &mut SecretsService,
    caller: &Caller,
    server: &mut Server,
    peer: PeerId,
    request: u32,
    names: &[SecretName],
    target: &TypingTarget,
    shape: TypingShape,
    outgoing: &UnboundedSender<Outgoing>,
) {
    let text = typing_target_text(target);
    match service.start_typing(caller, names, target, shape, &text, Instant::now()) {
        Ok(TypingStart::Refused(outcome)) => send_reply(server, peer, request, &Ok(outcome)),
        Err(error) => send_reply::<UseOutcome>(server, peer, request, &Err(error.into())),
        Ok(TypingStart::Waiting(answer)) => {
            let outgoing = outgoing.clone();
            tokio::spawn(async move {
                let outcome = answer.await.map_or(UseOutcome::Cancelled, typing_outcome);
                let _ = outgoing.send(Outgoing::Reply {
                    peer,
                    request,
                    reply: encoded(Ok(outcome)),
                });
            });
        }
    }
}

/// Opens the dialog in a task; the answer comes back as [`Outgoing::Answered`].
fn ask_first(
    service: &mut SecretsService,
    peer: PeerId,
    message: Message,
    request: DialogRequest,
    outgoing: &UnboundedSender<Outgoing>,
) {
    service.dialog_opened(&request);
    let asker = service.confirmation_asker();
    let outgoing = outgoing.clone();
    tokio::spawn(async move {
        let verdict = asker.ask(request.clone()).await;
        let _ = outgoing.send(Outgoing::Answered {
            peer,
            message,
            request,
            verdict,
        });
    });
}

/// The secrets that a request wants to use, and a text for the dialog, or `None` for a request
/// that uses no secret.
fn use_request(
    service: &mut SecretsService,
    message: &Message,
) -> Option<(Vec<SecretName>, String)> {
    let payload = &message.payload;
    let decode_failed = |_| ();
    match message.selector {
        selector if selector == <secrets::type_into as MethodMsg>::SELECTOR => {
            let request: secrets::type_into = crownos_ipc::postcard::from_bytes(payload)
                .map_err(decode_failed)
                .ok()?;
            Some((vec![request.name], typing_target_text(&request.target)))
        }
        selector if selector == <secrets::fill_login as MethodMsg>::SELECTOR => {
            let request: secrets::fill_login = crownos_ipc::postcard::from_bytes(payload)
                .map_err(decode_failed)
                .ok()?;
            Some((
                vec![request.username, request.password],
                typing_target_text(&request.target),
            ))
        }
        selector if selector == <secrets::run as MethodMsg>::SELECTOR => {
            let request: secrets::run = crownos_ipc::postcard::from_bytes(payload)
                .map_err(decode_failed)
                .ok()?;
            let names = service.template_secret_names(&request.template, Instant::now())?;
            Some((
                names,
                format!("the command template “{}”", request.template),
            ))
        }
        selector if selector == <secrets::proxy_session as MethodMsg>::SELECTOR => {
            let request: secrets::proxy_session = crownos_ipc::postcard::from_bytes(payload)
                .map_err(decode_failed)
                .ok()?;
            let hosts = service.proxy_hosts(&request.names, Instant::now());
            Some((request.names, format!("HTTPS requests to {hosts}")))
        }
        _ => None,
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
        start_run(service, caller, server, peer, &message, finished_runs);
        return Ok(());
    }
    if message.kind == Kind::Request
        && let Some((names, target, shape)) = typing_request(&message)
    {
        start_typing(
            service,
            caller,
            server,
            peer,
            message.req_id,
            &names,
            &target,
            shape,
            finished_runs,
        );
        return Ok(());
    }
    let mut requests = PeerRequests {
        service: &mut *service,
        identity,
    };
    secrets::dispatch_with_peer(&mut requests, server, peer, message)
}

/// Checks a run at once; a run that passes goes to a task, which answers when it ends.
fn start_run(
    service: &mut SecretsService,
    caller: &Caller,
    server: &mut Server,
    peer: PeerId,
    message: &Message,
    finished_runs: &UnboundedSender<Outgoing>,
) {
    let Ok(arguments) = crownos_ipc::postcard::from_bytes::<secrets::run>(&message.payload) else {
        server.drop_peer(peer);
        return;
    };
    let request = message.req_id;
    let started = service.prepare_run(
        caller,
        &arguments.template,
        &arguments.arguments,
        &arguments.cwd,
        Instant::now(),
    );
    match started {
        Ok(RunStart::Refused(reply)) => send_reply(server, peer, request, &Ok(reply)),
        Err(error) => send_reply::<RunReply>(server, peer, request, &Err(error.into())),
        Ok(RunStart::Ready(job)) => {
            let finished_runs = finished_runs.clone();
            tokio::spawn(async move {
                let reply = job.execute().await.map_err(RemoteError::from);
                let _ = finished_runs.send(Outgoing::Reply {
                    peer,
                    request,
                    reply: encoded(reply),
                });
            });
        }
    }
}

struct PeerRequests<'request, Identity> {
    service: &'request mut SecretsService,
    identity: &'request Identity,
}

impl<Identity: IdentifyCaller> PeerHandler for PeerRequests<'_, Identity> {
    fn status(&mut self, peer: crownos_ipc::Caller<'_>) -> Result<VaultStatus, RemoteError> {
        Ok(self
            .service
            .status(&self.identity.identify(peer.credentials), Instant::now()))
    }

    fn list(&mut self, _peer: crownos_ipc::Caller<'_>) -> Result<Vec<SecretMeta>, RemoteError> {
        self.service.list(Instant::now()).map_err(Into::into)
    }

    fn templates(
        &mut self,
        _peer: crownos_ipc::Caller<'_>,
    ) -> Result<Vec<TemplateMeta>, RemoteError> {
        self.service.templates(Instant::now()).map_err(Into::into)
    }

    fn request(
        &mut self,
        peer: crownos_ipc::Caller<'_>,
        name: SecretName,
        kind: SecretKind,
        purpose: String,
    ) -> Result<RequestId, RemoteError> {
        self.service
            .request(
                &self.identity.identify(peer.credentials),
                name,
                kind,
                &purpose,
                Instant::now(),
            )
            .map_err(Into::into)
    }

    /// Never reached: [`start_typing`] answers `type_into` first.
    fn type_into(
        &mut self,
        _peer: crownos_ipc::Caller<'_>,
        _name: SecretName,
        _target: TypingTarget,
    ) -> Result<UseOutcome, RemoteError> {
        Err(RemoteError::handler("typing is answered by its own task"))
    }

    /// Never reached: [`start_typing`] answers `fill_login` first.
    fn fill_login(
        &mut self,
        _peer: crownos_ipc::Caller<'_>,
        _username: SecretName,
        _password: SecretName,
        _target: TypingTarget,
    ) -> Result<UseOutcome, RemoteError> {
        Err(RemoteError::handler("typing is answered by its own task"))
    }

    /// Never reached: [`start_run`] answers `run` before the generated dispatch sees it.
    fn run(
        &mut self,
        _peer: crownos_ipc::Caller<'_>,
        _template: TemplateName,
        _arguments: Vec<String>,
        _cwd: String,
    ) -> Result<RunReply, RemoteError> {
        Err(RemoteError::handler("run is answered by its own task"))
    }

    fn proxy_session(
        &mut self,
        peer: crownos_ipc::Caller<'_>,
        names: Vec<SecretName>,
        ttl_minutes: u32,
    ) -> Result<ProxySessionReply, RemoteError> {
        self.service
            .proxy_session(
                &self.identity.identify(peer.credentials),
                &names,
                ttl_minutes,
                Instant::now(),
            )
            .map_err(Into::into)
    }

    fn revoke_session(
        &mut self,
        peer: crownos_ipc::Caller<'_>,
        session: u64,
    ) -> Result<bool, RemoteError> {
        Ok(self
            .service
            .revoke_session(&self.identity.identify(peer.credentials), session))
    }

    fn init(
        &mut self,
        peer: crownos_ipc::Caller<'_>,
        master_password: OwnedFd,
    ) -> Result<(), RemoteError> {
        self.service
            .init(
                &self.identity.identify(peer.credentials),
                || read_value(&master_password),
                Instant::now(),
            )
            .map_err(Into::into)
    }

    fn unlock(
        &mut self,
        peer: crownos_ipc::Caller<'_>,
        master_password: OwnedFd,
    ) -> Result<(), RemoteError> {
        self.service
            .unlock(
                &self.identity.identify(peer.credentials),
                || read_value(&master_password),
                Instant::now(),
            )
            .map_err(Into::into)
    }

    fn lock(&mut self, peer: crownos_ipc::Caller<'_>) -> Result<(), RemoteError> {
        self.service
            .lock(&self.identity.identify(peer.credentials))
            .map_err(Into::into)
    }

    fn add(
        &mut self,
        peer: crownos_ipc::Caller<'_>,
        name: SecretName,
        kind: SecretKind,
        master_password: OwnedFd,
        value: OwnedFd,
    ) -> Result<(), RemoteError> {
        self.service
            .add(
                &self.identity.identify(peer.credentials),
                &name,
                kind,
                || read_value(&master_password),
                || read_value(&value),
                Instant::now(),
            )
            .map_err(Into::into)
    }

    fn remove(
        &mut self,
        peer: crownos_ipc::Caller<'_>,
        name: SecretName,
        master_password: OwnedFd,
    ) -> Result<bool, RemoteError> {
        self.service
            .remove(
                &self.identity.identify(peer.credentials),
                &name,
                || read_value(&master_password),
                Instant::now(),
            )
            .map_err(Into::into)
    }

    fn bind(
        &mut self,
        peer: crownos_ipc::Caller<'_>,
        name: SecretName,
        binding: Binding,
        master_password: OwnedFd,
    ) -> Result<(), RemoteError> {
        self.service
            .bind(
                &self.identity.identify(peer.credentials),
                &name,
                binding,
                || read_value(&master_password),
                Instant::now(),
            )
            .map_err(Into::into)
    }

    fn set_template(
        &mut self,
        peer: crownos_ipc::Caller<'_>,
        name: TemplateName,
        template: Option<RunTemplate>,
        master_password: OwnedFd,
    ) -> Result<(), RemoteError> {
        self.service
            .set_template(
                &self.identity.identify(peer.credentials),
                &name,
                template,
                || read_value(&master_password),
                Instant::now(),
            )
            .map_err(Into::into)
    }

    fn configure(
        &mut self,
        peer: crownos_ipc::Caller<'_>,
        settings: VaultSettings,
        master_password: OwnedFd,
    ) -> Result<(), RemoteError> {
        self.service
            .configure(
                &self.identity.identify(peer.credentials),
                settings,
                || read_value(&master_password),
                Instant::now(),
            )
            .map_err(Into::into)
    }
}
