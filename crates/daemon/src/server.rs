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
    ProxySessionReply, RequestId, RunReply, SecretMeta, TemplateMeta, VaultStatus,
};

use crate::util::caller_text::sanitized;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

use crate::service::RunStart;
use crate::{Caller, IdentifyCaller, SecretsService};

const LOCK_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const MAX_WINDOW_CHARACTERS: usize = 128;

/// What the rest of the daemon sends to the request loop.
enum Outgoing {
    LockCheck,
    RunFinished {
        peer: PeerId,
        request: u32,
        reply: Result<RunReply, RemoteError>,
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
        |server, outgoing| match outgoing {
            Outgoing::LockCheck => {
                if let Ok(mut service) = service.try_borrow_mut() {
                    service.lock_if_expired(Instant::now());
                }
            }
            Outgoing::RunFinished {
                peer,
                request,
                reply,
            } => send_reply(server, peer, request, &reply),
        },
    )
    .await
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
    if message.kind == Kind::Request && message.selector == <secrets::run as MethodMsg>::SELECTOR {
        start_run(service, &caller, server, peer, &message, finished_runs);
    } else {
        let mut requests = PeerRequests {
            service: &mut *service,
            identity,
        };
        secrets::dispatch_with_peer(&mut requests, server, peer, message)?;
    }
    for event in service.take_events() {
        if let Err(error) = server.emit(&event) {
            tracing::debug!(%error, "cannot send a Used event");
        }
    }
    Ok(())
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
                let _ = finished_runs.send(Outgoing::RunFinished {
                    peer,
                    request,
                    reply,
                });
            });
        }
    }
}

struct PeerRequests<'request, Identity> {
    service: &'request mut SecretsService,
    identity: &'request Identity,
}

fn window_target(window: &str) -> String {
    format!("window:{}", sanitized(window, MAX_WINDOW_CHARACTERS))
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

    fn type_into(
        &mut self,
        peer: crownos_ipc::Caller<'_>,
        name: SecretName,
        window: String,
    ) -> Result<UseOutcome, RemoteError> {
        self.service
            .use_secrets(
                &self.identity.identify(peer.credentials),
                &[name],
                &window_target(&window),
                Instant::now(),
            )
            .map_err(Into::into)
    }

    fn fill_login(
        &mut self,
        peer: crownos_ipc::Caller<'_>,
        _username: String,
        password: SecretName,
        window: String,
    ) -> Result<UseOutcome, RemoteError> {
        self.service
            .use_secrets(
                &self.identity.identify(peer.credentials),
                &[password],
                &window_target(&window),
                Instant::now(),
            )
            .map_err(Into::into)
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
