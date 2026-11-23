//! The crownos-ipc side: every request runs with the identity of its caller, and the `Used`
//! events of a request go to subscribers after its reply.

use std::cell::RefCell;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use crownos_ipc::adapter::tokio::serve_with_outbox;
use crownos_ipc::{Message, PeerId, RemoteError, Server};
use secrets_core::{Binding, SecretKind, SecretName, UseOutcome};
use secrets_protocol::secrets::{self, Handler};
use secrets_protocol::transfer::read_value;
use secrets_protocol::{RequestId, SecretMeta, VaultStatus};

use crate::{Caller, ConfigStore, IdentifyCaller, SecretsService, ServiceError};

const LOCK_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Serves until the socket fails.
///
/// # Errors
///
/// Fails when the listening socket fails.
pub async fn serve<Store: ConfigStore, Identity: IdentifyCaller>(
    server: &mut Server,
    service: SecretsService<Store>,
    identity: Identity,
) -> Result<(), crownos_ipc::Error> {
    let service = RefCell::new(service);
    let mut lock_checks = tokio::time::interval(LOCK_CHECK_INTERVAL);
    serve_with_outbox(
        server,
        |server, peer, message| {
            if let Ok(mut service) = service.try_borrow_mut() {
                dispatch(&mut service, &identity, server, peer, message)?;
            }
            Ok(true)
        },
        |context| lock_checks.poll_tick(context).map(|_| Some(())),
        |_, ()| {
            if let Ok(mut service) = service.try_borrow_mut() {
                service.lock_if_expired(Instant::now());
            }
        },
    )
    .await
}

fn dispatch<Store: ConfigStore, Identity: IdentifyCaller>(
    service: &mut SecretsService<Store>,
    identity: &Identity,
    server: &mut Server,
    peer: PeerId,
    message: Message,
) -> Result<(), crownos_ipc::Error> {
    let caller = server
        .credentials(peer)
        .map_or_else(Caller::unidentified, |credentials| {
            identity.identify(credentials)
        });
    let mut requests = PeerRequests {
        service: &mut *service,
        caller: &caller,
    };
    secrets::dispatch(&mut requests, server, peer, message)?;
    for event in service.take_events() {
        if let Err(error) = server.emit(&event) {
            tracing::debug!(%error, "cannot send a Used event");
        }
    }
    Ok(())
}

struct PeerRequests<'request, Store> {
    service: &'request mut SecretsService<Store>,
    caller: &'request Caller,
}

impl<Store: ConfigStore> PeerRequests<'_, Store> {
    fn use_secrets(
        &mut self,
        names: &[SecretName],
        target: &str,
    ) -> Result<UseOutcome, RemoteError> {
        self.service
            .use_secrets(self.caller, names, target, Instant::now())
            .map_err(Into::into)
    }
}

impl<Store: ConfigStore> Handler for PeerRequests<'_, Store> {
    fn status(&mut self) -> Result<VaultStatus, RemoteError> {
        Ok(self.service.status(Instant::now()))
    }

    fn list(&mut self) -> Result<Vec<SecretMeta>, RemoteError> {
        Ok(self.service.list())
    }

    fn request(
        &mut self,
        name: SecretName,
        kind: SecretKind,
        purpose: String,
    ) -> Result<RequestId, RemoteError> {
        self.service
            .request(self.caller, name, kind, &purpose, Instant::now())
            .map_err(Into::into)
    }

    fn type_into(&mut self, name: SecretName, window: String) -> Result<UseOutcome, RemoteError> {
        self.use_secrets(&[name], &format!("window:{window}"))
    }

    fn fill_login(
        &mut self,
        _username: String,
        password: SecretName,
        window: String,
    ) -> Result<UseOutcome, RemoteError> {
        self.use_secrets(&[password], &format!("window:{window}"))
    }

    fn run(&mut self, template: String) -> Result<UseOutcome, RemoteError> {
        self.service
            .run_template(self.caller, &template, Instant::now())
            .map_err(Into::into)
    }

    fn proxy_session(&mut self, names: Vec<SecretName>) -> Result<UseOutcome, RemoteError> {
        self.use_secrets(&names, "http-session")
    }

    fn revoke_session(&mut self, _session: u64) -> Result<UseOutcome, RemoteError> {
        Err(ServiceError::Unavailable.into())
    }

    fn add(
        &mut self,
        name: SecretName,
        kind: SecretKind,
        value: OwnedFd,
    ) -> Result<(), RemoteError> {
        let value = read_value(&value).map_err(ServiceError::from)?;
        self.service
            .add(self.caller, &name, kind, value, Instant::now())
            .map_err(Into::into)
    }

    fn remove(&mut self, name: SecretName) -> Result<bool, RemoteError> {
        self.service
            .remove(self.caller, &name, Instant::now())
            .map_err(Into::into)
    }

    fn bind(&mut self, name: SecretName, binding: Binding) -> Result<(), RemoteError> {
        self.service
            .bind(self.caller, &name, binding, Instant::now())
            .map_err(Into::into)
    }

    fn lock(&mut self) -> Result<(), RemoteError> {
        self.service.lock(self.caller).map_err(Into::into)
    }

    fn unlock(&mut self, master_password: OwnedFd) -> Result<(), RemoteError> {
        let password = read_value(&master_password).map_err(ServiceError::from)?;
        self.service
            .unlock(self.caller, &password, Instant::now())
            .map_err(Into::into)
    }
}
