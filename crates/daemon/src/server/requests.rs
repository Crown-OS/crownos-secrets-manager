use std::os::fd::OwnedFd;
use std::time::Instant;

use crownos_ipc::RemoteError;
use secrets_core::{
    Binding, RunTemplate, SecretKind, SecretName, TemplateName, UseOutcome, VaultSettings,
};
use secrets_protocol::secrets::PeerHandler;
use secrets_protocol::transfer::read_value;
use secrets_protocol::{
    ProxySessionReply, RequestId, RunReply, SecretMeta, TemplateMeta, TypingTarget, VaultStatus,
};

use crate::{IdentifyCaller, SecretsService};

pub(super) struct PeerRequests<'request, Identity> {
    pub(super) service: &'request mut SecretsService,
    pub(super) identity: &'request Identity,
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
