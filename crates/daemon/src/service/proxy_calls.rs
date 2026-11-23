//! HTTPS proxy sessions: the agent gets a proxy URL and a CA to trust, never a key.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::SecretName;
use secrets_protocol::{Placeholder, ProxySession, ProxySessionReply};
use secrets_proxy::{CertificateAuthority, PLACEHOLDER_PREFIX, Proxy, SessionSecret};

use super::{SecretsService, ServiceError};
use crate::{Caller, audit};

const CA_KEY_RECORD: &str = "proxy-ca-key";
const CA_CERTIFICATE_RECORD: &str = "proxy-ca-certificate";
const CA_FILE_NAME: &str = "secrets-ca.pem";
const MAX_SESSION_MINUTES: u32 = 60;

impl SecretsService {
    /// Starts a proxy session for `names`. Each secret needs an HTTP binding.
    ///
    /// # Errors
    ///
    /// Fails when the CA or the proxy cannot be set up.
    pub fn proxy_session(
        &mut self,
        caller: &Caller,
        names: &[SecretName],
        ttl_minutes: u32,
        now: Instant,
    ) -> Result<ProxySessionReply, ServiceError> {
        if let Some(outcome) = self.refusal_for_use(caller, names, "http-session", now) {
            return Ok(ProxySessionReply::Refused(outcome));
        }
        let contents = self.vault.contents(now)?;
        let mut secrets = Vec::with_capacity(names.len());
        for name in names {
            let http = contents
                .rules()
                .secrets
                .get(name)
                .map(|entry| entry.binding.http.clone())
                .unwrap_or_default();
            if http.is_empty() {
                return Ok(ProxySessionReply::NoHttpBinding(name.clone()));
            }
            let value = contents
                .value(name)
                .ok_or_else(|| ServiceError::UnknownSecret(name.clone()))?;
            secrets.push(SessionSecret {
                name: name.clone(),
                value: SecretSlice::from(value.expose_secret().to_vec()),
                http,
            });
        }
        let ca_path = self.ca_path();
        let id = self.next_session_id;
        self.next_session_id += 1;
        let minutes = ttl_minutes.clamp(1, MAX_SESSION_MINUTES);
        let lifetime = Duration::from_secs(u64::from(minutes) * 60);
        let proxy_url = self
            .running_proxy(now)?
            .open_session(id, &caller.to_string(), secrets, lifetime)
            .map_err(|error| ServiceError::Proxy(error.to_string()))?;
        audit::use_decided(caller, names, "http-session", "started");
        self.mark_used(names);
        Ok(ProxySessionReply::Started(ProxySession {
            session: id,
            proxy_url,
            ca_path: ca_path.to_string_lossy().into_owned(),
            placeholders: names
                .iter()
                .map(|name| Placeholder {
                    name: name.clone(),
                    text: format!("{PLACEHOLDER_PREFIX}{name}"),
                })
                .collect(),
            expires_in_seconds: lifetime.as_secs(),
        }))
    }

    /// Returns whether the caller had this session open.
    pub fn revoke_session(&mut self, caller: &Caller, session: u64) -> bool {
        self.proxy
            .as_ref()
            .is_some_and(|proxy| proxy.revoke_session(session, &caller.to_string()))
    }

    fn ca_path(&self) -> PathBuf {
        self.data_directory.join(CA_FILE_NAME)
    }

    fn running_proxy(&mut self, now: Instant) -> Result<&Proxy, ServiceError> {
        if self.proxy.is_none() {
            let authority = self.certificate_authority(now)?;
            std::fs::create_dir_all(&self.data_directory)
                .and_then(|()| std::fs::write(self.ca_path(), authority.certificate_pem()))
                .map_err(|error| ServiceError::Proxy(error.to_string()))?;
            let roots = self
                .upstream_roots
                .clone()
                .unwrap_or_else(secrets_proxy::system_roots);
            let proxy = Proxy::start(authority, roots)
                .map_err(|error| ServiceError::Proxy(error.to_string()))?;
            self.proxy = Some(proxy);
        }
        self.proxy
            .as_ref()
            .ok_or_else(|| ServiceError::Proxy("the proxy did not start".into()))
    }

    /// The CA from the vault, or a new one that goes into the vault.
    fn certificate_authority(
        &mut self,
        now: Instant,
    ) -> Result<CertificateAuthority, ServiceError> {
        let contents = self.vault.contents_mut(now)?;
        if let (Some(key), Some(certificate)) = (
            contents.internal(CA_KEY_RECORD),
            contents.internal(CA_CERTIFICATE_RECORD),
        ) {
            return CertificateAuthority::load(key, certificate.expose_secret())
                .map_err(|error| ServiceError::Proxy(error.to_string()));
        }
        let (authority, key, certificate) = CertificateAuthority::generate()
            .map_err(|error| ServiceError::Proxy(error.to_string()))?;
        contents.set_internal(CA_KEY_RECORD, key)?;
        contents.set_internal(CA_CERTIFICATE_RECORD, SecretSlice::from(certificate))?;
        Ok(authority)
    }
}
