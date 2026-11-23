//! HTTPS proxy sessions: the agent gets a proxy URL and a CA to trust, never a key.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::SecretName;
use secrets_protocol::{ProxySession, ProxySessionReply};
use secrets_proxy::{CertificateAuthority, Proxy, SessionSecret};

use super::{SecretsService, ServiceError};
use crate::{Caller, audit};

const CA_KEY_RECORD: &str = "proxy-ca-key";
const CA_CERTIFICATE_RECORD: &str = "proxy-ca-certificate";
const CA_SCOPE_RECORD: &str = "proxy-ca-scope";
const CA_FILE_NAME: &str = "secrets-ca.pem";
/// A CA with less time left than this is replaced at the next session.
const CA_RENEW_BEFORE_SECONDS: i64 = 30 * 24 * 60 * 60;
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

    /// The running proxy, started or restarted when the CA it needs differs from the one it
    /// has: a new set of bound hosts, or a CA close to its end.
    fn running_proxy(&mut self, now: Instant) -> Result<&Proxy, ServiceError> {
        let hosts = self.bound_hosts(now)?;
        let scope_is_current = self
            .proxy
            .as_ref()
            .is_some_and(|_| self.proxy_ca_hosts.as_deref() == Some(hosts.as_str()));
        if !scope_is_current {
            self.proxy = None;
            let authority = self.certificate_authority(&hosts, now)?;
            write_replacing(&self.ca_path(), authority.certificate_pem().as_bytes())
                .map_err(|error| ServiceError::Proxy(error.to_string()))?;
            let roots = self
                .upstream_roots
                .clone()
                .unwrap_or_else(secrets_proxy::system_roots);
            let proxy = Proxy::start(authority, roots)
                .map_err(|error| ServiceError::Proxy(error.to_string()))?;
            self.proxy = Some(proxy);
            self.proxy_ca_hosts = Some(hosts);
        }
        self.proxy
            .as_ref()
            .ok_or_else(|| ServiceError::Proxy("the proxy did not start".into()))
    }

    /// Every HTTP binding host in the vault, sorted and joined by `,`.
    fn bound_hosts(&mut self, now: Instant) -> Result<String, ServiceError> {
        let contents = self.vault.contents(now)?;
        let hosts: std::collections::BTreeSet<&str> = contents
            .rules()
            .secrets
            .values()
            .flat_map(|entry| entry.binding.http.iter().map(|http| http.host.as_str()))
            .collect();
        Ok(hosts.into_iter().collect::<Vec<_>>().join(","))
    }

    /// The CA from the vault when it covers `hosts` and has more than 30 days left; otherwise a
    /// new one that replaces it in the vault.
    fn certificate_authority(
        &mut self,
        hosts: &str,
        now: Instant,
    ) -> Result<CertificateAuthority, ServiceError> {
        let contents = self.vault.contents_mut(now)?;
        if let (Some(key), Some(certificate), Some(scope)) = (
            contents.internal(CA_KEY_RECORD),
            contents.internal(CA_CERTIFICATE_RECORD),
            contents.internal(CA_SCOPE_RECORD),
        ) && CaScope::parse(scope.expose_secret()).is_some_and(|scope| scope.covers(hosts))
        {
            return CertificateAuthority::load(key, certificate.expose_secret())
                .map_err(|error| ServiceError::Proxy(error.to_string()));
        }
        let patterns: Vec<String> = hosts.split(',').map(str::to_owned).collect();
        let generated = CertificateAuthority::generate(&patterns)
            .map_err(|error| ServiceError::Proxy(error.to_string()))?;
        let scope = format!("{}\n{hosts}", generated.expires_at);
        contents.set_internals(vec![
            (CA_KEY_RECORD, generated.key),
            (
                CA_CERTIFICATE_RECORD,
                SecretSlice::from(generated.certificate),
            ),
            (CA_SCOPE_RECORD, SecretSlice::from(scope.into_bytes())),
        ])?;
        audit::proxy_authority_made(hosts);
        Ok(generated.authority)
    }
}

/// The end time and the hosts of the stored CA.
struct CaScope<'scope> {
    expires_at: i64,
    hosts: &'scope str,
}

impl<'scope> CaScope<'scope> {
    fn parse(record: &'scope [u8]) -> Option<Self> {
        let text = std::str::from_utf8(record).ok()?;
        let (expires_at, hosts) = text.split_once('\n')?;
        Some(Self {
            expires_at: expires_at.parse().ok()?,
            hosts,
        })
    }

    fn covers(&self, hosts: &str) -> bool {
        let left = self.expires_at - crate::util::unix_time::unix_seconds_now_signed();
        self.hosts == hosts && left > CA_RENEW_BEFORE_SECONDS
    }
}

/// Writes a temporary file next to `path` and renames it over `path`, so an agent never reads a
/// half-written certificate.
fn write_replacing(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let directory = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(directory)?;
    let temporary = directory.join(format!(".{CA_FILE_NAME}.{}.tmp", std::process::id()));
    let written = std::fs::write(&temporary, bytes)
        .and_then(|()| std::fs::File::open(&temporary)?.sync_all())
        .and_then(|()| std::fs::rename(&temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}
