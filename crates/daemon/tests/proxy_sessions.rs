//! Proxy sessions through the service: who gets one, what goes to disk, and what a lock ends.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;
use std::time::Instant;

use crownos_secretsd::{Caller, SecretsService};
use secrecy::SecretSlice;
use secrets_core::{Binding, HttpBinding, SecretKind, SecretName, UseOutcome};
use secrets_protocol::ProxySessionReply;
use secrets_protocol::transfer::TransferError;
use secrets_vault::{KdfParams, Vault};

const AGENT: &str = "/usr/bin/crownos-secrets-mcp";
const ADMIN: &str = "/usr/bin/crownos-secrets";
const PASSWORD: &[u8] = b"master";

fn name(text: &str) -> SecretName {
    SecretName::parse(text).unwrap()
}

fn bytes(value: &'static [u8]) -> impl FnOnce() -> Result<SecretSlice<u8>, TransferError> {
    move || Ok(SecretSlice::from(value.to_vec()))
}

fn admin() -> Caller {
    Caller::from_executable(Path::new(ADMIN))
}

fn agent() -> Caller {
    Caller::from_executable(Path::new(AGENT))
}

fn add(service: &mut SecretsService, secret: &str, http: Vec<HttpBinding>, now: Instant) {
    service
        .add(
            &admin(),
            &name(secret),
            SecretKind::ApiKey,
            bytes(PASSWORD),
            bytes(b"sk-planted-0001"),
            now,
        )
        .unwrap();
    let binding = Binding {
        agents: vec![AGENT.into()],
        http,
        ..Binding::default()
    };
    service
        .bind(&admin(), &name(secret), binding, bytes(PASSWORD), now)
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_exports_only_the_ca_certificate_and_ends_with_the_lock() {
    let directory = tempfile::tempdir().unwrap();
    let data_directory = directory.path().join("data");
    let vault_path = data_directory.join("secrets.vault");
    let vault = Vault::new(vault_path.clone()).with_kdf_params(KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    });
    let mut service = SecretsService::new(vault, vec![ADMIN.into()], data_directory.clone())
        .with_upstream_roots(rustls::RootCertStore::empty());
    let now = Instant::now();
    service.init(&admin(), bytes(PASSWORD), now).unwrap();
    let http = HttpBinding {
        host: "api.example.com".into(),
        header: "Authorization".into(),
        format: "Bearer {value}".into(),
        methods: Vec::new(),
        paths: Vec::new(),
    };
    add(&mut service, "api", vec![http], now);
    add(&mut service, "no_http", Vec::new(), now);

    let stranger = Caller::from_executable(Path::new("/usr/bin/other"));
    let denied = service
        .proxy_session(&stranger, &[name("api")], 5, now)
        .unwrap();
    assert_eq!(denied, ProxySessionReply::Refused(UseOutcome::Denied));
    let unbound = service
        .proxy_session(&agent(), &[name("no_http")], 5, now)
        .unwrap();
    assert_eq!(unbound, ProxySessionReply::NoHttpBinding(name("no_http")));

    let ProxySessionReply::Started(session) = service
        .proxy_session(&agent(), &[name("api")], 500, now)
        .unwrap()
    else {
        panic!("no session");
    };
    assert_eq!(session.expires_in_seconds, 60 * 60);
    assert_eq!(session.placeholders[0].text, "crown-secret://api");
    let pem = std::fs::read_to_string(&session.ca_path).unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    for entry in std::fs::read_dir(&data_directory).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("PRIVATE KEY"));
        assert!(!text.contains("sk-planted-0001"));
    }
    let address = session
        .proxy_url
        .rsplit_once('@')
        .map(|(_, address)| address.to_owned())
        .unwrap();
    assert!(tokio::net::TcpStream::connect(&address).await.is_ok());

    let second = service
        .proxy_session(&agent(), &[name("api")], 5, now)
        .unwrap();
    let ProxySessionReply::Started(second) = second else {
        panic!("no second session");
    };
    assert_eq!(second.ca_path, session.ca_path);
    assert!(service.revoke_session(&agent(), second.session));
    assert!(!service.revoke_session(&stranger, session.session));

    service.lock(&admin()).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(tokio::net::TcpStream::connect(&address).await.is_err());
}
