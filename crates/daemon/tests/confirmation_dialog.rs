//! The confirmation dialog through the real socket, with scripted answers instead of a portal.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crownos_ipc::Pending;
use crownos_secretsd::confirmation::{ConfirmationAsker, DialogRequest, Verdict, VerdictFuture};
use crownos_secretsd::{AcceptedProgramIdentity, AdminPolicy, SecretsService};
use secrets_core::{Binding, Confirm, HttpBinding, SecretKind, SecretName, UseOutcome};
use secrets_protocol::secrets::Client;
use secrets_protocol::{ProxySessionReply, transfer};
use secrets_vault::{KdfParams, Vault};
use serde::de::DeserializeOwned;

const TIMEOUT: Option<Duration> = Some(Duration::from_secs(30));
const PASSWORD: &[u8] = b"master";

#[derive(Default)]
struct ScriptedAsker {
    answers: Mutex<VecDeque<(Verdict, Duration)>>,
    asked: Mutex<Vec<DialogRequest>>,
}

impl ScriptedAsker {
    fn answer(&self, verdict: Verdict, after: Duration) {
        self.answers.lock().unwrap().push_back((verdict, after));
    }

    fn asked(&self) -> Vec<DialogRequest> {
        self.asked.lock().unwrap().clone()
    }
}

/// The asker the daemon holds; the test keeps the same `ScriptedAsker` to read what it asked.
struct SharedAsker(Arc<ScriptedAsker>);

impl ConfirmationAsker for SharedAsker {
    fn ask(&self, request: DialogRequest) -> VerdictFuture {
        self.0.asked.lock().unwrap().push(request);
        let (verdict, after) = self
            .0
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or((Verdict::Denied, Duration::ZERO));
        Box::pin(async move {
            tokio::time::sleep(after).await;
            verdict
        })
    }
}

fn name(text: &str) -> SecretName {
    SecretName::parse(text).unwrap()
}

fn test_executable() -> PathBuf {
    std::env::current_exe().unwrap()
}

fn start_daemon(directory: &Path, asker: Arc<ScriptedAsker>) -> PathBuf {
    let socket_directory = directory.join("runtime");
    let mut server = crownos_secretsd::server::bind_socket(Some(&socket_directory)).unwrap();
    let data = directory.join("data");
    std::thread::spawn(move || {
        let vault = Vault::new(data.join("secrets.vault")).with_kdf_params(KdfParams {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
        });
        let service =
            SecretsService::new(vault, AdminPolicy::trusting(vec![test_executable()]), data)
                .with_upstream_roots(rustls::RootCertStore::empty())
                .with_confirmation_asker(Arc::new(SharedAsker(asker)));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = runtime.block_on(crownos_secretsd::server::serve(
            &mut server,
            service,
            AcceptedProgramIdentity,
        ));
    });
    socket_directory
}

fn call<Reply: DeserializeOwned>(
    client: &mut Client,
    start: impl FnOnce(&mut Client) -> Result<Pending<Reply>, crownos_ipc::Error>,
) -> Reply {
    let pending = start(client).unwrap();
    client.wait(pending, TIMEOUT).unwrap()
}

fn password() -> std::os::fd::OwnedFd {
    transfer::value_pipe(PASSWORD).unwrap()
}

/// A daemon with the secret `api`, bound to this test with `confirm`.
fn daemon_with_secret(confirm: Confirm, asker: &Arc<ScriptedAsker>) -> (tempfile::TempDir, Client) {
    let directory = tempfile::tempdir().unwrap();
    let socket = start_daemon(directory.path(), Arc::clone(asker));
    let mut client = Client::connect_in(&socket).unwrap();
    call(&mut client, |client| client.init(password()));
    let value = transfer::value_pipe(b"sk-dialog-0001").unwrap();
    call(&mut client, |client| {
        client.add(name("api"), SecretKind::ApiKey, password(), value)
    });
    let binding = Binding {
        agents: vec![format!("exe:{}", test_executable().display())],
        confirm: Some(confirm),
        http: vec![HttpBinding {
            host: "api.example.com".into(),
            header: "Authorization".into(),
            format: "Bearer {value}".into(),
            methods: Vec::new(),
            paths: Vec::new(),
        }],
        ..Binding::default()
    };
    call(&mut client, |client| {
        client.bind(name("api"), binding, password())
    });
    (directory, client)
}

fn session(client: &mut Client) -> ProxySessionReply {
    call(client, |client| client.proxy_session(vec![name("api")], 5))
}

#[test]
fn every_use_asks_each_time_and_names_agent_secret_and_target() {
    let asker = Arc::new(ScriptedAsker::default());
    let (_directory, mut client) = daemon_with_secret(Confirm::EveryUse, &asker);
    asker.answer(Verdict::Granted, Duration::ZERO);
    asker.answer(Verdict::Granted, Duration::ZERO);
    assert!(matches!(
        session(&mut client),
        ProxySessionReply::Started(_)
    ));
    assert!(matches!(
        session(&mut client),
        ProxySessionReply::Started(_)
    ));
    let asked = asker.asked();
    assert_eq!(asked.len(), 2);
    let program = test_executable()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(asked[0].title().contains(&program), "{}", asked[0].title());
    assert!(asked[0].title().contains("“api”"), "{}", asked[0].title());
    assert!(
        asked[0]
            .body()
            .contains("HTTPS requests to api.example.com"),
        "{}",
        asked[0].body()
    );
    assert!(
        asked[0]
            .body()
            .contains(&format!("exe:{}", test_executable().display()))
    );
}

#[test]
fn a_session_answer_covers_its_minutes() {
    let asker = Arc::new(ScriptedAsker::default());
    let (_directory, mut client) = daemon_with_secret(Confirm::PerSession(5), &asker);
    asker.answer(Verdict::Granted, Duration::ZERO);
    assert!(matches!(
        session(&mut client),
        ProxySessionReply::Started(_)
    ));
    assert!(matches!(
        session(&mut client),
        ProxySessionReply::Started(_)
    ));
    assert_eq!(asker.asked().len(), 1);
    assert_eq!(asker.asked()[0].session_minutes, Some(5));
}

#[test]
fn a_deny_refuses_and_cools_down_and_no_portal_refuses() {
    let asker = Arc::new(ScriptedAsker::default());
    let (_directory, mut client) = daemon_with_secret(Confirm::EveryUse, &asker);
    asker.answer(Verdict::Denied, Duration::ZERO);
    assert_eq!(
        session(&mut client),
        ProxySessionReply::Refused(UseOutcome::Denied)
    );
    assert_eq!(
        session(&mut client),
        ProxySessionReply::Refused(UseOutcome::Denied)
    );
    assert_eq!(
        asker.asked().len(),
        1,
        "a denied agent got a second dialog at once"
    );

    let other = Arc::new(ScriptedAsker::default());
    let (_other_directory, mut other_client) = daemon_with_secret(Confirm::EveryUse, &other);
    other.answer(Verdict::Unreachable, Duration::ZERO);
    assert_eq!(
        session(&mut other_client),
        ProxySessionReply::Refused(UseOutcome::NeedsConfirmation)
    );
}

#[test]
fn one_open_dialog_per_agent_and_the_daemon_keeps_answering() {
    let asker = Arc::new(ScriptedAsker::default());
    let (directory, mut client) = daemon_with_secret(Confirm::EveryUse, &asker);
    asker.answer(Verdict::Granted, Duration::from_millis(800));
    let pending = client.proxy_session(vec![name("api")], 5).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let mut second = Client::connect_in(&directory.path().join("runtime")).unwrap();
    assert_eq!(
        session(&mut second),
        ProxySessionReply::Refused(UseOutcome::Denied)
    );
    let status = call(&mut second, |client| client.status());
    assert!(!status.locked);
    let first: ProxySessionReply = client.wait(pending, TIMEOUT).unwrap();
    assert!(matches!(first, ProxySessionReply::Started(_)), "{first:?}");
    assert_eq!(asker.asked().len(), 1);
}

#[test]
fn a_peer_that_leaves_during_the_dialog_gets_nothing_and_the_next_peer_is_asked_again() {
    let asker = Arc::new(ScriptedAsker::default());
    let (directory, mut client) = daemon_with_secret(Confirm::EveryUse, &asker);
    asker.answer(Verdict::Granted, Duration::from_millis(500));
    let _pending = client.proxy_session(vec![name("api")], 5).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    drop(client);
    std::thread::sleep(Duration::from_millis(800));

    let mut next = Client::connect_in(&directory.path().join("runtime")).unwrap();
    asker.answer(Verdict::Granted, Duration::ZERO);
    let reply = session(&mut next);
    assert!(matches!(reply, ProxySessionReply::Started(_)), "{reply:?}");
    assert_eq!(
        asker.asked().len(),
        2,
        "the gone peer's answer was used again"
    );
}
