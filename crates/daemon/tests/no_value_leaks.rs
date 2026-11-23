//! Runs the daemon on a real socket, uses it like the CLI and an agent would, and checks that no
//! reply, no event and no log line holds the planted value or the master password.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use crownos_ipc::{Pending, ServiceBuilder};
use crownos_secretsd::{MemoryConfigStore, ProcExecutableIdentity, SecretsService};
use secrets_core::config::SecretEntry;
use secrets_core::{Binding, SecretKind, SecretName, SecretsConfig, UseOutcome};
use secrets_protocol::secrets::{self, Client, Event};
use secrets_protocol::{error_code, transfer};
use secrets_vault::{KdfParams, Vault};
use serde::de::DeserializeOwned;

const PLANTED_VALUE: &[u8] = b"ghp_PLANTED_v4lue_0123456789";
const MASTER_PASSWORD: &[u8] = b"master-PASSWORD-planted";
const TIMEOUT: Option<Duration> = Some(Duration::from_secs(30));

#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn name(text: &str) -> SecretName {
    SecretName::parse(text).unwrap()
}

fn test_executable() -> String {
    std::env::current_exe()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

fn config(admin: &str) -> SecretsConfig {
    let mut config = SecretsConfig {
        admin_executables: vec![admin.to_owned()],
        ..SecretsConfig::default()
    };
    config.secrets.insert(
        name("github_token"),
        SecretEntry {
            kind: SecretKind::Token,
            binding: Binding {
                agents: vec![test_executable()],
                ..Binding::default()
            },
        },
    );
    config
}

/// Starts a daemon on its own thread, serving in `socket_directory`.
fn start_daemon(
    socket_directory: &Path,
    vault_path: PathBuf,
    store: Arc<MemoryConfigStore>,
    log: CapturedLog,
) {
    let mut server = ServiceBuilder::new(secrets::SERVICE)
        .directory(socket_directory)
        .build()
        .unwrap();
    std::thread::spawn(move || {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || log.clone())
            .finish();
        let _default = tracing::subscriber::set_default(subscriber);
        let vault = Vault::new(vault_path, Duration::from_secs(60)).with_kdf_params(KdfParams {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
        });
        let service = SecretsService::new(store, vault);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = runtime.block_on(crownos_secretsd::server::serve(
            &mut server,
            service,
            ProcExecutableIdentity,
        ));
    });
}

struct Recorder {
    client: Client,
    seen: String,
}

impl Recorder {
    fn call<R: DeserializeOwned + std::fmt::Debug>(
        &mut self,
        start: impl FnOnce(&mut Client) -> Result<Pending<R>, crownos_ipc::Error>,
    ) -> Result<R, crownos_ipc::RemoteError> {
        let pending = start(&mut self.client).unwrap();
        let reply = match self.client.wait(pending, TIMEOUT) {
            Ok(reply) => Ok(reply),
            Err(crownos_ipc::Error::Remote(remote)) => Err(remote),
            Err(other) => panic!("transport: {other}"),
        };
        self.seen.push_str(&format!("{reply:?}\n"));
        reply
    }

    fn drain_events(&mut self) -> Vec<secrets::Used> {
        let mut used = Vec::new();
        while let Some(Event::Used(event)) = self.client.next_event() {
            self.seen.push_str(&format!("{event:?}\n"));
            used.push(event);
        }
        used
    }
}

fn revealing_forms() -> Vec<Vec<u8>> {
    vec![
        PLANTED_VALUE.to_vec(),
        MASTER_PASSWORD.to_vec(),
        base64::engine::general_purpose::STANDARD
            .encode(PLANTED_VALUE)
            .into_bytes(),
        PLANTED_VALUE
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            .into_bytes(),
        format!("{:?}", PLANTED_VALUE).into_bytes(),
    ]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn no_reply_event_or_log_line_holds_a_value() {
    let directory = tempfile::tempdir().unwrap();
    let socket_directory = directory.path().join("runtime");
    let vault_path = directory.path().join("data/crownos/secrets.vault");
    let store = Arc::new(MemoryConfigStore::new(config(&test_executable())));
    let log = CapturedLog::default();
    start_daemon(&socket_directory, vault_path.clone(), store, log.clone());

    let mut recorder = Recorder {
        client: Client::connect_in(&socket_directory).unwrap(),
        seen: String::new(),
    };
    recorder
        .client
        .subscribe_blocking::<secrets::Used>(TIMEOUT)
        .unwrap();

    let status = recorder.call(|client| client.status()).unwrap();
    assert!(!status.vault_exists && status.locked);

    let locked_use = recorder.call(|client| client.type_into(name("github_token"), "w1".into()));
    assert_eq!(locked_use.unwrap(), UseOutcome::Locked);

    let pipe = transfer::value_pipe(MASTER_PASSWORD).unwrap();
    recorder.call(|client| client.unlock(pipe)).unwrap();
    let pipe = transfer::value_pipe(PLANTED_VALUE).unwrap();
    recorder
        .call(|client| client.add(name("github_token"), SecretKind::Token, pipe))
        .unwrap();
    let pipe = transfer::value_pipe(PLANTED_VALUE).unwrap();
    recorder
        .call(|client| client.add(name("unbound"), SecretKind::ApiKey, pipe))
        .unwrap();

    let pipe = transfer::value_pipe(b"wrong-password").unwrap();
    recorder.call(|client| client.lock()).unwrap();
    let wrong = recorder.call(|client| client.unlock(pipe)).unwrap_err();
    assert_eq!(wrong.code, error_code::VAULT);
    let pipe = transfer::value_pipe(MASTER_PASSWORD).unwrap();
    recorder.call(|client| client.unlock(pipe)).unwrap();

    let listed = recorder.call(|client| client.list()).unwrap();
    let names: Vec<&str> = listed.iter().map(|meta| meta.name.as_str()).collect();
    assert_eq!(names, ["github_token", "unbound"]);

    let permitted = recorder
        .call(|client| client.type_into(name("github_token"), "w1".into()))
        .unwrap_err();
    assert_eq!(permitted.code, error_code::UNAVAILABLE);
    let denied =
        recorder.call(|client| client.fill_login("user".into(), name("unbound"), "w1".into()));
    assert_eq!(denied.unwrap(), UseOutcome::Denied);
    let unknown = recorder.call(|client| client.proxy_session(vec![name("missing")]));
    assert_eq!(unknown.unwrap(), UseOutcome::Unknown);
    let request = recorder.call(|client| {
        client.request(
            name("openai_api_key"),
            SecretKind::ApiKey,
            "call the OpenAI API".into(),
        )
    });
    assert!(request.is_ok());
    let status = recorder.call(|client| client.status()).unwrap();
    assert_eq!(status.pending_requests.len(), 1);
    assert!(!status.locked);

    let events = recorder.drain_events();
    let outcomes: Vec<UseOutcome> = events.iter().map(|event| event.outcome).collect();
    assert_eq!(
        outcomes,
        [UseOutcome::Locked, UseOutcome::Denied, UseOutcome::Unknown]
    );

    let log = log.0.lock().unwrap().clone();
    let log_text = String::from_utf8_lossy(&log);
    assert!(log_text.contains("crownos::audit::secrets"), "{log_text}");
    assert!(log_text.contains("github_token"), "{log_text}");
    let vault_file = std::fs::read(&vault_path).unwrap();
    for form in revealing_forms() {
        let shown = String::from_utf8_lossy(&form);
        assert!(!contains(&log, &form), "log holds {shown}");
        assert!(
            !contains(recorder.seen.as_bytes(), &form),
            "replies hold {shown}"
        );
        assert!(!contains(&vault_file, &form), "vault file holds {shown}");
    }
}

#[test]
fn bindings_survive_a_restart_and_only_admins_change_them() {
    let directory = tempfile::tempdir().unwrap();
    let vault_path = directory.path().join("secrets.vault");
    let store = Arc::new(MemoryConfigStore::new(config(&test_executable())));

    let first_socket = directory.path().join("first");
    start_daemon(
        &first_socket,
        vault_path.clone(),
        store.clone(),
        CapturedLog::default(),
    );
    let mut first = Recorder {
        client: Client::connect_in(&first_socket).unwrap(),
        seen: String::new(),
    };
    let pipe = transfer::value_pipe(MASTER_PASSWORD).unwrap();
    first.call(|client| client.unlock(pipe)).unwrap();
    let pipe = transfer::value_pipe(PLANTED_VALUE).unwrap();
    first
        .call(|client| client.add(name("mail"), SecretKind::Password, pipe))
        .unwrap();
    let binding = Binding {
        agents: vec!["/usr/bin/crownos-secrets-mcp".into()],
        require_password_field: true,
        ..Binding::default()
    };
    first
        .call(|client| client.bind(name("mail"), binding.clone()))
        .unwrap();
    let invalid = Binding {
        agents: vec![String::new()],
        ..Binding::default()
    };
    let refused = first
        .call(|client| client.bind(name("mail"), invalid))
        .unwrap_err();
    assert_eq!(refused.code, error_code::INVALID_ARGUMENT);

    let second_socket = directory.path().join("second");
    start_daemon(
        &second_socket,
        vault_path,
        store.clone(),
        CapturedLog::default(),
    );
    let mut second = Recorder {
        client: Client::connect_in(&second_socket).unwrap(),
        seen: String::new(),
    };
    let status = second.call(|client| client.status()).unwrap();
    assert!(status.vault_exists && status.locked);
    let listed = second.call(|client| client.list()).unwrap();
    let mail = listed
        .iter()
        .find(|meta| meta.name.as_str() == "mail")
        .unwrap();
    assert_eq!(mail.kind, SecretKind::Password);
    assert_eq!(mail.binding, binding);
    let pipe = transfer::value_pipe(MASTER_PASSWORD).unwrap();
    second.call(|client| client.unlock(pipe)).unwrap();
    assert!(second.call(|client| client.remove(name("mail"))).unwrap());

    let mut not_admin = store.load_for_test();
    not_admin.admin_executables = vec!["/usr/bin/crownos-secrets".into()];
    store.replace_for_test(not_admin);
    let pipe = transfer::value_pipe(PLANTED_VALUE).unwrap();
    let refused = second
        .call(|client| client.add(name("mail"), SecretKind::Password, pipe))
        .unwrap_err();
    assert_eq!(refused.code, error_code::UNAUTHORIZED);
    let refused = second.call(|client| client.lock()).unwrap_err();
    assert_eq!(refused.code, error_code::UNAUTHORIZED);
}

trait StoreForTest {
    fn load_for_test(&self) -> SecretsConfig;
    fn replace_for_test(&self, config: SecretsConfig);
}

impl StoreForTest for MemoryConfigStore {
    fn load_for_test(&self) -> SecretsConfig {
        crownos_secretsd::ConfigStore::load(self).unwrap()
    }

    fn replace_for_test(&self, config: SecretsConfig) {
        crownos_secretsd::ConfigStore::save(self, &config).unwrap();
    }
}
