//! Typing through a small fake compositor that offers `crownos_secret_input_manager_v1`: the
//! value reaches the compositor by fd, and the bindings decide which windows may get it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::VecDeque;
use std::io::Read as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crownos_protocols::secret_input::v1::server::crownos_secret_input_manager_v1::{
    self, CrownosSecretInputManagerV1,
};
use crownos_protocols::secret_input::v1::server::crownos_secret_input_request_v1::{
    self, CrownosSecretInputRequestV1, Outcome,
};
use crownos_secretsd::service::{TypingShape, TypingStart, typing_outcome};
use crownos_secretsd::typing::CompositorTyping;
use crownos_secretsd::{AdminPolicy, Caller, SecretsService, ServiceError};
use secrecy::SecretSlice;
use secrets_core::{Binding, Confirm, SecretKind, SecretName, Target, UseOutcome, VaultSettings};
use secrets_protocol::TypingTarget;
use secrets_protocol::transfer::TransferError;
use secrets_vault::{KdfParams, Vault};
use wayland_server::backend::ClientData;
use wayland_server::{Client, DataInit, Dispatch, Display, DisplayHandle, GlobalDispatch, New};

const AGENT: &str = "/usr/bin/crownos-computer-use";
const ADMIN: &str = "/usr/bin/crownos-secrets";
const PASSWORD: &[u8] = b"master";

/// What the fake compositor got for one committed request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct TypedRequest {
    window: String,
    app_id: String,
    require_password_field: u32,
    secret_names: String,
    origin: String,
    /// Value, kind (0 user name, 1 password), Tab after.
    values: Vec<(Vec<u8>, u32, u32)>,
}

#[derive(Default)]
struct FakeCompositor {
    typed: Arc<Mutex<Vec<TypedRequest>>>,
    outcomes: Arc<Mutex<VecDeque<Outcome>>>,
}

struct NoClientData;

impl ClientData for NoClientData {}

impl GlobalDispatch<CrownosSecretInputManagerV1, ()> for FakeCompositor {
    fn bind(
        _: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        resource: New<CrownosSecretInputManagerV1>,
        _: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        data_init.init(resource, ());
    }
}

impl Dispatch<CrownosSecretInputManagerV1, ()> for FakeCompositor {
    fn request(
        _: &mut Self,
        _: &Client,
        _: &CrownosSecretInputManagerV1,
        request: crownos_secret_input_manager_v1::Request,
        _: &(),
        _: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        if let crownos_secret_input_manager_v1::Request::CreateRequest {
            id,
            window_identifier,
            app_id,
            require_password_field,
            secret_name,
            origin,
            ..
        } = request
        {
            data_init.init(
                id,
                Mutex::new(TypedRequest {
                    window: window_identifier,
                    app_id,
                    require_password_field,
                    secret_names: secret_name,
                    origin,
                    values: Vec::new(),
                }),
            );
        }
    }
}

impl Dispatch<CrownosSecretInputRequestV1, Mutex<TypedRequest>> for FakeCompositor {
    fn request(
        state: &mut Self,
        _: &Client,
        resource: &CrownosSecretInputRequestV1,
        request: crownos_secret_input_request_v1::Request,
        data: &Mutex<TypedRequest>,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        match request {
            crownos_secret_input_request_v1::Request::AddValue {
                value,
                kind,
                tab_after,
            } => {
                let mut bytes = Vec::new();
                std::fs::File::from(value).read_to_end(&mut bytes).unwrap();
                let kind = match kind {
                    wayland_server::WEnum::Value(kind) => kind as u32,
                    wayland_server::WEnum::Unknown(kind) => kind,
                };
                data.lock().unwrap().values.push((bytes, kind, tab_after));
            }
            crownos_secret_input_request_v1::Request::Commit => {
                state
                    .typed
                    .lock()
                    .unwrap()
                    .push(data.lock().unwrap().clone());
                let outcome = state
                    .outcomes
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(Outcome::Typed);
                resource.done(outcome);
            }
            _ => {}
        }
    }
}

/// Starts the fake compositor on one end of a socket pair; returns the other end.
fn start_compositor(compositor: FakeCompositor, stop: Arc<AtomicBool>) -> UnixStream {
    let (client_end, server_end) = UnixStream::pair().unwrap();
    std::thread::spawn(move || {
        let mut display: Display<FakeCompositor> = Display::new().unwrap();
        display
            .handle()
            .create_global::<FakeCompositor, CrownosSecretInputManagerV1, ()>(1, ());
        display
            .handle()
            .insert_client(server_end, Arc::new(NoClientData))
            .unwrap();
        let mut state = compositor;
        while !stop.load(Ordering::Relaxed) {
            let _ = display.dispatch_clients(&mut state);
            let _ = display.flush_clients();
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    client_end
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

fn name(text: &str) -> SecretName {
    SecretName::parse(text).unwrap()
}

fn service(directory: &Path, typing: CompositorTyping) -> SecretsService {
    let data = directory.join("data");
    let vault = Vault::new(data.join("secrets.vault")).with_kdf_params(KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    });
    let mut service = SecretsService::new(vault, AdminPolicy::trusting(vec![ADMIN.into()]), data)
        .with_typing(typing);
    let now = Instant::now();
    service.init(&admin(), bytes(PASSWORD), now).unwrap();
    let mut settings = VaultSettings::default();
    settings.rate_limit.uses_per_minute = 1000;
    service
        .configure(&admin(), settings, bytes(PASSWORD), now)
        .unwrap();
    let app = Target::AppId("org.example.*".into());
    let site = Target::Origin("https://*.example.com".into());
    for (secret, kind, value, targets) in [
        (
            "user",
            SecretKind::Note,
            b"alice@example.com".to_vec(),
            vec![app.clone()],
        ),
        (
            "pass",
            SecretKind::Password,
            b"hunter2-planted".to_vec(),
            vec![app.clone()],
        ),
        (
            "site",
            SecretKind::Token,
            b"site-planted".to_vec(),
            vec![app.clone(), site],
        ),
        (
            "huge",
            SecretKind::Note,
            vec![b'x'; 5000],
            vec![app],
        ),
    ] {
        let value: &'static [u8] = Box::leak(value.into_boxed_slice());
        service
            .add(
                &admin(),
                &name(secret),
                kind,
                bytes(PASSWORD),
                bytes(value),
                now,
            )
            .unwrap();
        let binding = Binding {
            agents: vec![format!("exe:{AGENT}")],
            targets,
            confirm: Some(Confirm::PerSession(5)),
            ..Binding::default()
        };
        service
            .bind(&admin(), &name(secret), binding, bytes(PASSWORD), now)
            .unwrap();
    }
    service
}

fn target(app_id: &str, origin: Option<&str>) -> TypingTarget {
    TypingTarget {
        window: "window-7".into(),
        app_id: app_id.into(),
        origin: origin.map(str::to_owned),
    }
}

async fn type_secrets(
    service: &mut SecretsService,
    names: &[SecretName],
    target: &TypingTarget,
    shape: TypingShape,
) -> UseOutcome {
    match service
        .start_typing(&agent(), names, target, shape, "test", Instant::now())
        .unwrap()
    {
        TypingStart::Refused(outcome) => outcome,
        TypingStart::Waiting(answer) => typing_outcome(answer.await.unwrap()),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_compositor_gets_one_request_per_typing_and_only_for_a_bound_window() {
    let compositor = FakeCompositor::default();
    let typed = Arc::clone(&compositor.typed);
    let outcomes = Arc::clone(&compositor.outcomes);
    let stop = Arc::new(AtomicBool::new(false));
    let typing = CompositorTyping::from_socket(start_compositor(compositor, Arc::clone(&stop)));
    assert!(typing.is_available());
    let directory = tempfile::tempdir().unwrap();
    let mut service = service(directory.path(), typing);
    let browser = target("org.example.browser", Some("https://login.example.com"));

    let first = type_secrets(&mut service, &[name("pass")], &browser, TypingShape::Single).await;
    assert_eq!(first, UseOutcome::Done);
    let second = type_secrets(&mut service, &[name("pass")], &browser, TypingShape::Single).await;
    assert_eq!(second, UseOutcome::Done);
    let requests = typed.lock().unwrap().clone();
    assert_eq!(
        requests.len(),
        2,
        "a session approval skipped the compositor's dialog"
    );
    assert_eq!(
        requests[0].values,
        vec![(b"hunter2-planted".to_vec(), 1, 0)]
    );
    assert_eq!(
        requests[0].require_password_field, 1,
        "a password kind forces a password field"
    );
    assert_eq!(requests[0].app_id, "org.example.browser");
    assert_eq!(requests[0].window, "window-7");

    let login = type_secrets(
        &mut service,
        &[name("user"), name("pass")],
        &browser,
        TypingShape::Login,
    )
    .await;
    assert_eq!(login, UseOutcome::Done);
    let login_request = typed.lock().unwrap()[2].clone();
    assert_eq!(
        login_request.values.len(),
        2,
        "a login is one request with two values"
    );
    assert_eq!(
        login_request.values[0],
        (b"alice@example.com".to_vec(), 0, 1)
    );
    assert_eq!(login_request.values[1], (b"hunter2-planted".to_vec(), 1, 0));
    assert_eq!(login_request.secret_names, "user, pass");

    outcomes.lock().unwrap().push_back(Outcome::TimedOut);
    let timed_out =
        type_secrets(&mut service, &[name("pass")], &browser, TypingShape::Single).await;
    assert_eq!(timed_out, UseOutcome::TimedOut);
    let after = type_secrets(&mut service, &[name("pass")], &browser, TypingShape::Single).await;
    assert_eq!(after, UseOutcome::Done, "a request after a timeout failed");

    let reached = typed.lock().unwrap().len();
    let wrong_app = type_secrets(
        &mut service,
        &[name("pass")],
        &target("org.evil.app", None),
        TypingShape::Single,
    )
    .await;
    assert_eq!(wrong_app, UseOutcome::Denied);
    let wrong_origin = type_secrets(
        &mut service,
        &[name("site")],
        &target("org.example.browser", Some("https://example.com.evil.test")),
        TypingShape::Single,
    )
    .await;
    assert_eq!(wrong_origin, UseOutcome::OriginMismatch);
    let no_origin = type_secrets(
        &mut service,
        &[name("site")],
        &target("org.example.browser", None),
        TypingShape::Single,
    )
    .await;
    assert_ne!(
        no_origin,
        UseOutcome::Done,
        "an origin target needs an origin"
    );
    let huge = type_secrets(&mut service, &[name("huge")], &browser, TypingShape::Single).await;
    assert_eq!(huge, UseOutcome::Denied);
    assert_eq!(
        typed.lock().unwrap().len(),
        reached,
        "a refused request reached the compositor"
    );
    stop.store(true, Ordering::Relaxed);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_global_typing_is_unavailable() {
    let directory = tempfile::tempdir().unwrap();
    let mut service = service(directory.path(), CompositorTyping::unavailable());
    let result = service.start_typing(
        &agent(),
        &[name("pass")],
        &target("org.example.browser", None),
        TypingShape::Single,
        "test",
        Instant::now(),
    );
    assert!(matches!(result, Err(ServiceError::Unavailable)));

    let (client_end, server_end) = UnixStream::pair().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    std::thread::spawn(move || {
        let mut display: Display<FakeCompositor> = Display::new().unwrap();
        display
            .handle()
            .insert_client(server_end, Arc::new(NoClientData))
            .unwrap();
        let mut state = FakeCompositor::default();
        while !thread_stop.load(Ordering::Relaxed) {
            let _ = display.dispatch_clients(&mut state);
            let _ = display.flush_clients();
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    assert!(!CompositorTyping::from_socket(client_end).is_available());
    stop.store(true, Ordering::Relaxed);
}
