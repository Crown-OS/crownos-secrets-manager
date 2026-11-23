//! Typing through a small fake compositor that offers `crownos_secret_input_manager_v1`: the
//! value reaches the compositor by fd, and the bindings decide which windows may get it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Read as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crownos_protocols::secret_input::v1::server::crownos_secret_input_manager_v1::{
    self, CrownosSecretInputManagerV1, Flags, Outcome,
};
use crownos_secretsd::service::{TypingShape, TypingStart, typing_outcome};
use crownos_secretsd::typing::CompositorTyping;
use crownos_secretsd::{AdminPolicy, Caller, SecretsService, ServiceError};
use secrecy::SecretSlice;
use secrets_core::{Binding, Confirm, SecretKind, SecretName, Target, UseOutcome};
use secrets_protocol::TypingTarget;
use secrets_protocol::transfer::TransferError;
use secrets_vault::{KdfParams, Vault};
use wayland_server::backend::ClientData;
use wayland_server::{Client, DataInit, Dispatch, Display, DisplayHandle, GlobalDispatch, New};

const AGENT: &str = "/usr/bin/crownos-computer-use";
const ADMIN: &str = "/usr/bin/crownos-secrets";
const PASSWORD: &[u8] = b"master";

/// What the fake compositor got for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TypedRequest {
    window: String,
    value: Vec<u8>,
    require_password_field: u32,
    flags: u32,
    secret_name: String,
    origin: String,
}

#[derive(Default)]
struct FakeCompositor {
    typed: Arc<Mutex<Vec<TypedRequest>>>,
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
        state: &mut Self,
        _: &Client,
        resource: &CrownosSecretInputManagerV1,
        request: crownos_secret_input_manager_v1::Request,
        _: &(),
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        if let crownos_secret_input_manager_v1::Request::TypeSecret {
            id,
            window_identifier,
            require_password_field,
            flags,
            secret_name,
            origin,
            value,
            ..
        } = request
        {
            let mut bytes = Vec::new();
            std::fs::File::from(value).read_to_end(&mut bytes).unwrap();
            let flags = match flags {
                wayland_server::WEnum::Value(flags) => flags.bits(),
                wayland_server::WEnum::Unknown(bits) => bits,
            };
            state.typed.lock().unwrap().push(TypedRequest {
                window: window_identifier,
                value: bytes,
                require_password_field,
                flags,
                secret_name,
                origin,
            });
            resource.done(id, Outcome::Typed);
        }
    }
}

/// Starts the fake compositor on one end of a socket pair; returns the other end.
fn start_compositor(typed: Arc<Mutex<Vec<TypedRequest>>>, stop: Arc<AtomicBool>) -> UnixStream {
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
        let mut state = FakeCompositor { typed };
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
    for (secret, value, targets, password_field) in [
        (
            "user",
            &b"alice@example.com"[..],
            vec![Target::AppId("org.example.*".into())],
            false,
        ),
        (
            "pass",
            &b"hunter2-planted"[..],
            vec![Target::AppId("org.example.*".into())],
            true,
        ),
        (
            "site",
            &b"site-planted"[..],
            vec![Target::Origin("https://*.example.com".into())],
            true,
        ),
    ] {
        let value: &'static [u8] = Box::leak(value.to_vec().into_boxed_slice());
        service
            .add(
                &admin(),
                &name(secret),
                SecretKind::Password,
                bytes(PASSWORD),
                bytes(value),
                now,
            )
            .unwrap();
        let binding = Binding {
            agents: vec![format!("exe:{AGENT}")],
            targets,
            require_password_field: password_field,
            confirm: Some(Confirm::Never),
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
async fn the_compositor_gets_the_value_only_for_a_bound_window() {
    let typed = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let socket = start_compositor(Arc::clone(&typed), Arc::clone(&stop));
    let typing = CompositorTyping::from_socket(socket);
    assert!(typing.is_available());
    let directory = tempfile::tempdir().unwrap();
    let mut service = service(directory.path(), typing);

    let typed_pass = type_secrets(
        &mut service,
        &[name("pass")],
        &target("org.example.browser", None),
        TypingShape::Single,
    )
    .await;
    assert_eq!(typed_pass, UseOutcome::Done);
    let first = typed.lock().unwrap()[0].clone();
    assert_eq!(first.value, b"hunter2-planted");
    assert_eq!(first.window, "window-7");
    assert_eq!(first.require_password_field, 1);
    assert_eq!(first.secret_name, "pass");

    let login = type_secrets(
        &mut service,
        &[name("user"), name("pass")],
        &target("org.example.browser", None),
        TypingShape::Login,
    )
    .await;
    assert_eq!(login, UseOutcome::Done);
    let requests = typed.lock().unwrap().clone();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1].value, b"alice@example.com");
    assert_eq!(
        requests[1].flags & Flags::TabAfter.bits(),
        Flags::TabAfter.bits()
    );
    assert_eq!(requests[1].require_password_field, 0);
    assert_eq!(requests[2].require_password_field, 1);

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
    let right_origin = type_secrets(
        &mut service,
        &[name("site")],
        &target("org.example.browser", Some("https://login.example.com")),
        TypingShape::Single,
    )
    .await;
    assert_eq!(right_origin, UseOutcome::Done);
    let requests = typed.lock().unwrap().clone();
    assert_eq!(requests.len(), 4, "a refused target reached the compositor");
    assert_eq!(requests[3].origin, "https://login.example.com");
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
