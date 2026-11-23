//! A local HTTPS host behind the proxy: the key reaches the host, and never the agent.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use secrecy::SecretSlice;
use secrets_core::{HttpBinding, SecretName};
use secrets_proxy::{CertificateAuthority, Proxy, SessionSecret};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const VALUE: &str = "sk-PLANTED-proxy-value-42";

type Seen = Arc<Mutex<Vec<(Option<String>, Option<String>)>>>;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// An HTTPS host on `127.0.0.1` with a certificate for `localhost` from its own CA. It answers
/// with the headers it got, so a scrubber failure would show the value to the agent.
async fn start_host(seen: Seen) -> (u16, RootCertStore) {
    let mut ca_parameters = CertificateParams::default();
    ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_certificate = ca_parameters.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_parameters, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                    let header = |name: &str| {
                        request
                            .headers()
                            .get(name)
                            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                    };
                    let authorization = header("authorization");
                    let key = header("x-key");
                    seen.lock()
                        .unwrap()
                        .push((authorization.clone(), key.clone()));
                    let body = format!(
                        "auth={authorization:?} key={key:?} path={}",
                        request.uri().path()
                    );
                    let mut response = Response::new(Full::new(Bytes::from(body)));
                    if let Some(authorization) = authorization {
                        response
                            .headers_mut()
                            .insert("x-echo", authorization.parse().unwrap());
                    }
                    async move { Ok::<_, Infallible>(response) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    let mut roots = RootCertStore::empty();
    roots.add(ca_certificate.der().clone()).unwrap();
    (port, roots)
}

fn proxy_roots(proxy: &Proxy) -> RootCertStore {
    let pem = proxy.ca_certificate_pem();
    let base64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(STANDARD.decode(base64).unwrap()))
        .unwrap();
    roots
}

/// Sends `CONNECT target` and returns the status code and, on 200, the open stream.
async fn connect(proxy: SocketAddr, token: &str, target: &str) -> (u16, TcpStream) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let credentials = STANDARD.encode(format!("crownos:{token}"));
    let head = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {credentials}\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut received = Vec::new();
    while !received.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        if stream.read(&mut byte).await.unwrap() == 0 {
            break;
        }
        received.push(byte[0]);
    }
    let status = String::from_utf8_lossy(&received)
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, stream)
}

/// A request through an open tunnel; returns the status, the `x-echo` header and the body.
async fn request_through(
    stream: TcpStream,
    roots: RootCertStore,
    host: &str,
    method: &str,
    path: &str,
    key_header: Option<&str>,
) -> (u16, Option<String>, String) {
    let config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(connection);
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host);
    if let Some(key) = key_header {
        request = request.header("x-key", key);
    }
    let response = sender
        .send_request(request.body(Empty::<Bytes>::new()).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let echo = response
        .headers()
        .get("x-echo")
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, echo, String::from_utf8_lossy(&body).into_owned())
}

fn token_of(url: &str) -> String {
    url.split_once("crownos:")
        .and_then(|(_, rest)| rest.split_once('@'))
        .map(|(token, _)| token.to_owned())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_key_reaches_the_bound_host_and_never_the_agent() {
    let seen = Seen::default();
    let (port, host_roots) = start_host(Arc::clone(&seen)).await;
    let (authority, _key, _certificate) = CertificateAuthority::generate().unwrap();
    let proxy = Proxy::start(authority, host_roots).unwrap();
    let secret = SessionSecret {
        name: SecretName::parse("api").unwrap(),
        value: SecretSlice::from(VALUE.as_bytes().to_vec()),
        http: vec![HttpBinding {
            host: "localhost".into(),
            header: "Authorization".into(),
            format: "Bearer {value}".into(),
            methods: vec!["GET".into()],
            paths: vec!["/v1/*".into()],
        }],
    };
    let url = proxy
        .open_session(7, "agent", vec![secret], Duration::from_secs(60))
        .unwrap();
    let token = token_of(&url);
    let target = format!("localhost:{port}");

    let (status, stream) = connect(proxy.address(), &token, &target).await;
    assert_eq!(status, 200);
    let (status, echo, body) = request_through(
        stream,
        proxy_roots(&proxy),
        &target,
        "GET",
        "/v1/echo",
        Some("crown-secret://api"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let host_saw = seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(host_saw.0.as_deref(), Some(&*format!("Bearer {VALUE}")));
    assert_eq!(host_saw.1.as_deref(), Some(VALUE));
    assert!(!body.contains(VALUE), "{body}");
    assert!(body.contains("[secret:api]"), "{body}");
    assert_eq!(echo.as_deref(), Some("Bearer [secret:api]"));

    let (_, stream) = connect(proxy.address(), &token, &target).await;
    let (status, _, body) = request_through(
        stream,
        proxy_roots(&proxy),
        &target,
        "POST",
        "/v1/echo",
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        seen.lock().unwrap().last().cloned().unwrap().0,
        None,
        "{body}"
    );

    let (_, stream) = connect(proxy.address(), &token, &target).await;
    let (status, _, _) = request_through(
        stream,
        proxy_roots(&proxy),
        &target,
        "GET",
        "/v2/other",
        Some("crown-secret://api"),
    )
    .await;
    assert_eq!(status, 403);

    let (_, stream) = connect(proxy.address(), &token, &target).await;
    let other_host = format!("admin.localhost:{port}");
    let (status, _, _) = request_through(
        stream,
        proxy_roots(&proxy),
        &other_host,
        "GET",
        "/v1/echo",
        None,
    )
    .await;
    assert_eq!(status, 403, "another virtual host on the same server");
    let (_, stream) = connect(proxy.address(), &token, &target).await;
    let (status, _, _) = request_through(
        stream,
        proxy_roots(&proxy),
        &target,
        "GET",
        "/v1/../admin",
        None,
    )
    .await;
    assert_eq!(status, 403, "a dot segment out of the bound path");
    let before = seen.lock().unwrap().len();
    let (_, stream) = connect(proxy.address(), &token, &target).await;
    let (status, _, _) = request_through(
        stream,
        proxy_roots(&proxy),
        &target,
        "GET",
        "/v1/%2e%2e/admin",
        None,
    )
    .await;
    assert_eq!(status, 403, "an encoded dot segment");
    assert_eq!(
        seen.lock().unwrap().len(),
        before,
        "a refused request reached the host"
    );

    let (status, _) = connect(proxy.address(), &token, &format!("127.0.0.1:{port}")).await;
    assert_eq!(status, 403);
    let (status, _) = connect(proxy.address(), "not-the-token", &target).await;
    assert_eq!(status, 407);

    assert!(proxy.revoke_session(7, "agent"));
    let (status, _) = connect(proxy.address(), &token, &target).await;
    assert_eq!(status, 407);
}
