//! A local HTTPS host behind the proxy: the key reaches the bound host, and never the agent.
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
use http::header::HeaderValue;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::client::conn::http1::SendRequest;
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

type Seen = Arc<Mutex<Vec<HeaderMap>>>;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn host_response(path: &str, headers: &HeaderMap) -> Response<Full<Bytes>> {
    let shown = |name: &str| {
        headers
            .get(name)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
    };
    let body = format!(
        "auth={:?} key={:?} range={:?} path={path}",
        shown("authorization"),
        shown("x-key"),
        shown("range")
    );
    let mut response = Response::new(Full::new(Bytes::from(body)));
    if let Some(authorization) = headers.get("authorization") {
        response
            .headers_mut()
            .insert("x-echo", authorization.clone());
    }
    match path {
        "/v1/partial" => *response.status_mut() = StatusCode::PARTIAL_CONTENT,
        "/v1/encoded" => {
            let encodings = response.headers_mut();
            encodings.append("content-encoding", HeaderValue::from_static("identity"));
            encodings.append("content-encoding", HeaderValue::from_static("gzip"));
        }
        _ => {}
    }
    response
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
                    seen.lock().unwrap().push(request.headers().clone());
                    let response = host_response(request.uri().path(), request.headers());
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

/// Sends `CONNECT target` and returns the status code and the stream.
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

/// A TLS connection through the tunnel, ready for several requests.
async fn open_tunnel(proxy: &Proxy, token: &str, target: &str) -> SendRequest<Empty<Bytes>> {
    let (status, stream) = connect(proxy.address(), token, target).await;
    assert_eq!(status, 200);
    let config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(proxy_roots(proxy))
        .with_no_client_auth();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(connection);
    sender
}

struct Answer {
    status: u16,
    headers: HeaderMap,
    body: String,
}

async fn send(
    sender: &mut SendRequest<Empty<Bytes>>,
    method: &str,
    uri: &str,
    headers: &[(&str, &[u8])],
) -> Answer {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, HeaderValue::from_bytes(value).unwrap());
    }
    sender.ready().await.unwrap();
    let response = sender
        .send_request(request.body(Empty::<Bytes>::new()).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Answer {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn token_of(url: &str) -> String {
    url.split_once("crownos:")
        .and_then(|(_, rest)| rest.split_once('@'))
        .map(|(token, _)| token.to_owned())
        .unwrap()
}

fn secret(host: &str) -> SessionSecret {
    SessionSecret {
        name: SecretName::parse("api").unwrap(),
        value: SecretSlice::from(VALUE.as_bytes().to_vec()),
        http: vec![HttpBinding {
            host: host.into(),
            header: "Authorization".into(),
            format: "Bearer {value}".into(),
            methods: vec!["GET".into()],
            paths: vec!["/v1/*".into()],
        }],
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_key_reaches_the_bound_host_and_never_the_agent() {
    let seen = Seen::default();
    let (port, host_roots) = start_host(Arc::clone(&seen)).await;
    let (authority, _key, _certificate) = CertificateAuthority::generate().unwrap();
    let proxy = Proxy::start(authority, host_roots).unwrap();
    let target = format!("localhost:{port}");
    let url = proxy
        .open_session(7, "agent", vec![secret(&target)], Duration::from_secs(60))
        .unwrap();
    let token = token_of(&url);
    let host = target.as_bytes();
    let mut tunnel = open_tunnel(&proxy, &token, &target).await;

    let answer = send(
        &mut tunnel,
        "GET",
        "/v1/echo",
        &[
            ("host", host),
            ("x-key", b"crown-secret://api"),
            ("range", b"bytes=0-3"),
            ("accept-charset", b"utf-16"),
        ],
    )
    .await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    let host_saw = seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        host_saw.get("authorization").unwrap(),
        &*format!("Bearer {VALUE}")
    );
    assert_eq!(
        host_saw.get("x-key").unwrap(),
        "crown-secret://api",
        "placeholders are gone"
    );
    assert!(host_saw.get("range").is_none() && host_saw.get("accept-charset").is_none());
    assert!(
        !answer.body.contains(VALUE) && answer.body.contains("[secret:api]"),
        "{}",
        answer.body
    );
    assert_eq!(answer.headers.get("x-echo").unwrap(), "Bearer [secret:api]");

    let answer = send(&mut tunnel, "POST", "/v1/echo", &[("host", host)]).await;
    assert_eq!(answer.status, 200);
    assert!(
        seen.lock()
            .unwrap()
            .last()
            .unwrap()
            .get("authorization")
            .is_none()
    );

    let answer = send(&mut tunnel, "GET", "/v1/partial", &[("host", host)]).await;
    assert_eq!(answer.status, 502, "a 206 to a request with a key");
    let answer = send(&mut tunnel, "GET", "/v1/encoded", &[("host", host)]).await;
    assert_eq!(answer.status, 502, "a second Content-Encoding line");

    let reached = seen.lock().unwrap().len();
    let other_host = format!("admin.localhost:{port}");
    let refusals: [(&str, &[u8]); 7] = [
        ("/v1/echo", other_host.as_bytes()),
        ("/v1/echo", b"local\xffhost"),
        ("/v1/../admin", host),
        ("/v1/%2e%2e/admin", host),
        ("/v1/%252e%252e/admin", host),
        ("/v1/..;/admin", host),
        ("https://evil.example/v1/echo", host),
    ];
    for (uri, host_header) in refusals {
        let mut tunnel = open_tunnel(&proxy, &token, &target).await;
        let answer = send(&mut tunnel, "GET", uri, &[("host", host_header)]).await;
        assert_eq!(
            answer.status,
            403,
            "{uri} {}",
            String::from_utf8_lossy(host_header)
        );
    }
    assert_eq!(
        seen.lock().unwrap().len(),
        reached,
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

#[tokio::test(flavor = "multi_thread")]
async fn a_binding_without_a_port_means_443_and_a_session_ends_mid_tunnel() {
    let seen = Seen::default();
    let (port, host_roots) = start_host(Arc::clone(&seen)).await;
    let (authority, _key, _certificate) = CertificateAuthority::generate().unwrap();
    let proxy = Proxy::start(authority, host_roots).unwrap();
    let target = format!("localhost:{port}");

    let url = proxy
        .open_session(
            1,
            "agent",
            vec![secret("localhost")],
            Duration::from_secs(60),
        )
        .unwrap();
    let (status, _) = connect(proxy.address(), &token_of(&url), &target).await;
    assert_eq!(status, 403, "a binding without a port reached port {port}");

    let url = proxy
        .open_session(
            2,
            "agent",
            vec![secret(&target)],
            Duration::from_millis(800),
        )
        .unwrap();
    let mut tunnel = open_tunnel(&proxy, &token_of(&url), &target).await;
    let first = send(
        &mut tunnel,
        "GET",
        "/v1/echo",
        &[("host", target.as_bytes())],
    )
    .await;
    assert_eq!(first.status, 200);
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let second = send(
        &mut tunnel,
        "GET",
        "/v1/echo",
        &[("host", target.as_bytes())],
    )
    .await;
    assert_eq!(
        second.status, 403,
        "the expired session still sent a request"
    );
}
