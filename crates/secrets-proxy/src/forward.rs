//! One request inside a tunnel: add the bound header, replace placeholders, send it on, and
//! scrub the response.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use http::header::{self, HeaderName, HeaderValue};
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use secrecy::ExposeSecret as _;
use secrets_core::{HttpBinding, Scrubber};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::connect::{ProxyBody, plain_response};
use crate::scrubbed_body::ScrubbedBody;
use crate::session::Session;
use crate::{PLACEHOLDER_PREFIX, Shared, audit};

pub(crate) async fn forward(
    shared: Arc<Shared>,
    token: String,
    authority: String,
    sender: Arc<Mutex<SendRequest<Incoming>>>,
    mut request: Request<Incoming>,
) -> Result<Response<ProxyBody>, Infallible> {
    let Some(session) = shared.sessions.find(&token, Instant::now()) else {
        return Ok(plain_response(
            StatusCode::FORBIDDEN,
            "the proxy session is over\n",
        ));
    };
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let injected = match prepare(&session, &authority, &method, &path, request.headers_mut()) {
        Ok(injected) => injected,
        Err(reason) => {
            audit::request_refused(&session.actor, &authority, reason);
            return Ok(plain_response(StatusCode::FORBIDDEN, reason));
        }
    };
    let response = sender.lock().await.send_request(request).await;
    let Ok(response) = response else {
        return Ok(plain_response(
            StatusCode::BAD_GATEWAY,
            "the host did not answer\n",
        ));
    };
    audit::request_forwarded(
        &session.actor,
        &injected,
        &authority,
        &method,
        &path,
        response.status().as_u16(),
    );
    let compressed = response
        .headers()
        .get(header::CONTENT_ENCODING)
        .is_some_and(|encoding| !encoding.as_bytes().eq_ignore_ascii_case(b"identity"));
    if compressed {
        return Ok(plain_response(
            StatusCode::BAD_GATEWAY,
            "the host sent a compressed response, which cannot be scrubbed\n",
        ));
    }
    let (mut parts, body) = response.into_parts();
    scrub_headers(&mut parts.headers, &session.scrubber);
    parts.headers.remove(header::CONTENT_LENGTH);
    let body = ScrubbedBody::new(body, Arc::clone(&session.scrubber)).boxed();
    Ok(Response::from_parts(parts, body))
}

/// Adds the bound headers and replaces placeholders. Returns the names it used, joined by `,`.
fn prepare(
    session: &Session,
    authority: &str,
    method: &str,
    path: &str,
    headers: &mut HeaderMap,
) -> Result<String, &'static str> {
    headers.remove(header::PROXY_AUTHORIZATION);
    headers.insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    let bound: Vec<_> = session
        .secrets
        .iter()
        .filter_map(|secret| Some((secret, secret.binding_for(authority, method, path)?)))
        .collect();
    replace_placeholders(headers, &bound)?;
    for (secret, binding) in &bound {
        let value = header_value(binding, secret.value.expose_secret())?;
        let name = HeaderName::from_bytes(binding.header.as_bytes())
            .map_err(|_| "the bound header name is not valid\n")?;
        headers.insert(name, value);
    }
    Ok(bound
        .iter()
        .map(|(secret, _)| secret.name.as_str())
        .collect::<Vec<_>>()
        .join(","))
}

fn header_value(binding: &HttpBinding, value: &[u8]) -> Result<HeaderValue, &'static str> {
    let (before, after) = binding
        .format
        .split_once(HttpBinding::VALUE_PLACEHOLDER)
        .ok_or("the bound header format has no {value}\n")?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(before.len() + value.len() + after.len()));
    bytes.extend_from_slice(before.as_bytes());
    bytes.extend_from_slice(value);
    bytes.extend_from_slice(after.as_bytes());
    let mut header =
        HeaderValue::from_bytes(&bytes).map_err(|_| "the value cannot go into a header\n")?;
    header.set_sensitive(true);
    Ok(header)
}

fn replace_placeholders(
    headers: &mut HeaderMap,
    bound: &[(&crate::SessionSecret, &HttpBinding)],
) -> Result<(), &'static str> {
    for value in headers.values_mut() {
        let original = value.as_bytes();
        if !contains(original, PLACEHOLDER_PREFIX.as_bytes()) {
            continue;
        }
        let mut replaced = Zeroizing::new(Vec::with_capacity(original.len() + 64));
        let mut rest = original;
        while let Some(start) = find(rest, PLACEHOLDER_PREFIX.as_bytes()) {
            let (before, from_prefix) = rest.split_at(start);
            replaced.extend_from_slice(before);
            let after_prefix = from_prefix
                .get(PLACEHOLDER_PREFIX.len()..)
                .unwrap_or_default();
            let name_length = after_prefix
                .iter()
                .position(|&byte| !is_name_byte(byte))
                .unwrap_or(after_prefix.len());
            let (name, tail) = after_prefix.split_at(name_length);
            let secret = bound
                .iter()
                .find(|(secret, _)| secret.name.as_str().as_bytes() == name)
                .ok_or("a placeholder names a secret that is not bound to this request\n")?;
            replaced.extend_from_slice(secret.0.value.expose_secret());
            rest = tail;
        }
        replaced.extend_from_slice(rest);
        let mut header = HeaderValue::from_bytes(&replaced)
            .map_err(|_| "the value cannot go into a header\n")?;
        header.set_sensitive(true);
        *value = header;
    }
    Ok(())
}

const fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn scrub_headers(headers: &mut HeaderMap, scrubber: &Scrubber) {
    for value in headers.values_mut() {
        let scrubbed = scrubber.scrub(value.as_bytes());
        if scrubbed != value.as_bytes()
            && let Ok(clean) = HeaderValue::from_bytes(&scrubbed)
        {
            *value = clean;
        }
    }
}
