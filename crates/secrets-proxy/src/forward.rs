//! One request inside a tunnel: add the bound header, send it on, and scrub the response.
//!
//! There are no placeholders: the only place a value goes is the header of its own binding. A
//! request that carries a key cannot ask for a part of a response (`Range`, `If-Range`) or for
//! another character set (`Accept-Charset`), because both can make the host echo the key in a
//! form that the scrubber does not know.

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
use crate::{Shared, audit};

/// Request headers that a request with a key must not carry.
const HEADERS_REMOVED_WITH_A_KEY: [HeaderName; 3] =
    [header::RANGE, header::IF_RANGE, header::ACCEPT_CHARSET];

fn refused(
    actor: &str,
    authority: &str,
    status: StatusCode,
    reason: &'static str,
) -> Response<ProxyBody> {
    audit::request_refused(actor, authority, reason);
    plain_response(status, reason)
}

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
    let actor = session.actor.as_str();
    let method = request.method().as_str().to_owned();
    let path = match crate::target::pin_to_tunnel(&mut request, &authority) {
        Ok(path) => path,
        Err(reason) => return Ok(refused(actor, &authority, StatusCode::FORBIDDEN, reason)),
    };
    let injected = match inject(&session, &authority, &method, &path, request.headers_mut()) {
        Ok(injected) => injected,
        Err(reason) => return Ok(refused(actor, &authority, StatusCode::FORBIDDEN, reason)),
    };
    let response = {
        let mut sender = sender.lock().await;
        match sender.ready().await {
            Ok(()) => sender.send_request(request).await,
            Err(error) => Err(error),
        }
    };
    let Ok(response) = response else {
        return Ok(plain_response(
            StatusCode::BAD_GATEWAY,
            "the host did not answer\n",
        ));
    };
    audit::request_forwarded(
        actor,
        &injected,
        &authority,
        &method,
        &path,
        response.status().as_u16(),
    );
    if !injected.is_empty() && response.status() == StatusCode::PARTIAL_CONTENT {
        return Ok(refused(
            actor,
            &authority,
            StatusCode::BAD_GATEWAY,
            "the host sent a part of a response to a request with a key\n",
        ));
    }
    if is_encoded(response.headers()) {
        return Ok(refused(
            actor,
            &authority,
            StatusCode::BAD_GATEWAY,
            "the host sent an encoded response, which cannot be scrubbed\n",
        ));
    }
    let (mut parts, body) = response.into_parts();
    parts.headers = scrubbed_headers(&parts.headers, &session.scrubber);
    parts.headers.remove(header::CONTENT_LENGTH);
    let body = ScrubbedBody::new(body, Arc::clone(&session.scrubber)).boxed();
    Ok(Response::from_parts(parts, body))
}

/// Any `Content-Encoding` other than `identity`, or any `Transfer-Encoding` other than
/// `chunked` or `identity`, in any of the header lines.
fn is_encoded(headers: &HeaderMap) -> bool {
    let content = headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .flat_map(|value| value.as_bytes().split(|&byte| byte == b','))
        .any(|coding| !coding.trim_ascii().eq_ignore_ascii_case(b"identity"));
    let transfer = headers
        .get_all(header::TRANSFER_ENCODING)
        .iter()
        .flat_map(|value| value.as_bytes().split(|&byte| byte == b','))
        .any(|coding| {
            let coding = coding.trim_ascii();
            !coding.eq_ignore_ascii_case(b"chunked") && !coding.eq_ignore_ascii_case(b"identity")
        });
    content || transfer
}

/// Adds the header of each binding that matches. Returns the names it used, joined by `,`.
fn inject(
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
    if !bound.is_empty() {
        for name in &HEADERS_REMOVED_WITH_A_KEY {
            headers.remove(name);
        }
    }
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

/// Each header line scrubbed. A line whose scrubbed form is not a valid header goes away.
fn scrubbed_headers(headers: &HeaderMap, scrubber: &Scrubber) -> HeaderMap {
    let mut clean = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let scrubbed = scrubber.scrub(value.as_bytes());
        if scrubbed == value.as_bytes() {
            clean.append(name, value.clone());
        } else if let Ok(scrubbed) = HeaderValue::from_bytes(&scrubbed) {
            clean.append(name, scrubbed);
        }
    }
    clean
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_encoding_line_counts() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        assert!(!is_encoded(&headers));
        headers.append(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(is_encoded(&headers));
        let mut chunked = HeaderMap::new();
        chunked.append(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("gzip, chunked"),
        );
        assert!(is_encoded(&chunked));
    }

    #[test]
    fn a_header_that_cannot_be_cleaned_goes_away() {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(&secrets_core::SecretName::parse("k").unwrap(), b"key1");
        let mut headers = HeaderMap::new();
        headers.append("x-echo", HeaderValue::from_static("Bearer key1"));
        headers.append("x-plain", HeaderValue::from_static("fine"));
        let clean = scrubbed_headers(&headers, &scrubber);
        assert_eq!(clean.get("x-echo").unwrap(), "Bearer [secret:k]");
        assert_eq!(clean.get("x-plain").unwrap(), "fine");
    }
}
