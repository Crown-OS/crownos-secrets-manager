//! The first hop: a `CONNECT` with the session token, to a host that the session may reach.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::util::basic_auth::token_from_header;
use crate::{Shared, audit, tunnel};

pub(crate) type ProxyBody = BoxBody<Bytes, hyper::Error>;

pub(crate) async fn accept_clients(listener: TcpListener, shared: Arc<Shared>) {
    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            continue;
        };
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let service = service_fn(move |request| handle_connect(Arc::clone(&shared), request));
            let served = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await;
            if let Err(error) = served {
                tracing::debug!(%error, "proxy client connection ended");
            }
        });
    }
}

pub(crate) fn plain_response(status: StatusCode, text: &'static str) -> Response<ProxyBody> {
    let mut response = Response::new(
        Full::new(Bytes::from_static(text.as_bytes()))
            .map_err(|never: Infallible| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response
}

async fn handle_connect(
    shared: Arc<Shared>,
    request: Request<Incoming>,
) -> Result<Response<ProxyBody>, Infallible> {
    if request.method() != Method::CONNECT {
        return Ok(plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "this proxy only tunnels HTTPS with CONNECT\n",
        ));
    }
    let token = request
        .headers()
        .get(header::PROXY_AUTHORIZATION)
        .and_then(|value| token_from_header(value.as_bytes()));
    let Some((token, session)) = token.and_then(|token| {
        let session = shared.sessions.find(&token, Instant::now())?;
        Some((token, session))
    }) else {
        let mut response = plain_response(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "the session is unknown or over\n",
        );
        response.headers_mut().insert(
            header::PROXY_AUTHENTICATE,
            header::HeaderValue::from_static("Basic realm=\"crownos-secrets\""),
        );
        return Ok(response);
    };
    let Some(authority) = request
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_owned())
    else {
        return Ok(plain_response(
            StatusCode::BAD_REQUEST,
            "CONNECT needs host:port\n",
        ));
    };
    if !session.allows_authority(&authority) {
        audit::connect_refused(&session.actor, &authority);
        return Ok(plain_response(
            StatusCode::FORBIDDEN,
            "no secret of this session is bound to this host\n",
        ));
    }
    tokio::spawn(async move {
        match hyper::upgrade::on(request).await {
            Ok(upgraded) => tunnel::serve(shared, token, authority, upgraded).await,
            Err(error) => tracing::debug!(%error, "the CONNECT upgrade failed"),
        }
    });
    Ok(Response::new(
        http_body_util::Empty::new()
            .map_err(|never: Infallible| match never {})
            .boxed(),
    ))
}
