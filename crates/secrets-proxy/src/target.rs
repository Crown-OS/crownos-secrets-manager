//! The request inside a tunnel must go to the tunnel's host, with a path that means one thing.

use http::Request;
use http::header::{self, HeaderValue};
use http::uri::{PathAndQuery, Uri};

use crate::tunnel::host_of;

/// Makes the request origin-form with `Host` set to the tunnel host, after a check that an
/// absolute URI or a `Host` header names that host and no other. Returns the path to match.
pub(crate) fn pin_to_tunnel<Body>(
    request: &mut Request<Body>,
    authority: &str,
) -> Result<String, &'static str> {
    if let Some(requested) = request.uri().authority()
        && !same_authority(requested.as_str(), authority)
    {
        return Err("the request names another host than the tunnel\n");
    }
    if let Some(host) = request.headers().get(header::HOST) {
        let host = host
            .to_str()
            .map_err(|_| "the Host header is not valid\n")?;
        if !same_authority(host, authority) {
            return Err("the Host header names another host than the tunnel\n");
        }
    }
    let path_and_query = request
        .uri()
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    let path = path_and_query.path().to_owned();
    if !is_canonical_path(&path) {
        return Err("the path has dot segments, empty segments or encoded separators\n");
    }
    *request.uri_mut() = Uri::from(path_and_query);
    let host_header = HeaderValue::from_str(&host_header_for(authority))
        .map_err(|_| "the tunnel host is not a valid Host header\n")?;
    request.headers_mut().insert(header::HOST, host_header);
    Ok(path)
}

/// `host` or `host:port` against the tunnel's `host:port`; port 443 may be left out.
fn same_authority(named: &str, tunnel: &str) -> bool {
    let tunnel_host = host_of(tunnel);
    let tunnel_port = tunnel.rsplit_once(':').map_or("443", |(_, port)| port);
    let (named_host, named_port) = match named.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(':') && !port.contains(']') => (host_of(named), port),
        _ => (host_of(named), "443"),
    };
    named_host.eq_ignore_ascii_case(tunnel_host) && named_port == tunnel_port
}

fn host_header_for(authority: &str) -> String {
    match authority.rsplit_once(':') {
        Some((host, "443")) => host.to_owned(),
        _ => authority.to_owned(),
    }
}

/// No `.` or `..` segment, no empty segment, and no encoded `.`, `/` or `\`, so a binding for
/// `/v1/*` cannot reach `/v1/../admin`.
fn is_canonical_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let encoded_separator = ["%2e", "%2f", "%5c"]
        .iter()
        .any(|code| lower.contains(code));
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    let last = segments.len().saturating_sub(1);
    let bad_segment = segments.iter().enumerate().any(|(index, segment)| {
        matches!(*segment, "." | "..") || (segment.is_empty() && index != last)
    });
    path.starts_with('/') && !encoded_separator && !path.contains('\\') && !bad_segment
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn only_canonical_paths_pass() {
        for good in ["/", "/v1/echo", "/v1/echo/", "/repos/a/b"] {
            assert!(is_canonical_path(good), "{good}");
        }
        for bad in [
            "/v1/../admin",
            "/v1/./x",
            "//v1",
            "/v1//x",
            "/v1/%2e%2e/admin",
            "/v1%2Fx",
            "/v1\\x",
            "v1",
        ] {
            assert!(!is_canonical_path(bad), "{bad}");
        }
    }

    #[test]
    fn authorities_compare_with_the_default_port() {
        assert!(same_authority("api.example.com", "api.example.com:443"));
        assert!(same_authority("API.example.com:443", "api.example.com:443"));
        assert!(!same_authority("other.example.com", "api.example.com:443"));
        assert!(!same_authority(
            "api.example.com:8443",
            "api.example.com:443"
        ));
        assert!(same_authority("localhost:8443", "localhost:8443"));
    }

    #[test]
    fn a_request_is_pinned_to_the_tunnel() {
        let mut request = Request::builder()
            .uri("/v1/echo?x=1")
            .header("host", "localhost:8443")
            .body(())
            .unwrap();
        assert_eq!(
            pin_to_tunnel(&mut request, "localhost:8443").unwrap(),
            "/v1/echo"
        );
        assert_eq!(request.uri(), "/v1/echo?x=1");
        let mut other = Request::builder()
            .uri("https://evil.example/v1/echo")
            .body(())
            .unwrap();
        assert!(pin_to_tunnel(&mut other, "localhost:8443").is_err());
        let mut virtual_host = Request::builder()
            .uri("/v1/echo")
            .header("host", "admin.localhost:8443")
            .body(())
            .unwrap();
        assert!(pin_to_tunnel(&mut virtual_host, "localhost:8443").is_err());
    }
}
