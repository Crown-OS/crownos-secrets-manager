//! `host:port` text, as in a CONNECT request or an HTTP binding.

/// The host part of `host:port`, without the brackets of an IPv6 address.
pub fn host_of(authority: &str) -> &str {
    let host = authority
        .rsplit_once(':')
        .filter(|(host, _port)| !host.ends_with(':') && !host.is_empty())
        .map_or(authority, |(host, _port)| host);
    host.trim_start_matches('[').trim_end_matches(']')
}

/// The port of `host:port`, or 443 when there is none.
pub fn port_of(authority: &str) -> &str {
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(':') && !host.is_empty() && !port.contains(']') => {
            port
        }
        _ => "443",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_port_split_with_the_default_port() {
        assert_eq!(host_of("api.github.com:443"), "api.github.com");
        assert_eq!(host_of("[::1]:8443"), "::1");
        assert_eq!(host_of("localhost"), "localhost");
        assert_eq!(port_of("localhost"), "443");
        assert_eq!(port_of("localhost:8443"), "8443");
        assert_eq!(port_of("[::1]:8443"), "8443");
    }
}
