use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// The user name in the proxy URL. The token is the password.
pub(crate) const USER: &str = "crownos";

/// The token from a `Proxy-Authorization: Basic <base64(user:token)>` header.
pub(crate) fn token_from_header(header: &[u8]) -> Option<String> {
    let encoded = header.strip_prefix(b"Basic ")?;
    let decoded = STANDARD.decode(encoded.trim_ascii()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, token) = decoded.split_once(':')?;
    (user == USER).then(|| token.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_token_of_the_proxy_user_only() {
        let header = format!("Basic {}", STANDARD.encode("crownos:abc"));
        assert_eq!(token_from_header(header.as_bytes()).unwrap(), "abc");
        let other = format!("Basic {}", STANDARD.encode("someone:abc"));
        assert!(token_from_header(other.as_bytes()).is_none());
        assert!(token_from_header(b"Bearer abc").is_none());
    }
}
