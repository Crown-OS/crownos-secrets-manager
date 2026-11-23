use std::fmt::Write as _;

use crate::ProxyError;

/// 32 random bytes as 64 hex characters.
pub(crate) fn random_token() -> Result<String, ProxyError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| ProxyError::Random)?;
    let mut token = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    Ok(token)
}

/// Compares in time that does not depend on where the texts differ.
pub(crate) fn same_token(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0u8, |difference, (left, right)| difference | (left ^ right))
            == 0
}
