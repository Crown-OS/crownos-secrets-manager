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
