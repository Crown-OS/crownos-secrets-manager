//! Moves a secret value from the CLI to the daemon through a pipe.
//!
//! crownos-ipc keeps message bytes in buffers that it does not zero. A pipe keeps the value out of
//! those buffers: the CLI writes the value and closes its end, then sends the read end with the
//! message. The daemon reads it into a buffer that is zeroed on drop.

use std::os::fd::{AsFd, OwnedFd};

use rustix::fs::OFlags;
use rustix::io::Errno;
use rustix::pipe::{PipeFlags, pipe_with};
use secrecy::SecretSlice;
use secrets_core::MAX_VALUE_BYTES;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("a value is larger than {MAX_VALUE_BYTES} bytes")]
    TooLarge,
    #[error("the value is empty")]
    Empty,
    #[error("the sender did not close the value pipe")]
    PipeStillOpen,
    #[error("pipe: {0}")]
    Io(#[from] std::io::Error),
}

/// A pipe that holds `value`; send the returned read end.
///
/// # Errors
///
/// Fails when the value is empty or too large, or when the pipe cannot be made.
pub fn value_pipe(value: &[u8]) -> Result<OwnedFd, TransferError> {
    if value.is_empty() {
        return Err(TransferError::Empty);
    }
    if value.len() > MAX_VALUE_BYTES {
        return Err(TransferError::TooLarge);
    }
    let (read_end, write_end) = pipe_with(PipeFlags::CLOEXEC).map_err(std::io::Error::from)?;
    let mut rest = value;
    while !rest.is_empty() {
        let written = rustix::io::write(&write_end, rest).map_err(std::io::Error::from)?;
        rest = rest.get(written..).unwrap_or_default();
    }
    Ok(read_end)
}

/// Reads the whole value without waiting: the sender wrote it before it sent the pipe.
///
/// # Errors
///
/// Fails when the value is empty or too large, or when the write end is still open.
pub fn read_value(pipe: &impl AsFd) -> Result<SecretSlice<u8>, TransferError> {
    let flags = rustix::fs::fcntl_getfl(pipe).map_err(std::io::Error::from)?;
    rustix::fs::fcntl_setfl(pipe, flags | OFlags::NONBLOCK).map_err(std::io::Error::from)?;
    let mut buffer = Zeroizing::new(vec![0u8; MAX_VALUE_BYTES + 1]);
    let mut filled = 0;
    loop {
        let Some(free) = buffer.get_mut(filled..) else {
            return Err(TransferError::TooLarge);
        };
        if free.is_empty() {
            return Err(TransferError::TooLarge);
        }
        match rustix::io::read(pipe, free) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => return Err(TransferError::PipeStillOpen),
            Err(errno) => return Err(std::io::Error::from(errno).into()),
        }
    }
    match buffer.get(..filled) {
        Some([]) | None => Err(TransferError::Empty),
        Some(value) => Ok(SecretSlice::from(value.to_vec())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use secrecy::ExposeSecret as _;

    use super::*;

    #[test]
    fn a_value_arrives_whole() {
        let pipe = value_pipe(b"s3cret").unwrap();
        assert_eq!(read_value(&pipe).unwrap().expose_secret(), b"s3cret");
    }

    #[test]
    fn the_largest_value_fits_and_a_larger_one_is_refused() {
        let largest = vec![7u8; MAX_VALUE_BYTES];
        let pipe = value_pipe(&largest).unwrap();
        assert_eq!(
            read_value(&pipe).unwrap().expose_secret().len(),
            MAX_VALUE_BYTES
        );
        assert!(matches!(
            value_pipe(&[0u8; MAX_VALUE_BYTES + 1]),
            Err(TransferError::TooLarge)
        ));
    }

    #[test]
    fn an_open_write_end_does_not_block_the_reader() {
        let (read_end, _write_end) = pipe_with(PipeFlags::CLOEXEC).unwrap();
        assert!(matches!(
            read_value(&read_end),
            Err(TransferError::PipeStillOpen)
        ));
    }
}
